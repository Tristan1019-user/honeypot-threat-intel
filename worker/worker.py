import argparse
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

import ijson
import psycopg
from dateutil import parser as dt_parser
from psycopg.rows import dict_row
from taxii2client.v21 import Collection, Server

DB_CFG = {
    "host": os.getenv("DB_HOST", "postgres"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "stix"),
    "user": os.getenv("DB_USER", "stix"),
    "password": os.getenv("DB_PASSWORD", "stix_dev_change_me"),
}

INBOX = Path(os.getenv("STIX_INBOX_DIR", "/data/inbox"))
ARCHIVE = Path(os.getenv("STIX_ARCHIVE_DIR", "/data/archive"))
QUAR = Path(os.getenv("STIX_QUARANTINE_DIR", "/data/quarantine"))
BATCH_SIZE = int(os.getenv("STIX_BATCH_SIZE", "500"))
MAX_FILE_MB = int(os.getenv("STIX_MAX_FILE_MB", "1024"))
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "30"))

TAXII_ENABLED = os.getenv("TAXII_ENABLED", "false").lower() == "true"
TAXII_DISCOVERY_URL = os.getenv("TAXII_DISCOVERY_URL", "").strip()
TAXII_API_ROOT = os.getenv("TAXII_API_ROOT", "").strip()
TAXII_COLLECTION_ID = os.getenv("TAXII_COLLECTION_ID", "").strip()
TAXII_USERNAME = os.getenv("TAXII_USERNAME", "").strip() or None
TAXII_PASSWORD = os.getenv("TAXII_PASSWORD", "").strip() or None
TAXII_TOKEN = os.getenv("TAXII_TOKEN", "").strip() or None
TAXII_VERIFY_TLS = os.getenv("TAXII_VERIFY_TLS", "true").lower() == "true"
TAXII_POLL_SECONDS = int(os.getenv("TAXII_POLL_SECONDS", "900"))
TAXII_BACKOFF_MIN_SECONDS = int(os.getenv("TAXII_BACKOFF_MIN_SECONDS", "60"))
TAXII_BACKOFF_MAX_SECONDS = int(os.getenv("TAXII_BACKOFF_MAX_SECONDS", "3600"))

TAXII_SOURCE_KEY = "taxii:" + (TAXII_COLLECTION_ID or "default")


def parse_ts(v):
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return dt_parser.isoparse(v)
    except Exception:
        return None


def stream_stix_objects(file_path: Path):
    with file_path.open("rb") as f:
        for obj in ijson.items(f, "objects.item"):
            yield obj


def upsert_batch(conn, batch: List[dict], source: str):
    upserted = 0
    skipped = 0
    errored = 0

    with conn.cursor() as cur:
        for obj in batch:
            try:
                otype = obj.get("type")
                oid = obj.get("id")
                if not otype or not oid:
                    skipped += 1
                    continue

                created = parse_ts(obj.get("created"))
                modified = parse_ts(obj.get("modified")) or created or datetime.now(timezone.utc)
                revoked = bool(obj.get("revoked", False))
                spec_version = obj.get("spec_version")

                cur.execute(
                    """
                    INSERT INTO stix_objects (id, type, spec_version, created, modified, revoked, source, object_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (id, modified) DO UPDATE
                    SET object_json = EXCLUDED.object_json,
                        revoked = EXCLUDED.revoked,
                        source = EXCLUDED.source,
                        last_seen_at = NOW()
                    """,
                    (
                        oid,
                        otype,
                        spec_version,
                        created,
                        modified,
                        revoked,
                        source,
                        json.dumps(obj),
                    ),
                )
                upserted += 1

                if otype == "relationship":
                    src = obj.get("source_ref")
                    tgt = obj.get("target_ref")
                    if src and tgt:
                        cur.execute(
                            """
                            INSERT INTO stix_relationships (rel_id, source_ref, target_ref, relationship_type, modified)
                            VALUES (%s,%s,%s,%s,%s)
                            ON CONFLICT (rel_id, modified) DO UPDATE
                            SET source_ref = EXCLUDED.source_ref,
                                target_ref = EXCLUDED.target_ref,
                                relationship_type = EXCLUDED.relationship_type
                            """,
                            (
                                oid,
                                src,
                                tgt,
                                obj.get("relationship_type"),
                                modified,
                            ),
                        )
            except Exception:
                errored += 1

    return upserted, skipped, errored


def start_run(conn, source: str):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "INSERT INTO ingest_runs (source, status) VALUES (%s, 'running') RETURNING run_id",
            (source,),
        )
        run_id = cur.fetchone()["run_id"]
    conn.commit()
    return run_id


def finish_run(conn, run_id, status, total, upserted, skipped, errored, summary):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ingest_runs
            SET ended_at = NOW(), status = %s, objects_total = %s, upserted = %s, skipped = %s, errored = %s,
                error_summary = %s::jsonb
            WHERE run_id = %s
            """,
            (status, total, upserted, skipped, errored, json.dumps(summary), run_id),
        )
    conn.commit()


def update_checkpoint(conn, source: str, run_id=None, added_after: Optional[datetime] = None):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingest_checkpoints (source, added_after, last_run_id, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (source) DO UPDATE
            SET added_after = EXCLUDED.added_after,
                last_run_id = EXCLUDED.last_run_id,
                updated_at = NOW()
            """,
            (source, added_after or datetime.now(timezone.utc), run_id),
        )
    conn.commit()


def get_checkpoint(conn, source: str) -> Optional[datetime]:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT added_after FROM ingest_checkpoints WHERE source = %s", (source,))
        row = cur.fetchone()
    if not row:
        return None
    return row["added_after"]


def process_objects(conn, source: str, objects: Iterable[dict], checkpoint_after: Optional[datetime] = None):
    run_id = start_run(conn, source)
    total = upserted = skipped = errored = 0
    started = time.time()

    try:
        batch: List[dict] = []
        max_modified = checkpoint_after

        for obj in objects:
            total += 1
            obj_mod = parse_ts(obj.get("modified"))
            if obj_mod and (max_modified is None or obj_mod > max_modified):
                max_modified = obj_mod

            batch.append(obj)
            if len(batch) >= BATCH_SIZE:
                u, s, e = upsert_batch(conn, batch, source)
                upserted += u
                skipped += s
                errored += e
                conn.commit()
                batch = []

        if batch:
            u, s, e = upsert_batch(conn, batch, source)
            upserted += u
            skipped += s
            errored += e
            conn.commit()

        status = "success" if errored == 0 else "partial"
        elapsed = max(time.time() - started, 0.001)
        finish_run(
            conn,
            run_id,
            status,
            total,
            upserted,
            skipped,
            errored,
            {
                "source": source,
                "duration_seconds": round(elapsed, 3),
                "objects_per_second": round(total / elapsed, 3),
            },
        )
        update_checkpoint(conn, source, run_id, added_after=max_modified or datetime.now(timezone.utc))
        print(f"[ok] {source}: total={total} upserted={upserted} skipped={skipped} errored={errored}")
        return True

    except Exception as e:
        conn.rollback()
        finish_run(
            conn,
            run_id,
            "fail",
            total,
            upserted,
            skipped,
            errored + 1,
            {"source": source, "error": str(e)},
        )
        print(f"[fail] {source}: {e}")
        return False


def process_file(conn, file_path: Path):
    source = f"file:{file_path.name}"
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > MAX_FILE_MB:
            raise RuntimeError(f"file too large ({size_mb:.1f} MB > {MAX_FILE_MB} MB)")

        ok = process_objects(conn, source, stream_stix_objects(file_path))
        if ok:
            ARCHIVE.mkdir(parents=True, exist_ok=True)
            shutil.move(str(file_path), str(ARCHIVE / file_path.name))
        else:
            QUAR.mkdir(parents=True, exist_ok=True)
            shutil.move(str(file_path), str(QUAR / file_path.name))

    except Exception as e:
        QUAR.mkdir(parents=True, exist_ok=True)
        shutil.move(str(file_path), str(QUAR / file_path.name))
        print(f"[fail] {file_path.name}: {e}")


def taxii_collection() -> Collection:
    headers = {}
    if TAXII_TOKEN:
        headers["Authorization"] = f"Bearer {TAXII_TOKEN}"

    if TAXII_API_ROOT:
        return Collection(
            f"{TAXII_API_ROOT.rstrip('/')}/collections/{TAXII_COLLECTION_ID}/",
            user=TAXII_USERNAME,
            password=TAXII_PASSWORD,
            verify=TAXII_VERIFY_TLS,
            headers=headers or None,
        )

    if not TAXII_DISCOVERY_URL:
        raise RuntimeError("TAXII_DISCOVERY_URL or TAXII_API_ROOT is required when TAXII is enabled")

    server = Server(
        TAXII_DISCOVERY_URL,
        user=TAXII_USERNAME,
        password=TAXII_PASSWORD,
        verify=TAXII_VERIFY_TLS,
        headers=headers or None,
    )

    if not server.api_roots:
        raise RuntimeError("No TAXII API roots discovered")

    api_root = server.api_roots[0]
    for coll in api_root.collections:
        if coll.id == TAXII_COLLECTION_ID:
            return coll

    raise RuntimeError(f"Collection not found: {TAXII_COLLECTION_ID}")


def run_taxii_once(conn):
    if not TAXII_COLLECTION_ID:
        print("[taxii] TAXII_COLLECTION_ID is required")
        return False

    coll = taxii_collection()
    added_after = get_checkpoint(conn, TAXII_SOURCE_KEY)
    kwargs = {}
    if added_after:
        kwargs["added_after"] = added_after.astimezone(timezone.utc).isoformat()

    bundle = coll.get_objects(**kwargs)
    objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

    if not objects:
        print("[taxii] no new objects")
        # heartbeat checkpoint so stale detection can work
        update_checkpoint(conn, TAXII_SOURCE_KEY, added_after=datetime.now(timezone.utc))
        return True

    return process_objects(conn, TAXII_SOURCE_KEY, objects, checkpoint_after=added_after)


def run_files_once(conn):
    INBOX.mkdir(parents=True, exist_ok=True)
    files = sorted([p for p in INBOX.glob("*.json") if p.is_file()])
    for p in files:
        process_file(conn, p)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--taxii-once", action="store_true")
    args = parser.parse_args()

    conn = psycopg.connect(**DB_CFG)
    try:
        if args.taxii_once:
            run_taxii_once(conn)
            return

        if args.watch:
            last_taxii = 0
            taxii_backoff = TAXII_BACKOFF_MIN_SECONDS
            while True:
                run_files_once(conn)
                if TAXII_ENABLED:
                    now = time.time()
                    if now - last_taxii >= TAXII_POLL_SECONDS:
                        try:
                            ok = run_taxii_once(conn)
                            if ok:
                                taxii_backoff = TAXII_BACKOFF_MIN_SECONDS
                            last_taxii = now
                        except Exception as e:
                            print(f"[taxii] error: {e}; backing off {taxii_backoff}s")
                            time.sleep(taxii_backoff)
                            taxii_backoff = min(taxii_backoff * 2, TAXII_BACKOFF_MAX_SECONDS)
                            last_taxii = time.time()
                time.sleep(POLL_SECONDS)
        else:
            run_files_once(conn)
            if TAXII_ENABLED:
                run_taxii_once(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
