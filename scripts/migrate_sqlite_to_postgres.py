#!/usr/bin/env python3
"""
migrate_sqlite_to_postgres.py
------------------------------
One-shot migration: copy all data from an existing SQLite database into
the production Postgres instance.

Usage:
    python3 scripts/migrate_sqlite_to_postgres.py \
        --sqlite-path ./data/threat_intel.db \
        --postgres-url "postgresql://threatintel:SECRET@127.0.0.1:5432/threat_intel" \
        [--dry-run]

Flags:
    --dry-run   Read SQLite and Postgres, compare counts, print summary — no writes.
    --batch     Batch insert size (default: 500).

Exit codes:
    0  — success (or dry-run with matching counts)
    1  — row count mismatch or error
"""

import argparse
import json
import sqlite3
import sys
from typing import Any

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 is required. pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Postgres schema (mirrors app/database.py _PG_DDL)
# --------------------------------------------------------------------------- #

PG_DDL = [
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id               TEXT PRIMARY KEY,
        src_ip           TEXT NOT NULL,
        src_port         INTEGER,
        timestamp_start  TEXT NOT NULL,
        timestamp_end    TEXT,
        duration_seconds DOUBLE PRECISION,
        ssh_client       TEXT,
        hassh            TEXT,
        attack_type      TEXT,
        threat_level     TEXT,
        mitre_techniques TEXT,
        summary          TEXT,
        stix_bundle      TEXT,
        raw_session      TEXT,
        created_at       TEXT,
        enriched_at      TEXT,
        asn              TEXT,
        org              TEXT,
        country          TEXT,
        cloud_provider   TEXT,
        observed_features TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS indicators (
        id             TEXT PRIMARY KEY,
        session_id     TEXT REFERENCES sessions(id),
        type           TEXT NOT NULL,
        value          TEXT NOT NULL,
        first_seen     TEXT,
        last_seen      TEXT,
        times_seen     INTEGER DEFAULT 1,
        threat_level   TEXT,
        stix_object    TEXT,
        revoked        INTEGER DEFAULT 0,
        revoked_reason TEXT,
        UNIQUE (type, value)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS malware_samples (
        sha256              TEXT PRIMARY KEY,
        session_id          TEXT,
        url                 TEXT,
        size_bytes          INTEGER,
        file_type           TEXT,
        first_seen          TEXT,
        vt_detection_ratio  TEXT,
        stix_object         TEXT,
        vt_malware_families TEXT,
        vt_first_submission BIGINT,
        vt_known            INTEGER,
        vt_enriched_at      TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_src_ip  ON sessions(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_start   ON sessions(timestamp_start DESC)",
    "CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value)",
    "CREATE INDEX IF NOT EXISTS idx_indicators_last  ON indicators(last_seen DESC)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(type, value)",
]

PG_MIGRATIONS = [
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS asn TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS cloud_provider TEXT",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS observed_features TEXT",
    "ALTER TABLE indicators ADD COLUMN IF NOT EXISTS revoked INTEGER DEFAULT 0",
    "ALTER TABLE indicators ADD COLUMN IF NOT EXISTS revoked_reason TEXT",
    "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_detection_ratio TEXT",
    "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_malware_families TEXT",
    "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_first_submission BIGINT",
    "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_known INTEGER",
    "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_enriched_at TEXT",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(type, value)",
]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def sqlite_count(db: sqlite3.Connection, table: str) -> int:
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def pg_count(pg: Any, table: str) -> int:
    with pg.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0]


def init_pg_schema(pg: Any) -> None:
    with pg.cursor() as cur:
        for stmt in PG_DDL:
            cur.execute(stmt)
        for stmt in PG_MIGRATIONS:
            try:
                cur.execute(stmt)
            except Exception:
                pg.rollback()
    pg.commit()
    print("  Postgres schema initialised.")


def migrate_sessions(sqlite_db: sqlite3.Connection, pg: Any, batch_size: int, dry_run: bool) -> int:
    sqlite_db.row_factory = sqlite3.Row
    rows = sqlite_db.execute("SELECT * FROM sessions ORDER BY timestamp_start").fetchall()
    if dry_run:
        return len(rows)

    columns = [
        "id", "src_ip", "src_port", "timestamp_start", "timestamp_end",
        "duration_seconds", "ssh_client", "hassh", "attack_type", "threat_level",
        "mitre_techniques", "summary", "stix_bundle", "raw_session",
        "created_at", "enriched_at", "asn", "org", "country", "cloud_provider", "observed_features",
    ]
    col_str = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    upsert_sql = (
        f"INSERT INTO sessions ({col_str}) VALUES ({placeholders}) "
        f"ON CONFLICT (id) DO NOTHING"
    )

    inserted = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        values = [tuple(dict(r).get(c) for c in columns) for r in batch]
        with pg.cursor() as cur:
            psycopg2.extras.execute_batch(cur, upsert_sql, values)
        pg.commit()
        inserted += len(batch)
        print(f"  sessions: {inserted}/{len(rows)}", end="\r")
    print()
    return len(rows)


def migrate_indicators(sqlite_db: sqlite3.Connection, pg: Any, batch_size: int, dry_run: bool) -> int:
    sqlite_db.row_factory = sqlite3.Row
    rows = sqlite_db.execute("SELECT * FROM indicators").fetchall()
    if dry_run:
        return len(rows)

    columns = [
        "id", "session_id", "type", "value", "first_seen", "last_seen",
        "times_seen", "threat_level", "stix_object", "revoked", "revoked_reason",
    ]
    col_str = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    upsert_sql = (
        f"INSERT INTO indicators ({col_str}) VALUES ({placeholders}) "
        f"ON CONFLICT (type, value) DO UPDATE SET "
        f"times_seen = EXCLUDED.times_seen, "
        f"last_seen = EXCLUDED.last_seen, "
        f"threat_level = EXCLUDED.threat_level"
    )

    inserted = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        values = [tuple(dict(r).get(c) for c in columns) for r in batch]
        with pg.cursor() as cur:
            psycopg2.extras.execute_batch(cur, upsert_sql, values)
        pg.commit()
        inserted += len(batch)
        print(f"  indicators: {inserted}/{len(rows)}", end="\r")
    print()
    return len(rows)


def migrate_malware(sqlite_db: sqlite3.Connection, pg: Any, batch_size: int, dry_run: bool) -> int:
    sqlite_db.row_factory = sqlite3.Row
    rows = sqlite_db.execute("SELECT * FROM malware_samples").fetchall()
    if dry_run:
        return len(rows)

    columns = [
        "sha256", "session_id", "url", "size_bytes", "file_type", "first_seen",
        "vt_detection_ratio", "stix_object", "vt_malware_families",
        "vt_first_submission", "vt_known", "vt_enriched_at",
    ]
    col_str = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    upsert_sql = (
        f"INSERT INTO malware_samples ({col_str}) VALUES ({placeholders}) "
        f"ON CONFLICT (sha256) DO NOTHING"
    )

    inserted = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i : i + batch_size]
        values = [tuple(dict(r).get(c) for c in columns) for r in batch]
        with pg.cursor() as cur:
            psycopg2.extras.execute_batch(cur, upsert_sql, values)
        pg.commit()
        inserted += len(batch)
        print(f"  malware_samples: {inserted}/{len(rows)}", end="\r")
    print()
    return len(rows)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate SQLite → Postgres")
    parser.add_argument("--sqlite-path", required=True, help="Path to threat_intel.db")
    parser.add_argument("--postgres-url", required=True, help="Postgres DSN")
    parser.add_argument("--dry-run", action="store_true", help="Read-only: compare counts only")
    parser.add_argument("--batch", type=int, default=500, help="Insert batch size (default 500)")
    args = parser.parse_args()

    print(f"\n{'DRY RUN — ' if args.dry_run else ''}Migrating {args.sqlite_path} → Postgres")
    print("=" * 60)

    # Open connections
    sqlite_db = sqlite3.connect(args.sqlite_path)
    pg = psycopg2.connect(args.postgres_url)

    try:
        # Count SQLite source
        src_sessions   = sqlite_count(sqlite_db, "sessions")
        src_indicators = sqlite_count(sqlite_db, "indicators")
        src_malware    = sqlite_count(sqlite_db, "malware_samples")
        print(f"\nSource (SQLite):")
        print(f"  sessions:        {src_sessions:,}")
        print(f"  indicators:      {src_indicators:,}")
        print(f"  malware_samples: {src_malware:,}")

        if not args.dry_run:
            print("\nInitialising Postgres schema...")
            init_pg_schema(pg)

            print("\nMigrating data...")
            migrate_sessions(sqlite_db, pg, args.batch, dry_run=False)
            migrate_indicators(sqlite_db, pg, args.batch, dry_run=False)
            migrate_malware(sqlite_db, pg, args.batch, dry_run=False)

        # Verify
        dst_sessions   = pg_count(pg, "sessions")
        dst_indicators = pg_count(pg, "indicators")
        dst_malware    = pg_count(pg, "malware_samples")
        print(f"\n{'Counts after dry-run' if args.dry_run else 'Verification'}:")
        print(f"  {'Table':<20} {'SQLite':>12} {'Postgres':>12}  {'Match':>8}")
        print(f"  {'-'*56}")
        ok = True
        for name, src, dst in [
            ("sessions",        src_sessions,   dst_sessions),
            ("indicators",      src_indicators, dst_indicators),
            ("malware_samples", src_malware,    dst_malware),
        ]:
            match = "✓" if src == dst else "✗ MISMATCH"
            if src != dst:
                ok = False
            print(f"  {name:<20} {src:>12,} {dst:>12,}  {match:>8}")

        if args.dry_run:
            print("\n[DRY RUN] No data written.")
        elif ok:
            print("\n✓ Migration complete — all counts match.")
        else:
            print("\n✗ Count mismatch — check for duplicates or failed rows.", file=sys.stderr)
            return 1

    finally:
        sqlite_db.close()
        pg.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
