"""
Session assembly + enrichment pipeline.

Reads Cowrie JSON logs, assembles complete attack sessions,
enriches via Ollama AI, generates STIX bundles, stores in SQLite.
"""

import asyncio
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import database as db
from .enrichment import enrich_session, enrich_ip_geo, enrich_malware_vt
from .scrub import SENSOR_NAME  # single source of truth — do not redefine here
from .stix import session_to_stix_bundle

logger = logging.getLogger(__name__)

# Matches RFC-1918 IPs at the START of a string — used to filter session.src_ip.
# Intentionally different from scrub.INTERNAL_IP_RE which is a mid-text substitution
# regex with lookbehind/lookahead; this one only needs to match whole IP fields.
# Loopback (127.x) is excluded: Cowrie's src_ip is never localhost in practice.
INTERNAL_IP_PATTERN = re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)")

DEFAULT_STATE_PATH = "/data/pipeline_state.json"


@contextmanager
def _pipeline_file_lock(state_path: str):
    """Exclusive non-blocking file lock for multi-process safety.

    asyncio.Lock() (_PIPELINE_LOCK) guards within a single process/event loop.
    fcntl.flock(LOCK_NB) guards across processes (e.g. cron vs. manual API trigger).

    Raises OSError(errno.EWOULDBLOCK) if another process holds the lock — the caller
    should catch this and skip the run.

    Infrastructure errors (lock file dir doesn't exist, permissions) are logged
    as warnings and the lock is skipped (best-effort) so the pipeline still runs.
    The lock file is never deleted (avoids TOCTOU on reacquire).
    """
    lock_path = state_path + ".lock"
    fd = None
    try:
        fd = open(lock_path, "w")
    except OSError as e:
        # Can't create lock file (missing dir, permissions, read-only fs).
        # Log and proceed without the file lock — asyncio.Lock still guards
        # same-process concurrency.
        logger.warning("pipeline_file_lock: cannot open lock file %s (%s) — proceeding without file lock", lock_path, e)
        yield
        return

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as e:
        fd.close()
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise  # another process holds the lock — caller should skip this run
        # Other unexpected error (e.g. EBADF) — log and proceed best-effort
        logger.warning("pipeline_file_lock: flock failed (%s) — proceeding without file lock", e)
        yield
        return

    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        fd.close()

def _indicator_id(itype: str, value: str) -> str:
    """Generate a stable, collision-free indicator DB id from (type, value).

    Uses the first 32 hex chars of SHA-256(type:value) so the id is:
      - Globally unique per (type, value) pair
      - Fixed length regardless of URL or credential length
      - Backward-compatible with ON CONFLICT (type, value) DO UPDATE — the id
        is only used as the PRIMARY KEY; conflicts resolve on (type, value).

    Previous id format used truncated raw values (e.g. url[:64]), which could
    cause PRIMARY KEY collisions for URLs sharing a long common prefix.
    """
    sig = hashlib.sha256(f"{itype}:{value}".encode()).hexdigest()[:32]
    return f"indicator-{itype}-{sig}"


# Prevent concurrent pipeline runs from racing on the state file.
# Only one pipeline invocation runs at a time; concurrent callers queue.
# Note: this is an in-process lock. It does NOT protect against two separate
# OS processes (e.g. a manual CLI run alongside the FastAPI background task).
_PIPELINE_LOCK = asyncio.Lock()


def _load_state(state_path: str) -> dict:
    """Load pipeline state (last processed file + offset)."""
    try:
        with open(state_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_file": None, "last_line_offset": 0, "last_run": None, "sessions_processed": 0}


def _save_state(state_path: str, state: dict) -> None:
    """Save pipeline state atomically via write-then-rename.

    If the process is killed mid-write (OOM, SIGKILL), the existing state file
    is left intact rather than being truncated or partially overwritten.
    os.replace() is atomic on POSIX when src and dst are on the same filesystem.
    """
    p = Path(state_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(p)


def _scrub_internal_ips(obj: Any) -> Any:
    """Recursively scrub internal IPs from data structures."""
    if isinstance(obj, str):
        if INTERNAL_IP_PATTERN.match(obj):
            return SENSOR_NAME
        return obj
    elif isinstance(obj, dict):
        return {k: _scrub_internal_ips(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_scrub_internal_ips(v) for v in obj]
    return obj


def _get_log_files(log_path: str) -> list[str]:
    """
    Get all Cowrie log files in chronological order.

    Cowrie rotates daily: cowrie.json.YYYY-MM-DD (completed days) + cowrie.json (current).
    Returns sorted list with dated files first, then the current file last.
    """
    import glob
    base = Path(log_path)
    parent = base.parent
    name = base.name

    # Find all rotated files (cowrie.json.YYYY-MM-DD)
    rotated = sorted(glob.glob(str(parent / f"{name}.*")))
    # Filter to only date-stamped rotations (not .bak etc)
    rotated = [f for f in rotated if re.search(r'\.\d{4}-\d{2}-\d{2}$', f)]

    files = rotated
    # Add current file last (if it exists and has content)
    if base.exists() and base.stat().st_size > 0:
        files.append(str(base))

    return files


def read_new_events(log_path: str, offset: int, last_file: str | None = None) -> tuple[list[dict[str, Any]], int, str | None]:
    """
    Read new events from Cowrie log files, handling daily rotation.

    Tracks which file was last processed. When a new rotated file appears,
    reads it from the start. Continues reading the current file from offset.

    Returns (events, new_offset, current_file).
    """
    files = _get_log_files(log_path)
    if not files:
        logger.error(f"No log files found matching {log_path}")
        return [], 0, last_file

    events = []
    current_file = last_file
    current_offset = offset

    # Find where to start reading.
    # Compare by basename only so a Docker bind-mount path change (e.g. from
    # /data/logs/ to /cowrie/var/log/cowrie/) doesn't cause a full re-read.
    # _get_log_files() always returns absolute paths, so basename() is safe.
    file_basenames = [os.path.basename(f) for f in files]
    last_basename = os.path.basename(last_file) if last_file else None

    start_idx = 0
    if last_basename:
        try:
            start_idx = file_basenames.index(last_basename)
        except ValueError:
            # Last file no longer exists (deleted/archived), start from beginning
            logger.warning(f"Last processed file {last_file} not found in log dir, scanning all files")
            start_idx = 0
            current_offset = 0

    for file_path in files[start_idx:]:
        file_offset = current_offset if os.path.basename(file_path) == last_basename else 0

        try:
            # If the active log was truncated/rotated in place (same basename,
            # smaller line count), reset offset so new lines are not skipped forever.
            # Fast path: use file size as a cheap proxy before counting lines.
            # Cowrie JSON lines are typically 200-2000 bytes; 50 bytes/line is a
            # safe lower bound — if the file is too small to contain file_offset
            # lines even at minimum density, it was definitely truncated and a
            # full line-count confirms it. This avoids reading millions of lines
            # on every run just to detect a rare truncation event.
            _MIN_BYTES_PER_LINE = 50
            if file_offset > 0 and os.path.basename(file_path) == last_basename:
                try:
                    file_size = os.path.getsize(file_path)
                except OSError:
                    file_size = 0
                if file_size < file_offset * _MIN_BYTES_PER_LINE:
                    # File is suspiciously small — do the exact line count only now
                    with open(file_path) as probe:
                        line_count = sum(1 for _ in probe)
                    if line_count < file_offset:
                        logger.warning(
                            "Detected log truncation for %s (saved offset=%s, current lines=%s) — resetting offset to 0",
                            file_path,
                            file_offset,
                            line_count,
                        )
                        file_offset = 0
                        current_offset = 0

            with open(file_path) as f:
                for line_num, line in enumerate(f, 1):
                    if line_num <= file_offset:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError:
                        logger.warning(f"Skipping malformed JSON at {file_path}:{line_num}")
                    current_offset = line_num
            current_file = file_path
        except FileNotFoundError:
            logger.warning(f"Log file disappeared: {file_path}")
            continue

    return events, current_offset, current_file


def assemble_sessions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Group raw Cowrie events by session ID into assembled session dicts.

    Returns list of assembled sessions ready for enrichment.
    """
    session_events = defaultdict(list)
    for event in events:
        sid = event.get("session")
        if sid:
            session_events[sid].append(event)

    sessions = []
    for sid, evts in session_events.items():
        session = _build_session(sid, evts)
        if session:
            sessions.append(session)

    return sessions


def _build_session(session_id: str, events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Build a session dict from a list of events for that session."""
    session: dict[str, Any] = {
        "session_id": session_id,
        "src_ip": None,
        "src_port": None,
        "timestamp_start": None,
        "timestamp_end": None,
        "duration_seconds": None,
        "ssh_client": None,
        "hassh": None,
        "credentials_attempted": [],
        "commands": [],
        "downloads": [],
    }

    for evt in sorted(events, key=lambda e: e.get("timestamp", "")):
        eid = evt.get("eventid", "")
        ts = evt.get("timestamp")

        # Source IP (from any event)
        if evt.get("src_ip") and not INTERNAL_IP_PATTERN.match(evt["src_ip"]):
            session["src_ip"] = evt["src_ip"]
        if evt.get("src_port"):
            session["src_port"] = evt["src_port"]

        # Timestamps
        if ts:
            if not session["timestamp_start"] or ts < session["timestamp_start"]:
                session["timestamp_start"] = ts
            if not session["timestamp_end"] or ts > session["timestamp_end"]:
                session["timestamp_end"] = ts

        # Session events
        if eid == "cowrie.session.connect":
            pass  # Already handled src_ip/timestamp

        elif eid == "cowrie.session.closed":
            duration = evt.get("duration")
            if duration:
                try:
                    session["duration_seconds"] = float(duration)
                except (ValueError, TypeError):
                    pass

        elif eid == "cowrie.client.version":
            session["ssh_client"] = evt.get("version")

        elif eid == "cowrie.client.kex":
            session["hassh"] = evt.get("hassh")

        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            session["credentials_attempted"].append({
                "username": evt.get("username", ""),
                "password": evt.get("password", ""),
                "success": eid == "cowrie.login.success",
            })

        elif eid == "cowrie.command.input":
            cmd = evt.get("input", "").strip()
            if cmd:
                session["commands"].append(cmd)

        elif eid == "cowrie.session.file_download":
            session["downloads"].append({
                "url": evt.get("url", ""),
                "sha256": evt.get("shasum", ""),
            })

    # Skip sessions with no source IP (shouldn't happen, but safety)
    if not session["src_ip"]:
        return None

    return session


async def process_cowrie_log(
    log_path: str,
    state_path: str = DEFAULT_STATE_PATH,
    db_path: str | None = None,
) -> dict:
    """Main pipeline entry point.

    1. Read new events from cowrie.json since last offset
    2. Assemble into sessions
    3. Enrich each session via Ollama AI + geo
    4. Generate STIX bundles
    5. Store in DB; defer VT enrichment after all sessions complete
    6. Run VT enrichment (15s/sample sleep outside of session loop)

    Returns summary dict with counts.
    Only one pipeline run executes at a time:
    - _PIPELINE_LOCK (asyncio.Lock) prevents same-process concurrent runs.
    - _pipeline_file_lock (fcntl.LOCK_EX|LOCK_NB) prevents cross-process races,
      e.g., a cron job starting while a manual API trigger is running.
    """
    async with _PIPELINE_LOCK:
        try:
            with _pipeline_file_lock(state_path):
                return await _run_pipeline(log_path, state_path, db_path)
        except OSError as e:
            if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                logger.warning(
                    "process_cowrie_log: another process holds the pipeline file lock — "
                    "skipping this run to avoid state corruption"
                )
                return {"new_events": 0, "sessions_assembled": 0, "sessions_enriched": 0, "skipped": "locked"}
            raise  # unexpected OSError — propagate


async def _run_pipeline(
    log_path: str,
    state_path: str = DEFAULT_STATE_PATH,
    db_path: str | None = None,
) -> dict:
    """Internal pipeline implementation — called under _PIPELINE_LOCK."""
    from datetime import datetime, timezone

    if db_path:
        if db._is_postgres():
            logger.warning(
                "db_path=%r passed to process_cowrie_log but DATABASE_URL is set — "
                "db_path is ignored in Postgres mode. Use DATABASE_PATH env var for SQLite fallback.",
                db_path,
            )
        else:
            os.environ["DATABASE_PATH"] = db_path

    # Ensure DB exists
    await db.init_db()

    # Load state
    state = _load_state(state_path)
    offset = state.get("last_line_offset", 0)
    last_file = state.get("last_file")
    if not isinstance(last_file, str):
        last_file = None

    # Read new events (handles log rotation)
    events, new_offset, current_file = read_new_events(log_path, offset, last_file)
    if not events:
        logger.info(f"No new events since {last_file}:{offset}")
        # Still record heartbeat so pipeline freshness reflects successful runs
        state["last_file"] = current_file or last_file
        state["last_line_offset"] = new_offset or offset
        state["last_run"] = datetime.now(timezone.utc).isoformat()
        state["sessions_processed"] = state.get("sessions_processed", 0)
        _save_state(state_path, state)
        return {"new_events": 0, "sessions_assembled": 0, "sessions_enriched": 0}

    logger.info(f"Read {len(events)} new events (file {current_file}, offset {new_offset})")

    # Assemble sessions
    sessions = assemble_sessions(events)
    logger.info(f"Assembled {len(sessions)} sessions")

    enriched_count = 0
    skipped_count = 0
    # Collect malware SHA-256s for VT enrichment after the main loop.
    # VT free tier requires a 15-second sleep between calls; running it inside the
    # per-session loop would block all session processing for 15s × N new samples.
    vt_pending: list[str] = []

    for session in sessions:
        try:
            # Skip sessions already in DB — avoids re-enriching on path reset or log re-read
            if await db.session_exists(session["session_id"]):
                skipped_count += 1
                continue

            # Enrich via AI
            enrichment = await enrich_session(session)
            session.update(enrichment)

            # Geo enrichment — check DB cache first to avoid redundant API calls
            # for IPs we've seen before (repeat attackers are common)
            geo = await db.get_cached_geo(session["src_ip"])
            if not geo:
                geo = await enrich_ip_geo(session["src_ip"])
            session.update(geo)

            # Generate STIX bundle
            stix_bundle = session_to_stix_bundle(session)
            session["stix_bundle"] = stix_bundle

            # Store session
            await db.insert_session(session)

            # Store indicators — _indicator_id() hashes (type, value) so IDs are
            # collision-free regardless of URL length or credential content.
            await db.upsert_indicator({
                "id": _indicator_id("ipv4-addr", session["src_ip"]),
                "session_id": session["session_id"],
                "type": "ipv4-addr",
                "value": session["src_ip"],
                "first_seen": session["timestamp_start"],
                "last_seen": session["timestamp_start"],
                "threat_level": session.get("threat_level"),
            })

            for cred in session.get("credentials_attempted", []):
                cred_str = f"{cred['username']}:{cred['password']}"
                await db.upsert_indicator({
                    "id": _indicator_id("credential", cred_str),
                    "session_id": session["session_id"],
                    "type": "credential",
                    "value": cred_str,
                    "first_seen": session["timestamp_start"],
                    "last_seen": session["timestamp_start"],
                    "threat_level": session.get("threat_level"),
                })

            for dl in session.get("downloads", []):
                if dl.get("sha256"):
                    await db.insert_malware({
                        "sha256": dl["sha256"],
                        "session_id": session["session_id"],
                        "url": dl.get("url"),
                        "first_seen": session["timestamp_start"],
                    })
                    # Layer 1 dedup: skip VT if already enriched in a prior run
                    # (ON CONFLICT DO NOTHING on insert means same sha256 can arrive
                    # from multiple sessions without re-triggering VT)
                    if not await db.is_malware_vt_enriched(dl["sha256"]):
                        vt_pending.append(dl["sha256"])
                    await db.upsert_indicator({
                        "id": _indicator_id("file-hash", dl["sha256"]),
                        "session_id": session["session_id"],
                        "type": "file-hash",
                        "value": dl["sha256"],
                        "first_seen": session["timestamp_start"],
                        "last_seen": session["timestamp_start"],
                        "threat_level": session.get("threat_level"),
                    })
                if dl.get("url"):
                    await db.upsert_indicator({
                        "id": _indicator_id("url", dl["url"]),
                        "session_id": session["session_id"],
                        "type": "url",
                        "value": dl["url"],
                        "first_seen": session["timestamp_start"],
                        "last_seen": session["timestamp_start"],
                        "threat_level": session.get("threat_level"),
                    })

            enriched_count += 1

        except Exception as e:
            err_str = str(e).lower()
            # Connectivity/pool errors are systemic — abort the run so subsequent
            # sessions don't all fail silently and advance the state file past them.
            if any(kw in err_str for kw in (
                "connection", "pool", "timeout", "ssl", "closed", "too many"
            )):
                logger.error(
                    "Systemic DB/network error on session %s — aborting pipeline run: %s",
                    session.get("session_id"), e,
                )
                raise
            # Session-level failure (AI parse error, malformed data, etc.) — skip and continue
            logger.error("Failed to process session %s — skipping: %s", session.get("session_id"), e)

    # VirusTotal enrichment — runs after all sessions so the 15s rate-limit sleep
    # doesn't block session enrichment.
    #
    # Two-layer dedup:
    #   Layer 1 (at collection): is_malware_vt_enriched() — skips samples already
    #     enriched in a prior pipeline run (cross-run dedup via vt_enriched_at column)
    #   Layer 2 (at processing): seen_vt set — deduplicates within this batch when
    #     multiple sessions in the same run downloaded the same file
    vt_enriched_count = 0
    seen_vt: set[str] = set()
    for sha256 in vt_pending:
        if sha256 in seen_vt:
            continue
        seen_vt.add(sha256)
        try:
            vt_data = await enrich_malware_vt(sha256)
            if vt_data:
                await db.update_malware_vt(sha256, vt_data)
                vt_enriched_count += 1
        except Exception as e:
            logger.error("VT enrichment failed for %s: %s", sha256[:16], e)

    # Save state
    now_iso = datetime.now(timezone.utc).isoformat()
    state["last_file"] = current_file
    state["last_line_offset"] = new_offset
    state["last_run"] = now_iso
    state["sessions_processed"] = state.get("sessions_processed", 0) + enriched_count
    # last_insert_at tracks when data was ACTUALLY written to the DB.
    # It differs from last_run when the pipeline runs but finds no new sessions
    # (zero-event heartbeat runs).  Use this for data-freshness alarms, not last_run.
    if enriched_count > 0:
        state["last_insert_at"] = now_iso
    _save_state(state_path, state)

    result = {
        "new_events": len(events),
        "sessions_assembled": len(sessions),
        "sessions_enriched": enriched_count,
        "sessions_skipped_dedup": skipped_count,
        "vt_samples_enriched": vt_enriched_count,
        "new_offset": new_offset,
    }
    logger.info(f"Pipeline complete: {result}")
    return result
