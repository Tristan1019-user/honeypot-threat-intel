"""
Session assembly + enrichment pipeline.

Reads Cowrie JSON logs, assembles complete attack sessions,
enriches via Ollama AI, generates STIX bundles, stores in SQLite.
"""

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

from . import database as db
from .enrichment import enrich_session, enrich_ip_geo
from .stix import session_to_stix_bundle

logger = logging.getLogger(__name__)

# Internal IPs to scrub from output
INTERNAL_IP_PATTERN = re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
SENSOR_NAME = "honeypot-svr04"

DEFAULT_STATE_PATH = "/data/pipeline_state.json"


def _load_state(state_path: str) -> dict:
    """Load pipeline state (last processed file + offset)."""
    try:
        with open(state_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"last_file": None, "last_line_offset": 0, "last_run": None, "sessions_processed": 0}


def _save_state(state_path: str, state: dict):
    """Save pipeline state."""
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)


def _scrub_internal_ips(obj):
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


def read_new_events(log_path: str, offset: int, last_file: str = None) -> tuple[list[dict], int, str]:
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

    # Find where to start reading
    start_idx = 0
    if last_file:
        try:
            start_idx = files.index(last_file)
        except ValueError:
            # Last file no longer exists (deleted/archived), start from beginning
            logger.warning(f"Last processed file {last_file} not found, scanning all files")
            start_idx = 0
            current_offset = 0

    for file_path in files[start_idx:]:
        file_offset = current_offset if file_path == last_file else 0

        try:
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


def assemble_sessions(events: list[dict]) -> list[dict]:
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


def _build_session(session_id: str, events: list[dict]) -> Optional[dict]:
    """Build a session dict from a list of events for that session."""
    session = {
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
    db_path: Optional[str] = None,
) -> dict:
    """
    Main pipeline entry point.

    1. Read new events from cowrie.json since last offset
    2. Assemble into sessions
    3. Enrich each session via Ollama AI
    4. Generate STIX bundles
    5. Store in SQLite

    Returns summary dict with counts.
    """
    from datetime import datetime, timezone

    if db_path:
        import os
        os.environ["DATABASE_PATH"] = db_path

    # Ensure DB exists
    await db.init_db()

    # Load state
    state = _load_state(state_path)
    offset = state.get("last_line_offset", 0)
    last_file = state.get("last_file")

    # Read new events (handles log rotation)
    events, new_offset, current_file = read_new_events(log_path, offset, last_file)
    if not events:
        logger.info(f"No new events since {last_file}:{offset}")
        return {"new_events": 0, "sessions_assembled": 0, "sessions_enriched": 0}

    logger.info(f"Read {len(events)} new events (file {current_file}, offset {new_offset})")

    # Assemble sessions
    sessions = assemble_sessions(events)
    logger.info(f"Assembled {len(sessions)} sessions")

    enriched_count = 0
    for session in sessions:
        try:
            # Enrich via AI
            enrichment = await enrich_session(session)
            session.update(enrichment)

            # Geo enrichment
            geo = await enrich_ip_geo(session["src_ip"])
            session.update(geo)

            # Generate STIX bundle
            stix_bundle = session_to_stix_bundle(session)
            session["stix_bundle"] = stix_bundle

            # Store session
            await db.insert_session(session)

            # Store indicators
            # IP indicator
            await db.upsert_indicator({
                "id": f"indicator-ip-{session['src_ip']}",
                "session_id": session["session_id"],
                "type": "ipv4-addr",
                "value": session["src_ip"],
                "first_seen": session["timestamp_start"],
                "last_seen": session["timestamp_start"],
                "threat_level": session.get("threat_level"),
            })

            # Credential indicators
            for cred in session.get("credentials_attempted", []):
                cred_str = f"{cred['username']}:{cred['password']}"
                await db.upsert_indicator({
                    "id": f"indicator-cred-{cred_str}",
                    "session_id": session["session_id"],
                    "type": "credential",
                    "value": cred_str,
                    "first_seen": session["timestamp_start"],
                    "last_seen": session["timestamp_start"],
                    "threat_level": session.get("threat_level"),
                })

            # Download/malware indicators
            for dl in session.get("downloads", []):
                if dl.get("sha256"):
                    await db.insert_malware({
                        "sha256": dl["sha256"],
                        "session_id": session["session_id"],
                        "url": dl.get("url"),
                        "first_seen": session["timestamp_start"],
                    })
                    await db.upsert_indicator({
                        "id": f"indicator-hash-{dl['sha256'][:32]}",
                        "session_id": session["session_id"],
                        "type": "file-hash",
                        "value": dl["sha256"],
                        "first_seen": session["timestamp_start"],
                        "last_seen": session["timestamp_start"],
                        "threat_level": session.get("threat_level"),
                    })
                if dl.get("url"):
                    await db.upsert_indicator({
                        "id": f"indicator-url-{dl['url'][:64]}",
                        "session_id": session["session_id"],
                        "type": "url",
                        "value": dl["url"],
                        "first_seen": session["timestamp_start"],
                        "last_seen": session["timestamp_start"],
                        "threat_level": session.get("threat_level"),
                    })

            enriched_count += 1

        except Exception as e:
            logger.error(f"Failed to process session {session.get('session_id')}: {e}")

    # Save state
    state["last_file"] = current_file
    state["last_line_offset"] = new_offset
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    state["sessions_processed"] = state.get("sessions_processed", 0) + enriched_count
    _save_state(state_path, state)

    result = {
        "new_events": len(events),
        "sessions_assembled": len(sessions),
        "sessions_enriched": enriched_count,
        "new_offset": new_offset,
    }
    logger.info(f"Pipeline complete: {result}")
    return result
