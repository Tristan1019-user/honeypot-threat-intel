"""SQLite database layer for the Threat Intel Feed."""

import json
import logging
import aiosqlite
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DATABASE_PATH = Path("/data/threat_intel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    timestamp_start TEXT NOT NULL,
    timestamp_end TEXT,
    duration_seconds REAL,
    ssh_client TEXT,
    hassh TEXT,
    attack_type TEXT,
    threat_level TEXT,
    mitre_techniques TEXT,
    summary TEXT,
    stix_bundle TEXT,
    raw_session TEXT,
    created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    enriched_at TEXT,
    asn TEXT,
    org TEXT,
    country TEXT,
    cloud_provider TEXT,
    observed_features TEXT
);

CREATE TABLE IF NOT EXISTS indicators (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(id),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    times_seen INTEGER DEFAULT 1,
    threat_level TEXT,
    stix_object TEXT,
    revoked INTEGER DEFAULT 0,
    revoked_reason TEXT
);

CREATE TABLE IF NOT EXISTS malware_samples (
    sha256 TEXT PRIMARY KEY,
    session_id TEXT,
    url TEXT,
    size_bytes INTEGER,
    file_type TEXT,
    first_seen TEXT,
    vt_detection_ratio TEXT,
    stix_object TEXT
);

CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_attack_type ON sessions(attack_type);
CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp_start);
"""


def _get_db_path() -> str:
    """Return the database path, using env override if set."""
    import os
    return os.environ.get("DATABASE_PATH", str(DATABASE_PATH))


async def get_db() -> aiosqlite.Connection:
    """Get a database connection."""
    db = await aiosqlite.connect(_get_db_path())
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


MIGRATIONS = [
    "ALTER TABLE sessions ADD COLUMN asn TEXT",
    "ALTER TABLE sessions ADD COLUMN org TEXT",
    "ALTER TABLE sessions ADD COLUMN country TEXT",
    "ALTER TABLE sessions ADD COLUMN cloud_provider TEXT",
    "ALTER TABLE indicators ADD COLUMN revoked INTEGER DEFAULT 0",
    "ALTER TABLE indicators ADD COLUMN revoked_reason TEXT",
    "ALTER TABLE sessions ADD COLUMN observed_features TEXT",
]


async def init_db():
    """Initialize the database schema and run migrations."""
    db_path = _get_db_path()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    db = await get_db()
    try:
        await db.executescript(SCHEMA)
        # Run migrations (ignore errors for already-applied)
        for sql in MIGRATIONS:
            try:
                await db.execute(sql)
            except Exception:
                pass
        await db.commit()
        logger.info(f"Database initialized at {db_path}")
    finally:
        await db.close()


async def insert_session(session: dict) -> str:
    """Insert an enriched session. Returns session id."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT OR REPLACE INTO sessions
               (id, src_ip, src_port, timestamp_start, timestamp_end,
                duration_seconds, ssh_client, hassh, attack_type, threat_level,
                mitre_techniques, summary, stix_bundle, raw_session, enriched_at,
                asn, org, country, cloud_provider, observed_features)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?, ?, ?, ?, ?)""",
            (
                session["session_id"],
                session.get("src_ip"),
                session.get("src_port"),
                session.get("timestamp_start"),
                session.get("timestamp_end"),
                session.get("duration_seconds"),
                session.get("ssh_client"),
                session.get("hassh"),
                session.get("attack_type"),
                session.get("threat_level"),
                json.dumps(session.get("mitre_techniques", [])),
                session.get("summary"),
                json.dumps(session.get("stix_bundle")) if session.get("stix_bundle") else None,
                json.dumps(session),
                session.get("asn"),
                session.get("org"),
                session.get("country"),
                session.get("cloud_provider"),
                json.dumps(session.get("observed_features")) if session.get("observed_features") else None,
            ),
        )
        await db.commit()
        return session["session_id"]
    finally:
        await db.close()


async def upsert_indicator(indicator: dict):
    """Insert or update an indicator, incrementing times_seen."""
    db = await get_db()
    try:
        existing = await db.execute_fetchall(
            "SELECT times_seen, first_seen FROM indicators WHERE type=? AND value=?",
            (indicator["type"], indicator["value"]),
        )
        if existing:
            row = existing[0]
            await db.execute(
                """UPDATE indicators SET times_seen=?, last_seen=?, threat_level=?,
                   session_id=?, stix_object=? WHERE type=? AND value=?""",
                (
                    row[0] + 1,
                    indicator.get("last_seen"),
                    indicator.get("threat_level"),
                    indicator.get("session_id"),
                    json.dumps(indicator.get("stix_object")) if indicator.get("stix_object") else None,
                    indicator["type"],
                    indicator["value"],
                ),
            )
        else:
            await db.execute(
                """INSERT INTO indicators (id, session_id, type, value, first_seen,
                   last_seen, times_seen, threat_level, stix_object)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (
                    indicator["id"],
                    indicator.get("session_id"),
                    indicator["type"],
                    indicator["value"],
                    indicator.get("first_seen"),
                    indicator.get("last_seen"),
                    indicator.get("threat_level"),
                    json.dumps(indicator.get("stix_object")) if indicator.get("stix_object") else None,
                ),
            )
        await db.commit()
    finally:
        await db.close()


async def insert_malware(sample: dict):
    """Insert a malware sample record."""
    db = await get_db()
    try:
        await db.execute(
            """INSERT OR IGNORE INTO malware_samples
               (sha256, session_id, url, size_bytes, file_type, first_seen, stix_object)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                sample["sha256"],
                sample.get("session_id"),
                sample.get("url"),
                sample.get("size_bytes"),
                sample.get("file_type"),
                sample.get("first_seen"),
                json.dumps(sample.get("stix_object")) if sample.get("stix_object") else None,
            ),
        )
        await db.commit()
    finally:
        await db.close()


# --- Query functions for API ---

async def query_sessions(
    since: Optional[str] = None,
    attack_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query sessions with optional filters."""
    db = await get_db()
    try:
        conditions = []
        params = []
        if since:
            conditions.append("timestamp_start >= ?")
            params.append(since)
        if attack_type:
            conditions.append("attack_type = ?")
            params.append(attack_type)
        if threat_level:
            levels = [l.strip() for l in threat_level.split(",")]
            placeholders = ",".join("?" * len(levels))
            conditions.append(f"threat_level IN ({placeholders})")
            params.extend(levels)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM sessions {where} ORDER BY timestamp_start DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await db.execute_fetchall(query, params)
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_session(session_id: str) -> Optional[dict]:
    """Get a single session by ID."""
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT * FROM sessions WHERE id=?", (session_id,))
        return dict(rows[0]) if rows else None
    finally:
        await db.close()


async def query_indicators(
    since: Optional[str] = None,
    indicator_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query indicators with optional filters."""
    db = await get_db()
    try:
        conditions = []
        params = []
        if since:
            conditions.append("first_seen >= ?")
            params.append(since)
        if indicator_type and indicator_type != "all":
            conditions.append("type = ?")
            params.append(indicator_type)
        if threat_level:
            levels = [l.strip() for l in threat_level.split(",")]
            placeholders = ",".join("?" * len(levels))
            conditions.append(f"threat_level IN ({placeholders})")
            params.extend(levels)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM indicators {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await db.execute_fetchall(query, params)
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def count_indicators(
    since: Optional[str] = None,
    indicator_type: Optional[str] = None,
    threat_level: Optional[str] = None,
) -> int:
    """Count indicators matching filters."""
    db = await get_db()
    try:
        conditions = []
        params = []
        if since:
            conditions.append("first_seen >= ?")
            params.append(since)
        if indicator_type and indicator_type != "all":
            conditions.append("type = ?")
            params.append(indicator_type)
        if threat_level:
            levels = [l.strip() for l in threat_level.split(",")]
            placeholders = ",".join("?" * len(levels))
            conditions.append(f"threat_level IN ({placeholders})")
            params.extend(levels)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = await db.execute_fetchall(f"SELECT COUNT(*) as c FROM indicators {where}", params)
        return rows[0][0]
    finally:
        await db.close()


async def count_sessions(
    since: Optional[str] = None,
    attack_type: Optional[str] = None,
    threat_level: Optional[str] = None,
) -> int:
    """Count sessions matching filters."""
    db = await get_db()
    try:
        conditions = []
        params = []
        if since:
            conditions.append("timestamp_start >= ?")
            params.append(since)
        if attack_type:
            conditions.append("attack_type = ?")
            params.append(attack_type)
        if threat_level:
            levels = [l.strip() for l in threat_level.split(",")]
            placeholders = ",".join("?" * len(levels))
            conditions.append(f"threat_level IN ({placeholders})")
            params.extend(levels)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = await db.execute_fetchall(f"SELECT COUNT(*) as c FROM sessions {where}", params)
        return rows[0][0]
    finally:
        await db.close()


async def lookup_indicator(value: str) -> list[dict]:
    """Look up all sessions involving a specific indicator value."""
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            """SELECT i.*, s.attack_type, s.summary, s.timestamp_start
               FROM indicators i
               LEFT JOIN sessions s ON i.session_id = s.id
               WHERE i.value = ?
               ORDER BY i.last_seen DESC""",
            (value,),
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_stats() -> dict:
    """Get dashboard statistics."""
    db = await get_db()
    try:
        total_sessions = (await db.execute_fetchall("SELECT COUNT(*) as c FROM sessions"))[0][0]
        total_indicators = (await db.execute_fetchall("SELECT COUNT(*) as c FROM indicators"))[0][0]
        total_malware = (await db.execute_fetchall("SELECT COUNT(*) as c FROM malware_samples"))[0][0]

        attack_types = await db.execute_fetchall(
            "SELECT attack_type, COUNT(*) as c FROM sessions WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY c DESC"
        )
        threat_levels = await db.execute_fetchall(
            "SELECT threat_level, COUNT(*) as c FROM sessions WHERE threat_level IS NOT NULL GROUP BY threat_level ORDER BY c DESC"
        )
        top_ips = await db.execute_fetchall(
            "SELECT src_ip, COUNT(*) as c FROM sessions GROUP BY src_ip ORDER BY c DESC LIMIT 20"
        )
        top_creds = await db.execute_fetchall(
            "SELECT value, times_seen FROM indicators WHERE type='credential' ORDER BY times_seen DESC LIMIT 20"
        )

        # MITRE technique frequency
        mitre_rows = await db.execute_fetchall(
            "SELECT mitre_techniques FROM sessions WHERE mitre_techniques IS NOT NULL"
        )
        mitre_counts = {}
        for row in mitre_rows:
            try:
                techniques = json.loads(row[0])
                for t in techniques:
                    mitre_counts[t] = mitre_counts.get(t, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        last_update = await db.execute_fetchall(
            "SELECT MAX(created_at) FROM sessions"
        )

        # Country distribution
        countries = await db.execute_fetchall(
            "SELECT country, COUNT(*) as c FROM sessions WHERE country IS NOT NULL AND country != '' GROUP BY country ORDER BY c DESC LIMIT 20"
        )

        # Top ASNs
        asns = await db.execute_fetchall(
            "SELECT asn, org, COUNT(*) as c FROM sessions WHERE asn IS NOT NULL AND asn != '' GROUP BY asn ORDER BY c DESC LIMIT 15"
        )

        # Recent sessions for live preview
        recent = await db.execute_fetchall(
            "SELECT id, src_ip, attack_type, threat_level, mitre_techniques, summary, timestamp_start, country, asn, org FROM sessions ORDER BY timestamp_start DESC LIMIT 3"
        )

        # Recent indicators for live preview
        recent_indicators = await db.execute_fetchall(
            "SELECT type, value, first_seen, last_seen, times_seen, threat_level FROM indicators WHERE type != 'credential' ORDER BY last_seen DESC LIMIT 5"
        )

        return {
            "total_sessions": total_sessions,
            "total_indicators": total_indicators,
            "total_malware_samples": total_malware,
            "attack_types": {r[0]: r[1] for r in attack_types},
            "threat_levels": {r[0]: r[1] for r in threat_levels},
            "top_source_ips": [{r[0]: r[1]} for r in top_ips],
            "top_credentials": [{r[0]: r[1]} for r in top_creds],
            "mitre_technique_frequency": dict(sorted(mitre_counts.items(), key=lambda x: -x[1])),
            "top_countries": {r[0]: r[1] for r in countries},
            "top_asns": [{"asn": r[0], "org": r[1], "count": r[2]} for r in asns],
            "recent_sessions": [dict(r) for r in recent],
            "recent_indicators": [dict(r) for r in recent_indicators],
            "last_update": _normalize_ts(last_update[0][0]) if last_update and last_update[0][0] else None,
        }
    finally:
        await db.close()


def _normalize_ts(ts: str) -> str:
    """Normalize timestamps to RFC 3339 (ISO 8601 with T and Z)."""
    if not ts:
        return ts
    # Handle 'YYYY-MM-DD HH:MM:SS' from old SQLite datetime('now')
    if " " in ts and "T" not in ts:
        ts = ts.replace(" ", "T") + "Z"
    # Ensure trailing Z if no timezone info
    if ts and not ts.endswith("Z") and "+" not in ts and "-" not in ts[10:]:
        ts += "Z"
    return ts


async def get_ip_sightings(ip: str) -> dict:
    """Get sighting count and date range for an IP."""
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            """SELECT COUNT(*) as sighting_count,
                      MIN(timestamp_start) as first_seen,
                      MAX(timestamp_start) as last_seen,
                      asn, org, country, cloud_provider
               FROM sessions WHERE src_ip = ?""",
            (ip,),
        )
        if rows and rows[0][0] > 0:
            r = rows[0]
            return {
                "ip": ip, "sighting_count": r[0], "first_seen": r[1], "last_seen": r[2],
                "asn": r[3], "org": r[4], "country": r[5], "cloud_provider": r[6],
            }
        return {"ip": ip, "sighting_count": 0}
    finally:
        await db.close()


async def revoke_indicator(value: str, reason: str = "false_positive") -> bool:
    """Mark an indicator as revoked. Returns True if found."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "UPDATE indicators SET revoked=1, revoked_reason=? WHERE value=?",
            (reason, value),
        )
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


async def unrevoke_indicator(value: str) -> bool:
    """Remove revocation from an indicator."""
    conn = await get_db()
    try:
        cursor = await conn.execute(
            "UPDATE indicators SET revoked=0, revoked_reason=NULL WHERE value=?",
            (value,),
        )
        await conn.commit()
        return cursor.rowcount > 0
    finally:
        await conn.close()


async def query_indicators_cursor(
    cursor: Optional[str] = None,
    indicator_type: Optional[str] = None,
    threat_level: Optional[str] = None,
    include_revoked: bool = False,
    limit: int = 100,
) -> tuple[list[dict], Optional[str]]:
    """Query indicators with cursor-based pagination. Returns (rows, next_cursor).
    Cursor is the rowid for monotonic ordering."""
    conn = await get_db()
    try:
        conditions = []
        params = []
        if cursor:
            conditions.append("rowid > ?")
            params.append(int(cursor))
        if indicator_type and indicator_type != "all":
            conditions.append("type = ?")
            params.append(indicator_type)
        if threat_level:
            levels = [l.strip() for l in threat_level.split(",")]
            placeholders = ",".join("?" * len(levels))
            conditions.append(f"threat_level IN ({placeholders})")
            params.extend(levels)
        if not include_revoked:
            conditions.append("(revoked = 0 OR revoked IS NULL)")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT rowid, * FROM indicators {where} ORDER BY rowid ASC LIMIT ?"
        params.append(limit + 1)  # fetch one extra to detect has_more

        rows = await conn.execute_fetchall(query, params)
        results = [dict(r) for r in rows[:limit]]
        next_cursor = None
        if len(rows) > limit:
            next_cursor = str(rows[limit - 1]["rowid"])

        # Strip internal rowid from results
        for r in results:
            r.pop("rowid", None)

        return results, next_cursor
    finally:
        await conn.close()


async def query_by_hassh(hassh: str, limit: int = 50) -> list[dict]:
    """Query sessions by HASSH fingerprint."""
    db = await get_db()
    try:
        rows = await db.execute_fetchall(
            "SELECT * FROM sessions WHERE hassh = ? ORDER BY timestamp_start DESC LIMIT ?",
            (hassh, limit),
        )
        return [dict(r) for r in rows]
    finally:
        await db.close()
