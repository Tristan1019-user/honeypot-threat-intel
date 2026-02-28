"""Database layer — asyncpg pool (Postgres, production) with aiosqlite fallback (SQLite, tests/dev).

Production path: asyncpg connection pool, $1/$2 positional parameters.
Test/dev path:   aiosqlite with automatic $N → ? conversion.

The pool is managed via init_pool() / close_pool(), called from the FastAPI lifespan.
"""

import asyncio
import base64
import copy
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import asyncpg
except ImportError:  # pragma: no cover
    asyncpg = None  # noqa: F811

try:
    import aiosqlite
except ImportError:  # pragma: no cover
    aiosqlite = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Strip trailing RETURNING clause for SQLite fallback writes.
# Supports single/multi-column and optional trailing semicolon.
_RETURNING_CLAUSE_RE = re.compile(r"\s+RETURNING\s+.+?\s*;?\s*$", flags=re.IGNORECASE)

# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #

def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "").strip()


def _allow_sqlite_fallback() -> bool:
    return os.environ.get("ALLOW_SQLITE_FALLBACK", "false").lower() == "true"


def _is_postgres() -> bool:
    return bool(_database_url())


def _get_db_path() -> str:
    return os.environ.get("DATABASE_PATH", "/data/threat_intel.db")


# --------------------------------------------------------------------------- #
# asyncpg connection pool  (None when using SQLite)
# --------------------------------------------------------------------------- #

_pool: Any = None  # asyncpg.Pool when in Postgres mode


async def init_pool() -> None:
    """Create the asyncpg connection pool and initialise the schema.

    Must be called once from the FastAPI lifespan startup hook.
    In SQLite fallback mode (test/dev), this just ensures the schema exists.
    """
    global _pool

    if not _is_postgres():
        if not _allow_sqlite_fallback():
            raise RuntimeError(
                "DATABASE_URL is required for production. "
                "Set ALLOW_SQLITE_FALLBACK=true only for local dev/test."
            )
        if aiosqlite is None:
            raise RuntimeError("aiosqlite is required in SQLite fallback mode.")
        logger.critical(
            "⚠️  SQLite fallback is ACTIVE — this is a dev/test mode only. "
            "Set DATABASE_URL to a Postgres DSN for production. "
            "If DATABASE_URL is unset in prod, all writes go to local SQLite "
            "and Postgres data will be stale."
        )
        await _sqlite_init()
        logger.info("Database initialised in SQLite fallback mode")
        return

    # Guard: if the pool was already created (e.g. called from process_cowrie_log
    # while the FastAPI lifespan has already initialised it), skip re-creation.
    # Without this guard, every manual pipeline trigger leaks the existing pool.
    if _pool is not None:
        logger.debug("init_pool() called but pool already exists — skipping")
        return

    if asyncpg is None:  # pragma: no cover
        raise RuntimeError("asyncpg is required when DATABASE_URL is set. pip install asyncpg")

    _pool = await asyncpg.create_pool(
        _database_url(),
        min_size=2,
        max_size=10,
        command_timeout=30,
        # Recycle idle connections after 5 minutes so stale connections from a
        # Postgres restart don't persist silently in the pool.
        max_inactive_connection_lifetime=300,
    )
    await _pg_init()
    logger.info("asyncpg connection pool created (min=2 max=10)")


async def close_pool() -> None:
    """Drain and close the asyncpg pool. Called from the FastAPI lifespan shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("asyncpg connection pool closed")


# Compat alias so existing call-sites (tests, scripts) still work
async def init_db() -> None:
    """Alias for init_pool() — kept for backwards compatibility."""
    await init_pool()


# --------------------------------------------------------------------------- #
# Stats cache
# --------------------------------------------------------------------------- #

_STATS_CACHE_TTL_SECONDS = 60.0
# Minimum gap between cache invalidations. During a pipeline run that writes
# hundreds of sessions, _invalidate_stats_cache() is called on every insert.
# Without a cooldown the TTL never fires, making the cache useless.
_STATS_CACHE_INVALIDATION_COOLDOWN = 5.0
_stats_cache_data: dict[str, Any] | None = None
_stats_cache_ts: float = 0.0
_stats_last_invalidated: float = 0.0


def _invalidate_stats_cache() -> None:
    global _stats_cache_data, _stats_cache_ts, _stats_last_invalidated
    now = time.monotonic()
    if now - _stats_last_invalidated < _STATS_CACHE_INVALIDATION_COOLDOWN:
        return  # cooldown active — don't bust the cache on every pipeline write
    _stats_cache_data = None
    _stats_cache_ts = 0.0
    _stats_last_invalidated = now


# --------------------------------------------------------------------------- #
# SQL helpers
# --------------------------------------------------------------------------- #

def _pg_to_sqlite(query: str) -> str:
    """Convert $1, $2, ... positional params to ? for SQLite (tests only)."""
    return re.sub(r"\$\d+", "?", query)


class _Params:
    """Explicit positional-parameter builder for dynamic SQL queries.

    Eliminates the _p() closure anti-pattern where parameter numbering
    depended on hidden append-order side effects.

    Usage:
        p = _Params()
        conditions = [f"src_ip = {p.add(ip)}"]
        if attack_type:
            conditions.append(f"attack_type = {p.add(attack_type)}")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = await _fetch(f"SELECT * FROM sessions {where}", *p.values)
    """

    __slots__ = ("_params",)

    def __init__(self) -> None:
        self._params: list[Any] = []

    def add(self, value: Any) -> str:
        """Append a value and return its $N placeholder."""
        self._params.append(value)
        return f"${len(self._params)}"

    def add_many(self, values: list[Any]) -> str:
        """Append multiple values and return comma-separated $N placeholders."""
        return ", ".join(self.add(v) for v in values)

    @property
    def values(self) -> list[Any]:
        return self._params


def _encode_pg_cursor(last_seen: str | None, last_id: str) -> str:
    """Encode a Postgres keyset cursor as a URL-safe base64 string.

    Encodes (last_seen, id) of the final row on a page so the next page
    query can use a WHERE clause instead of OFFSET.
    """
    raw = f"{last_seen or ''}|{last_id}"
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def _decode_pg_cursor(cursor: str) -> tuple[str | None, str] | None:
    """Decode a keyset cursor. Returns (last_seen, last_id) or None if invalid."""
    try:
        # Restore base64 padding
        pad = (4 - len(cursor) % 4) % 4
        raw = base64.urlsafe_b64decode((cursor + "=" * pad).encode()).decode()
        ts, sep, id_ = raw.partition("|")
        if not sep:
            return None
        return (ts or None, id_)
    except Exception:
        return None


def _24h_ago_iso() -> str:
    """Return an ISO 8601 timestamp string for 24 hours ago (UTC).

    Used as a query parameter so the same SQL works on both backends.
    """
    return (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _normalize_ts(ts: str | None) -> str | None:
    """Normalise timestamps to RFC 3339 (ISO 8601 with T and Z)."""
    if not ts:
        return ts
    if " " in ts and "T" not in ts:
        ts = ts.replace(" ", "T") + "Z"
    if ts and not ts.endswith("Z") and "+" not in ts and "-" not in ts[10:]:
        ts += "Z"
    return ts


def _strip_nul(value: Any) -> Any:
    """Recursively strip NUL bytes from DB-bound strings.

    Postgres text fields reject embedded NUL (0x00). Cowrie payloads can contain
    raw NUL in command/summary strings, so sanitize before execute/fetch.
    """
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [_strip_nul(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_strip_nul(v) for v in value)
    if isinstance(value, dict):
        return {k: _strip_nul(v) for k, v in value.items()}
    return value


def _sanitize_params(params: tuple[Any, ...]) -> tuple[Any, ...]:
    return tuple(_strip_nul(p) for p in params)


# --------------------------------------------------------------------------- #
# Core query primitives
# --------------------------------------------------------------------------- #

async def _fetch(query: str, *params: Any) -> list[dict[str, Any]]:
    """Execute a SELECT and return all rows as list of dicts."""
    params = _sanitize_params(params)
    if _pool is not None:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    # SQLite fallback
    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(_pg_to_sqlite(query), params) as cur:
            rows = await cur.fetchall()
            return [dict(row) for row in rows]


async def _fetchval(query: str, *params: Any) -> Any:
    """Execute a SELECT and return a single scalar value."""
    params = _sanitize_params(params)
    if _pool is not None:
        async with _pool.acquire() as conn:
            return await conn.fetchval(query, *params)
    rows = await _fetch(query, *params)
    if not rows:
        return None
    return next(iter(rows[0].values()), None)


async def _execute(query: str, *params: Any) -> None:
    """Execute a single DML statement (INSERT/UPDATE/DELETE)."""
    params = _sanitize_params(params)
    if _pool is not None:
        async with _pool.acquire() as conn:
            await conn.execute(query, *params)
        return
    async with aiosqlite.connect(_get_db_path()) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute(_pg_to_sqlite(query), params)
        await db.commit()


async def _fetch_affected(query: str, *params: Any) -> int:
    """Execute a DML ... RETURNING id and return the count of affected rows.

    Postgres: conn.fetch() with RETURNING clause — exact count, no string parsing.
    SQLite:   RETURNING is stripped; execute()+commit() used with cursor.rowcount.
              (SQLite RETURNING requires a commit path, not the read-only _fetch path.)
    """
    params = _sanitize_params(params)
    if _pool is not None:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            return len(rows)
    # SQLite: strip trailing RETURNING clause and commit properly.
    # SQLite fallback path doesn't rely on returned rows; rowcount is authoritative.
    sqlite_query = _RETURNING_CLAUSE_RE.sub("", query)
    async with aiosqlite.connect(_get_db_path()) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        cur = await db.execute(_pg_to_sqlite(sqlite_query), params)
        await db.commit()
        return cur.rowcount


# --------------------------------------------------------------------------- #
# Schema definitions
# --------------------------------------------------------------------------- #

_PG_DDL = [
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
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version    TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_src_ip  ON sessions(src_ip)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_start   ON sessions(timestamp_start DESC)",
    "CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value)",
    "CREATE INDEX IF NOT EXISTS idx_indicators_last  ON indicators(last_seen DESC)",
]

# Named migrations — each runs exactly once, tracked in schema_migrations table.
# Append new entries; never remove or reorder existing ones.
_PG_NAMED_MIGRATIONS: list[tuple[str, str]] = [
    ("m001_sessions_asn",
     "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS asn TEXT"),
    ("m002_sessions_org",
     "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS org TEXT"),
    ("m003_sessions_country",
     "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country TEXT"),
    ("m004_sessions_cloud_provider",
     "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS cloud_provider TEXT"),
    ("m005_sessions_observed_features",
     "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS observed_features TEXT"),
    ("m006_indicators_revoked",
     "ALTER TABLE indicators ADD COLUMN IF NOT EXISTS revoked INTEGER DEFAULT 0"),
    ("m007_indicators_revoked_reason",
     "ALTER TABLE indicators ADD COLUMN IF NOT EXISTS revoked_reason TEXT"),
    ("m008_malware_vt_detection_ratio",
     "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_detection_ratio TEXT"),
    ("m009_malware_vt_families",
     "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_malware_families TEXT"),
    ("m010_malware_vt_first_submission",
     "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_first_submission BIGINT"),
    ("m011_malware_vt_known",
     "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_known INTEGER"),
    ("m012_malware_vt_enriched_at",
     "ALTER TABLE malware_samples ADD COLUMN IF NOT EXISTS vt_enriched_at TEXT"),
    ("m013_indicators_unique_idx",
     "CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(type, value)"),
]

# SQLite equivalents — ADD COLUMN IF NOT EXISTS is not supported; wrap in try/except
_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    src_ip           TEXT NOT NULL,
    src_port         INTEGER,
    timestamp_start  TEXT NOT NULL,
    timestamp_end    TEXT,
    duration_seconds REAL,
    ssh_client       TEXT,
    hassh            TEXT,
    attack_type      TEXT,
    threat_level     TEXT,
    mitre_techniques TEXT,
    summary          TEXT,
    stix_bundle      TEXT,
    raw_session      TEXT,
    created_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    enriched_at      TEXT,
    asn              TEXT,
    org              TEXT,
    country          TEXT,
    cloud_provider   TEXT,
    observed_features TEXT
);
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
);
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
    vt_first_submission INTEGER,
    vt_known            INTEGER,
    vt_enriched_at      TEXT
);
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_indicators_value    ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_indicators_last     ON indicators(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip     ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_start      ON sessions(timestamp_start DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators(type, value);
"""

_SQLITE_NAMED_MIGRATIONS: list[tuple[str, str]] = [
    ("m001_sessions_asn",
     "ALTER TABLE sessions ADD COLUMN asn TEXT"),
    ("m002_sessions_org",
     "ALTER TABLE sessions ADD COLUMN org TEXT"),
    ("m003_sessions_country",
     "ALTER TABLE sessions ADD COLUMN country TEXT"),
    ("m004_sessions_cloud_provider",
     "ALTER TABLE sessions ADD COLUMN cloud_provider TEXT"),
    ("m005_sessions_observed_features",
     "ALTER TABLE sessions ADD COLUMN observed_features TEXT"),
    ("m006_indicators_revoked",
     "ALTER TABLE indicators ADD COLUMN revoked INTEGER DEFAULT 0"),
    ("m007_indicators_revoked_reason",
     "ALTER TABLE indicators ADD COLUMN revoked_reason TEXT"),
    ("m008_malware_vt_detection_ratio",
     "ALTER TABLE malware_samples ADD COLUMN vt_detection_ratio TEXT"),
    ("m009_malware_vt_families",
     "ALTER TABLE malware_samples ADD COLUMN vt_malware_families TEXT"),
    ("m010_malware_vt_first_submission",
     "ALTER TABLE malware_samples ADD COLUMN vt_first_submission INTEGER"),
    ("m011_malware_vt_known",
     "ALTER TABLE malware_samples ADD COLUMN vt_known INTEGER"),
    ("m012_malware_vt_enriched_at",
     "ALTER TABLE malware_samples ADD COLUMN vt_enriched_at TEXT"),
    # m013: idx_indicators_type_value is created in the DDL SCHEMA, not here
]


async def _pg_init() -> None:
    """Create Postgres schema and run named migrations (each exactly once).

    Migration state is stored in the schema_migrations table.  Re-running
    _pg_init() after adding new entries to _PG_NAMED_MIGRATIONS applies only
    the new ones; already-applied versions are skipped.
    """
    async with _pool.acquire() as conn:
        async with conn.transaction():
            # 1. Core DDL — all IF NOT EXISTS, fully idempotent
            for stmt in _PG_DDL:
                await conn.execute(stmt)

            # 2. Named migrations — check schema_migrations before each run
            now_iso = datetime.now(timezone.utc).isoformat()
            for version, stmt in _PG_NAMED_MIGRATIONS:
                already = await conn.fetchval(
                    "SELECT 1 FROM schema_migrations WHERE version = $1", version
                )
                if already:
                    continue
                mark_applied = True
                try:
                    await conn.execute(stmt)
                except Exception as exc:
                    msg = str(exc).lower()
                    if "already exists" in msg or "duplicate column" in msg:
                        pass  # idempotent error — column/index already there, safe to mark applied
                    else:
                        logger.error(
                            "Migration %s FAILED — will NOT mark applied; "
                            "it will retry on next restart: %s",
                            version, exc,
                        )
                        mark_applied = False
                if mark_applied:
                    await conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) "
                        "VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        version,
                        now_iso,
                    )
    logger.info("Postgres schema ready")


async def _sqlite_init() -> None:
    """Create SQLite schema and run named migrations (each exactly once). Tests/dev only."""
    db_path = _get_db_path()
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(_SQLITE_SCHEMA)
        now_iso = datetime.now(timezone.utc).isoformat()
        for version, sql in _SQLITE_NAMED_MIGRATIONS:
            async with db.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?", (version,)
            ) as cur:
                already = await cur.fetchone()
            if already:
                continue
            try:
                await db.execute(sql)
            except Exception:
                pass  # column already exists (idempotent)
            await db.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, now_iso),
            )
        await db.commit()
    logger.info(f"SQLite schema ready at {db_path}")


# --------------------------------------------------------------------------- #
# Write operations
# --------------------------------------------------------------------------- #

async def insert_session(session: dict) -> str:
    """Insert or replace an enriched session. Returns session id."""
    await _execute(
        """
        INSERT INTO sessions
            (id, src_ip, src_port, timestamp_start, timestamp_end,
             duration_seconds, ssh_client, hassh, attack_type, threat_level,
             mitre_techniques, summary, stix_bundle, raw_session, created_at,
             enriched_at, asn, org, country, cloud_provider, observed_features)
        VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
             $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
        ON CONFLICT (id) DO UPDATE SET
            src_ip           = EXCLUDED.src_ip,
            src_port         = EXCLUDED.src_port,
            timestamp_start  = EXCLUDED.timestamp_start,
            timestamp_end    = EXCLUDED.timestamp_end,
            duration_seconds = EXCLUDED.duration_seconds,
            ssh_client       = EXCLUDED.ssh_client,
            hassh            = EXCLUDED.hassh,
            attack_type      = EXCLUDED.attack_type,
            threat_level     = EXCLUDED.threat_level,
            mitre_techniques = EXCLUDED.mitre_techniques,
            summary          = EXCLUDED.summary,
            stix_bundle      = EXCLUDED.stix_bundle,
            raw_session      = EXCLUDED.raw_session,
            enriched_at      = EXCLUDED.enriched_at,
            asn              = EXCLUDED.asn,
            org              = EXCLUDED.org,
            country          = EXCLUDED.country,
            cloud_provider   = EXCLUDED.cloud_provider,
            observed_features = EXCLUDED.observed_features
        """,
        session["session_id"],           # $1
        session.get("src_ip"),           # $2
        session.get("src_port"),         # $3
        session.get("timestamp_start"),  # $4
        session.get("timestamp_end"),    # $5
        session.get("duration_seconds"), # $6
        session.get("ssh_client"),       # $7
        session.get("hassh"),            # $8
        session.get("attack_type"),      # $9
        session.get("threat_level"),     # $10
        json.dumps(session.get("mitre_techniques", [])),  # $11
        session.get("summary"),          # $12
        json.dumps(session.get("stix_bundle")) if session.get("stix_bundle") else None,  # $13
        json.dumps(session),             # $14
        # $15 = created_at: set once at first insert and never updated (tracks when
        # the row first entered the DB). enriched_at ($16) may change on re-enrichment.
        # Both use the same timestamp so created_at is never greater than enriched_at.
        *([session.get("enriched_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")] * 2),
        session.get("asn"),              # $17
        session.get("org"),              # $18
        session.get("country"),          # $19
        session.get("cloud_provider"),   # $20
        json.dumps(session.get("observed_features")) if session.get("observed_features") else None,  # $21
    )
    _invalidate_stats_cache()
    return session["session_id"]


async def upsert_indicator(indicator: dict) -> None:
    """Insert or update an indicator, incrementing times_seen on conflict.

    Uses INSERT ... ON CONFLICT (type, value) DO UPDATE — safe on Postgres and
    SQLite ≥ 3.24. No SELECT-then-write race condition.
    """
    await _execute(
        """
        INSERT INTO indicators
            (id, session_id, type, value, first_seen, last_seen, times_seen, threat_level, stix_object)
        VALUES
            ($1, $2, $3, $4, $5, $6, 1, $7, $8)
        ON CONFLICT (type, value) DO UPDATE SET
            times_seen   = indicators.times_seen + 1,
            last_seen    = EXCLUDED.last_seen,
            threat_level = EXCLUDED.threat_level,
            session_id   = EXCLUDED.session_id,
            stix_object  = EXCLUDED.stix_object
        """,
        indicator["id"],
        indicator.get("session_id"),
        indicator["type"],
        indicator["value"],
        indicator.get("first_seen"),
        indicator.get("last_seen"),
        indicator.get("threat_level"),
        json.dumps(indicator.get("stix_object")) if indicator.get("stix_object") else None,
    )
    _invalidate_stats_cache()


async def insert_malware(sample: dict) -> None:
    """Insert a malware sample record (ignore if SHA-256 already exists)."""
    await _execute(
        """
        INSERT INTO malware_samples
            (sha256, session_id, url, size_bytes, file_type, first_seen, stix_object)
        VALUES
            ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (sha256) DO NOTHING
        """,
        sample["sha256"],
        sample.get("session_id"),
        sample.get("url"),
        sample.get("size_bytes"),
        sample.get("file_type"),
        sample.get("first_seen"),
        json.dumps(sample.get("stix_object")) if sample.get("stix_object") else None,
    )
    _invalidate_stats_cache()


async def revoke_indicator(value: str, reason: str = "false_positive") -> bool:
    """Mark an indicator as revoked. Returns True if a row was updated."""
    rows = await _fetch_affected(
        "UPDATE indicators SET revoked = 1, revoked_reason = $1 WHERE value = $2 RETURNING id",
        reason,
        value,
    )
    _invalidate_stats_cache()
    return rows > 0


async def unrevoke_indicator(value: str) -> bool:
    """Remove revocation from an indicator. Returns True if a row was updated."""
    rows = await _fetch_affected(
        "UPDATE indicators SET revoked = 0, revoked_reason = NULL WHERE value = $1 RETURNING id",
        value,
    )
    _invalidate_stats_cache()
    return rows > 0


async def get_revoked_indicators(limit: int = 100, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Return (rows, total) for all revoked indicators, ordered by last_seen DESC.

    Public API so admin.py router never has to call the private _fetch/_fetchval
    primitives directly.
    """
    rows, total_val = await asyncio.gather(
        _fetch(
            "SELECT * FROM indicators WHERE revoked = 1 ORDER BY last_seen DESC "
            "LIMIT $1 OFFSET $2",
            limit,
            offset,
        ),
        _fetchval("SELECT COUNT(*) FROM indicators WHERE revoked = 1"),
    )
    return rows, int(total_val or 0)


async def update_malware_vt(sha256: str, vt_data: dict) -> None:
    """Persist VirusTotal enrichment results for a malware sample."""
    await _execute(
        """
        UPDATE malware_samples SET
            vt_detection_ratio  = $1,
            vt_malware_families = $2,
            vt_first_submission = $3,
            vt_known            = $4,
            vt_enriched_at      = $5
        WHERE sha256 = $6
        """,
        vt_data.get("vt_detection_ratio"),
        json.dumps(vt_data.get("vt_malware_families", [])),
        vt_data.get("vt_first_submission"),
        1 if vt_data.get("vt_known") else 0,
        datetime.now(timezone.utc).isoformat(),
        sha256,
    )
    _invalidate_stats_cache()


# --------------------------------------------------------------------------- #
# Read operations — sessions
# --------------------------------------------------------------------------- #

async def get_session(session_id: str) -> dict[str, Any] | None:
    rows = await _fetch("SELECT * FROM sessions WHERE id = $1", session_id)
    return rows[0] if rows else None


async def session_exists(session_id: str) -> bool:
    """Fast existence check — avoids fetching the full row before enrichment."""
    val = await _fetchval(
        "SELECT 1 FROM sessions WHERE id = $1 LIMIT 1", session_id
    )
    return val is not None


async def query_sessions(
    since: str | None = None,
    attack_type: str | None = None,
    threat_level: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    p = _Params()
    conditions: list[str] = []

    if since:
        conditions.append(f"timestamp_start >= {p.add(since)}")
    if attack_type:
        conditions.append(f"attack_type = {p.add(attack_type)}")
    if threat_level:
        levels = [lvl.strip() for lvl in threat_level.split(",")]
        conditions.append(f"threat_level IN ({p.add_many(levels)})")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return await _fetch(
        f"SELECT * FROM sessions {where} "
        f"ORDER BY timestamp_start DESC LIMIT {p.add(limit)} OFFSET {p.add(offset)}",
        *p.values,
    )


async def count_sessions(
    since: str | None = None,
    attack_type: str | None = None,
    threat_level: str | None = None,
) -> int:
    p = _Params()
    conditions: list[str] = []

    if since:
        conditions.append(f"timestamp_start >= {p.add(since)}")
    if attack_type:
        conditions.append(f"attack_type = {p.add(attack_type)}")
    if threat_level:
        levels = [lvl.strip() for lvl in threat_level.split(",")]
        conditions.append(f"threat_level IN ({p.add_many(levels)})")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    val = await _fetchval(f"SELECT COUNT(*) FROM sessions {where}", *p.values)
    return int(val or 0)


async def query_by_hassh(hassh: str, limit: int = 50) -> list[dict[str, Any]]:
    return await _fetch(
        "SELECT * FROM sessions WHERE hassh = $1 ORDER BY timestamp_start DESC LIMIT $2",
        hassh,
        limit,
    )


# --------------------------------------------------------------------------- #
# Read operations — indicators
# --------------------------------------------------------------------------- #

async def query_indicators(
    since: str | None = None,
    indicator_type: str | None = None,
    threat_level: str | None = None,
    limit: int = 100,
    offset: int = 0,
    include_revoked: bool = True,
    exclude_credentials: bool = False,
) -> list[dict[str, Any]]:
    p = _Params()
    conditions: list[str] = []

    if since:
        conditions.append(f"first_seen >= {p.add(since)}")
    if indicator_type and indicator_type != "all":
        conditions.append(f"type = {p.add(indicator_type)}")
    if threat_level:
        levels = [lvl.strip() for lvl in threat_level.split(",")]
        conditions.append(f"threat_level IN ({p.add_many(levels)})")
    if not include_revoked:
        conditions.append("(revoked = 0 OR revoked IS NULL)")
    if exclude_credentials:
        conditions.append("type != 'credential'")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return await _fetch(
        f"SELECT * FROM indicators {where} "
        f"ORDER BY last_seen DESC LIMIT {p.add(limit)} OFFSET {p.add(offset)}",
        *p.values,
    )


async def count_indicators(
    since: str | None = None,
    indicator_type: str | None = None,
    threat_level: str | None = None,
    include_revoked: bool = True,
    exclude_credentials: bool = False,
) -> int:
    p = _Params()
    conditions: list[str] = []

    if since:
        conditions.append(f"first_seen >= {p.add(since)}")
    if indicator_type and indicator_type != "all":
        conditions.append(f"type = {p.add(indicator_type)}")
    if threat_level:
        levels = [lvl.strip() for lvl in threat_level.split(",")]
        conditions.append(f"threat_level IN ({p.add_many(levels)})")
    if not include_revoked:
        conditions.append("(revoked = 0 OR revoked IS NULL)")
    if exclude_credentials:
        conditions.append("type != 'credential'")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    val = await _fetchval(f"SELECT COUNT(*) FROM indicators {where}", *p.values)
    return int(val or 0)


async def lookup_indicator(value: str) -> list[dict[str, Any]]:
    return await _fetch(
        """
        SELECT i.*, s.attack_type, s.summary, s.timestamp_start
        FROM   indicators i
        LEFT JOIN sessions s ON i.session_id = s.id
        WHERE  i.value = $1
        ORDER  BY i.last_seen DESC
        """,
        value,
    )


async def query_indicators_cursor(
    cursor: str | None = None,
    since: str | None = None,
    indicator_type: str | None = None,
    threat_level: str | None = None,
    include_revoked: bool = False,
    exclude_credentials: bool = False,
    limit: int = 100,
) -> tuple[list[dict[str, Any]], str | None]:
    """Cursor-based pagination over indicators.

    Postgres (production): keyset cursor on (last_seen DESC, id DESC).
    Cursor is base64-encoded "last_seen|id" of the final row on the previous page.
    WHERE (last_seen < $ts OR (last_seen = $ts AND id < $id)) eliminates OFFSET
    drift when rows are inserted between fetches.

    SQLite (tests only): rowid-based cursor — stable, monotonic, immune to concurrent
    inserts. Cursor value is a plain integer string representing the last rowid.
    The two formats are incompatible; do not mix Postgres and SQLite cursors.

    Returns (rows, next_cursor).  next_cursor is None when no more pages exist.
    """
    if _pool is not None:
        # Postgres: keyset cursor on (last_seen DESC, id DESC).
        # Encodes the final row's (last_seen, id) as a base64 token so callers
        # can resume without OFFSET drift when new rows are inserted mid-page.
        p = _Params()
        conditions: list[str] = []

        # Decode the cursor into (ts, id) — None means first page
        cursor_ts: str | None = None
        cursor_id: str | None = None
        if cursor:
            decoded = _decode_pg_cursor(cursor)
            if decoded:
                cursor_ts, cursor_id = decoded
            else:
                logger.warning(
                    "query_indicators_cursor: malformed cursor %r — "
                    "ignoring and restarting from page 1",
                    cursor[:60],
                )

        if cursor_ts and cursor_id:
            # Rows "after" the cursor in (last_seen DESC, id DESC) order.
            # $N and $N+1 both hold cursor_ts; asyncpg passes them separately.
            ts_lt = p.add(cursor_ts)
            ts_eq = p.add(cursor_ts)   # same value, different positional slot
            id_lt = p.add(cursor_id)
            conditions.append(
                f"(last_seen < {ts_lt} OR (last_seen = {ts_eq} AND id < {id_lt}))"
            )

        if since:
            conditions.append(f"first_seen >= {p.add(since)}")
        if indicator_type and indicator_type != "all":
            conditions.append(f"type = {p.add(indicator_type)}")
        if threat_level:
            levels = [lvl.strip() for lvl in threat_level.split(",")]
            conditions.append(f"threat_level IN ({p.add_many(levels)})")
        if not include_revoked:
            conditions.append("(revoked = 0 OR revoked IS NULL)")
        if exclude_credentials:
            conditions.append("type != 'credential'")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = await _fetch(
            f"SELECT * FROM indicators {where} "
            f"ORDER BY last_seen DESC, id DESC LIMIT {p.add(limit + 1)}",
            *p.values,
        )
        results = rows[:limit]
        next_cursor_val: str | None = None
        if len(rows) > limit and results:
            last = results[-1]
            # str(... or "") guards against NULL id (shouldn't happen, id is PK,
            # but dict.get returns None not "" when key exists with NULL value)
            next_cursor_val = _encode_pg_cursor(
                last.get("last_seen"),
                str(last.get("id") or ""),
            )
        return results, next_cursor_val

    # SQLite: rowid-based cursor (stable monotonic ordering).
    # Use ? placeholders directly — this branch never goes through _pg_to_sqlite().
    sqlite_conditions: list[str] = []
    sqlite_params: list[Any] = []

    if cursor:
        try:
            sqlite_params.append(int(cursor))
            sqlite_conditions.append("rowid > ?")
        except ValueError:
            logger.warning(
                "SQLite cursor branch received non-integer cursor %r — "
                "ignoring (may be a Postgres keyset cursor sent to wrong backend)",
                cursor[:60],
            )
    if since:
        sqlite_params.append(since)
        sqlite_conditions.append("first_seen >= ?")
    if indicator_type and indicator_type != "all":
        sqlite_params.append(indicator_type)
        sqlite_conditions.append("type = ?")
    if threat_level:
        levels = [lvl.strip() for lvl in threat_level.split(",")]
        sqlite_params.extend(levels)
        sqlite_conditions.append(f"threat_level IN ({', '.join('?' for _ in levels)})")
    if not include_revoked:
        sqlite_conditions.append("(revoked = 0 OR revoked IS NULL)")
    if exclude_credentials:
        sqlite_conditions.append("type != 'credential'")

    where = f"WHERE {' AND '.join(sqlite_conditions)}" if sqlite_conditions else ""
    sqlite_params.append(limit + 1)

    async with aiosqlite.connect(_get_db_path()) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT rowid, * FROM indicators {where} ORDER BY rowid ASC LIMIT ?",
            sqlite_params,
        ) as cur_obj:
            all_rows: list = list(await cur_obj.fetchall())

    results = [dict(r) for r in all_rows[:limit]]
    next_cursor = None
    if len(all_rows) > limit:
        next_cursor = str(all_rows[limit - 1]["rowid"])

    for r in results:
        r.pop("rowid", None)

    return results, next_cursor


# --------------------------------------------------------------------------- #
# Read operations — IPs / malware
# --------------------------------------------------------------------------- #

async def get_ip_sightings(ip: str) -> dict[str, Any]:
    rows = await _fetch(
        """
        SELECT COUNT(*)           AS sighting_count,
               MIN(timestamp_start) AS first_seen,
               MAX(timestamp_start) AS last_seen,
               asn, org, country, cloud_provider
        FROM sessions
        WHERE src_ip = $1
        """,
        ip,
    )
    if rows and rows[0]["sighting_count"] > 0:
        r = rows[0]
        return {
            "ip": ip,
            "sighting_count": r["sighting_count"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "asn": r["asn"],
            "org": r["org"],
            "country": r["country"],
            "cloud_provider": r["cloud_provider"],
        }
    return {"ip": ip, "sighting_count": 0}


async def get_cached_geo(ip: str) -> dict[str, Any]:
    """Return geo/ASN data cached from a prior session for this IP.

    Avoids redundant ipwho.is API calls for IPs already seen in the feed.
    """
    rows = await _fetch(
        """
        SELECT asn, org, country, cloud_provider
        FROM   sessions
        WHERE  src_ip = $1
          AND  country IS NOT NULL
          AND  country != ''
        ORDER  BY timestamp_start DESC
        LIMIT  1
        """,
        ip,
    )
    if rows:
        r = rows[0]
        return {
            "asn": r.get("asn") or "",
            "org": r.get("org") or "",
            "country": r.get("country") or "",
            "cloud_provider": r.get("cloud_provider") or "",
        }
    return {}


async def get_malware_samples() -> list[dict[str, Any]]:
    return await _fetch("SELECT * FROM malware_samples ORDER BY first_seen DESC")


async def is_malware_vt_enriched(sha256: str) -> bool:
    """Return True if this sample already has a completed VT enrichment result.

    Used by the pipeline to skip re-querying VT for samples that were enriched
    in a previous run (e.g., same SHA-256 downloaded by a new session).
    """
    val = await _fetchval(
        "SELECT vt_enriched_at FROM malware_samples WHERE sha256 = $1", sha256
    )
    return val is not None


_FINGERPRINT_CACHE_TTL = 60.0
_fingerprint_cache_data: dict[str, Any] | None = None
_fingerprint_cache_ts: float = 0.0


async def get_dataset_fingerprint() -> dict[str, Any]:
    """Compute a SHA-256 fingerprint over all non-revoked indicators, with 60-second cache.

    Previous approach (get_indicators_for_fingerprint) loaded every row into the
    application process for hashing in Python — O(N) network transfer on every
    /integrity request. This version caches the result for 60 seconds so the
    full-table scan runs at most once per minute regardless of request rate.

    Returns {"fingerprint": str, "total_indicators": int}.
    """
    global _fingerprint_cache_data, _fingerprint_cache_ts
    now = time.monotonic()
    if _fingerprint_cache_data is not None and (now - _fingerprint_cache_ts) <= _FINGERPRINT_CACHE_TTL:
        return _fingerprint_cache_data

    rows = await _fetch(
        "SELECT value, last_seen FROM indicators "
        "WHERE revoked = 0 OR revoked IS NULL "
        "ORDER BY last_seen ASC"
    )
    h = hashlib.sha256()
    for r in rows:
        h.update(f"{r['value']}|{r['last_seen'] or ''}\n".encode())

    result: dict[str, Any] = {
        "fingerprint": h.hexdigest(),
        "total_indicators": len(rows),
    }
    _fingerprint_cache_data = result
    _fingerprint_cache_ts = now
    return result


async def get_integrity_meta() -> dict[str, Any]:
    """Return scalar counts used by the /integrity endpoint.

    Avoids exposing private _fetchval() to router modules.
    All three queries run concurrently via asyncio.gather().
    """
    total_sessions, total_malware, last_update = await asyncio.gather(
        _fetchval("SELECT COUNT(*) FROM sessions"),
        _fetchval("SELECT COUNT(*) FROM malware_samples"),
        _fetchval("SELECT MAX(enriched_at) FROM sessions"),
    )
    return {
        "total_sessions": int(total_sessions or 0),
        "total_malware_samples": int(total_malware or 0),
        "last_update": last_update,
    }


# --------------------------------------------------------------------------- #
# Aggregates & dashboards
# --------------------------------------------------------------------------- #

async def get_stats() -> dict[str, Any]:
    global _stats_cache_data, _stats_cache_ts
    now = time.monotonic()
    if _stats_cache_data is not None and (now - _stats_cache_ts) <= _STATS_CACHE_TTL_SECONDS:
        return copy.deepcopy(_stats_cache_data)

    total_sessions   = await _fetchval("SELECT COUNT(*) FROM sessions")
    total_indicators = await _fetchval("SELECT COUNT(*) FROM indicators")
    total_malware    = await _fetchval("SELECT COUNT(*) FROM malware_samples")

    attack_types  = await _fetch(
        "SELECT attack_type, COUNT(*) AS c FROM sessions "
        "WHERE attack_type IS NOT NULL GROUP BY attack_type ORDER BY c DESC"
    )
    threat_levels = await _fetch(
        "SELECT threat_level, COUNT(*) AS c FROM sessions "
        "WHERE threat_level IS NOT NULL GROUP BY threat_level ORDER BY c DESC"
    )
    top_ips  = await _fetch(
        "SELECT src_ip, COUNT(*) AS c FROM sessions GROUP BY src_ip ORDER BY c DESC LIMIT 20"
    )
    top_creds = await _fetch(
        "SELECT value, times_seen FROM indicators WHERE type = 'credential' "
        "ORDER BY times_seen DESC LIMIT 20"
    )
    # Postgres: push aggregation server-side via jsonb_array_elements_text().
    # Avoids transferring up to N JSON strings across the network just to count them in Python.
    # SQLite: no jsonb support — fall back to the Python loop (test/dev only).
    if _is_postgres():
        mitre_agg = await _fetch(
            "SELECT t.technique, COUNT(*) AS c "
            "FROM sessions, jsonb_array_elements_text(mitre_techniques::jsonb) AS t(technique) "
            "WHERE mitre_techniques IS NOT NULL "
            "GROUP BY t.technique ORDER BY c DESC"
        )
        mitre_counts: dict[str, int] = {r["technique"]: int(r["c"]) for r in mitre_agg}
    else:
        mitre_rows = await _fetch(
            "SELECT mitre_techniques FROM sessions WHERE mitre_techniques IS NOT NULL"
        )
        mitre_counts = {}
        for row in mitre_rows:
            try:
                for t in json.loads(row["mitre_techniques"]):
                    mitre_counts[t] = mitre_counts.get(t, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

    last_update_row = await _fetch("SELECT MAX(enriched_at) AS ts FROM sessions")
    last_ts = last_update_row[0]["ts"] if last_update_row else None

    countries = await _fetch(
        "SELECT country, COUNT(*) AS c FROM sessions "
        "WHERE country IS NOT NULL AND country != '' "
        "GROUP BY country ORDER BY c DESC LIMIT 20"
    )
    asns = await _fetch(
        "SELECT asn, MAX(org) AS org, COUNT(*) AS c FROM sessions "
        "WHERE asn IS NOT NULL AND asn != '' "
        "GROUP BY asn ORDER BY c DESC LIMIT 15"
    )
    recent = await _fetch(
        "SELECT id, src_ip, attack_type, threat_level, mitre_techniques, "
        "summary, timestamp_start, country, asn, org "
        "FROM sessions ORDER BY timestamp_start DESC LIMIT 3"
    )
    recent_indicators = await _fetch(
        "SELECT type, value, first_seen, last_seen, times_seen, threat_level "
        "FROM indicators WHERE type != 'credential' "
        "ORDER BY last_seen DESC LIMIT 5"
    )

    result: dict[str, Any] = {
        "total_sessions": int(total_sessions or 0),
        "total_indicators": int(total_indicators or 0),
        "total_malware_samples": int(total_malware or 0),
        "attack_types": {r["attack_type"]: r["c"] for r in attack_types},
        "threat_levels": {r["threat_level"]: r["c"] for r in threat_levels},
        "top_source_ips": [{r["src_ip"]: r["c"]} for r in top_ips],
        "top_credentials": [{r["value"]: r["times_seen"]} for r in top_creds],
        "mitre_technique_frequency": dict(
            sorted(mitre_counts.items(), key=lambda x: -x[1])
        ),
        "top_countries": {r["country"]: r["c"] for r in countries},
        "top_asns": [{"asn": r["asn"], "org": r["org"], "count": r["c"]} for r in asns],
        "recent_sessions": list(recent),
        "recent_indicators": list(recent_indicators),
        "last_update": _normalize_ts(last_ts),
    }

    _stats_cache_data = result
    _stats_cache_ts = time.monotonic()
    return copy.deepcopy(result)


async def get_operational_metrics() -> dict[str, Any]:
    """Operational quality metrics. Time threshold computed in Python — works on both backends."""
    cutoff = _24h_ago_iso()

    sessions_24h      = await _fetchval(
        "SELECT COUNT(*) FROM sessions WHERE timestamp_start >= $1", cutoff
    )
    indicators_24h    = await _fetchval(
        "SELECT COUNT(*) FROM indicators WHERE last_seen >= $1", cutoff
    )
    high_critical_24h = await _fetchval(
        "SELECT COUNT(*) FROM sessions "
        "WHERE timestamp_start >= $1 AND threat_level IN ('high','critical')",
        cutoff,
    )
    unique_attackers  = await _fetchval(
        "SELECT COUNT(DISTINCT src_ip) FROM sessions WHERE timestamp_start >= $1", cutoff
    )
    top_attack_rows   = await _fetch(
        "SELECT attack_type, COUNT(*) AS c FROM sessions "
        "WHERE timestamp_start >= $1 AND attack_type IS NOT NULL "
        "GROUP BY attack_type ORDER BY c DESC LIMIT 1",
        cutoff,
    )
    top_attack = (
        {"name": top_attack_rows[0]["attack_type"], "count": top_attack_rows[0]["c"]}
        if top_attack_rows
        else None
    )
    last_row = await _fetch("SELECT MAX(enriched_at) AS ts FROM sessions")
    last_update = _normalize_ts(last_row[0]["ts"] if last_row else None)

    return {
        "sessions_24h": int(sessions_24h or 0),
        "indicators_24h": int(indicators_24h or 0),
        "high_or_critical_sessions_24h": int(high_critical_24h or 0),
        "unique_attacker_ips_24h": int(unique_attackers or 0),
        "top_attack_type_24h": top_attack,
        "last_update": last_update,
    }


async def get_db_diagnostics() -> dict[str, Any]:
    backend = "postgres" if _pool is not None else "sqlite"

    if _pool is not None:
        table_rows = await _fetch(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' "
            "AND table_name IN ('sessions', 'indicators', 'malware_samples')"
        )
        found = {r["table_name"] for r in table_rows}
    else:
        table_rows = await _fetch(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' "
            "AND name IN ('sessions', 'indicators', 'malware_samples')"
        )
        found = {r["name"] for r in table_rows}

    counts: dict[str, int] = {}
    for t in ("sessions", "indicators", "malware_samples"):
        val = await _fetchval(f"SELECT COUNT(*) FROM {t}")
        counts[t] = int(val or 0)

    return {
        "backend": backend,
        "pool_size": _pool.get_size() if _pool is not None else None,
        "pool_min": _pool.get_min_size() if _pool is not None else None,
        "pool_max": _pool.get_max_size() if _pool is not None else None,
        "sqlite_fallback_active": _pool is None,
        "tables": {
            "sessions_table":       "sessions" in found,
            "indicators_table":     "indicators" in found,
            "malware_samples_table":"malware_samples" in found,
        },
        "counts": counts,
    }
