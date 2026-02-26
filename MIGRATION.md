# Migration: SQLite → PostgreSQL

## Overview

The production stack uses PostgreSQL 16 (via the `threat-intel-db` service in `compose.yml`).
SQLite is **only** supported for local development and automated tests (`ALLOW_SQLITE_FALLBACK=true`).

This guide covers migrating an existing SQLite database file to Postgres if you started the service
before Postgres was wired into the compose stack.

---

## Pre-flight checks

```bash
# 1 – Verify the Postgres service is healthy
docker compose ps threat-intel-db

# 2 – Confirm the API container reads DATABASE_URL (not DATABASE_PATH)
docker exec threat-intel-api env | grep DATABASE_URL

# 3 – Check row counts in the existing SQLite file
python3 scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path ./data/threat_intel.db \
  --postgres-url "postgresql://threatintel:SECRET@localhost:5432/threat_intel" \
  --dry-run
```

---

## Migration steps

### 1. Stop the API (avoid writes during migration)

```bash
docker compose stop threat-intel-api
```

### 2. Back up the SQLite file

```bash
cp ./data/threat_intel.db ./data/threat_intel.db.bak-$(date +%Y%m%d-%H%M%S)
```

### 3. Run the migration script

```bash
python3 scripts/migrate_sqlite_to_postgres.py \
  --sqlite-path ./data/threat_intel.db \
  --postgres-url "postgresql://threatintel:SECRET@127.0.0.1:5432/threat_intel"
```

The script will:
- Connect to both databases
- Create the Postgres schema (idempotent)
- Copy all rows in batches (sessions → indicators → malware_samples)
- Verify row counts match before exiting
- Print a summary table

### 4. Verify counts match

The script exits non-zero if counts mismatch. Check manually if needed:

```bash
# SQLite
sqlite3 ./data/threat_intel.db "SELECT COUNT(*) FROM sessions; SELECT COUNT(*) FROM indicators;"

# Postgres
docker exec threat-intel-db psql -U threatintel -d threat_intel \
  -c "SELECT COUNT(*) FROM sessions; SELECT COUNT(*) FROM indicators;"
```

### 5. Start the stack

```bash
docker compose up -d
```

The API container will connect to Postgres via `DATABASE_URL` from the `.env` file.
SQLite file is kept as a backup — you can remove it once confirmed healthy.

---

## Rollback

If anything goes wrong:

```bash
docker compose stop threat-intel-api
# Edit .env: remove DATABASE_URL, set ALLOW_SQLITE_FALLBACK=true
docker compose up -d
```

The SQLite backup at `./data/threat_intel.db.bak-*` is the source of truth.

---

## Schema migrations (ongoing)

New columns are added via the `_PG_MIGRATIONS` list in `app/database.py`.
These use `ADD COLUMN IF NOT EXISTS` and are applied automatically on startup
(inside `_pg_init()` called from `init_pool()`).

No manual schema changes are needed after a code update.

---

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | **Yes (prod)** | – | `postgresql://user:pass@host:port/db` |
| `POSTGRES_PASSWORD` | **Yes (prod)** | – | Password for the `threat-intel-db` service |
| `ALLOW_SQLITE_FALLBACK` | No | `false` | Set `true` for local dev/test only |
| `DATABASE_PATH` | No | `/data/threat_intel.db` | SQLite file path (dev/test only) |
