# Architecture

## System flow

1. **Ingest**
   - Cowrie JSON logs are read incrementally by `app/pipeline.py`
   - Pipeline tracks position using `/data/pipeline_state.json`

2. **Session assembly + enrichment**
   - Raw events are grouped into sessions
   - Session behavior is enriched (AI + deterministic fallback)
   - Geo/IP enrichment is applied

3. **Normalization + storage**
   - Sessions, indicators, and malware metadata are persisted to SQLite
   - STIX bundles are generated per session

4. **API serving (FastAPI)**
   - Public feed, sessions, indicators, STIX/TAXII, quality/health endpoints
   - Internal data scrubbing for private IP topology exposure prevention

## API module layout

- `app/main.py` — app setup, shared utilities, core public routes
- `app/routers/quality.py` — `/api/v1/quality`, `/api/v1/limitations`
- `app/routers/taxii.py` — TAXII discovery/collections/objects
- `app/routers/intel.py` — IP/HASSH/integrity enrichment routes
- `app/routers/admin.py` — revoked feed + revoke/unrevoke operations
- `app/database.py` — SQLite schema + query/write layer
- `app/stix.py` — STIX 2.1 object and bundle construction
- `app/pipeline.py` — log processing and enrichment pipeline

## Data model

Primary SQLite tables:
- `sessions`
- `indicators`
- `malware_samples`

Indexes are present for common access patterns (`src_ip`, indicator value/type, attack_type, timestamp).

## Operational reliability

- CI gates: lint + type-check + tests + smoke test
- Reproducible deploy script for CT103
- Startup self-check endpoint validates schema + pipeline state readability
- Stats query cache (short TTL + invalidation on writes) reduces repeated query load

## Security posture notes

- Internal/private IPs scrubbed from exposed payloads
- Credentials are redacted in public outputs
- Revocation system supports known false positives / benign scanner handling
- Public feed explicitly separates pipeline heartbeat freshness from data insert freshness
