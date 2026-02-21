# 🛡️ Honeypot Threat Intel Feed

AI-enriched SSH honeypot threat intelligence published as a free, public API with STIX 2.1 output and MITRE ATT&CK mappings.

**Live API:** [https://threat-intel.101904.xyz](https://threat-intel.101904.xyz)  
**Swagger Docs:** [https://threat-intel.101904.xyz/docs](https://threat-intel.101904.xyz/docs)  
**OpenAPI Schema:** [https://threat-intel.101904.xyz/openapi.json](https://threat-intel.101904.xyz/openapi.json)

## What Is This?

A live SSH honeypot ([Cowrie](https://github.com/cowrie/cowrie)) captures real attack traffic. Each session is:

1. **Assembled** from raw Cowrie JSON logs into complete attack sessions
2. **Classified** by a local LLM (Mistral Small 3.2 via Ollama) with rule-based fallback
3. **Mapped** to [MITRE ATT&CK](https://attack.mitre.org/) techniques
4. **Published** as STIX 2.1 bundles with TLP:CLEAR marking

No API key required. Rate limit: 100 req/min.

## Quick Start

```bash
# Latest IOCs (JSON)
curl -s https://threat-intel.101904.xyz/api/v1/feed?since=24h | jq .

# Full STIX 2.1 bundle
curl -s https://threat-intel.101904.xyz/api/v1/feed/stix -o threat-intel.json

# CSV export
curl -s "https://threat-intel.101904.xyz/api/v1/feed?format=csv&since=7d" -o iocs.csv

# Browse attack sessions
curl -s https://threat-intel.101904.xyz/api/v1/sessions?limit=10 | jq .

# Dashboard stats
curl -s https://threat-intel.101904.xyz/api/v1/stats | jq .
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/feed` | IOC feed (JSON, CSV, or STIX). Filters: `since`, `type`, `threat_level`, `format` |
| GET | `/api/v1/feed/stix` | Full STIX 2.1 bundle with all sessions |
| GET | `/api/v1/indicators` | Flat indicator list with pagination |
| GET | `/api/v1/indicators/{value}` | Lookup sessions for a specific indicator |
| GET | `/api/v1/sessions` | Browse enriched attack sessions |
| GET | `/api/v1/sessions/{id}` | Full session detail with STIX bundle |
| GET | `/api/v1/stats` | Dashboard statistics + MITRE heatmap |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/about` | Scoring methodology, data policy, API metadata |
| GET | `/docs` | Swagger UI |
| GET | `/openapi.json` | OpenAPI 3.1 schema |

### Filtering

- **`since`**: ISO 8601 (`2026-02-20T00:00:00Z`), relative (`1h`, `6h`, `24h`, `7d`, `30d`), or Unix epoch
- **`type`**: `ipv4-addr`, `url`, `file-hash`, `all`
- **`threat_level`**: Comma-separated: `low`, `medium`, `high`, `critical`
- **`attack_type`**: `brute_force`, `credential_stuffing`, `recon`, `malware_deployment`, `cryptominer`, `botnet_recruitment`, `lateral_movement`, `data_exfil`, `unknown`
- **`limit`/`offset`**: Pagination (max 1000 per page). Responses include `total` and `has_more`.

### Caching

All list endpoints support `ETag` / `If-None-Match`. Returns `304 Not Modified` when data hasn't changed.

## Scoring

| Level | Confidence | Description |
|-------|-----------|-------------|
| `low` | 40 | Failed brute force only |
| `medium` | 65 | Successful login + basic recon |
| `high` | 85 | Malware download or persistence |
| `critical` | 95 | Cryptominer, C2, or active exploitation |

- **Source**: AI classification (Mistral Small 3.2) with deterministic rule-based fallback
- **TTL**: STIX `valid_until` = 7 days from first observation
- **Scope**: Reflects *observed behavior severity*, not victim impact

## STIX 2.1 Quality

- Consistent `identity` producer object with `created_by_ref` on all indicators
- `TLP:CLEAR` marking definition included
- Correct STIX patterns: `ipv4-addr:value`, `url:value`, `file:hashes.'SHA-256'`
- `observed-data` for raw observations, `indicator` for assessed threats
- `attack-pattern` objects with MITRE ATT&CK `external_references`
- `kill_chain_phases` on indicators
- `relationship` objects linking indicators → attack-patterns, indicators → malware

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│ Cowrie SSH   │────▶│ Pipeline     │────▶│ SQLite DB      │
│ Honeypot     │     │ (assembler + │     │                │
│              │     │  enrichment) │     └───────┬────────┘
└─────────────┘     └──────┬───────┘             │
                           │                     ▼
                    ┌──────▼───────┐     ┌────────────────┐
                    │ Ollama LLM   │     │ FastAPI        │
                    │ (Mistral 3.2)│     │ REST API       │
                    └──────────────┘     └────────────────┘
```

- **Cowrie** captures SSH attacks (port 22, NAT from WAN)
- **Pipeline** runs every 15 minutes, reads new log events, assembles sessions
- **Ollama** classifies attacks; rule-based fallback if unavailable
- **FastAPI** serves the public API with STIX, JSON, and CSV output
- **SQLite** stores sessions, indicators, and malware samples

## Data Handling & Privacy

**Collected:** Source IPs, usernames (passwords redacted), commands, malware URLs/hashes, SSH fingerprints  
**Not exposed:** Internal IPs (scrubbed), raw passwords, sensor topology  
**Retention:** Indefinite; STIX indicators have 7-day validity window

⚠️ **Disclaimer:** Indicators are from a single SSH honeypot and may include NAT/VPN/shared IPs, Tor exit nodes, or legitimate researchers. Do not use as sole blocking evidence.

## Self-Hosting

```bash
git clone https://github.com/Tristan1019-user/honeypot-threat-intel.git
cd honeypot-threat-intel

# Edit compose.yml to set OLLAMA_URL and cowrie log path
docker compose up -d

# Trigger initial backfill
curl http://localhost:8099/api/v1/pipeline/run?log_path=/cowrie/var/log/cowrie/cowrie.json
```

### Requirements
- Docker + Docker Compose
- Cowrie honeypot (or compatible JSON logs)
- Ollama instance (optional — falls back to rule-based classification)

## License

MIT
