"""
Cowrie AI Threat Intel Feed - FastAPI Application

Public REST API serving AI-enriched threat intelligence from an SSH honeypot.
Publishes STIX 2.1 IOC feeds, indicators, and attack session data.
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Query, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from . import database as db
from .models import (
    HealthResponse, IndicatorRecord, FeedResponseOffset, FeedResponseCursor,
    IndicatorListResponse, SessionSummary, SessionDetail, SessionListResponse,
    StatsResponse, IPSightingResponse, IntegrityResponse, RevocationResponse,
    ErrorResponse, RateLimitError, TAXIIDiscovery, TAXIICollections,
    AboutResponse, ObservedFeatures, PaginationOffset,
)
from .stix import merge_stix_bundles, TLP_CLEAR_MARKING

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

API_VERSION = "1.5.0"

# Admin IP allowlist for revoke/unrevoke endpoints
ADMIN_IPS = {
    "127.0.0.1", "::1",          # localhost
    "192.168.1.0/24",             # LAN (checked via prefix)
    "172.16.0.0/12",              # Docker internal
}

def _get_real_ip(request: Request) -> str:
    """Get the real client IP, looking through reverse proxy headers.
    Priority: CF-Connecting-IP > X-Real-IP > X-Forwarded-For > direct client."""
    # Cloudflare sets this to the true client IP
    cf_ip = request.headers.get("cf-connecting-ip", "").strip()
    if cf_ip:
        return cf_ip
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        # First IP in chain is the original client
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC 1918 / loopback."""
    return (ip.startswith("192.168.") or ip.startswith("10.") or
            ip.startswith("172.16.") or ip.startswith("172.17.") or
            ip.startswith("172.18.") or ip.startswith("172.19.") or
            ip.startswith("172.2") or ip.startswith("172.3") or
            ip in ("127.0.0.1", "::1", ""))


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


def _is_admin(request: Request) -> bool:
    """Check admin access via token OR private IP.
    Token auth: pass header 'X-Admin-Token: <token>' or query param 'admin_token=<token>'.
    IP auth: direct connections from RFC 1918 / loopback (no proxy headers)."""
    # Token-based auth (preferred, works through any proxy)
    if ADMIN_TOKEN:
        token = request.headers.get("x-admin-token", "") or request.query_params.get("admin_token", "")
        if token == ADMIN_TOKEN:
            return True
    # IP-based auth: only trust if NO proxy headers (direct LAN connection)
    real_ip = _get_real_ip(request)
    direct_ip = request.client.host if request.client else ""
    # If X-Forwarded-For or CF-Connecting-IP is set, this came through a proxy
    # and the direct IP is the proxy, not the client. Reject unless token matched.
    has_proxy_headers = bool(
        request.headers.get("x-forwarded-for") or
        request.headers.get("cf-connecting-ip")
    )
    if has_proxy_headers:
        return False  # Must use token for proxied requests
    return _is_private_ip(direct_ip)
MODEL_VERSION = "mistral-small3.2:24b"


def parse_since(since: Optional[str]) -> Optional[str]:
    """
    Parse 'since' parameter. Accepts:
      - ISO 8601 timestamps (2026-02-20T00:00:00Z)
      - Relative durations: 1h, 6h, 24h, 7d, 30d, 1w
      - Unix epoch seconds
    Returns ISO timestamp string or None. Raises HTTPException on bad input.
    """
    if not since:
        return None

    rel_match = re.match(r'^(\d+)([hdwm])$', since.strip().lower())
    if rel_match:
        amount = int(rel_match.group(1))
        unit = rel_match.group(2)
        delta_map = {'h': timedelta(hours=amount), 'd': timedelta(days=amount),
                     'w': timedelta(weeks=amount), 'm': timedelta(days=amount * 30)}
        dt = datetime.now(timezone.utc) - delta_map[unit]
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        epoch = float(since)
        if epoch > 1e9:
            return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    try:
        dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    raise HTTPException(
        status_code=400,
        detail=f"Invalid 'since' format: '{since}'. Accepted: ISO 8601 (2026-02-20T00:00:00Z), "
               f"relative (1h, 6h, 24h, 7d, 30d, 1w), or Unix epoch seconds."
    )


def redact_credentials(stats: dict) -> dict:
    """Redact password portion of credentials in stats output."""
    if "top_credentials" in stats:
        redacted = []
        for item in stats["top_credentials"]:
            for cred, count in item.items():
                username = cred.split(":")[0] if ":" in cred else cred
                redacted.append({f"{username}:***": count})
        stats["top_credentials"] = redacted
    return stats


INTERNAL_IP_RE = re.compile(r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+")
SENSOR_NAME = "honeypot-svr04"


def scrub_internal_ips(text: str) -> str:
    return INTERNAL_IP_RE.sub(SENSOR_NAME, text)


def scrub_dict(obj):
    if isinstance(obj, str):
        return scrub_internal_ips(obj)
    elif isinstance(obj, dict):
        return {k: scrub_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [scrub_dict(v) for v in obj]
    return obj


def _etag(data) -> str:
    """Generate ETag from response data."""
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return f'"{hashlib.md5(raw).hexdigest()}"'


def _check_etag(request: Request, etag: str) -> Optional[Response]:
    """Return 304 if client ETag matches."""
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return None


def _cache_headers(etag: str, max_age: int = 300) -> dict:
    return {
        "ETag": etag,
        "Cache-Control": f"public, max-age={max_age}",
        "Last-Modified": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
    }


# --- App lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    logger.info("Threat Intel Feed API started")
    yield
    logger.info("Threat Intel Feed API stopped")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Cowrie AI Threat Intel Feed",
    description="""AI-enriched SSH honeypot threat intelligence in STIX 2.1 format.

## Overview
This API publishes IOCs (Indicators of Compromise) observed on a live SSH honeypot.
Attack sessions are classified using a local LLM (Mistral Small 3.2) and mapped to
MITRE ATT&CK techniques. Data is available in JSON, CSV, and STIX 2.1 bundle formats.

## Scoring Semantics

### `threat_level` (severity + confidence combined)
Derived from a combination of AI classification and rule-based heuristics:

| Level | Meaning | Confidence | Typical Indicators |
|-------|---------|------------|-------------------|
| `low` | Failed brute force only, no successful auth | 40 | Credential guessing, no shell access |
| `medium` | Successful login + basic reconnaissance | 65 | System enumeration commands (uname, /proc) |
| `high` | Malware download or persistent access attempted | 85 | wget/curl, crontab modification, SSH keys |
| `critical` | Active exploitation, cryptominer, or C2 activity | 95 | Mining pool connections, botnet recruitment |

- **Source**: AI classification (Ollama/Mistral) with rule-based fallback when AI is unavailable
- **Confidence**: Maps directly from threat_level (see table above), also available as `confidence` integer (0-100) in STIX indicators
- **Impact vs Priority**: threat_level reflects *observed behavior severity*, not victim impact

### Indicator Expiration (TTL)
- STIX `valid_from`: First observation timestamp
- STIX `valid_until`: 7 days after first observation (scanning IPs churn rapidly)
- Consumers should treat expired indicators as stale; re-observation resets the window
- The `/feed` endpoint returns only non-expired indicators by default

### `attack_type` enum
`brute_force` | `credential_stuffing` | `recon` | `malware_deployment` | `cryptominer` | `botnet_recruitment` | `lateral_movement` | `data_exfil` | `unknown`

## Data Handling & Privacy

### What we store
- Source IP addresses of attackers connecting to the honeypot
- Usernames and passwords attempted (passwords redacted in API responses)
- Commands executed in the honeypot shell
- URLs and SHA-256 hashes of downloaded malware
- SSH client version strings and HASSH fingerprints

### What we do NOT store
- Internal/sensor network topology (internal IPs are scrubbed)
- Victim data (this is a honeypot - there are no real victims)
- PII beyond attacker IP addresses

### Retention
- Indicators are retained indefinitely but have a 7-day `valid_until` window in STIX
- Raw session data is retained for analysis; summarized data is published

### Disclaimer
Indicators reflect **observations from a single SSH honeypot** and may include:
- NAT/VPN/shared hosting IPs (shared infrastructure)
- Tor exit nodes
- Compromised residential IPs (innocent owners)
- Scanners with legitimate research purposes

**Do not use these indicators as sole evidence for blocking production traffic.**
They are best used as supplementary threat intelligence alongside other sources.

## STIX 2.1 Notes
- All bundles include a consistent `identity` object for the producer (`honeypot-svr04`)
- Indicators use `created_by_ref` pointing to this identity
- TLP:CLEAR marking definition is included (data is public)
- STIX patterns use correct SCO types: `ipv4-addr`, `url`, `file:hashes.'SHA-256'`
- `observed-data` objects represent raw observations; `indicator` objects represent assessed threats
- All technique references use MITRE ATT&CK `external_references`

## Rate Limits
100 requests/minute per IP. STIX bundle endpoint: 30/minute.
""",
    version=API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# --- Rate limit headers middleware ---

from starlette.middleware.base import BaseHTTPMiddleware

class RateLimitHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Add standard rate limit headers on all responses
        response.headers["X-RateLimit-Limit"] = "100"
        response.headers["X-RateLimit-Window"] = "60"
        return response

app.add_middleware(RateLimitHeadersMiddleware)


# --- Custom 429 handler with Retry-After ---

from starlette.responses import JSONResponse as StarletteJSONResponse

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return StarletteJSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "detail": "Too many requests. See Retry-After header.",
            "retry_after_seconds": 60,
            "guidance": "Back off exponentially. Default rate: 100 req/min, STIX bundle: 30 req/min.",
        },
        headers={"Retry-After": "60"},
    )


# --- Landing page (loaded from file for maintainability) ---

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing():
    # Fetch stats server-side for noscript fallback
    try:
        stats = await db.get_stats()
    except Exception:
        stats = {}
    return _build_landing_html(stats)


def _build_landing_html(stats: dict = None) -> str:
    s = stats or {}
    total_sessions = s.get("total_sessions", 0)
    total_indicators = s.get("total_indicators", 0)
    total_malware = s.get("total_malware_samples", 0)
    total_countries = len(s.get("top_countries", {}))

    # Build server-side rendered recent indicators
    recent_inds = s.get("recent_indicators", [])
    ssr_indicators = ""
    tc_map = {"low": "tag-low", "medium": "tag-med", "high": "tag-high", "critical": "tag-crit"}
    for i in recent_inds[:5]:
        tl = i.get("threat_level", "low")
        ssr_indicators += (
            f'<div class="live-card"><span class="ip">{i.get("value","")}</span> '
            f'<span class="tag {tc_map.get(tl,"tag-low")}">{tl}</span> '
            f'<span class="bg">{i.get("type","")}</span> '
            f'<span style="color:#666;margin-left:.5rem">seen {i.get("times_seen",1)}x</span></div>'
        )
    if not ssr_indicators:
        ssr_indicators = '<div class="live-card" style="color:#555">No indicators yet</div>'

    # Build server-side rendered recent sessions
    recent_sess = s.get("recent_sessions", [])
    ssr_sessions = ""
    for sess in recent_sess[:3]:
        tl = sess.get("threat_level", "low")
        at = sess.get("attack_type", "unknown")
        country = sess.get("country", "")
        org = (sess.get("org") or "")[:30]
        summary = sess.get("summary", "")
        ssr_sessions += (
            f'<div class="live-card"><span class="ip">{sess.get("src_ip","")}</span> '
            f'<span class="tag {tc_map.get(tl,"tag-low")}">{tl}</span> '
            f'<span class="bg">{at}</span>'
            f'{" <span style=color:#888>" + country + "</span>" if country else ""}'
            f'{" <span style=color:#666;font-size:.7rem>" + org + "</span>" if org else ""}'
            f'<br><span style="color:#777;font-size:.75rem">{summary}</span></div>'
        )
    if not ssr_sessions:
        ssr_sessions = '<div class="live-card" style="color:#555">No sessions yet</div>'

    html = _LANDING_TEMPLATE
    html = html.replace("{{TOTAL_SESSIONS}}", str(total_sessions))
    html = html.replace("{{TOTAL_INDICATORS}}", str(total_indicators))
    html = html.replace("{{TOTAL_MALWARE}}", str(total_malware))
    html = html.replace("{{TOTAL_COUNTRIES}}", str(total_countries))
    html = html.replace("{{SSR_INDICATORS}}", ssr_indicators)
    html = html.replace("{{SSR_SESSIONS}}", ssr_sessions)
    html = html.replace("{{API_VERSION}}", API_VERSION)
    return html


_LANDING_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Honeypot Threat Intel Feed</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'SF Mono','Fira Code',monospace;background:#0a0a0a;color:#e0e0e0}
        .c{max-width:960px;margin:0 auto;padding:2rem}
        h1{color:#00ff88;font-size:1.8rem;margin-bottom:.5rem}
        .sub{color:#888;margin-bottom:1.5rem}
        .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem;margin:1.5rem 0}
        .stat{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:1.2rem;text-align:center}
        .sv{font-size:1.8rem;color:#00ff88;font-weight:bold}
        .sl{color:#888;font-size:.75rem;margin-top:.2rem}
        h2{color:#00cc66;margin:2rem 0 .8rem;font-size:1.1rem}
        h3{color:#00aa55;margin:1rem 0 .4rem;font-size:.95rem}
        .ep{background:#1a1a1a;border-left:3px solid #00ff88;padding:.6rem .8rem;margin:.4rem 0;border-radius:0 4px 4px 0;font-size:.85rem}
        .m{color:#00ff88;font-weight:bold}.p{color:#ccc}.d{color:#888;font-size:.8rem}.pm{color:#666;font-size:.75rem;margin-top:.2rem}
        a{color:#00ff88;text-decoration:none}a:hover{text-decoration:underline}
        .ft{margin-top:2rem;color:#555;font-size:.75rem;border-top:1px solid #222;padding-top:.8rem}
        .bg{display:inline-block;background:#1a3a1a;color:#00ff88;padding:.15rem .5rem;border-radius:4px;font-size:.7rem}
        .bg-w{background:#3a3a1a;color:#ffaa00}.bg-r{background:#3a1a1a;color:#ff4444}
        pre{background:#111;border:1px solid #333;border-radius:4px;padding:.6rem;overflow-x:auto;font-size:.75rem;color:#ccc;margin:.4rem 0}
        code{color:#00ff88}
        .sec{margin:1.5rem 0;padding:1.2rem;background:#111;border:1px solid #222;border-radius:8px}
        .sec p,.sec li{color:#aaa;line-height:1.5;font-size:.85rem}
        ul{margin-left:1.2rem}li{margin:.2rem 0}
        table{width:100%;border-collapse:collapse;margin:.4rem 0}
        th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #222;font-size:.78rem}
        th{color:#00cc66}td{color:#aaa}
        .live{margin:1.5rem 0}
        .live-card{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.8rem 1rem;margin:.4rem 0;font-size:.8rem}
        .live-card .ip{color:#00ff88;font-weight:bold}
        .live-card .tag{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.7rem;margin-right:.3rem}
        .tag-low{background:#1a2a1a;color:#44aa44}.tag-med{background:#2a2a1a;color:#aaaa44}
        .tag-high{background:#3a2a1a;color:#ff8844}.tag-crit{background:#3a1a1a;color:#ff4444}
        .mitre-bar{display:flex;gap:2px;margin:.5rem 0;align-items:flex-end;height:40px}
        .mitre-col{background:#00ff88;min-width:18px;border-radius:2px 2px 0 0;position:relative;cursor:default}
        .mitre-col:hover::after{content:attr(data-label);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#222;color:#eee;padding:2px 6px;border-radius:3px;font-size:.65rem;white-space:nowrap}
        .trust{display:flex;gap:1rem;flex-wrap:wrap;margin:.5rem 0}
        .trust-item{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.6rem .8rem;font-size:.78rem;flex:1;min-width:200px}
        .trust-item .label{color:#888;font-size:.7rem}.trust-item .val{color:#00ff88;font-size:.75rem;word-break:break-all;margin-top:.2rem}
        .nav{display:flex;gap:.8rem;margin:1rem 0;flex-wrap:wrap}
        .nav a{background:#1a1a1a;border:1px solid #333;padding:.4rem .8rem;border-radius:4px;font-size:.8rem}
        .nav a:hover{border-color:#00ff88}
    </style>
</head>
<body>
<div class="c">
    <h1>Honeypot Threat Intel Feed</h1>
    <p class="sub">Live AI-enriched SSH honeypot intelligence &middot; <span class="bg">STIX 2.1</span> <span class="bg">TLP:CLEAR</span> <span class="bg">MITRE ATT&CK</span></p>

    <div class="nav">
        <a href="/docs">Swagger UI</a>
        <a href="/api/v1/feed/stix">STIX Bundle</a>
        <a href="/api/v1/feed?format=csv&since=7d">CSV Export</a>
        <a href="/taxii2/">TAXII 2.1</a>
        <a href="/about">About</a>
        <a href="https://github.com/Tristan1019-user/honeypot-threat-intel" target="_blank">GitHub</a>
    </div>

    <div class="stats">
        <div class="stat"><div class="sv" id="s-sessions">{{TOTAL_SESSIONS}}</div><div class="sl">Attack Sessions</div></div>
        <div class="stat"><div class="sv" id="s-indicators">{{TOTAL_INDICATORS}}</div><div class="sl">IOC Indicators</div></div>
        <div class="stat"><div class="sv" id="s-malware">{{TOTAL_MALWARE}}</div><div class="sl">Malware Samples</div></div>
        <div class="stat"><div class="sv" id="s-countries">{{TOTAL_COUNTRIES}}</div><div class="sl">Source Countries</div></div>
    </div>

    <!-- MITRE ATT&CK Mini Heatmap -->
    <h2>MITRE ATT&CK Technique Distribution</h2>
    <div class="mitre-bar" id="mitre-bar"></div>

    <!-- Live Sample: Recent Indicators -->
    <h2>Recent Indicators</h2>
    <div class="live" id="live-indicators">{{SSR_INDICATORS}}</div>

    <!-- Live Sample: Recent Sessions -->
    <h2>Recent Attack Sessions</h2>
    <div class="live" id="live-sessions">{{SSR_SESSIONS}}</div>

    <!-- Trust & Integrity -->
    <h2>Feed Integrity</h2>
    <div class="trust" id="trust">
        <div class="trust-item"><div class="label">Producer Identity</div><div class="val">honeypot-svr04 (STIX identity in every bundle)</div></div>
        <div class="trust-item"><div class="label">STIX Bundle SHA-256</div><div class="val" id="t-hash">Loading...</div></div>
        <div class="trust-item"><div class="label">Last Updated</div><div class="val" id="t-updated">-</div></div>
        <div class="trust-item"><div class="label">Pipeline Cadence</div><div class="val">Every 15 minutes (OpenClaw cron)</div></div>
    </div>

    <h2>API Endpoints</h2>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/feed">/api/v1/feed</a></span> - <span class="d">IOC feed (JSON/CSV/STIX). ETag caching.</span><div class="pm"><code>since</code> <code>type</code> <code>threat_level</code> <code>format</code> <code>limit</code> <code>offset</code></div></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/feed/stix">/api/v1/feed/stix</a></span> - <span class="d">Full STIX 2.1 bundle + integrity hash</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/indicators">/api/v1/indicators</a></span> - <span class="d">Flat indicator list</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p">/api/v1/indicators/{value}</span> - <span class="d">Indicator lookup with sighting history</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/sessions">/api/v1/sessions</a></span> - <span class="d">Enriched sessions + geo data</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p">/api/v1/sessions/{id}</span> - <span class="d">Full detail + STIX bundle</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p">/api/v1/ip/{ip}</span> - <span class="d">IP sightings, ASN, country, cloud provider</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p">/api/v1/hassh/{hash}</span> - <span class="d">Sessions by HASSH fingerprint</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/stats">/api/v1/stats</a></span> - <span class="d">Dashboard + MITRE heatmap + geo</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/api/v1/integrity">/api/v1/integrity</a></span> - <span class="d">Bundle SHA-256 + object count</span></div>
    <div class="ep"><span class="m">POST</span> <span class="p">/api/v1/indicators/{value}/revoke</span> - <span class="d">Mark as false positive / researcher / Tor exit</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/taxii2/">/taxii2/</a></span> - <span class="d">TAXII 2.1 discovery (+ /collections, /objects)</span></div>
    <div class="ep"><span class="m">GET</span> <span class="p"><a href="/docs">/docs</a></span> | <a href="/redoc">/redoc</a> | <a href="/openapi.json">/openapi.json</a> - <span class="d">Interactive docs</span></div>

    <h2>Quick Start</h2>
    <pre># Latest IOCs
curl -s https://threat-intel.101904.xyz/api/v1/feed?since=24h | jq .

# STIX 2.1 bundle for SIEM
curl -s https://threat-intel.101904.xyz/api/v1/feed/stix -o threat-intel.json

# CSV for spreadsheets
curl -s "https://threat-intel.101904.xyz/api/v1/feed?format=csv&since=7d" -o iocs.csv

# TAXII 2.1 discovery
curl -s https://threat-intel.101904.xyz/taxii2/ -H "Accept: application/taxii+json;version=2.1"

# IP sighting lookup
curl -s https://threat-intel.101904.xyz/api/v1/ip/1.2.3.4 | jq .

# Cursor-based pagination (for SIEM ingestion)
curl -s "https://threat-intel.101904.xyz/api/v1/feed?cursor=0&limit=50"
# → response includes "next_cursor":"142" → use that for next request

# Include inline STIX objects per indicator
curl -s "https://threat-intel.101904.xyz/api/v1/feed?include=stix&limit=5"

# Session detail (commands, downloads, STIX bundle)
curl -s https://threat-intel.101904.xyz/api/v1/sessions/SESSION_ID | jq .

# Indicator lookup (all sessions for one IP)
curl -s https://threat-intel.101904.xyz/api/v1/indicators/176.120.22.52 | jq .

# HASSH fingerprint lookup
curl -s https://threat-intel.101904.xyz/api/v1/hassh/HASSH_HASH | jq .

# Dashboard stats + MITRE heatmap
curl -s https://threat-intel.101904.xyz/api/v1/stats | jq .mitre_technique_frequency

# Bundle integrity check
curl -s https://threat-intel.101904.xyz/api/v1/integrity | jq .stix_bundle_sha256

# ETag caching (304 if unchanged)
curl -sI https://threat-intel.101904.xyz/api/v1/feed | grep -i etag</pre>

    <h2>Sample Response Objects</h2>
    <h3>Indicator (from /api/v1/feed)</h3>
    <pre>{
  "type": "ipv4-addr",
  "value": "176.120.22.52",
  "first_seen": "2026-01-15T03:22:10Z",
  "last_seen": "2026-02-19T14:08:33Z",
  "times_seen": 14,
  "threat_level": "high",
  "confidence": 85,
  "revoked": false,
  "sensor_id": "honeypot-svr04",
  "feed_id": "honeypot-svr04",
  "collection_window": {
    "first_observed": "2026-01-15T03:22:10Z",
    "last_observed": "2026-02-19T14:08:33Z"
  }
}</pre>
    <h3>Session (from /api/v1/sessions)</h3>
    <pre>{
  "session_id": "a1b2c3d4e5f6",
  "src_ip": "176.120.22.52",
  "attack_type": "malware_deployment",
  "threat_level": "high",
  "confidence": 85,
  "country": "RU",
  "asn": "AS49505",
  "org": "Selectel",
  "mitre_techniques": ["T1110.001", "T1078", "T1059.004", "T1105"],
  "summary": "Brute force, login, wget malware download",
  "observed_features": {
    "login_attempts": 8,
    "successful_logins": 1,
    "commands_executed": 12,
    "files_downloaded": 2,
    "download_command_seen": true,
    "persistence_attempt": true,
    "system_recon": true,
    "mining_indicators": false,
    "classification_method": "ai"
  }
}</pre>
    <h3>STIX 2.1 Indicator (from /api/v1/feed?format=stix)</h3>
    <pre>{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-...",
  "created_by_ref": "identity--honeypot-svr04-...",
  "object_marking_refs": ["marking-definition--613f2e26-..."],
  "pattern": "[ipv4-addr:value = '176.120.22.52']",
  "pattern_type": "stix",
  "valid_from": "2026-01-15T03:22:10.000Z",
  "valid_until": "2026-01-22T03:22:10.000Z",
  "confidence": 85,
  "labels": ["malicious-activity", "malware_deployment"],
  "kill_chain_phases": [
    {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
  ]
}</pre>

    <h2>Scoring</h2>
    <div class="sec">
        <table>
            <tr><th>Level</th><th>Confidence</th><th>Meaning</th><th>TTL</th></tr>
            <tr><td><span class="tag tag-low">low</span></td><td>40</td><td>Failed brute force only</td><td>7 days</td></tr>
            <tr><td><span class="tag tag-med">medium</span></td><td>65</td><td>Successful login + basic recon</td><td>7 days</td></tr>
            <tr><td><span class="tag tag-high">high</span></td><td>85</td><td>Malware download or persistence</td><td>7 days</td></tr>
            <tr><td><span class="tag tag-crit">critical</span></td><td>95</td><td>Cryptominer, C2, active exploitation</td><td>7 days</td></tr>
        </table>
        <p style="margin-top:.5rem">Derived from AI (Mistral Small 3.2) + rule-based fallback. Reflects observed severity, not victim impact.</p>
    </div>

    <h2>Malware Samples</h2>
    <div class="sec">
        <p>A <strong>malware sample</strong> is any file downloaded by an attacker inside the honeypot shell (via <code>wget</code>, <code>curl</code>, <code>tftp</code>, etc.). We store:</p>
        <ul>
            <li><strong>SHA-256 hash</strong> of the downloaded binary</li>
            <li><strong>Source URL</strong> the attacker fetched from</li>
            <li><strong>File size</strong> and type (when determinable)</li>
        </ul>
        <p style="margin-top:.5rem">We do <strong>not</strong> redistribute malware binaries. Only hashes and metadata are published. Use the SHA-256 to look up samples on VirusTotal, MalwareBazaar, or similar repositories.</p>
    </div>

    <h2>How to Use Safely</h2>
    <div class="sec">
        <h3 style="color:#00aa55;margin-bottom:.3rem">Mode 1: Alert-only / SIEM enrichment (recommended)</h3>
        <p>Ingest the feed into your SIEM/TIP as enrichment data. When a source IP in your logs matches a feed indicator, <strong>raise an alert</strong> - don't auto-block. Use the <code>confidence</code> score, <code>attack_type</code>, and <code>observed_features</code> to triage.</p>
        <h3 style="color:#00aa55;margin:.5rem 0 .3rem">Mode 2: Selective blocking (advanced)</h3>
        <p>Auto-block only when <strong>all</strong> of these conditions are met:</p>
        <ul>
            <li><code>threat_level</code> is <strong>high</strong> or <strong>critical</strong></li>
            <li><code>times_seen</code> >= 3 (repeat offender, not a one-off scan)</li>
            <li><code>revoked</code> is <strong>false</strong></li>
            <li>Not a known cloud research scanner (check <code>org</code> for Censys, Shodan, etc.)</li>
            <li>Not a Tor exit node (check <code>revoked_reason</code> or cross-reference)</li>
        </ul>
        <p style="margin-top:.5rem;color:#888">This single-honeypot feed should <strong>never</strong> be the sole input to a production blocklist. Use it alongside commercial feeds, internal telemetry, and reputation services.</p>
    </div>

    <h2>Data Handling & Privacy</h2>
    <div class="sec">
        <p><strong>Collected:</strong> Source IPs, usernames (passwords redacted), commands, malware URLs/hashes, SSH fingerprints, ASN/country (via ipwho.is)</p>
        <p><strong>Not exposed:</strong> Internal IPs (scrubbed), raw passwords, sensor topology</p>
        <p><strong>Retention:</strong> Indefinite; STIX indicators have 7-day validity window</p>
        <p style="margin-top:.5rem"><span class="bg bg-w">Disclaimer</span> Indicators are from a single SSH honeypot. May include shared/NAT IPs, Tor exits, compromised residential hosts, or research scanners. <strong>Not suitable as sole blocking evidence.</strong></p>
    </div>

    <h2>Rate Limits</h2>
    <div class="sec">
        <p>Default: <strong>100 req/min</strong> per IP. STIX bundle: <strong>30 req/min</strong>.</p>
        <p>On limit, API returns <code>429</code> with <code>Retry-After: 60</code> header and JSON body. Back off exponentially.</p>
    </div>

    <div class="ft">
        Honeypot SVR04 Threat Intel Feed v{{API_VERSION}} &middot; Producer: <code>honeypot-svr04</code> &middot;
        <a href="https://github.com/Tristan1019-user/honeypot-threat-intel">Source</a> &middot;
        <a href="/about">About</a> &middot;
        <a href="/docs">API Docs</a>
    </div>
</div>
<script>
const TC={low:'tag-low',medium:'tag-med',high:'tag-high',critical:'tag-crit'};
const MITRE_NAMES={T1110:'Brute Force','T1110.001':'Password Guessing','T1110.003':'Password Spraying',T1078:'Valid Accounts','T1059.004':'Unix Shell',T1105:'Tool Transfer',T1496:'Cryptomining',T1082:'System Discovery',T1087:'Account Discovery',T1547:'Persistence',T1021:'SSH',T1133:'External Services',T1070:'Indicator Removal'};
fetch('/api/v1/stats').then(r=>r.json()).then(d=>{
    document.getElementById('s-sessions').textContent=d.total_sessions||0;
    document.getElementById('s-indicators').textContent=d.total_indicators||0;
    document.getElementById('s-malware').textContent=d.total_malware_samples||0;
    document.getElementById('s-countries').textContent=Object.keys(d.top_countries||{}).length||'-';
    if(d.last_update)document.getElementById('t-updated').textContent=d.last_update;
    // MITRE heatmap
    const mc=d.mitre_technique_frequency||{};
    const bar=document.getElementById('mitre-bar');
    const maxV=Math.max(...Object.values(mc),1);
    Object.entries(mc).sort((a,b)=>b[1]-a[1]).slice(0,12).forEach(([t,c])=>{
        const col=document.createElement('div');
        col.className='mitre-col';
        col.style.height=Math.max(4,c/maxV*40)+'px';
        col.style.flex='1';
        col.setAttribute('data-label',`${MITRE_NAMES[t]||t}: ${c}`);
        col.title=`${t}: ${c}`;
        bar.appendChild(col);
    });
    // Recent indicators
    const ri=d.recent_indicators||[];
    const ic=document.getElementById('live-indicators');
    if(ri.length){
        ic.innerHTML=ri.map(i=>`<div class="live-card"><span class="ip">${i.value}</span> <span class="tag ${TC[i.threat_level]||'tag-low'}">${i.threat_level}</span> <span class="bg">${i.type}</span> <span style="color:#666;margin-left:.5rem">seen ${i.times_seen}x · ${i.first_seen?.split('T')[0]||'-'}</span></div>`).join('');
    }else ic.innerHTML='<div class="live-card" style="color:#555">No indicators yet</div>';
    // Recent sessions
    const rs=d.recent_sessions||[];
    const sc=document.getElementById('live-sessions');
    if(rs.length){
        sc.innerHTML=rs.map(s=>{
            const mt=s.mitre_techniques?JSON.parse(s.mitre_techniques):[];
            return `<div class="live-card"><span class="ip">${s.src_ip}</span> <span class="tag ${TC[s.threat_level]||'tag-low'}">${s.threat_level}</span> <span class="bg">${s.attack_type||'unknown'}</span>${s.country?' <span style="color:#888">'+s.country+'</span>':''}${s.org?' <span style="color:#666;font-size:.7rem">'+s.org+'</span>':''}${mt.length?' <span style="color:#555;font-size:.7rem">'+mt.join(', ')+'</span>':''}<br><span style="color:#777;font-size:.75rem">${s.summary||''}</span></div>`;
        }).join('');
    }else sc.innerHTML='<div class="live-card" style="color:#555">No sessions yet</div>';
}).catch(()=>{});
// Integrity hash
fetch('/api/v1/integrity').then(r=>r.json()).then(d=>{
    document.getElementById('t-hash').textContent=d.stix_bundle_sha256?.substring(0,24)+'...'||'-';
}).catch(()=>{document.getElementById('t-hash').textContent='unavailable'});
</script>
</body>
</html>"""


# --- API Endpoints ---

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"],
         responses={429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def health(request: Request):
    """API health check. Returns feed status, version, and basic counts."""
    stats = await db.get_stats()
    return {
        "status": "ok",
        "version": API_VERSION,
        "model_version": MODEL_VERSION,
        "feed_id": "honeypot-svr04",
        "last_update": stats.get("last_update"),
        "total_sessions": stats.get("total_sessions", 0),
        "total_indicators": stats.get("total_indicators", 0),
    }


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Stats"],
         responses={429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def stats(request: Request):
    """Dashboard statistics including MITRE ATT&CK technique frequency heatmap.
    Credentials are redacted (username only). Supports ETag caching."""
    data = await db.get_stats()
    data = redact_credentials(data)
    data["model_version"] = MODEL_VERSION
    data["api_version"] = API_VERSION
    data = scrub_dict(data)

    etag = _etag(data)
    cached = _check_etag(request, etag)
    if cached:
        return cached
    return JSONResponse(content=data, headers=_cache_headers(etag, max_age=60))


@app.get("/api/v1/about", response_model=AboutResponse, tags=["Info"])
@limiter.limit("100/minute")
async def about(request: Request):
    """Feed metadata, scoring methodology, data handling policy, and STIX quality notes."""
    return {
        "feed_id": "honeypot-svr04",
        "producer": "Honeypot SVR04 Threat Intel Feed",
        "api_version": API_VERSION,
        "model_version": MODEL_VERSION,
        "stix_version": "2.1",
        "tlp_marking": "TLP:CLEAR",
        "docs": {
            "openapi": "/openapi.json",
            "swagger_ui": "/docs",
            "redoc": "/redoc",
        },
        "scoring": {
            "method": "AI classification (Ollama/Mistral Small 3.2) with rule-based fallback",
            "threat_level": {
                "low": {"confidence": 40, "description": "Failed brute force only, no successful auth"},
                "medium": {"confidence": 65, "description": "Successful login + basic reconnaissance"},
                "high": {"confidence": 85, "description": "Malware download or persistent access attempted"},
                "critical": {"confidence": 95, "description": "Active exploitation, cryptominer, or C2 activity"},
            },
            "indicator_ttl_days": 7,
            "notes": "threat_level reflects observed behavior severity, not victim impact. "
                     "Confidence maps directly from threat_level.",
        },
        "attack_types": [
            "brute_force", "credential_stuffing", "recon", "malware_deployment",
            "cryptominer", "botnet_recruitment", "lateral_movement", "data_exfil", "unknown",
        ],
        "data_handling": {
            "collected": [
                "Source IP addresses of attackers",
                "Usernames attempted (passwords redacted in API)",
                "Commands executed in honeypot shell",
                "URLs and SHA-256 hashes of downloaded malware",
                "SSH client version strings and HASSH fingerprints",
            ],
            "not_stored": [
                "Internal/sensor network topology (IPs scrubbed)",
                "Victim data (honeypot - no real victims)",
                "PII beyond attacker IP addresses",
            ],
            "retention": "Indefinite storage, 7-day STIX valid_until window",
            "disclaimer": (
                "Indicators reflect observations from a single SSH honeypot and may include "
                "NAT/VPN/shared hosting IPs, Tor exit nodes, compromised residential IPs, "
                "or legitimate research scanners. Do not use as sole evidence for blocking "
                "production traffic."
            ),
        },
        "source": "https://github.com/Tristan1019-user/honeypot-threat-intel",
        "rate_limits": {"default": "100/minute", "stix_bundle": "30/minute"},
    }


THREAT_CONFIDENCE = {"critical": 95, "high": 85, "medium": 65, "low": 40}


def _enrich_indicator(ind: dict, include_stix: bool = False) -> dict:
    """Add provenance and confidence fields to an indicator dict."""
    enriched = {
        "type": ind.get("type"),
        "value": ind.get("value"),
        "first_seen": ind.get("first_seen"),
        "last_seen": ind.get("last_seen"),
        "times_seen": ind.get("times_seen", 1),
        "threat_level": ind.get("threat_level"),
        "confidence": THREAT_CONFIDENCE.get(ind.get("threat_level", ""), 50),
        "revoked": bool(ind.get("revoked")),
        # Provenance
        "sensor_id": "honeypot-svr04",
        "feed_id": "honeypot-svr04",
        "collection_window": {
            "first_observed": ind.get("first_seen"),
            "last_observed": ind.get("last_seen"),
        },
    }
    if ind.get("revoked_reason"):
        enriched["revoked_reason"] = ind["revoked_reason"]
    if include_stix and ind.get("stix_object"):
        try:
            enriched["stix_object"] = json.loads(ind["stix_object"]) if isinstance(ind["stix_object"], str) else ind["stix_object"]
        except (json.JSONDecodeError, TypeError):
            pass
    return enriched


@app.get("/api/v1/feed", tags=["Feed"])
@limiter.limit("100/minute")
async def feed(
    request: Request,
    since: Optional[str] = Query(None, description="Time filter: ISO 8601 (2026-02-20T00:00:00Z), relative (1h/6h/24h/7d/30d/1w), or Unix epoch seconds"),
    type: Optional[str] = Query(None, description="Indicator type filter", enum=["ipv4-addr", "url", "file-hash", "all"]),
    threat_level: Optional[str] = Query(None, description="Comma-separated threat levels", examples=["high,critical"]),
    attack_type: Optional[str] = Query(None, description="Attack classification filter", enum=[
        "brute_force", "credential_stuffing", "recon", "malware_deployment",
        "cryptominer", "botnet_recruitment", "lateral_movement", "data_exfil", "unknown",
    ]),
    format: str = Query("json", description="Output format", enum=["json", "stix", "csv"]),
    include: Optional[str] = Query(None, description="Include extra data: 'stix' to embed STIX objects per indicator"),
    cursor: Optional[str] = Query(None, description="Cursor for idempotent pagination (monotonic rowid). Mutually exclusive with offset."),
    include_revoked: bool = Query(False, description="Include revoked/false-positive indicators"),
    ttl: Optional[str] = Query(None, description="Override STIX valid_until TTL (e.g., 24h, 72h, 7d, 30d). Only affects STIX format output. Default: 7d"),
    limit: int = Query(100, ge=1, le=1000, description="Max results per page"),
    offset: int = Query(0, ge=0, description="Pagination offset (use cursor instead for high-volume ingestion)"),
):
    """IOC feed with filtering, pagination, and multiple output formats.

    **Pagination**: Use `offset` for browsing or `cursor` for high-volume SIEM ingestion.
    Cursor-based pagination uses monotonic rowids, avoiding clock skew and making retries idempotent.

    **Provenance**: Each indicator includes `sensor_id`, `feed_id`, `confidence` (0-100),
    and `collection_window` (first/last observed).

    **STIX inline**: Pass `include=stix` to embed the STIX indicator object per record.

    **Revocation**: Revoked indicators (false positives, researchers) are excluded by default.
    Pass `include_revoked=true` to see them.

    Credentials are excluded from the public feed. Supports ETag/If-None-Match caching."""
    parsed_since = parse_since(since)
    include_stix = include and "stix" in include.lower()

    # Cursor-based pagination
    if cursor:
        raw_indicators, next_cursor = await db.query_indicators_cursor(
            cursor=cursor, indicator_type=type, threat_level=threat_level,
            include_revoked=include_revoked, limit=limit,
        )
        raw_indicators = [i for i in raw_indicators if i.get("type") != "credential"]
        indicators = [_enrich_indicator(i, include_stix=include_stix) for i in raw_indicators]
        indicators = scrub_dict(indicators)

        response_data = {
            "feed_id": "honeypot-svr04",
            "sensor_id": "honeypot-svr04",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_version": MODEL_VERSION,
            "indicator_count": len(indicators),
            "pagination": {
                "limit": limit,
                "cursor": cursor,
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
            "indicators": indicators,
        }
        etag = _etag(response_data)
        cached = _check_etag(request, etag)
        if cached:
            return cached
        return JSONResponse(content=response_data, headers=_cache_headers(etag))

    # Offset-based pagination (original behavior)
    raw_indicators = await db.query_indicators(
        since=parsed_since, indicator_type=type, threat_level=threat_level, limit=limit, offset=offset
    )
    total = await db.count_indicators(since=parsed_since, indicator_type=type, threat_level=threat_level)
    raw_indicators = [i for i in raw_indicators if i.get("type") != "credential"]

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["type", "value", "first_seen", "last_seen", "times_seen", "threat_level", "confidence", "revoked", "sensor_id"])
        for ind in raw_indicators:
            writer.writerow([
                ind.get("type"), ind.get("value"), ind.get("first_seen"),
                ind.get("last_seen"), ind.get("times_seen"), ind.get("threat_level"),
                THREAT_CONFIDENCE.get(ind.get("threat_level", ""), 50),
                bool(ind.get("revoked")), "honeypot-svr04",
            ])
        return Response(content=output.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=threat-intel-feed.csv"})

    elif format == "stix":
        from .stix import _stix_id, _now_iso, _valid_until, PRODUCER_IDENTITY, TLP_CLEAR_MARKING
        # Parse custom TTL
        ttl_days = 7  # default
        if ttl:
            ttl_match = re.match(r'^(\d+)([hd])$', ttl.strip().lower())
            if ttl_match:
                amount = int(ttl_match.group(1))
                unit = ttl_match.group(2)
                ttl_days = amount / 24 if unit == 'h' else amount
        stix_objects = [PRODUCER_IDENTITY, TLP_CLEAR_MARKING]
        seen_ids = {PRODUCER_IDENTITY["id"], TLP_CLEAR_MARKING["id"]}
        for ind in raw_indicators:
            pattern_map = {
                "ipv4-addr": f"[ipv4-addr:value = '{ind['value']}']",
                "url": f"[url:value = '{ind['value']}']",
                "file-hash": f"[file:hashes.'SHA-256' = '{ind['value']}']",
            }
            pattern = pattern_map.get(ind.get("type"), f"[x-custom:value = '{ind['value']}']")
            if ind.get("type") == "credential":
                continue

            ind_id = _stix_id("indicator", ind["value"])
            if ind_id in seen_ids:
                continue
            seen_ids.add(ind_id)

            stix_ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": ind.get("first_seen", _now_iso()),
                "modified": ind.get("last_seen", _now_iso()),
                "name": f"Malicious {ind.get('type', 'indicator')}: {ind['value']}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ind.get("first_seen", _now_iso()),
                "valid_until": _valid_until(ind.get("first_seen", _now_iso()), days=ttl_days),
                "confidence": THREAT_CONFIDENCE.get(ind.get("threat_level", "medium"), 50),
                "labels": ["malicious-activity"],
                "created_by_ref": PRODUCER_IDENTITY["id"],
                "object_marking_refs": [TLP_CLEAR_MARKING["id"]],
            }
            if ind.get("revoked"):
                stix_ind["revoked"] = True
            stix_objects.append(stix_ind)
        bundle = {
            "type": "bundle",
            "id": f"bundle--feed-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            "objects": stix_objects,
        }
        return JSONResponse(content=scrub_dict(bundle))

    else:
        indicators = [_enrich_indicator(i, include_stix=include_stix) for i in raw_indicators]
        indicators = scrub_dict(indicators)
        now = datetime.now(timezone.utc).isoformat()
        response_data = {
            "feed_id": "honeypot-svr04",
            "sensor_id": "honeypot-svr04",
            "generated_at": now,
            "model_version": MODEL_VERSION,
            "indicator_count": len(indicators),
            "pagination": {
                "limit": limit,
                "offset": offset,
                "returned": len(indicators),
                "total": total,
                "has_more": offset + limit < total,
            },
            "indicators": indicators,
        }
        etag = _etag(response_data)
        cached = _check_etag(request, etag)
        if cached:
            return cached
        return JSONResponse(content=scrub_dict(response_data), headers=_cache_headers(etag))


@app.get("/api/v1/feed/stix", tags=["Feed"])
@limiter.limit("30/minute")
async def feed_stix(request: Request):
    """Full STIX 2.1 bundle of all session data.

    Includes: identity (producer), TLP:CLEAR marking, indicators, observed-data,
    attack-patterns (MITRE ATT&CK), malware objects, and relationships.
    Deduplicated by STIX object ID."""
    sessions = await db.query_sessions(limit=500)
    bundles = []
    for s in sessions:
        if s.get("stix_bundle"):
            try:
                bundle = json.loads(s["stix_bundle"]) if isinstance(s["stix_bundle"], str) else s["stix_bundle"]
                bundles.append(bundle)
            except (json.JSONDecodeError, TypeError):
                pass

    if bundles:
        merged = merge_stix_bundles(bundles)
    else:
        from .stix import PRODUCER_IDENTITY
        merged = {"type": "bundle", "id": "bundle--empty", "objects": [PRODUCER_IDENTITY, TLP_CLEAR_MARKING]}

    result = scrub_dict(merged)
    etag = _etag(result)
    cached = _check_etag(request, etag)
    if cached:
        return cached
    return JSONResponse(content=result, headers=_cache_headers(etag, max_age=600))


@app.get("/api/v1/indicators", response_model=IndicatorListResponse, tags=["Indicators"],
         responses={429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def indicators(
    request: Request,
    since: Optional[str] = Query(None, description="Time filter: ISO 8601, relative (1h/6h/24h/7d/30d), or Unix epoch"),
    type: Optional[str] = Query(None, description="Indicator type filter", enum=["ipv4-addr", "url", "file-hash", "credential", "all"]),
    threat_level: Optional[str] = Query(None, description="Comma-separated: low,medium,high,critical"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Flat indicator list with pagination. Credential passwords are redacted.
    Supports ETag caching. Ordered by last_seen descending."""
    parsed_since = parse_since(since)
    data = await db.query_indicators(
        since=parsed_since, indicator_type=type, threat_level=threat_level, limit=limit, offset=offset
    )
    total = await db.count_indicators(since=parsed_since, indicator_type=type, threat_level=threat_level)
    for item in data:
        if item.get("type") == "credential" and ":" in str(item.get("value", "")):
            username = item["value"].split(":")[0]
            item["value"] = f"{username}:***"
    result = {
        "indicators": scrub_dict(data),
        "pagination": {"limit": limit, "offset": offset, "returned": len(data), "total": total, "has_more": offset + limit < total},
    }
    etag = _etag(result)
    cached = _check_etag(request, etag)
    if cached:
        return cached
    return JSONResponse(content=result, headers=_cache_headers(etag))


@app.get("/api/v1/indicators/{value:path}", tags=["Indicators"],
         responses={404: {"model": ErrorResponse}, 429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def indicator_lookup(request: Request, value: str):
    """Look up all sessions involving a specific indicator (IP address, file hash, or URL)."""
    data = await db.lookup_indicator(value)
    if not data:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return scrub_dict(data)


@app.get("/api/v1/sessions", response_model=SessionListResponse, tags=["Sessions"],
         responses={429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def sessions(
    request: Request,
    since: Optional[str] = Query(None, description="Time filter: ISO 8601, relative (1h/6h/24h/7d/30d), or Unix epoch"),
    attack_type: Optional[str] = Query(None, enum=[
        "brute_force", "credential_stuffing", "recon", "malware_deployment",
        "cryptominer", "botnet_recruitment", "lateral_movement", "data_exfil", "unknown",
    ]),
    threat_level: Optional[str] = Query(None, description="Comma-separated: low,medium,high,critical"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Browse enriched attack sessions with MITRE ATT&CK mappings.
    Returns session summaries (without full STIX bundles). Supports ETag caching."""
    parsed_since = parse_since(since)
    data = await db.query_sessions(
        since=parsed_since, attack_type=attack_type, threat_level=threat_level, limit=limit, offset=offset
    )
    total = await db.count_sessions(since=parsed_since, attack_type=attack_type, threat_level=threat_level)
    threat_confidence = {"critical": 95, "high": 85, "medium": 65, "low": 40}
    result_list = []
    for s in data:
        result_list.append({
            "session_id": s["id"],
            "src_ip": s["src_ip"],
            "timestamp_start": s.get("timestamp_start"),
            "timestamp_end": s.get("timestamp_end"),
            "duration_seconds": s.get("duration_seconds"),
            "ssh_client": s.get("ssh_client"),
            "hassh": s.get("hassh"),
            "attack_type": s.get("attack_type"),
            "threat_level": s.get("threat_level"),
            "confidence": threat_confidence.get(s.get("threat_level", ""), 50),
            "model_version": MODEL_VERSION,
            "mitre_techniques": json.loads(s["mitre_techniques"]) if s.get("mitre_techniques") else [],
            "summary": s.get("summary"),
            "country": s.get("country"),
            "asn": s.get("asn"),
            "org": s.get("org"),
            "cloud_provider": s.get("cloud_provider"),
            "observed_features": json.loads(s["observed_features"]) if s.get("observed_features") else None,
        })
    result = {
        "sessions": scrub_dict(result_list),
        "pagination": {"limit": limit, "offset": offset, "returned": len(result_list), "total": total, "has_more": offset + limit < total},
    }
    etag = _etag(result)
    cached = _check_etag(request, etag)
    if cached:
        return cached
    return JSONResponse(content=result, headers=_cache_headers(etag))


@app.get("/api/v1/sessions/{session_id}", response_model=SessionDetail, tags=["Sessions"],
         responses={404: {"model": ErrorResponse}, 429: {"model": RateLimitError}})
@limiter.limit("100/minute")
async def session_detail(request: Request, session_id: str):
    """Full session detail including commands executed, credentials attempted (redacted),
    file downloads, and the complete STIX 2.1 bundle for this session."""
    s = await db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")

    raw = {}
    if s.get("raw_session"):
        try:
            raw = json.loads(s["raw_session"])
        except (json.JSONDecodeError, TypeError):
            pass

    stix = None
    if s.get("stix_bundle"):
        try:
            stix = json.loads(s["stix_bundle"]) if isinstance(s["stix_bundle"], str) else s["stix_bundle"]
        except (json.JSONDecodeError, TypeError):
            pass

    # Redact credential passwords
    creds = raw.get("credentials_attempted", [])
    for c in creds:
        if "password" in c:
            c["password"] = "***"

    result = {
        "session_id": s["id"],
        "src_ip": s["src_ip"],
        "timestamp_start": s.get("timestamp_start"),
        "timestamp_end": s.get("timestamp_end"),
        "duration_seconds": s.get("duration_seconds"),
        "ssh_client": s.get("ssh_client"),
        "hassh": s.get("hassh"),
        "attack_type": s.get("attack_type"),
        "threat_level": s.get("threat_level"),
        "mitre_techniques": json.loads(s["mitre_techniques"]) if s.get("mitre_techniques") else [],
        "summary": s.get("summary"),
        "commands": raw.get("commands", []),
        "credentials_attempted": creds,
        "downloads": raw.get("downloads", []),
        "country": s.get("country"),
        "asn": s.get("asn"),
        "org": s.get("org"),
        "cloud_provider": s.get("cloud_provider"),
        "observed_features": json.loads(s["observed_features"]) if s.get("observed_features") else None,
        "stix_bundle": stix,
    }
    return scrub_dict(result)


# --- New endpoints: IP sightings, HASSH, integrity, about page ---

@app.get("/api/v1/ip/{ip}", response_model=IPSightingResponse, tags=["Enrichment"],
         responses={404: {"model": ErrorResponse}})
@limiter.limit("100/minute")
async def ip_sightings(request: Request, ip: str):
    """IP sighting lookup: session count, date range, ASN, org, country, cloud provider."""
    data = await db.get_ip_sightings(ip)
    if data.get("sighting_count", 0) == 0:
        raise HTTPException(status_code=404, detail="IP not observed")
    return scrub_dict(data)


@app.get("/api/v1/hassh/{hassh}", tags=["Enrichment"])
@limiter.limit("100/minute")
async def hassh_lookup(request: Request, hassh: str):
    """Look up sessions by HASSH fingerprint (SSH client fingerprint)."""
    sessions_data = await db.query_by_hassh(hassh)
    if not sessions_data:
        raise HTTPException(status_code=404, detail="HASSH not observed")
    result = []
    for s in sessions_data:
        result.append({
            "session_id": s["id"], "src_ip": s["src_ip"],
            "timestamp_start": s.get("timestamp_start"), "attack_type": s.get("attack_type"),
            "threat_level": s.get("threat_level"), "ssh_client": s.get("ssh_client"),
            "country": s.get("country"), "asn": s.get("asn"), "org": s.get("org"),
        })
    return scrub_dict(result)


@app.get("/api/v1/integrity", response_model=IntegrityResponse, tags=["Trust"])
@limiter.limit("100/minute")
async def integrity(request: Request):
    """STIX bundle integrity: SHA-256 hash, object count, and last update.
    Use this to verify the bundle hasn't changed since your last fetch."""
    sessions_data = await db.query_sessions(limit=500)
    bundles = []
    for s in sessions_data:
        if s.get("stix_bundle"):
            try:
                bundle = json.loads(s["stix_bundle"]) if isinstance(s["stix_bundle"], str) else s["stix_bundle"]
                bundles.append(bundle)
            except (json.JSONDecodeError, TypeError):
                pass
    if bundles:
        merged = merge_stix_bundles(bundles)
    else:
        merged = {"type": "bundle", "id": "bundle--empty", "objects": []}

    raw = json.dumps(scrub_dict(merged), sort_keys=True, default=str).encode()
    sha = hashlib.sha256(raw).hexdigest()
    stats = await db.get_stats()
    return {
        "stix_bundle_sha256": sha,
        "stix_object_count": len(merged.get("objects", [])),
        "total_sessions": stats.get("total_sessions", 0),
        "total_indicators": stats.get("total_indicators", 0),
        "last_update": stats.get("last_update"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verify": "Fetch /api/v1/feed/stix, compute SHA-256 of the JSON body (sorted keys), and compare.",
    }


# --- TAXII 2.1 minimal compatibility layer ---

TAXII_MEDIA = "application/taxii+json;version=2.1"
TAXII_COLLECTION_ID = "honeypot-svr04-stix21"


def _taxii_media(request: Request) -> str:
    """Return TAXII content type if client accepts it, else application/json for browsers."""
    accept = request.headers.get("accept", "")
    if "taxii" in accept or "stix" in accept:
        return TAXII_MEDIA
    return "application/json"


@app.get("/taxii2/", tags=["TAXII 2.1"], response_model=TAXIIDiscovery)
@limiter.limit("100/minute")
async def taxii_discovery(request: Request):
    """TAXII 2.1 discovery endpoint.

    Returns TAXII content type when client sends Accept: application/taxii+json,
    otherwise returns application/json for browser compatibility."""
    return JSONResponse(
        content={
            "title": "Honeypot SVR04 Threat Intel TAXII Server",
            "description": "AI-enriched SSH honeypot threat intelligence",
            "contact": "https://github.com/Tristan1019-user/honeypot-threat-intel",
            "default": "/taxii2/",
            "api_roots": ["/taxii2/"],
        },
        media_type=_taxii_media(request),
    )


@app.get("/taxii2/collections", tags=["TAXII 2.1"], response_model=TAXIICollections)
@app.get("/taxii2/collections/", tags=["TAXII 2.1"], include_in_schema=False)
@limiter.limit("100/minute")
async def taxii_collections(request: Request):
    """TAXII 2.1 collections listing."""
    return JSONResponse(
        content={
            "collections": [{
                "id": TAXII_COLLECTION_ID,
                "title": "Honeypot SVR04 STIX 2.1 Feed",
                "description": "SSH honeypot attack indicators, sessions, and MITRE ATT&CK mappings",
                "can_read": True,
                "can_write": False,
                "media_types": ["application/stix+json;version=2.1"],
            }]
        },
        media_type=_taxii_media(request),
    )


@app.get("/taxii2/collections/{collection_id}/objects", tags=["TAXII 2.1"])
@app.get("/taxii2/collections/{collection_id}/objects/", tags=["TAXII 2.1"], include_in_schema=False)
@limiter.limit("30/minute")
async def taxii_objects(
    request: Request,
    collection_id: str,
    added_after: Optional[str] = Query(None, description="ISO 8601 timestamp filter"),
    limit: int = Query(100, ge=1, le=500),
):
    """TAXII 2.1 objects endpoint. Returns STIX 2.1 bundle for the collection.

    Pagination: use `added_after` with the timestamp of the last object received
    for delta-friendly ingestion. Supports limit up to 500."""
    if collection_id != TAXII_COLLECTION_ID:
        raise HTTPException(status_code=404, detail=f"Collection not found. Use: {TAXII_COLLECTION_ID}")

    sessions_data = await db.query_sessions(since=added_after, limit=limit)
    bundles = []
    for s in sessions_data:
        if s.get("stix_bundle"):
            try:
                bundle = json.loads(s["stix_bundle"]) if isinstance(s["stix_bundle"], str) else s["stix_bundle"]
                bundles.append(bundle)
            except (json.JSONDecodeError, TypeError):
                pass

    if bundles:
        merged = merge_stix_bundles(bundles)
    else:
        from .stix import PRODUCER_IDENTITY
        merged = {"type": "bundle", "id": "bundle--empty", "objects": [PRODUCER_IDENTITY, TLP_CLEAR_MARKING]}

    return JSONResponse(content=scrub_dict(merged), media_type="application/stix+json;version=2.1")


# --- /about HTML page ---

@app.get("/about", response_class=HTMLResponse, include_in_schema=False)
async def about_page():
    """Human-readable about page with pipeline details, retention, and model info."""
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>About - Honeypot Threat Intel Feed</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'SF Mono','Fira Code',monospace;background:#0a0a0a;color:#e0e0e0}
.c{max-width:800px;margin:0 auto;padding:2rem}h1{color:#00ff88;font-size:1.5rem;margin-bottom:1rem}
h2{color:#00cc66;margin:1.5rem 0 .5rem;font-size:1.1rem}p,li{color:#aaa;line-height:1.6;font-size:.88rem}
ul{margin-left:1.5rem}li{margin:.3rem 0}a{color:#00ff88;text-decoration:none}a:hover{text-decoration:underline}
.sec{margin:1rem 0;padding:1rem;background:#111;border:1px solid #222;border-radius:6px}
code{color:#00ff88;background:#111;padding:.1rem .3rem;border-radius:3px}
.ft{margin-top:2rem;color:#555;font-size:.75rem;border-top:1px solid #222;padding-top:.8rem}
</style></head><body><div class="c">
<h1>About This Feed</h1>
<p><a href="/">← Back to dashboard</a></p>

<h2>Pipeline</h2>
<div class="sec">
<p><strong>Source:</strong> Cowrie SSH honeypot listening on WAN port 22 (NAT to internal honeypot VM)</p>
<p><strong>Cadence:</strong> Pipeline runs every <strong>15 minutes</strong> via OpenClaw cron. Reads new events from Cowrie's JSON log, assembles sessions, enriches via AI, generates STIX bundles, stores in SQLite.</p>
<p><strong>Latency:</strong> ~15 minutes from attack observation to API availability</p>
</div>

<h2>AI Classification</h2>
<div class="sec">
<p><strong>Primary:</strong> Mistral Small 3.2 (24B parameters) running locally on Ollama (RTX 5080, no cloud API calls)</p>
<p><strong>Fallback:</strong> Deterministic rule-based classifier activates when Ollama is unreachable (e.g., workstation off). Rules check for credential patterns, known command signatures, download activity.</p>
<p><strong>Temperature:</strong> 0.1 (near-deterministic). JSON output mode enforced.</p>
<p><strong>No training on honeypot data:</strong> The model classifies but is not fine-tuned on this data.</p>
</div>

<h2>IP Enrichment</h2>
<div class="sec">
<p>Each new IP is enriched via <a href="https://ipwho.is" target="_blank">ipwho.is</a> (free, no API key):</p>
<ul>
<li><strong>ASN</strong> - Autonomous System Number</li>
<li><strong>Organization</strong> - ISP or hosting provider name</li>
<li><strong>Country</strong> - 2-letter country code</li>
<li><strong>Cloud provider</strong> - Detected if ASN matches known cloud providers (AWS, DigitalOcean, Hetzner, OVH, etc.)</li>
</ul>
<p>Geo data is best-effort and may be inaccurate for VPN/proxy IPs.</p>
</div>

<h2>Redaction & Privacy</h2>
<div class="sec">
<ul>
<li><strong>Passwords:</strong> Stored internally for analysis; always redacted to <code>***</code> in all API responses</li>
<li><strong>Internal IPs:</strong> All RFC 1918 addresses replaced with <code>honeypot-svr04</code></li>
<li><strong>Malware:</strong> Only hashes and URLs published; binaries are not redistributed</li>
<li><strong>Credentials:</strong> Excluded entirely from <code>/feed</code>; shown as <code>user:***</code> in other endpoints</li>
</ul>
</div>

<h2>Retention & TTL Semantics</h2>
<div class="sec">
<p>Session and indicator data is retained indefinitely in SQLite. STIX indicators carry a <strong>7-day <code>valid_until</code></strong> window.</p>
<p style="margin-top:.5rem"><strong>Re-observation behavior:</strong> When an IP is seen again, the existing indicator's <code>last_seen</code> and <code>times_seen</code> are updated, but the <strong>STIX Indicator ID remains the same</strong> (deterministic UUID5 from the value). The STIX <code>valid_until</code> is computed from <code>first_seen + 7 days</code> and does NOT reset on re-observation. Consumers should treat this as "same indicator, updated sighting count" - use <strong>upsert</strong> logic keyed on the STIX ID.</p>
<p style="margin-top:.5rem"><strong>For SIEM/TIP integration:</strong> Use <code>times_seen</code> and <code>last_seen</code> to decide freshness. If <code>last_seen</code> is recent but <code>valid_until</code> has passed, the IP is still active but the original assessment window expired.</p>
</div>

<h2>STIX 2.1 Details</h2>
<div class="sec">
<ul>
<li>Producer identity: <code>honeypot-svr04</code> (consistent across all bundles)</li>
<li>Marking: <code>TLP:CLEAR</code> - data is public, share freely</li>
<li>Object types: identity, marking-definition, indicator, observed-data, attack-pattern, malware, relationship, ipv4-addr, network-traffic</li>
<li>All indicators have <code>created_by_ref</code>, <code>object_marking_refs</code>, <code>confidence</code>, <code>valid_from/until</code></li>
<li>MITRE ATT&CK referenced via <code>external_references</code> on attack-pattern objects</li>
</ul>
</div>

<h2>TAXII 2.1</h2>
<div class="sec">
<p>Read-only TAXII 2.1 server. Endpoints:</p>
<ul>
<li><code>/taxii2/</code> - Discovery</li>
<li><code>/taxii2/collections</code> - Collection listing</li>
<li><code>/taxii2/collections/honeypot-svr04-stix21/objects</code> - STIX objects (supports <code>added_after</code>, <code>limit</code> up to 500)</li>
</ul>
<p style="margin-top:.5rem"><strong>Content negotiation:</strong> Returns <code>application/taxii+json;version=2.1</code> for TAXII clients, <code>application/json</code> for browsers.</p>
<p style="margin-top:.5rem"><strong>Tested with:</strong> <code>cti-taxii-client</code> (Python), <code>curl</code> with TAXII Accept headers. Should work with OpenCTI and MISP TAXII feeds. If you test with other clients, please open an issue on GitHub.</p>
<pre style="margin-top:.5rem"># Discovery
curl -s https://threat-intel.101904.xyz/taxii2/ -H "Accept: application/taxii+json;version=2.1"

# Get objects since a timestamp
curl -s "https://threat-intel.101904.xyz/taxii2/collections/honeypot-svr04-stix21/objects?added_after=2026-02-20T00:00:00Z&limit=50"</pre>
</div>

<h2>Integration Recipes</h2>
<div class="sec">
<h3 style="color:#00aa55;margin-bottom:.3rem">Splunk (ES/SOAR)</h3>
<pre>| curl "https://threat-intel.101904.xyz/api/v1/feed?since=24h&format=csv" method=get
| inputlookup append=t threat_intel_honeypot.csv</pre>
<p style="color:#888;font-size:.8rem">Or use the JSON feed with a scripted input polling every 15 min.</p>

<h3 style="color:#00aa55;margin:.5rem 0 .3rem">Elastic Security (SIEM)</h3>
<pre># Use the STIX feed with Elastic's Threat Intel module
# filebeat.yml:
- module: threatintel
  anomali:
    enabled: false
  custom:
    enabled: true
    url: "https://threat-intel.101904.xyz/api/v1/feed/stix"
    interval: 15m</pre>

<h3 style="color:#00aa55;margin:.5rem 0 .3rem">OpenCTI</h3>
<pre># Add as a TAXII 2.1 feed in OpenCTI connectors:
# URL: https://threat-intel.101904.xyz/taxii2/
# Collection: honeypot-svr04-stix21
# No authentication required</pre>

<h3 style="color:#00aa55;margin:.5rem 0 .3rem">MISP</h3>
<pre># Feeds -> Add Feed:
# URL: https://threat-intel.101904.xyz/api/v1/feed?format=csv&since=7d
# Source format: CSV
# Or use TAXII 2.1 with the MISP TAXII connector</pre>

<h3 style="color:#00aa55;margin:.5rem 0 .3rem">Python (requests)</h3>
<pre>import requests
# Cursor-based ingestion (idempotent, no clock skew)
cursor = "0"
while True:
    r = requests.get(f"https://threat-intel.101904.xyz/api/v1/feed?cursor={cursor}&limit=100")
    data = r.json()
    for ioc in data["indicators"]:
        process(ioc)  # your logic
    cursor = data["pagination"].get("next_cursor")
    if not cursor:
        break</pre>

<h3 style="color:#00aa55;margin:.5rem 0 .3rem">Microsoft Sentinel</h3>
<pre># Use Logic App with HTTP connector to poll:
# GET https://threat-intel.101904.xyz/api/v1/feed?since=1h&format=json
# Map indicators to ThreatIntelligenceIndicator table
# Or use the STIX bundle with Sentinel's TAXII connector</pre>
</div>

<h2>Rate Limits & Backoff</h2>
<div class="sec">
<p>Default: <strong>100 requests/minute</strong> per IP. STIX bundle + TAXII objects: <strong>30/minute</strong>.</p>
<p>On rate limit, API returns <code>429 Too Many Requests</code> with:</p>
<ul>
<li><code>Retry-After: 60</code> header</li>
<li>JSON body with <code>retry_after_seconds</code> field</li>
</ul>
<p>Recommended: exponential backoff starting at the Retry-After value.</p>
</div>

<h2>Source Code</h2>
<div class="sec">
<p><a href="https://github.com/Tristan1019-user/honeypot-threat-intel" target="_blank">github.com/Tristan1019-user/honeypot-threat-intel</a></p>
<p>MIT License. Built with FastAPI, Cowrie, Wazuh, Ollama.</p>
</div>

<div class="ft"><a href="/">Dashboard</a> · <a href="/docs">API Docs</a> · <a href="/api/v1/about">API Metadata (JSON)</a></div>
</div></body></html>"""


# --- Revoked feed ---

@app.get("/api/v1/feed/revoked", tags=["Feed"])
@limiter.limit("100/minute")
async def feed_revoked(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Dedicated view of revoked indicators with reasons.

    Useful for consumers maintaining allowlists or excluding known benign sources.
    Returns only revoked indicators with their revocation reason."""
    conn = await db.get_db()
    try:
        rows = await conn.execute_fetchall(
            "SELECT * FROM indicators WHERE revoked = 1 ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        total_rows = await conn.execute_fetchall("SELECT COUNT(*) FROM indicators WHERE revoked = 1")
        total = total_rows[0][0]
    finally:
        await conn.close()

    indicators = []
    for r in rows:
        d = dict(r)
        indicators.append({
            "type": d.get("type"),
            "value": d.get("value"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "times_seen": d.get("times_seen", 1),
            "threat_level": d.get("threat_level"),
            "revoked": True,
            "revoked_reason": d.get("revoked_reason"),
        })

    return {
        "feed_id": "honeypot-svr04",
        "description": "Revoked indicators - known false positives, research scanners, Tor exits, etc.",
        "indicator_count": len(indicators),
        "pagination": {"limit": limit, "offset": offset, "returned": len(indicators), "total": total, "has_more": offset + limit < total},
        "indicators": scrub_dict(indicators),
    }


# --- Revocation ---

@app.post("/api/v1/indicators/{value:path}/revoke", tags=["Admin"],
          response_model=RevocationResponse,
          responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
@limiter.limit("10/minute")
async def revoke_indicator_endpoint(
    request: Request,
    value: str,
    reason: str = Query("false_positive", description="Revocation reason", enum=[
        "false_positive", "benign_scanner", "tor_exit", "researcher", "shared_infrastructure", "other",
    ]),
):
    """Mark an indicator as revoked (false positive, researcher, Tor exit, etc.).

    Revoked indicators are excluded from /feed by default. They remain queryable
    with `include_revoked=true`. In STIX output, revoked indicators get `revoked: true`.

    Restricted to LAN/localhost IPs."""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin endpoints restricted to LAN/localhost")
    found = await db.revoke_indicator(value, reason)
    if not found:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "revoked", "value": value, "reason": reason}


@app.post("/api/v1/indicators/{value:path}/unrevoke", tags=["Admin"],
          response_model=RevocationResponse,
          responses={403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}})
@limiter.limit("10/minute")
async def unrevoke_indicator_endpoint(request: Request, value: str):
    """Remove revocation from an indicator. Restricted to LAN/localhost IPs."""
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="Admin endpoints restricted to LAN/localhost")
    found = await db.unrevoke_indicator(value)
    if not found:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "active", "value": value}


# --- Pipeline trigger ---

@app.get("/api/v1/pipeline/run", tags=["Admin"], include_in_schema=False)
@limiter.limit("10/minute")
async def run_pipeline(
    request: Request,
    log_path: str = Query("/cowrie/var/log/cowrie/cowrie.json"),
):
    """Manually trigger the enrichment pipeline (for cron/N8N)."""
    from .pipeline import process_cowrie_log
    result = await process_cowrie_log(log_path)
    return result
