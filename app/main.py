"""
Cowrie AI Threat Intel Feed - FastAPI Application

Public REST API serving AI-enriched threat intelligence from an SSH honeypot.
Publishes STIX 2.1 IOC feeds, indicators, and attack session data.
"""

import asyncio
import csv
import hashlib
import html as html_mod
import io
import json
import logging
import os
import re

import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, cast

from fastapi import BackgroundTasks, Depends, FastAPI, Query, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, Response, JSONResponse, StreamingResponse
# Use ORJSONResponse when orjson is installed (faster serialisation).
# Typed as type[Response] (common base class for both response classes).
AppJSONResponse: type[Response] = JSONResponse
try:
    import orjson  # noqa: F401
    from fastapi.responses import ORJSONResponse as _ORJSONResponse
    AppJSONResponse = _ORJSONResponse
    del _ORJSONResponse  # keep module namespace clean
except ImportError:  # pragma: no cover
    pass
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.ratelimit import limiter
from app.utils import parse_since

from . import database as db
from . import enrichment
from .auth import check_admin_auth
from .scrub import SENSOR_NAME, scrub_dict, scrub_internal_ips
from .models import (
    HealthResponse, IndicatorRecord, FeedResponseOffset, FeedResponseCursor,
    IndicatorListResponse, SessionSummary, SessionDetail, SessionListResponse,
    StatsResponse, IPSightingResponse, IntegrityResponse, RevocationResponse,
    ErrorResponse, RateLimitError,
    AboutResponse, ObservedFeatures, PaginationOffset,
)
from .stix import PRODUCER_IDENTITY, TLP_CLEAR_MARKING
from .routers.quality import router as quality_router
from .routers.taxii import router as taxii_router
from .routers.intel import router as intel_router
from .routers.admin import router as admin_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

API_VERSION = "1.5.0"



MODEL_VERSION = "mistral-small3.2:24b"

# parse_since() lives in app.utils — imported above.


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


# scrub_dict / scrub_internal_ips / SENSOR_NAME now live in app.scrub
# (imported above alongside check_admin_auth)


THREAT_CONFIDENCE = {
    "low": 40,
    "medium": 65,
    "high": 85,
    "critical": 95,
}


def _enrich_indicator(ind: dict, include_stix: bool = False) -> dict:
    out = {
        "type": ind.get("type"),
        "value": ind.get("value"),
        "first_seen": ind.get("first_seen"),
        "last_seen": ind.get("last_seen"),
        "times_seen": ind.get("times_seen", 1),
        "threat_level": ind.get("threat_level"),
        "confidence": THREAT_CONFIDENCE.get(ind.get("threat_level", ""), 50),
        "revoked": bool(ind.get("revoked")),
        "revoked_reason": ind.get("revoked_reason"),
        "sensor_id": "honeypot-svr04",
        "feed_id": "honeypot-svr04",
        "collection_window": {
            "first_observed": ind.get("first_seen"),
            "last_observed": ind.get("last_seen"),
        },
    }
    if include_stix and ind.get("stix_object"):
        raw_stix = ind.get("stix_object")
        # stix_object is stored as a JSON string in the DB; deserialize so
        # API consumers receive a proper object, not a double-encoded string.
        if isinstance(raw_stix, str):
            try:
                raw_stix = json.loads(raw_stix)
            except (json.JSONDecodeError, TypeError):
                pass
        out["stix_object"] = raw_stix
    return out


def _etag(data) -> str:
    """Generate ETag from response data (SHA-256 truncated to 32 hex chars)."""
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return f'"{hashlib.sha256(raw).hexdigest()[:32]}"'


def _check_etag(request: Request, etag: str) -> Optional[Response]:
    """Return 304 if client ETag matches."""
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match.strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return None


def _cache_headers(etag: str, max_age: int = 300, last_modified: Optional[str] = None) -> dict:
    """Build HTTP cache headers.

    last_modified: ISO 8601 or RFC 7231 datetime string reflecting when the
    underlying data last changed.  If None, the header is omitted rather than
    emitting a misleading 'now' value.
    """
    headers: dict[str, str] = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={max_age}",
    }
    if last_modified:
        try:
            dt = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
            headers["Last-Modified"] = dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
        except (ValueError, AttributeError):
            pass  # malformed timestamp — omit header rather than emit garbage
    return headers


# --- App lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    logger.info("Threat Intel Feed API started")
    yield
    await db.close_pool()
    await enrichment.close_http_session()
    logger.info("Threat Intel Feed API stopped")


app = FastAPI(
    title="Cowrie AI Threat Intel Feed",
    default_response_class=AppJSONResponse,
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
| `medium` | Successful login + discovery commands | 65 | Post-auth enumeration (uname, /proc, id, ls) |
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
`brute_force` | `credential_stuffing` | `recon` | `discovery` | `malware_deployment` | `cryptominer` | `botnet_recruitment` | `lateral_movement` | `data_exfil` | `unknown`

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
app.add_exception_handler(RateLimitExceeded, cast(Any, _rate_limit_exceeded_handler))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],  # POST needed for revoke/unrevoke and pipeline/run
    allow_headers=["*"],
)
# Compression helps large JSON/STIX responses significantly.
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.include_router(quality_router)
app.include_router(taxii_router)
app.include_router(intel_router)
app.include_router(admin_router)


# NOTE: RateLimitHeadersMiddleware removed — it unconditionally wrote
# X-RateLimit-Limit: 100 for all endpoints, which is wrong for STIX bundle
# endpoints (30/min).  Per-route rate limit information is conveyed via the
# 429 body + Retry-After header (see rate_limit_handler below).

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
@limiter.limit("60/minute")
async def landing(request: Request):
    # Fetch stats server-side for noscript fallback.
    # Stats are cached for 60s in database.py so this doesn't hit the DB every call.
    try:
        stats = await db.get_stats()
    except Exception:
        stats = {}
    return _build_landing_html(stats)


def _build_landing_html(stats: dict | None = None) -> str:
    s = stats or {}
    total_sessions = s.get("total_sessions", 0)
    total_indicators = s.get("total_indicators", 0)
    total_malware = s.get("total_malware_samples", 0)
    total_countries = len(s.get("top_countries", {}))

    # Build server-side rendered recent indicators
    recent_inds = s.get("recent_indicators", [])
    ssr_indicators = ""
    tc_map = {"low": "tag-low", "medium": "tag-med", "high": "tag-high", "critical": "tag-crit"}
    e = html_mod.escape  # shorthand for HTML escaping of DB-sourced values
    for i in recent_inds[:5]:
        tl = i.get("threat_level", "low")
        ssr_indicators += (
            f'<div class="live-card"><span class="ip">{e(str(i.get("value", "")))}</span> '
            f'<span class="tag {tc_map.get(tl,"tag-low")}">{e(tl)}</span> '
            f'<span class="bg">{e(str(i.get("type", "")))}</span> '
            f'<span style="color:#666;margin-left:.5rem">seen {i.get("times_seen",1)}x</span></div>'
        )
    if not ssr_indicators:
        ssr_indicators = '<div class="live-card" style="color:#555">No indicators yet</div>'

    # Build server-side rendered recent sessions
    recent_sess = s.get("recent_sessions", [])
    ssr_sessions = ""
    for sess in recent_sess[:3]:
        tl = sess.get("threat_level", "low")
        at = e(str(sess.get("attack_type", "unknown")))
        country = e(str(sess.get("country", "")))
        org = e((str(sess.get("org") or ""))[:30])
        summary = e(str(sess.get("summary", "")))
        ssr_sessions += (
            f'<div class="live-card"><span class="ip">{e(str(sess.get("src_ip", "")))}</span> '
            f'<span class="tag {tc_map.get(tl,"tag-low")}">{e(tl)}</span> '
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
    <title>Honeypot Threat Intelligence Feed</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'SF Mono','Fira Code',monospace;background:#0f0f10;color:#f2f2f2}
        .c{max-width:960px;margin:0 auto;padding:2rem}
        h1{color:#f2f2f2;font-size:1.8rem;margin-bottom:.5rem}
        .sub{color:#888;margin-bottom:1.5rem}
        .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:.8rem;margin:1.5rem 0}
        .stat{background:#1a1a1a;border:1px solid #333;border-radius:8px;padding:1.2rem;text-align:center}
        .sv{font-size:1.8rem;color:#f2f2f2;font-weight:bold}
        .sl{color:#888;font-size:.75rem;margin-top:.2rem}
        h2{color:#d0d0d0;margin:2rem 0 .8rem;font-size:1.1rem}
        h3{color:#c2c2c2;margin:1rem 0 .4rem;font-size:.95rem}
        .ep{background:#1a1a1a;border-left:3px solid #cfcfcf;padding:.6rem .8rem;margin:.4rem 0;border-radius:0 4px 4px 0;font-size:.85rem}
        .m{color:#f2f2f2;font-weight:bold}.p{color:#ccc}.d{color:#888;font-size:.8rem}.pm{color:#666;font-size:.75rem;margin-top:.2rem}
        a{color:#f2f2f2;text-decoration:none}a:hover{text-decoration:underline}
        .ft{margin-top:2rem;color:#555;font-size:.75rem;border-top:1px solid #222;padding-top:.8rem}
        .bg{display:inline-block;background:#1a3a1a;color:#f2f2f2;padding:.15rem .5rem;border-radius:4px;font-size:.7rem}
        .bg-w{background:#353535;color:#dddddd}.bg-r{background:#3a3a3a;color:#d5d5d5}
        pre{background:#111;border:1px solid #333;border-radius:4px;padding:.6rem;overflow-x:auto;font-size:.75rem;color:#ccc;margin:.4rem 0}
        code{color:#f2f2f2}
        .sec{margin:1.5rem 0;padding:1.2rem;background:#111;border:1px solid #222;border-radius:8px}
        .sec p,.sec li{color:#aaa;line-height:1.5;font-size:.85rem}
        ul{margin-left:1.2rem}li{margin:.2rem 0}
        table{width:100%;border-collapse:collapse;margin:.4rem 0}
        th,td{text-align:left;padding:.3rem .6rem;border-bottom:1px solid #222;font-size:.78rem}
        th{color:#d0d0d0}td{color:#aaa}
        .live{margin:1.5rem 0}
        .live-card{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.8rem 1rem;margin:.4rem 0;font-size:.8rem}
        .live-card .ip{color:#f2f2f2;font-weight:bold}
        .live-card .tag{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.7rem;margin-right:.3rem}
        .tag-low{background:#2b2b2b;color:#d9d9d9}.tag-med{background:#323232;color:#d9d9d9}
        .tag-high{background:#3a2a1a;color:#ff8844}.tag-crit{background:#3a3a3a;color:#d5d5d5}
        .mitre-bar{display:flex;gap:2px;margin:.5rem 0;align-items:flex-end;height:40px}
        .mitre-col{background:#d0d0d0;min-width:18px;border-radius:2px 2px 0 0;position:relative;cursor:default}
        .mitre-col:hover::after{content:attr(data-label);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#222;color:#eee;padding:2px 6px;border-radius:3px;font-size:.65rem;white-space:nowrap}
        .trust{display:flex;gap:1rem;flex-wrap:wrap;margin:.5rem 0}
        .trust-item{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.6rem .8rem;font-size:.78rem;flex:1;min-width:200px}
        .trust-item .label{color:#888;font-size:.7rem}.trust-item .val{color:#f2f2f2;font-size:.75rem;word-break:break-all;margin-top:.2rem}
        .nav{display:flex;gap:.8rem;margin:1rem 0;flex-wrap:wrap}
        .nav a{background:#1a1a1a;border:1px solid #333;padding:.4rem .8rem;border-radius:4px;font-size:.8rem}
        .nav a:hover{border-color:#f2f2f2}
    </style>
</head>
<body>
<div class="c">
    <h1>Honeypot Threat Intelligence Feed</h1>
    <p class="sub">AI-enriched SSH honeypot intelligence for analyst enrichment and research &middot; <span class="bg">STIX 2.1</span> <span class="bg">TLP:CLEAR</span> <span class="bg">MITRE ATT&CK</span></p>

    <div class="nav">
        <a href="/docs">Swagger UI</a>
        <a href="/api/v1/feed?output_format=stix&limit=500&offset=0">STIX Bundle (500)</a>
        <a href="/api/v1/feed?output_format=csv&since=7d">CSV Export</a>
        <a href="/taxii2/">TAXII 2.1</a>
        <a href="/about">About</a>
        <a href="https://github.com/Tristan1019-user/honeypot-threat-intel" target="_blank">GitHub</a>
    </div>

    <div class="stats">
        <div class="stat"><div class="sv" id="s-sessions">{{TOTAL_SESSIONS}}</div><div class="sl">Total Sessions</div></div>
        <div class="stat"><div class="sv" id="s-indicators">{{TOTAL_INDICATORS}}</div><div class="sl">Total Indicators</div></div>
        <div class="stat"><div class="sv" id="s-malware">{{TOTAL_MALWARE}}</div><div class="sl">Malware Samples</div></div>
        <div class="stat"><div class="sv" id="s-countries">{{TOTAL_COUNTRIES}}</div><div class="sl">Source Countries</div></div>
    </div>


    <h2>Operational Health (Last 24 Hours)</h2>
    <div class="stats" id="q-stats">
        <div class="stat"><div class="sv" id="q-sessions">-</div><div class="sl">Observed Sessions</div></div>
        <div class="stat"><div class="sv" id="q-indicators">-</div><div class="sl">Published Indicators</div></div>
        <div class="stat"><div class="sv" id="q-attackers">-</div><div class="sl">Unique Source IPs</div></div>
        <div class="stat"><div class="sv" id="q-freshness">-</div><div class="sl">Pipeline Freshness</div></div>
    </div>
    <div class="sec" style="margin-top:.6rem">
      <p><strong>Pipeline heartbeat:</strong> <span id="q-pipeline-heartbeat">-</span></p>
      <p style="margin-top:.3rem"><strong>Last new data insert:</strong> <span id="q-data-heartbeat">-</span></p>
    </div>

    <h2>Responsible Use Guidance</h2>
    <div class="sec" id="limits">
      <p><strong>Recommended use:</strong> <span id="lim-rec">Loading...</span></p>
      <p style="margin-top:.4rem"><strong>Avoid using as:</strong> <span id="lim-not">Loading...</span></p>
      <p style="margin-top:.4rem"><strong>Known limitations:</strong> <span id="lim-bias">Loading...</span></p>
    </div>

    <!-- MITRE ATT&CK Mini Heatmap -->
    <h2>MITRE ATT&CK Technique Distribution</h2>
    <div class="mitre-bar" id="mitre-bar"></div>

    <!-- Live Sample: Recent Indicators -->
    <h2>Recent Indicators</h2>
    <div class="live" id="live-indicators">{{SSR_INDICATORS}}</div>

    <!-- Live Sample: Recent Sessions -->
    <h2>Recent Sessions</h2>
    <div class="live" id="live-sessions">{{SSR_SESSIONS}}</div>

    <!-- Trust & Integrity -->
    <h2>Feed Integrity</h2>
    <div class="trust" id="trust">
        <div class="trust-item"><div class="label">Producer Identity</div><div class="val">honeypot-svr04 (STIX identity in every bundle)</div></div>
        <div class="trust-item"><div class="label">Dataset Fingerprint (SHA-256)</div><div class="val" id="t-hash">Loading...</div></div>
        <div class="trust-item"><div class="label">Last Updated</div><div class="val" id="t-updated">-</div></div>
        <div class="trust-item"><div class="label">Pipeline Cadence</div><div class="val">Every 15 minutes (local Proxmox cron)</div></div>
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

    <h2>SIEM Integration Quickstart</h2>
    <div class="sec">
      <div class="nav" style="margin-top:0">
        <a href="#" id="tab-splunk">Splunk</a>
        <a href="#" id="tab-elastic">Elastic</a>
        <a href="#" id="tab-sentinel">Sentinel</a>
      </div>
      <pre id="integration-snippet"># Splunk (CSV feed)
curl -s "https://threat-intel.101904.xyz/api/v1/feed?since=24h&output_format=csv"</pre>
    </div>

    <div class="sec"><p><strong>Note:</strong> <code>/api/v1/feed/stix</code> streams the full dataset directly from the database with no memory cap. For incremental sync use TAXII 2.1 or the paginated feed (<code>/api/v1/feed?output_format=stix&amp;limit=N</code>).</p></div>

    <h2>Quick Start</h2>
    <pre># Latest IOCs
curl -s https://threat-intel.101904.xyz/api/v1/feed?since=24h | jq .

# STIX 2.1 bundle for SIEM
curl -s https://threat-intel.101904.xyz/api/v1/feed/stix -o threat-intel.json

# CSV for spreadsheets
curl -s "https://threat-intel.101904.xyz/api/v1/feed?output_format=csv&since=7d" -o iocs.csv

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
curl -s https://threat-intel.101904.xyz/api/v1/integrity | jq .dataset_fingerprint

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
    <h3>STIX 2.1 Indicator (from /api/v1/feed?output_format=stix)</h3>
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
            <tr><td><span class="tag tag-med">medium</span></td><td>65</td><td>Successful login + discovery (post-auth enumeration)</td><td>7 days</td></tr>
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
        <h3 style="color:#c2c2c2;margin-bottom:.3rem">Mode 1: Alert-only / SIEM enrichment (recommended)</h3>
        <p>Ingest the feed into your SIEM/TIP as enrichment data. When a source IP in your logs matches a feed indicator, <strong>raise an alert</strong> - don't auto-block. Use the <code>confidence</code> score, <code>attack_type</code>, and <code>observed_features</code> to triage.</p>
        <h3 style="color:#c2c2c2;margin:.5rem 0 .3rem">Mode 2: Selective blocking (advanced)</h3>
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
        Honeypot SVR04 Threat Intelligence Feed v{{API_VERSION}} &middot; Producer: <code>honeypot-svr04</code> &middot;
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

// quality metrics
fetch('/api/v1/quality').then(r=>r.json()).then(q=>{
  document.getElementById('q-sessions').textContent=q.window_24h?.sessions ?? '-';
  document.getElementById('q-indicators').textContent=q.window_24h?.indicators ?? '-';
  document.getElementById('q-attackers').textContent=q.window_24h?.unique_attacker_ips ?? '-';
  const fr=q.freshness?.status || '-';
  document.getElementById('q-freshness').textContent=fr;
  const pr=q.pipeline||{};
  document.getElementById('q-pipeline-heartbeat').textContent=`${pr.last_run||'-'} (${q.freshness?.status||'unknown'})`;
  document.getElementById('q-data-heartbeat').textContent=`${pr.last_data_insert||'-'} (${pr.data_freshness?.status||'unknown'})`; 
}).catch(()=>{});

// limitations
fetch('/api/v1/limitations').then(r=>r.json()).then(l=>{
  document.getElementById('lim-rec').textContent=(l.recommended_usage||[]).join(', ');
  document.getElementById('lim-not').textContent=(l.not_recommended_as||[]).join(', ');
  document.getElementById('lim-bias').textContent=(l.known_biases||[]).join('; ');
}).catch(()=>{});

// integration tabs
const snippets={
  splunk:`# Splunk (CSV feed)
curl -s "https://threat-intel.101904.xyz/api/v1/feed?since=24h&output_format=csv"`,
  elastic:`# Elastic
curl -s "https://threat-intel.101904.xyz/api/v1/feed/stix" -o threat-intel.stix.json`,
  sentinel:`# Microsoft Sentinel
curl -s "https://threat-intel.101904.xyz/api/v1/feed?since=1h&output_format=json"`
};
['splunk','elastic','sentinel'].forEach(k=>{
  const el=document.getElementById('tab-'+k);
  if(!el) return;
  el.addEventListener('click',e=>{e.preventDefault();document.getElementById('integration-snippet').textContent=snippets[k];});
});
// Integrity hash
fetch('/api/v1/integrity').then(r=>r.json()).then(d=>{
    document.getElementById('t-hash').textContent=d.dataset_fingerprint?.substring(0,24)+'...'||'-';
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


@app.get("/api/v1/startup-check", tags=["Health"], include_in_schema=False)
@limiter.limit("60/minute")
async def startup_check(request: Request, _auth: None = Depends(check_admin_auth)):
    """Lightweight runtime self-check for DB schema and pipeline state readability."""
    checks: dict[str, Any] = {"db": {}, "pipeline_state": {}}
    try:
        checks["db"] = await db.get_db_diagnostics()
    except Exception as e:
        checks["db"] = {"error": str(e)}

    state_path = Path("/data/pipeline_state.json")
    if state_path.exists():
        try:
            parsed = json.loads(state_path.read_text())
            checks["pipeline_state"] = {
                "readable": True,
                "has_last_run": bool(parsed.get("last_run")),
                "last_run": parsed.get("last_run"),
            }
        except Exception as e:
            checks["pipeline_state"] = {"readable": False, "error": str(e)}
    else:
        checks["pipeline_state"] = {"readable": False, "error": "missing /data/pipeline_state.json"}

    db_tables = checks.get("db", {}).get("tables", checks.get("db", {}))
    ok = (
        db_tables.get("sessions_table")
        and db_tables.get("indicators_table")
        and db_tables.get("malware_samples_table")
        and checks.get("pipeline_state", {}).get("readable")
    )
    return {"status": "ok" if ok else "degraded", "checks": checks}


@app.get("/api/v1/db", tags=["Health"], include_in_schema=False)
@limiter.limit("60/minute")
async def db_diagnostics(request: Request, _auth: None = Depends(check_admin_auth)):
    """Database backend diagnostics and core table counts. LAN + ADMIN_TOKEN required."""
    return await db.get_db_diagnostics()

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
    return AppJSONResponse(content=data, headers=_cache_headers(etag, max_age=60, last_modified=data.get("last_update")))


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
                "medium": {"confidence": 65, "description": "Successful login + post-auth discovery commands"},
                "high": {"confidence": 85, "description": "Malware download or persistent access attempted"},
                "critical": {"confidence": 95, "description": "Active exploitation, cryptominer, or C2 activity"},
            },
            "indicator_ttl_days": 7,
            "notes": "threat_level reflects observed behavior severity, not victim impact. "
                     "Confidence maps directly from threat_level.",
        },
        "attack_types": [
            "brute_force", "credential_stuffing", "recon", "discovery", "malware_deployment",
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


@app.get("/api/v1/feed", tags=["Feed"])
@limiter.limit("100/minute")
async def feed(
    request: Request,
    since: Optional[str] = Query(None, description="Time filter: ISO 8601 (2026-02-20T00:00:00Z), relative (1h/6h/24h/7d/30d/1w), or Unix epoch seconds"),
    type: Optional[str] = Query(None, description="Indicator type filter", enum=["ipv4-addr", "url", "file-hash", "all"]),
    threat_level: Optional[str] = Query(None, description="Comma-separated threat levels", examples=["high,critical"]),
    output_format: str = Query("json", description="Output format: json, stix, or csv. Note: stix/csv require offset pagination (cursor mode always returns JSON).", enum=["json", "stix", "csv"]),
    include: Optional[str] = Query(None, description="Pass 'stix' to embed a STIX indicator object per record (JSON mode only).", enum=["stix"]),
    cursor: Optional[str] = Query(None, description="Opaque keyset cursor for idempotent pagination; pass next_cursor from the previous response. Mutually exclusive with offset and non-JSON output_format."),
    include_revoked: bool = Query(False, description="Include revoked/false-positive indicators"),
    ttl: Optional[str] = Query(None, description="Override STIX valid_until TTL (e.g., 24h, 72h, 7d, 30d). Only affects output_format=stix. Default: 7d"),
    limit: int = Query(100, ge=1, le=1000, description="Max results per page"),
    offset: int = Query(0, ge=0, description="Pagination offset (use cursor instead for high-volume ingestion)"),
):
    """IOC feed with filtering, pagination, and multiple output formats.

    **Pagination**: Use `offset` for browsing or `cursor` for high-volume SIEM ingestion.
    Cursor-based pagination uses (last_seen, id) keyset ordering on Postgres and rowid fallback on SQLite (test-only), avoiding clock skew and making retries idempotent.

    **Provenance**: Each indicator includes `sensor_id`, `feed_id`, `confidence` (0-100),
    and `collection_window` (first/last observed).

    **STIX inline**: Pass `include=stix` to embed the STIX indicator object per record.

    **Revocation**: Revoked indicators (false positives, researchers) are excluded by default.
    Pass `include_revoked=true` to see them.

    Credentials are excluded from the public feed. Supports ETag/If-None-Match caching.

    **Cursor pagination** always returns JSON and advances through the full dataset
    without OFFSET drift. `since`, `threat_level`, `type`, and `include_revoked` are
    all respected in cursor mode.

    **Note**: `attack_type` is a session-level attribute, not an indicator attribute.
    Filter by attack_type on `GET /api/v1/sessions` instead."""
    parsed_since = parse_since(since)
    include_stix = include == "stix"  # strict equality — not substring match

    # Validate mutually exclusive parameters
    if cursor and offset > 0:
        raise HTTPException(
            status_code=400,
            detail="cursor and offset are mutually exclusive — pass cursor only (omit offset, or set offset=0).",
        )
    if cursor and output_format != "json":
        raise HTTPException(
            status_code=400,
            detail=f"output_format={output_format!r} is not supported with cursor pagination. "
                   "Use offset pagination for CSV/STIX output, or omit output_format (defaults to json).",
        )

    # Cursor-based pagination
    if cursor:
        raw_indicators, next_cursor = await db.query_indicators_cursor(
            cursor=cursor,
            since=parsed_since,
            indicator_type=type,
            threat_level=threat_level,
            include_revoked=include_revoked,
            exclude_credentials=True,
            limit=limit,
        )
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
        return AppJSONResponse(content=response_data, headers=_cache_headers(etag))

    # Offset-based pagination
    # Credentials excluded in SQL so totals and page counts are consistent.
    raw_indicators, total = await asyncio.gather(
        db.query_indicators(
            since=parsed_since, indicator_type=type, threat_level=threat_level,
            limit=limit, offset=offset,
            include_revoked=include_revoked, exclude_credentials=True,
        ),
        db.count_indicators(
            since=parsed_since, indicator_type=type, threat_level=threat_level,
            include_revoked=include_revoked, exclude_credentials=True,
        ),
    )

    if output_format == "csv":
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

    elif output_format == "stix":
        from .stix import _stix_id, _now_iso, _valid_until, PRODUCER_IDENTITY, TLP_CLEAR_MARKING
        # Parse custom TTL
        ttl_days: float = 7  # default
        if ttl:
            ttl_match = re.match(r'^(\d+)([hd])$', ttl.strip().lower())
            if ttl_match:
                amount = int(ttl_match.group(1))
                unit = ttl_match.group(2)
                ttl_days = amount / 24 if unit == 'h' else amount
        stix_objects = [PRODUCER_IDENTITY, TLP_CLEAR_MARKING]
        seen_ids = {PRODUCER_IDENTITY["id"], TLP_CLEAR_MARKING["id"]}
        for ind in raw_indicators:
            # Credentials are excluded at the SQL layer (exclude_credentials=True).
            # No credential rows can reach this loop.
            ind_type = str(ind.get("type") or "")
            raw_val = str(ind.get("value") or "")
            # Escape single quotes in STIX pattern string literals (STIX 2.1 §9.3).
            # IPs (digits+dots) and SHA-256 hashes (hex) can never contain quotes,
            # but URLs are attacker-controlled text and must be escaped.
            escaped_val = raw_val.replace("\\", "\\\\").replace("'", "\\'")
            pattern_map = {
                "ipv4-addr": f"[ipv4-addr:value = '{escaped_val}']",
                "url": f"[url:value = '{escaped_val}']",
                "file-hash": f"[file:hashes.'SHA-256' = '{escaped_val}']",
            }
            pattern = pattern_map.get(ind_type, f"[x-custom:value = '{escaped_val}']")

            ind_id = _stix_id("indicator", raw_val)
            if ind_id in seen_ids:
                continue
            seen_ids.add(ind_id)

            stix_ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": ind.get("first_seen", _now_iso()),
                "modified": ind.get("last_seen", _now_iso()),
                "name": f"Malicious {ind_type or 'indicator'}: {raw_val}",
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
            "id": f"bundle--{uuid.uuid4()}",  # STIX 2.1 §2.9: must be bundle--<UUID4>
            "objects": stix_objects,
        }
        return AppJSONResponse(content=scrub_dict(bundle))

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
        return AppJSONResponse(content=scrub_dict(response_data), headers=_cache_headers(etag))


async def _stix_bundle_stream():
    """Async generator: stream the full STIX 2.1 bundle object-by-object from the DB.

    Enterprise streaming pattern — no in-memory cache, no session cap, no OOM risk.
    Objects are deduplicated by STIX ID on the fly. Each 500-session page is fetched,
    streamed, and discarded before the next page is loaded, keeping RSS flat regardless
    of dataset size.

    Compatible with Starlette's GZipMiddleware (processes chunks incrementally).
    Connection pool connections are acquired and released per page, not held for the
    full duration of the stream.
    """
    seen_ids: set[str] = set()
    bundle_id = f"bundle--{uuid.uuid4()}"
    first = True

    # Open the bundle array
    yield f'{{"type":"bundle","id":"{bundle_id}","objects":['.encode()

    # Shared objects always first
    for obj in (PRODUCER_IDENTITY, TLP_CLEAR_MARKING):
        oid = obj.get("id")
        if oid:
            seen_ids.add(oid)
        yield (("" if first else ",") + json.dumps(obj)).encode()
        first = False

    # Stream sessions from DB, one page at a time — never holds more than PAGE rows
    PAGE = 500
    offset = 0
    while True:
        sessions = await db.query_sessions(limit=PAGE, offset=offset)
        if not sessions:
            break
        for s in sessions:
            raw = s.get("stix_bundle")
            if not raw:
                continue
            try:
                bundle = json.loads(raw) if isinstance(raw, str) else raw
                for obj in bundle.get("objects", []):
                    if not isinstance(obj, dict):
                        continue
                    oid = obj.get("id")
                    if oid and oid in seen_ids:
                        continue
                    if oid:
                        seen_ids.add(oid)
                    yield (("," if not first else "") + json.dumps(scrub_dict(obj))).encode()
                    first = False
            except (json.JSONDecodeError, TypeError, AttributeError):
                continue
        if len(sessions) < PAGE:
            break
        offset += PAGE

    yield b"]}"


@app.get("/api/v1/feed/stix", tags=["Feed"])
@limiter.limit("10/minute")
async def feed_stix(request: Request):
    """Full STIX 2.1 bundle — streamed directly from the DB.

    Objects are deduplicated by STIX ID and emitted incrementally.
    No memory cap, no session limit, no OOM risk.

    For incremental/differential sync, prefer TAXII 2.1 (/taxii2/) which
    supports cursor-based pagination and added_after filtering.
    For a small capped snapshot, use /api/v1/feed?output_format=stix&limit=N.
    """
    return StreamingResponse(
        _stix_bundle_stream(),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="stix_bundle.json"',
            "X-STIX-Version": "2.1",
            "Cache-Control": "no-store",
        },
    )


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
    data, total = await asyncio.gather(
        db.query_indicators(
            since=parsed_since, indicator_type=type, threat_level=threat_level, limit=limit, offset=offset
        ),
        db.count_indicators(since=parsed_since, indicator_type=type, threat_level=threat_level),
    )
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
    return AppJSONResponse(content=result, headers=_cache_headers(etag))


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
        "brute_force", "credential_stuffing", "recon", "discovery", "malware_deployment",
        "cryptominer", "botnet_recruitment", "lateral_movement", "data_exfil", "unknown",
    ]),
    threat_level: Optional[str] = Query(None, description="Comma-separated: low,medium,high,critical"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Browse enriched attack sessions with MITRE ATT&CK mappings.
    Returns session summaries (without full STIX bundles). Supports ETag caching."""
    parsed_since = parse_since(since)
    data, total = await asyncio.gather(
        db.query_sessions(
            since=parsed_since, attack_type=attack_type, threat_level=threat_level, limit=limit, offset=offset
        ),
        db.count_sessions(since=parsed_since, attack_type=attack_type, threat_level=threat_level),
    )
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
            "confidence": THREAT_CONFIDENCE.get(s.get("threat_level", ""), 50),
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
    return AppJSONResponse(content=result, headers=_cache_headers(etag))


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

# --- Pipeline trigger ---

@app.post("/api/v1/pipeline/run", tags=["Admin"], include_in_schema=False)
@limiter.limit("10/minute")
async def run_pipeline(
    request: Request,
    background_tasks: BackgroundTasks,
    log_path: str = Query("/cowrie/var/log/cowrie/cowrie.json"),
    _auth: None = Depends(check_admin_auth),
):
    """Manually trigger the enrichment pipeline (async). LAN + ADMIN_TOKEN required.

    Returns 202 immediately; the pipeline runs as a background task.
    Monitor progress via GET /api/v1/quality (pipeline.last_run field).
    Blocking inline runs are impractical: VT enrichment adds ~15s per new malware sample.
    """
    from .pipeline import process_cowrie_log
    background_tasks.add_task(process_cowrie_log, log_path)
    return JSONResponse(
        status_code=202,
        content={
            "status": "started",
            "log_path": log_path,
            "message": "Pipeline running in background. Poll /api/v1/quality for progress.",
        },
    )
