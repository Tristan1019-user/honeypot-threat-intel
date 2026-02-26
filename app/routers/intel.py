import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app import database as db
from app.auth import check_admin_auth
from app.scrub import scrub_dict as _scrub_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Enrichment"])


@router.get("/ip/{ip}")
async def ip_sightings(request: Request, ip: str):
    data = await db.get_ip_sightings(ip)
    if data.get("sighting_count", 0) == 0:
        raise HTTPException(status_code=404, detail="IP not observed")
    return _scrub_dict(data)


@router.get("/hassh/{hassh}")
async def hassh_lookup(request: Request, hassh: str):
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
    return _scrub_dict(result)


@router.get("/integrity", tags=["Trust"])
async def integrity(request: Request):
    """Dataset fingerprint covering ALL indicators (not a partial STIX bundle hash).

    SHA-256 is computed over every non-revoked indicator's (value|last_seen) pair
    in last_seen ASC order.  Result is cached for 60 seconds to avoid a full-table
    scan on every request.

    Use this to detect whether the feed has changed since your last fetch without
    downloading the full dataset.
    """
    fp_data, meta = await asyncio.gather(
        db.get_dataset_fingerprint(),
        db.get_integrity_meta(),
    )

    return {
        "dataset_fingerprint": fp_data["fingerprint"],
        "coverage": "all non-revoked indicators",
        "total_sessions": meta["total_sessions"],
        "total_indicators": fp_data["total_indicators"],
        "total_malware_samples": meta["total_malware_samples"],
        "last_update": meta["last_update"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verify": (
            "SHA-256 over 'value|last_seen\\n' for each non-revoked indicator "
            "in last_seen ASC order. Recompute from GET /api/v1/indicators pages."
        ),
    }


_FEED_CDB_HARD_LIMIT = 10_000


@router.get("/feed/cdb", tags=["Wazuh"], response_class=PlainTextResponse)
async def feed_cdb(
    request: Request,
    min_sightings: int = Query(1, ge=1, description="Minimum times_seen to include"),
    threat_level: str = Query(
        "high,critical",
        description="Comma-separated threat levels to include",
    ),
    _auth: None = Depends(check_admin_auth),
):
    """Wazuh CDB-formatted IP list.

    Returns one line per IP in the format Wazuh's CDB expects:
        IP_ADDRESS:threat_level|times_seen

    Feed this directly into /var/ossec/etc/lists/malicious-ioc/malicious-ip
    to activate Wazuh's existing malicious-ioc rule set (rules 99902–99920).

    Excludes revoked indicators.
    """
    levels = [lv.strip() for lv in threat_level.split(",")]
    indicators = await db.query_indicators(
        indicator_type="ipv4-addr",
        threat_level=",".join(levels),
        limit=_FEED_CDB_HARD_LIMIT,
        include_revoked=False,  # push revoked filter into SQL — don't waste page slots
    )
    if len(indicators) == _FEED_CDB_HARD_LIMIT:
        logger.critical(
            "feed/cdb hit hard limit of %d rows — some high/critical IPs are "
            "missing from the Wazuh CDB feed.  Implement pagination or raise the limit.",
            _FEED_CDB_HARD_LIMIT,
        )
    lines = []
    for ind in indicators:
        if (ind.get("times_seen") or 1) < min_sightings:
            continue
        ip = ind["value"]
        tl = ind.get("threat_level", "unknown")
        ts = ind.get("times_seen", 1)
        lines.append(f"{ip}:{tl}|{ts}")
    return "\n".join(lines) + ("\n" if lines else "")


@router.get("/feed/hashes", tags=["Wazuh"], response_class=PlainTextResponse)
async def feed_hashes(request: Request, _auth: None = Depends(check_admin_auth)):
    """Wazuh CDB-formatted malware hash list.

    Returns one line per SHA-256 hash:
        sha256:malware_family_or_url

    Feed this into /var/ossec/etc/lists/malicious-ioc/malware-hashes
    to activate Wazuh rule 99901 (FIM: file with known malware hash).
    """
    samples = await db.get_malware_samples()
    lines = []
    for s in samples:
        sha = s.get("sha256", "")
        if not sha:
            continue
        families_raw = s.get("vt_malware_families")
        if families_raw:
            try:
                families = json.loads(families_raw) if isinstance(families_raw, str) else families_raw
                label = families[0] if families else ""
            except (json.JSONDecodeError, IndexError):
                label = ""
        else:
            label = ""
        if not label:
            # Fall back to domain from download URL
            url = s.get("url", "")
            label = url.split("/")[2] if url.count("/") >= 2 else (url[:40] if url else "honeypot-download")
        lines.append(f"{sha}:{label}")
    return "\n".join(lines) + ("\n" if lines else "")
