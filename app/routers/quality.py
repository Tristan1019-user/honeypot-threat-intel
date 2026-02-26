from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request

from app import database as db

router = APIRouter(prefix="/api/v1", tags=["Stats"])


def _freshness(ts: Optional[str]) -> dict:
    if not ts:
        return {"status": "unknown", "age_minutes": None}
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        age_minutes = int((datetime.now(timezone.utc) - dt).total_seconds() / 60)
        if age_minutes <= 20:
            status = "fresh"
        elif age_minutes <= 60:
            status = "stale"
        else:
            status = "degraded"
        return {"status": status, "age_minutes": age_minutes}
    except Exception:
        return {"status": "unknown", "age_minutes": None}


def _read_pipeline_state() -> dict:
    """Read pipeline state file; returns empty dict on any error."""
    state_path = Path("/data/pipeline_state.json")
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text())
    except Exception:
        return {}


@router.get("/quality")
async def quality_metrics(request: Request):
    ops = await db.get_operational_metrics()
    state = _read_pipeline_state()
    pipeline_last_run = state.get("last_run") or ops.get("last_update")

    # last_data_insert: the authoritative "when was the last new session?"
    # Primary: MAX(enriched_at) from the DB — the ground truth.
    # Fallback: state file last_insert_at (written by pipeline; absent in old state files).
    # Both are set to the same timestamp when data is inserted, so in practice they
    # agree. Using the DB value avoids the old split where the displayed timestamp
    # and the freshness status came from different sources and could contradict each other.
    last_data_insert = ops.get("last_update") or state.get("last_insert_at")

    freshness = _freshness(pipeline_last_run)
    data_freshness = _freshness(last_data_insert)
    return {
        "feed_id": "honeypot-svr04",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "freshness": freshness,
        "pipeline": {
            "run_interval_minutes": 15,
            "last_run": pipeline_last_run,
            "last_data_insert": last_data_insert,
            "data_freshness": data_freshness,
        },
        "window_24h": {
            "sessions": ops.get("sessions_24h", 0),
            "indicators": ops.get("indicators_24h", 0),
            "high_or_critical_sessions": ops.get("high_or_critical_sessions_24h", 0),
            "unique_attacker_ips": ops.get("unique_attacker_ips_24h", 0),
            "top_attack_type": ops.get("top_attack_type_24h"),
        },
    }


@router.get("/limitations", tags=["Info"])
async def limitations(request: Request):
    return {
        "source_scope": "single_sensor_ssh_honeypot",
        "recommended_usage": [
            "enrichment",
            "analyst triage",
            "supplementary detection",
        ],
        "not_recommended_as": [
            "sole_blocking_source",
            "standalone_attribution",
            "production_auto-block_without_secondary_signals",
        ],
        "known_biases": [
            "shared hosting and NAT overlap",
            "tor exit nodes",
            "vpn/proxy geolocation ambiguity",
            "internet-wide scanner overlap",
        ],
        "false_positive_controls": [
            "indicator revocation support",
            "reason codes for revocation",
            "confidence mapping by threat level",
        ],
    }
