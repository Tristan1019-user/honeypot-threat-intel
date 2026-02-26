from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app import database as db
from app.auth import check_admin_auth

router = APIRouter(prefix="/api/v1", tags=["Admin"])


@router.get("/feed/revoked", tags=["Feed"])
async def feed_revoked(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _auth: None = Depends(check_admin_auth),
):
    rows, total = await db.get_revoked_indicators(limit=limit, offset=offset)

    indicators = [
        {
            "type": r.get("type"),
            "value": r.get("value"),
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "times_seen": r.get("times_seen", 1),
            "threat_level": r.get("threat_level"),
            "revoked": True,
            "revoked_reason": r.get("revoked_reason"),
        }
        for r in rows
    ]

    return {
        "feed_id": "honeypot-svr04",
        "description": "Revoked indicators - known false positives, research scanners, Tor exits, etc.",
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


@router.post("/indicators/{value:path}/revoke")
async def revoke_indicator_endpoint(
    request: Request,
    value: str,
    reason: str = Query(
        "false_positive",
        description="Revocation reason",
        enum=[
            "false_positive",
            "benign_scanner",
            "tor_exit",
            "researcher",
            "shared_infrastructure",
            "other",
        ],
    ),
    _auth: None = Depends(check_admin_auth),
):
    found = await db.revoke_indicator(value, reason)
    if not found:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "revoked", "value": value, "reason": reason}


@router.post("/indicators/{value:path}/unrevoke")
async def unrevoke_indicator_endpoint(
    request: Request,
    value: str,
    _auth: None = Depends(check_admin_auth),
):
    found = await db.unrevoke_indicator(value)
    if not found:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"status": "active", "value": value}
