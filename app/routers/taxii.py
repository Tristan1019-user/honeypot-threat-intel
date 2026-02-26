import json
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app import database as db
from app.scrub import scrub_dict as _scrub_dict
from app.stix import TLP_CLEAR_MARKING, merge_stix_bundles

router = APIRouter(tags=["TAXII 2.1"])

TAXII_MEDIA = "application/taxii+json;version=2.1"
TAXII_COLLECTION_ID = "honeypot-svr04-stix21"


def _taxii_media(request: Request) -> str:
    accept = request.headers.get("accept", "")
    if "taxii" in accept or "stix" in accept:
        return TAXII_MEDIA
    return "application/json"


@router.get("/taxii2/")
async def taxii_discovery(request: Request):
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


@router.get("/taxii2/collections")
@router.get("/taxii2/collections/", include_in_schema=False)
async def taxii_collections(request: Request):
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


@router.get("/taxii2/collections/{collection_id}/objects")
@router.get("/taxii2/collections/{collection_id}/objects/", include_in_schema=False)
async def taxii_objects(
    request: Request,
    collection_id: str,
    added_after: Optional[str] = Query(None, description="ISO 8601 timestamp filter"),
    limit: int = Query(100, ge=1, le=500),
):
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
        from app.stix import PRODUCER_IDENTITY
        merged = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [PRODUCER_IDENTITY, TLP_CLEAR_MARKING]}

    return JSONResponse(content=_scrub_dict(merged), media_type="application/stix+json;version=2.1")
