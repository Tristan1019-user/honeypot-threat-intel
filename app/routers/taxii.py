"""TAXII 2.1 server endpoints.

Implements the TAXII 2.1 specification (https://docs.oasis-open.org/cti/taxii/v2.1/):
  - Discovery        GET /taxii2/
  - Collections      GET /taxii2/collections/
  - Objects          GET /taxii2/collections/{id}/objects/

Response format: TAXII Envelope
  {
    "more": bool,          -- true when additional pages exist
    "next": "cursor",      -- opaque cursor; pass as ?next= on subsequent requests
    "objects": [...]       -- STIX 2.1 objects, deduplicated by id
  }

Headers:
  Content-Type: application/taxii+json;version=2.1
  X-TAXII-Date-Added-Last: <ISO 8601 timestamp of last object in this page>
"""

import base64
import json
from typing import Optional, cast

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app import database as db
from app.ratelimit import limiter
from app.scrub import scrub_dict as _scrub_dict
from app.stix import PRODUCER_IDENTITY, TLP_CLEAR_MARKING
from app.utils import parse_since

router = APIRouter(tags=["TAXII 2.1"])

TAXII_MEDIA = "application/taxii+json;version=2.1"
TAXII_COLLECTION_ID = "honeypot-svr04-stix21"

# Maximum objects per TAXII page.  Kept modest because each session bundle
# holds ~10-20 STIX objects; 100 sessions → ~1,500-2,000 objects in one response.
# Clients should page via the `next` cursor for large datasets.
_MAX_SESSIONS_PER_PAGE = 100


def _taxii_media(request: Request) -> str:
    accept = request.headers.get("accept", "")
    if "taxii" in accept or "stix" in accept:
        return TAXII_MEDIA
    return "application/json"


def _encode_cursor(offset: int) -> str:
    """Encode an integer page offset as a URL-safe base64 cursor string."""
    return base64.urlsafe_b64encode(str(offset).encode()).rstrip(b"=").decode()


def _decode_cursor(token: str) -> int:
    """Decode a cursor back to an integer offset. Returns 0 on any error."""
    try:
        pad = (4 - len(token) % 4) % 4
        return int(base64.urlsafe_b64decode((token + "=" * pad).encode()).decode())
    except Exception:
        return 0


@router.get("/taxii2/")
async def taxii_discovery(request: Request):
    """TAXII 2.1 Discovery endpoint."""
    return JSONResponse(
        content={
            "title": "Honeypot SVR04 Threat Intel TAXII Server",
            "description": "AI-enriched SSH honeypot threat intelligence (STIX 2.1, MITRE ATT&CK mapped)",
            "contact": "https://github.com/Tristan1019-user/honeypot-threat-intel",
            "default": "/taxii2/",
            "api_roots": ["/taxii2/"],
        },
        media_type=_taxii_media(request),
    )


@router.get("/taxii2/collections")
@router.get("/taxii2/collections/", include_in_schema=False)
async def taxii_collections(request: Request):
    """TAXII 2.1 Collections endpoint — lists available STIX collections."""
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
@limiter.limit("30/minute")
async def taxii_objects(
    request: Request,
    collection_id: str,
    added_after: Optional[str] = Query(
        None,
        description=(
            "Return only objects added after this timestamp. "
            "Accepts ISO 8601 (2026-01-01T00:00:00Z), relative (1h, 24h, 7d), "
            "or Unix epoch seconds."
        ),
    ),
    limit: int = Query(
        50, ge=1, le=_MAX_SESSIONS_PER_PAGE,
        description=f"Sessions per page (1–{_MAX_SESSIONS_PER_PAGE}). Each session yields ~10-20 STIX objects.",
    ),
    next_token: Optional[str] = Query(
        None, alias="next",
        description="Opaque cursor returned in the previous response's 'next' field.",
    ),
):
    """TAXII 2.1 Objects endpoint.

    Returns a TAXII Envelope containing deduplicated STIX 2.1 objects from
    the requested collection, with cursor-based pagination.

    Pagination workflow:
      1. Call without ?next — receive first page and an optional 'next' cursor.
      2. If 'more': true, call again with ?next=<cursor> to retrieve the next page.
      3. Repeat until 'more': false.

    Use added_after for incremental sync (e.g., added_after=2026-02-01T00:00:00Z
    or added_after=24h) to retrieve only objects added since your last fetch.

    Response headers:
      X-TAXII-Date-Added-Last: timestamp of the last session in this page.
    """
    if collection_id != TAXII_COLLECTION_ID:
        raise HTTPException(
            status_code=404,
            detail=f"Collection not found. Available collection: {TAXII_COLLECTION_ID}",
        )

    # parse_since() supports all formats (ISO, relative, epoch) and raises
    # HTTP 400 with a clear message on bad input — no silent filter bypass.
    since = parse_since(added_after)

    # Decode cursor to get page offset (0 = first page)
    offset = _decode_cursor(next_token) if next_token else 0

    # Fetch one extra row to detect whether more pages exist (limit+1 trick).
    sessions = await db.query_sessions(since=since, limit=limit + 1, offset=offset)
    has_more = len(sessions) > limit
    page = sessions[:limit]

    # Build deduplicated STIX object list from session bundles.
    # Shared objects (identity, TLP marking) always lead the response.
    seen_ids: set[str] = set()
    objects: list[dict] = []
    last_added: Optional[str] = None

    for shared in (PRODUCER_IDENTITY, TLP_CLEAR_MARKING):
        # cast: PRODUCER_IDENTITY / TLP_CLEAR_MARKING have heterogeneous value
        # types so mypy infers shared["id"] as Collection[str]; cast to str.
        oid = cast(str, shared["id"])
        if oid not in seen_ids:
            seen_ids.add(oid)
            objects.append(shared)

    for s in page:
        ts: Optional[str] = s.get("timestamp_start")
        if ts and (last_added is None or ts > last_added):
            last_added = ts
        raw = s.get("stix_bundle")
        if not raw:
            continue
        try:
            bundle = json.loads(raw) if isinstance(raw, str) else raw
            for obj in bundle.get("objects", []):
                if not isinstance(obj, dict):
                    continue
                oid_inner: Optional[str] = obj.get("id")
                if oid_inner and oid_inner in seen_ids:
                    continue
                if oid_inner:
                    seen_ids.add(oid_inner)
                objects.append(obj)
        except (json.JSONDecodeError, TypeError):
            continue

    # TAXII 2.1 Envelope
    envelope: dict = {
        "more": has_more,
        "objects": _scrub_dict(objects),
    }
    if has_more:
        envelope["next"] = _encode_cursor(offset + limit)

    headers = {"Content-Type": TAXII_MEDIA}
    if last_added:
        # X-TAXII-Date-Added-Last: per TAXII 2.1 §3.4, set to the timestamp
        # of the last object in the response so clients can use it as the
        # added_after parameter for their next incremental fetch.
        headers["X-TAXII-Date-Added-Last"] = last_added

    return JSONResponse(content=envelope, headers=headers, media_type=TAXII_MEDIA)
