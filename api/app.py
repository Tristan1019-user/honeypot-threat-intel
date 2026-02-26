import hmac
import json
import logging
import os
import time
import uuid
from typing import Optional

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.rows import dict_row
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

API_TOKEN = os.getenv("API_TOKEN", "").strip()
ENABLE_DOCS = os.getenv("API_ENABLE_DOCS", "false").lower() == "true"
RATE_LIMIT = os.getenv("API_RATE_LIMIT", "120/minute")
ALLOWED_IPS = {ip.strip() for ip in os.getenv("API_ALLOWED_IPS", "").split(",") if ip.strip()}

app = FastAPI(
    title="STIX API",
    version="v2.2",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
security = HTTPBearer(auto_error=False)

DB_CFG = {
    "host": os.getenv("DB_HOST", "postgres"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "stix"),
    "user": os.getenv("DB_USER", "stix"),
    "password": os.getenv("DB_PASSWORD", "stix_dev_change_me"),
}
MAX_PAGE = int(os.getenv("API_MAX_PAGE_SIZE", "500"))

logger = logging.getLogger("stix-api")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_event(event: str, **fields):
    payload = {"event": event, "ts": int(time.time()), **fields}
    logger.info(json.dumps(payload, default=str))


@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    req_id = str(uuid.uuid4())
    request.state.req_id = req_id
    client_ip = get_client_ip(request)

    if ALLOWED_IPS and client_ip not in ALLOWED_IPS and request.url.path != "/health":
        log_event("deny_ip", req_id=req_id, ip=client_ip, path=request.url.path)
        return JSONResponse({"detail": "IP not allowed"}, status_code=403)

    started = time.time()
    response = await call_next(request)
    elapsed_ms = round((time.time() - started) * 1000, 2)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    log_event(
        "http_request",
        req_id=req_id,
        ip=client_ip,
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        elapsed_ms=elapsed_ms,
    )
    return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    log_event("rate_limited", ip=get_client_ip(request), path=request.url.path)
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})


def require_auth(request: Request, creds: HTTPAuthorizationCredentials = Security(security)):
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="API_TOKEN is not configured")
    if not creds or creds.scheme.lower() != "bearer":
        log_event("auth_fail", ip=get_client_ip(request), reason="missing_token", path=request.url.path)
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if not hmac.compare_digest(creds.credentials, API_TOKEN):
        log_event("auth_fail", ip=get_client_ip(request), reason="invalid_token", path=request.url.path)
        raise HTTPException(status_code=401, detail="Invalid bearer token")
    return True


def get_conn():
    return psycopg.connect(**DB_CFG, row_factory=dict_row)


@app.get("/health")
def health():
    return {"ok": True, "version": "v2.2"}


@app.get("/objects")
@limiter.limit(RATE_LIMIT)
def list_objects(
    request: Request,
    type: Optional[str] = None,
    source: Optional[str] = None,
    revoked: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    _: bool = Depends(require_auth),
):
    limit = min(limit, MAX_PAGE)
    where = []
    args = []

    if type:
        where.append("type = %s")
        args.append(type)
    if source:
        where.append("source = %s")
        args.append(source)
    if revoked is not None:
        where.append("revoked = %s")
        args.append(revoked)

    q = "SELECT id, type, modified, created, revoked, source FROM stix_objects"
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY modified DESC LIMIT %s OFFSET %s"
    args.extend([limit, offset])

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q, args)
        rows = cur.fetchall()

    return {"items": rows, "limit": limit, "offset": offset}


@app.get("/objects/{stix_id}")
@limiter.limit(RATE_LIMIT)
def get_object(
    request: Request,
    stix_id: str,
    version: str = "latest",
    _: bool = Depends(require_auth),
):
    with get_conn() as conn, conn.cursor() as cur:
        if version == "latest":
            cur.execute(
                """
                SELECT id, type, modified, created, revoked, source, object_json
                FROM stix_objects
                WHERE id = %s
                ORDER BY modified DESC
                LIMIT 1
                """,
                (stix_id,),
            )
        else:
            cur.execute(
                """
                SELECT id, type, modified, created, revoked, source, object_json
                FROM stix_objects
                WHERE id = %s AND modified = %s
                LIMIT 1
                """,
                (stix_id, version),
            )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Object not found")
    return row


@app.get("/relationships")
@limiter.limit(RATE_LIMIT)
def get_relationships(
    request: Request,
    source_ref: Optional[str] = None,
    target_ref: Optional[str] = None,
    relationship_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    _: bool = Depends(require_auth),
):
    limit = min(limit, MAX_PAGE)
    where = []
    args = []

    if source_ref:
        where.append("source_ref = %s")
        args.append(source_ref)
    if target_ref:
        where.append("target_ref = %s")
        args.append(target_ref)
    if relationship_type:
        where.append("relationship_type = %s")
        args.append(relationship_type)

    q = "SELECT rel_id, source_ref, target_ref, relationship_type, modified FROM stix_relationships"
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY modified DESC NULLS LAST LIMIT %s OFFSET %s"
    args.extend([limit, offset])

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(q, args)
        rows = cur.fetchall()

    return {"items": rows, "limit": limit, "offset": offset}


@app.get("/ingest/runs")
@limiter.limit(RATE_LIMIT)
def ingest_runs(
    request: Request,
    limit: int = Query(20, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: bool = Depends(require_auth),
):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT run_id, source, started_at, ended_at, status, objects_total, upserted, skipped, errored, error_summary
            FROM ingest_runs
            ORDER BY started_at DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        rows = cur.fetchall()
    return {"items": rows, "limit": limit, "offset": offset}
