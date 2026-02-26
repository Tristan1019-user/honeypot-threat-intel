"""
Admin authentication helpers.

Two-layer access control for admin/pipeline endpoints:
  1. Proxy header guard  — rejects anything arriving through Cloudflare/Caddy
  2. Private IP guard    — rejects direct connections from public IPs
  3. Token guard         — when ADMIN_TOKEN env var is set, requires a matching
                           Bearer token (or x-admin-token)
"""

import hmac
import os
import re
from ipaddress import ip_address, ip_network

from fastapi import HTTPException, Request

ADMIN_TOKEN = ""

_ADMIN_ALLOWED_NETS = [
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

# Backward-compatible test hook used by existing auth tests.
_PRIVATE_IP_RE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$)")


def _is_private_or_loopback(ip: str) -> bool:
    if not ip:
        return False
    if _PRIVATE_IP_RE.match(ip):
        return True
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return any(parsed in net for net in _ADMIN_ALLOWED_NETS)


def _extract_token(request: Request) -> str:
    token = request.headers.get("x-admin-token", "").strip()
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.removeprefix("Bearer ").strip()
    return ""


def check_admin_auth(request: Request) -> None:
    """Raise HTTP 403 when request is not authorized for admin endpoints."""
    # Layer 1: proxy header guard (internet-facing path)
    if (
        request.headers.get("x-forwarded-for")
        or request.headers.get("cf-connecting-ip")
        or request.headers.get("x-real-ip")
    ):
        raise HTTPException(status_code=403, detail="Admin endpoints restricted to direct LAN/localhost access")

    # Layer 2: local/private source guard
    ip = request.client.host if request.client else ""
    if not _is_private_or_loopback(ip):
        raise HTTPException(status_code=403, detail="Admin endpoints restricted to direct LAN/localhost access")

    # Layer 3: optional token guard (recommended for LAN threat model)
    configured = os.environ.get("ADMIN_TOKEN", ADMIN_TOKEN).strip()
    if configured:
        provided = _extract_token(request)
        if not provided:
            raise HTTPException(
                status_code=403,
                detail="Admin token required: provide Authorization: Bearer <ADMIN_TOKEN> or x-admin-token",
            )
        if not hmac.compare_digest(provided, configured):
            raise HTTPException(status_code=403, detail="Invalid admin token")
