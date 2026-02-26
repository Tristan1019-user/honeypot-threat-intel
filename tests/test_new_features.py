"""
Tests for the improvements introduced in this release:
  1. Integrity endpoint redesign (full-dataset fingerprint)
  2. /feed/cdb and /feed/hashes Wazuh integration endpoints
  3. Geo cache (get_cached_geo)
  4. VirusTotal update path (update_malware_vt)
  5. discovery attack_type in taxonomy
"""

import asyncio
import os
import re
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# LAN IP pattern extended with "testclient" for auth-protected endpoint tests
_LAN_RE = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|testclient)"
)


def _indicator(value: str, threat_level: str, times_seen: int = 1, **kw):
    return {
        "id": str(uuid.uuid4()),
        "type": "ipv4-addr",
        "value": value,
        "threat_level": threat_level,
        "times_seen": times_seen,
        **kw,
    }


# client, lan_client, db_path fixtures live in conftest.py


# ── 1. Integrity endpoint ──────────────────────────────────────────────────────

def test_integrity_returns_full_dataset_fingerprint(client):
    r = client.get("/api/v1/integrity")
    assert r.status_code == 200
    j = r.json()
    assert "dataset_fingerprint" in j
    assert "coverage" in j
    assert "all non-revoked" in j["coverage"]
    assert "total_indicators" in j
    assert "total_sessions" in j
    assert "total_malware_samples" in j
    # Old misleading field must NOT be present
    assert "stix_bundle_sha256" not in j
    assert "stix_object_count" not in j


def test_integrity_fingerprint_changes_when_data_added(db_path):
    from app import database as db
    fp1 = asyncio.run(_get_fingerprint())

    # Insert an indicator and check fingerprint changes
    asyncio.run(db.upsert_indicator(_indicator("1.2.3.4", "high", times_seen=3)))
    # Bust the fingerprint cache so the new indicator is reflected.
    db._fingerprint_cache_data = None
    db._fingerprint_cache_ts = 0.0
    fp2 = asyncio.run(_get_fingerprint())
    assert fp1 != fp2


async def _get_fingerprint() -> str:
    from app import database as db
    result = await db.get_dataset_fingerprint()
    return result["fingerprint"]


# ── 2. /feed/cdb and /feed/hashes ─────────────────────────────────────────────

def test_feed_cdb_returns_plain_text(lan_client):
    r = lan_client.get("/api/v1/feed/cdb")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


def test_feed_cdb_excludes_revoked(db_path):
    from app import database as db
    asyncio.run(db.upsert_indicator(_indicator("10.20.30.40", "high", times_seen=5)))
    asyncio.run(db.revoke_indicator("10.20.30.40", "false_positive"))

    os.environ["DATABASE_PATH"] = db_path
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app.main import app
    with patch("app.auth._PRIVATE_IP_RE", _LAN_RE):
        with TestClient(app) as c:
            r = c.get("/api/v1/feed/cdb")
    assert "10.20.30.40" not in r.text


def test_feed_cdb_contains_high_critical_ips(db_path):
    from app import database as db
    asyncio.run(db.upsert_indicator(_indicator("5.5.5.5", "critical", times_seen=10)))
    asyncio.run(db.upsert_indicator(_indicator("6.6.6.6", "low", times_seen=1)))

    os.environ["DATABASE_PATH"] = db_path
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app.main import app
    with patch("app.auth._PRIVATE_IP_RE", _LAN_RE):
        with TestClient(app) as c:
            r = c.get("/api/v1/feed/cdb")
    assert "5.5.5.5" in r.text
    assert "6.6.6.6" not in r.text  # low threat excluded by default


def test_feed_hashes_returns_plain_text(lan_client):
    r = lan_client.get("/api/v1/feed/hashes")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


def test_feed_hashes_contains_inserted_sample(db_path):
    from app import database as db
    sha = "a" * 64
    asyncio.run(db.insert_malware({
        "sha256": sha, "session_id": "sess-001",
        "url": "http://evil.example/payload.sh", "first_seen": "2026-01-01T00:00:00Z",
    }))

    os.environ["DATABASE_PATH"] = db_path
    os.environ["ALLOW_SQLITE_FALLBACK"] = "true"
    os.environ.pop("DATABASE_URL", None)
    from app.main import app
    with patch("app.auth._PRIVATE_IP_RE", _LAN_RE):
        with TestClient(app) as c:
            r = c.get("/api/v1/feed/hashes")
    assert sha in r.text


# ── 3. Geo cache ───────────────────────────────────────────────────────────────

def test_get_cached_geo_returns_empty_on_miss(db_path):
    from app import database as db
    result = asyncio.run(db.get_cached_geo("1.2.3.4"))
    assert result == {}


def test_get_cached_geo_returns_data_after_session_insert(db_path):
    from app import database as db
    asyncio.run(db.insert_session({
        "session_id": "geo-test-001",
        "src_ip": "203.0.113.99",
        "timestamp_start": "2026-01-01T00:00:00Z",
        "attack_type": "brute_force",
        "threat_level": "low",
        "mitre_techniques": [],
        "summary": "test",
        "asn": "AS12345",
        "org": "TestOrg",
        "country": "US",
        "cloud_provider": "DigitalOcean",
    }))
    geo = asyncio.run(db.get_cached_geo("203.0.113.99"))
    assert geo["country"] == "US"
    assert geo["asn"] == "AS12345"
    assert geo["org"] == "TestOrg"


def test_get_cached_geo_returns_empty_when_no_country(db_path):
    """Sessions without geo data (country='') should not be returned as cache hits."""
    from app import database as db
    asyncio.run(db.insert_session({
        "session_id": "geo-test-002",
        "src_ip": "203.0.113.88",
        "timestamp_start": "2026-01-01T00:00:00Z",
        "attack_type": "brute_force",
        "threat_level": "low",
        "mitre_techniques": [],
        "summary": "test",
        # No country/asn/org set
    }))
    geo = asyncio.run(db.get_cached_geo("203.0.113.88"))
    assert geo == {}


# ── 4. VirusTotal update path ──────────────────────────────────────────────────

def test_update_malware_vt_persists_data(db_path):
    from app import database as db
    sha = "b" * 64
    asyncio.run(db.insert_malware({
        "sha256": sha, "session_id": "sess-vt-001",
        "url": "http://malware.example/bot.sh", "first_seen": "2026-01-01T00:00:00Z",
    }))
    asyncio.run(db.update_malware_vt(sha, {
        "vt_known": True,
        "vt_detection_ratio": "42/72",
        "vt_malware_families": ["Mirai", "Gafgyt"],
        "vt_first_submission": 1700000000,
    }))

    import json as _json
    samples = asyncio.run(db.get_malware_samples())
    row = next(s for s in samples if s["sha256"] == sha)

    assert row["vt_known"] == 1
    assert row["vt_detection_ratio"] == "42/72"
    families = (
        _json.loads(row["vt_malware_families"])
        if isinstance(row["vt_malware_families"], str)
        else row["vt_malware_families"]
    )
    assert "Mirai" in families


# ── 5. discovery attack_type ───────────────────────────────────────────────────

def test_discovery_in_valid_attack_types():
    from app.enrichment import VALID_ATTACK_TYPES
    assert "discovery" in VALID_ATTACK_TYPES
    assert "recon" in VALID_ATTACK_TYPES


def test_validate_enrichment_upgrades_recon_to_discovery_on_auth():
    from app.enrichment import _validate_enrichment
    session = {
        "src_ip": "1.2.3.4",
        "credentials_attempted": [{"username": "root", "password": "123", "success": True}],
        "commands": ["uname -a", "ls /"],
        "downloads": [],
    }
    result = _validate_enrichment({"attack_type": "recon", "threat_level": "medium",
                                    "mitre_techniques": [], "summary": "test"}, session)
    assert result["attack_type"] == "discovery"


def test_validate_enrichment_keeps_recon_for_unauthenticated():
    from app.enrichment import _validate_enrichment
    session = {
        "src_ip": "1.2.3.4",
        "credentials_attempted": [{"username": "root", "password": "123", "success": False}],
        "commands": [],
        "downloads": [],
    }
    result = _validate_enrichment({"attack_type": "recon", "threat_level": "low",
                                    "mitre_techniques": [], "summary": "test"}, session)
    assert result["attack_type"] == "recon"


def test_default_enrichment_uses_discovery_after_login_with_commands():
    from app.enrichment import _default_enrichment
    session = {
        "src_ip": "1.2.3.4",
        "session_id": "test-session",
        "credentials_attempted": [{"username": "admin", "password": "admin", "success": True}],
        "commands": ["uname -a", "cat /etc/passwd"],
        "downloads": [],
    }
    result = _default_enrichment(session)
    assert result["attack_type"] == "discovery"
    assert "T1082" in result["mitre_techniques"]
