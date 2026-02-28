"""
Tests for the three fixes applied to the codebase:
  1. db.session_exists() helper
  2. Pipeline dedup — already-enriched sessions skipped
  3. /api/v1/pipeline/run restricted to LAN/localhost
"""

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


import re as _re

# client, lan_client, db_path fixtures live in conftest.py


# ─── Fix 1: session_exists() ──────────────────────────────────────────────────

def test_session_exists_false_on_empty_db(db_path):
    from app import database as db
    result = asyncio.run(db.session_exists("nonexistent-session-id"))
    assert result is False


def test_session_exists_true_after_insert(db_path):
    from app import database as db

    session = {
        "session_id": "test-session-abc123",
        "src_ip": "1.2.3.4",
        "timestamp_start": "2026-02-25T00:00:00Z",
        "attack_type": "brute_force",
        "threat_level": "low",
        "mitre_techniques": [],
        "summary": "test session",
    }
    asyncio.run(db.insert_session(session))
    assert asyncio.run(db.session_exists("test-session-abc123")) is True
    assert asyncio.run(db.session_exists("different-session-id")) is False


# ─── Fix 2: pipeline dedup ────────────────────────────────────────────────────

def test_pipeline_skips_existing_sessions(db_path, tmp_path):
    """Sessions already in DB must be skipped — enrich_session must NOT be called for them."""
    from app import database as db
    from app.pipeline import process_cowrie_log

    # Seed a cowrie.json with two sessions
    log = tmp_path / "cowrie.json"
    log.write_text(
        '{"eventid":"cowrie.session.connect","session":"aaa111","src_ip":"5.6.7.8","timestamp":"2026-02-25T10:00:00.000000Z"}\n'
        '{"eventid":"cowrie.login.failed","session":"aaa111","username":"root","password":"pass","timestamp":"2026-02-25T10:00:01.000000Z"}\n'
        '{"eventid":"cowrie.session.connect","session":"bbb222","src_ip":"9.9.9.9","timestamp":"2026-02-25T11:00:00.000000Z"}\n'
        '{"eventid":"cowrie.login.failed","session":"bbb222","username":"admin","password":"1234","timestamp":"2026-02-25T11:00:01.000000Z"}\n'
    )
    state_path = str(tmp_path / "state.json")

    mock_enrichment = {
        "attack_type": "brute_force",
        "mitre_techniques": ["T1110.001"],
        "threat_level": "low",
        "summary": "Brute force",
        "observed_features": {"classification_method": "ai"},
    }
    mock_geo = {"asn": "AS12345", "org": "TestOrg", "country": "US", "cloud_provider": ""}

    call_count = 0

    async def counting_enrich(session):
        nonlocal call_count
        call_count += 1
        return mock_enrichment

    with patch("app.pipeline.enrich_session", side_effect=counting_enrich), \
         patch("app.pipeline.enrich_ip_geo", return_value=mock_geo):
        result = asyncio.run(process_cowrie_log(str(log), state_path=state_path))

    assert result["sessions_enriched"] == 2
    assert result["sessions_skipped_dedup"] == 0
    assert call_count == 2

    # Run again — both sessions should be skipped
    call_count = 0
    with patch("app.pipeline.enrich_session", side_effect=counting_enrich), \
         patch("app.pipeline.enrich_ip_geo", return_value=mock_geo):
        result2 = asyncio.run(process_cowrie_log(str(log), state_path=state_path))

    # No new events (offset is at end), so assembled=0, enriched=0
    assert result2["sessions_enriched"] == 0
    assert call_count == 0


def test_pipeline_dedup_on_path_reset(db_path, tmp_path):
    """Simulate a state path-mismatch reset: offset rewinds to 0, but dedup prevents re-enrichment."""
    import json
    from app import database as db
    from app.pipeline import process_cowrie_log

    log = tmp_path / "cowrie.json"
    log.write_text(
        '{"eventid":"cowrie.session.connect","session":"ccc333","src_ip":"203.0.113.77","timestamp":"2026-02-25T12:00:00.000000Z"}\n'
        '{"eventid":"cowrie.login.failed","session":"ccc333","username":"root","password":"toor","timestamp":"2026-02-25T12:00:01.000000Z"}\n'
    )
    state_path = str(tmp_path / "state.json")

    mock_enrichment = {
        "attack_type": "brute_force",
        "mitre_techniques": ["T1110.001"],
        "threat_level": "low",
        "summary": "Brute force",
        "observed_features": {"classification_method": "ai"},
    }
    mock_geo = {}

    enrich_calls = []

    async def tracking_enrich(session):
        enrich_calls.append(session["session_id"])
        return mock_enrichment

    # First run — processes session normally
    with patch("app.pipeline.enrich_session", side_effect=tracking_enrich), \
         patch("app.pipeline.enrich_ip_geo", return_value=mock_geo):
        asyncio.run(process_cowrie_log(str(log), state_path=state_path))

    assert "ccc333" in enrich_calls
    enrich_calls.clear()

    # Corrupt the state to simulate a path-prefix mismatch reset
    state = json.loads(Path(state_path).read_text())
    state["last_file"] = "/different/mount/prefix/cowrie.json"  # bad path
    state["last_line_offset"] = 0
    Path(state_path).write_text(json.dumps(state))

    # Second run — offset resets to 0, reads same events again, but dedup skips enrichment
    with patch("app.pipeline.enrich_session", side_effect=tracking_enrich), \
         patch("app.pipeline.enrich_ip_geo", return_value=mock_geo):
        result = asyncio.run(process_cowrie_log(str(log), state_path=state_path))

    # Session was assembled again but skipped by dedup
    assert "ccc333" not in enrich_calls, "enrich_session should NOT be called for already-stored session"
    assert result["sessions_skipped_dedup"] == 1
    assert result["sessions_enriched"] == 0


# ─── Fix 3: pipeline/run restricted to LAN ────────────────────────────────────

# ─── Fix 3 (updated): pipeline/run — two-layer auth ──────────────────────────
# Layer 1: proxy header guard  (blocks Cloudflare / Caddy proxied traffic)
# Layer 2: private IP guard    (blocks direct public-IP connections)
# Layer 3: ADMIN_TOKEN guard   (requires Bearer token when token is configured)

def test_pipeline_run_blocked_layer1_cf_header(client):
    """Layer 1: cf-connecting-ip header → immediate 403 regardless of IP or token."""
    r = client.post(
        "/api/v1/pipeline/run",
        headers={"cf-connecting-ip": "1.2.3.4"},
    )
    assert r.status_code == 403
    assert "LAN" in r.json()["detail"]


def test_pipeline_run_blocked_layer1_x_forwarded_for(client):
    """Layer 1: x-forwarded-for header → 403 (Caddy/nginx proxy path)."""
    r = client.post(
        "/api/v1/pipeline/run",
        headers={"x-forwarded-for": "203.0.113.50"},
    )
    assert r.status_code == 403


def test_pipeline_run_blocked_layer2_public_ip(client):
    """Layer 2: direct connection from non-private IP → 403."""
    # Patch private IP regex to reject everything → simulates a public-IP direct connection
    with patch("app.auth._PRIVATE_IP_RE", _re.compile(r'^NOMATCH$')):
        r = client.post("/api/v1/pipeline/run")
    assert r.status_code == 403


def test_pipeline_run_blocked_layer3_missing_token(lan_client):
    """Layer 3: ADMIN_TOKEN configured but no Authorization header → 403."""
    with patch("app.auth.ADMIN_TOKEN", "super-secret"):
        r = lan_client.post("/api/v1/pipeline/run")
    assert r.status_code == 403
    assert "token" in r.json()["detail"].lower()


def test_pipeline_run_blocked_layer3_wrong_token(lan_client):
    """Layer 3: ADMIN_TOKEN configured but wrong token provided → 403."""
    with patch("app.auth.ADMIN_TOKEN", "super-secret"):
        r = lan_client.post(
            "/api/v1/pipeline/run",
            headers={"Authorization": "Bearer wrong-token"},
        )
    assert r.status_code == 403
    assert "Invalid" in r.json()["detail"]


def test_pipeline_run_allowed_with_correct_token(lan_client):
    """Layer 3: correct Bearer token from LAN → 202 Accepted (background task started)."""
    with patch("app.auth.ADMIN_TOKEN", "super-secret"), \
         patch("app.pipeline.process_cowrie_log", return_value={"new_events": 0, "sessions_enriched": 0, "sessions_skipped_dedup": 0}):
        r = lan_client.post(
            "/api/v1/pipeline/run",
            headers={"Authorization": "Bearer super-secret"},
        )
    assert r.status_code == 202
    assert r.json()["status"] == "started"


def test_pipeline_run_allowed_no_token_when_unconfigured(lan_client):
    """When ADMIN_TOKEN is not set, LAN access alone is sufficient → 202 Accepted."""
    with patch("app.auth.ADMIN_TOKEN", ""), \
         patch("app.pipeline.process_cowrie_log", return_value={"new_events": 0, "sessions_enriched": 0, "sessions_skipped_dedup": 0}):
        r = lan_client.post("/api/v1/pipeline/run")
    assert r.status_code == 202
