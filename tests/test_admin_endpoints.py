import asyncio
import re as _re
from unittest.mock import patch

from app import database as db


def test_revoked_feed_endpoint_exists(lan_client):
    """feed/revoked now requires LAN/admin auth — use lan_client fixture."""
    r = lan_client.get('/api/v1/feed/revoked')
    assert r.status_code == 200
    assert 'indicators' in r.json()


def test_revoked_feed_requires_auth(client):
    """feed/revoked must be 403 for public callers."""
    r = client.get('/api/v1/feed/revoked')
    assert r.status_code == 403


def test_revoke_requires_admin(client):
    r = client.post('/api/v1/indicators/1.2.3.4/revoke')
    assert r.status_code == 403


def test_revoke_with_token_auth(client, monkeypatch):
    monkeypatch.setenv('ADMIN_TOKEN', 'unit-test-token')

    asyncio.run(db.insert_session({
        'session_id': 'sess-test-1',
        'src_ip': '203.0.113.120',
        'src_port': 22,
        'timestamp_start': '2026-02-25T00:00:00Z',
        'timestamp_end': '2026-02-25T00:01:00Z',
        'duration_seconds': 60,
        'ssh_client': 'OpenSSH',
        'hassh': 'h',
        'attack_type': 'brute_force',
        'threat_level': 'medium',
        'mitre_techniques': ['T1110'],
        'summary': 'test',
    }))

    asyncio.run(db.upsert_indicator({
        'id': 'ind-test-1',
        'session_id': 'sess-test-1',
        'type': 'ipv4-addr',
        'value': '203.0.113.123',
        'first_seen': '2026-02-25T00:00:00Z',
        'last_seen': '2026-02-25T00:00:00Z',
        'threat_level': 'high',
    }))

    lan_re = _re.compile(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|testclient|::1$)')
    with patch('app.auth._PRIVATE_IP_RE', lan_re):
        r = client.post(
            '/api/v1/indicators/203.0.113.123/revoke?reason=false_positive',
            headers={'x-admin-token': 'unit-test-token'},
        )
        assert r.status_code == 200
        assert r.json()['status'] == 'revoked'

        r2 = client.post(
            '/api/v1/indicators/203.0.113.123/unrevoke',
            headers={'Authorization': 'Bearer unit-test-token'},
        )
    assert r2.status_code == 200
    assert r2.json()['status'] == 'active'
