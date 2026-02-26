import asyncio

from app import database as db
from app.pipeline import _indicator_id


def _insert_session(session_id: str, src_ip: str) -> None:
    asyncio.run(db.insert_session({
        'session_id': session_id,
        'src_ip': src_ip,
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


def test_query_indicators_cursor_pagination_and_filters(client):
    _insert_session('s1', '203.0.113.10')
    _insert_session('s2', '203.0.113.11')
    _insert_session('s3', '203.0.113.12')

    rows = [
        {
            'id': _indicator_id('ipv4-addr', '203.0.113.1'), 'session_id': 's1', 'type': 'ipv4-addr', 'value': '203.0.113.1',
            'first_seen': '2026-02-25T00:00:00Z', 'last_seen': '2026-02-25T00:00:00Z', 'threat_level': 'low'
        },
        {
            'id': _indicator_id('url', 'http://example.test/a'), 'session_id': 's2', 'type': 'url', 'value': 'http://example.test/a',
            'first_seen': '2026-02-25T00:00:00Z', 'last_seen': '2026-02-25T00:00:00Z', 'threat_level': 'high'
        },
        {
            'id': _indicator_id('ipv4-addr', '203.0.113.2'), 'session_id': 's3', 'type': 'ipv4-addr', 'value': '203.0.113.2',
            'first_seen': '2026-02-25T00:00:00Z', 'last_seen': '2026-02-25T00:00:00Z', 'threat_level': 'high'
        },
    ]
    for r in rows:
        asyncio.run(db.upsert_indicator(r))

    first_page, next_cursor = asyncio.run(db.query_indicators_cursor(limit=2))
    assert len(first_page) == 2
    assert next_cursor is not None

    second_page, next_cursor_2 = asyncio.run(db.query_indicators_cursor(cursor=next_cursor, limit=2))
    assert len(second_page) == 1
    assert next_cursor_2 is None

    high_only, _ = asyncio.run(db.query_indicators_cursor(threat_level='high', limit=10))
    assert len(high_only) == 2


def test_revoke_and_unrevoke_flow_reflected_in_queries(client):
    _insert_session('sr1', '198.51.100.10')
    asyncio.run(db.upsert_indicator({
        'id': 'ir1', 'session_id': 'sr1', 'type': 'ipv4-addr', 'value': '198.51.100.50',
        'first_seen': '2026-02-25T00:00:00Z', 'last_seen': '2026-02-25T00:00:00Z', 'threat_level': 'medium'
    }))

    assert asyncio.run(db.revoke_indicator('198.51.100.50', 'false_positive')) is True

    visible, _ = asyncio.run(db.query_indicators_cursor(include_revoked=False, limit=50))
    assert all(i['value'] != '198.51.100.50' for i in visible)

    all_rows, _ = asyncio.run(db.query_indicators_cursor(include_revoked=True, limit=50))
    revoked = next(i for i in all_rows if i['value'] == '198.51.100.50')
    assert revoked['revoked'] == 1
    assert revoked['revoked_reason'] == 'false_positive'

    assert asyncio.run(db.unrevoke_indicator('198.51.100.50')) is True
    all_rows_2, _ = asyncio.run(db.query_indicators_cursor(include_revoked=True, limit=50))
    restored = next(i for i in all_rows_2 if i['value'] == '198.51.100.50')
    assert restored['revoked'] == 0
