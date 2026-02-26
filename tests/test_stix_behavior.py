from app.stix import PRODUCER_IDENTITY, TLP_CLEAR_MARKING, merge_stix_bundles, session_to_stix_bundle


def test_session_to_stix_bundle_contains_required_core_objects():
    session = {
        'session_id': 'sess-1',
        'src_ip': '198.51.100.10',
        'timestamp_start': '2026-02-25T00:00:00Z',
        'timestamp_end': '2026-02-25T00:01:00Z',
        'summary': 'test session',
        'threat_level': 'high',
        'mitre_techniques': ['T1110'],
        'attack_type': 'brute_force',
    }
    bundle = session_to_stix_bundle(session)
    assert bundle['type'] == 'bundle'
    ids = {o.get('id') for o in bundle.get('objects', [])}
    assert PRODUCER_IDENTITY['id'] in ids
    assert TLP_CLEAR_MARKING['id'] in ids


def test_merge_stix_bundles_deduplicates_by_object_id():
    session = {
        'session_id': 'sess-2',
        'src_ip': '198.51.100.11',
        'timestamp_start': '2026-02-25T00:00:00Z',
        'timestamp_end': '2026-02-25T00:01:00Z',
        'summary': 'test session 2',
        'threat_level': 'medium',
        'mitre_techniques': ['T1110'],
        'attack_type': 'brute_force',
    }
    b1 = session_to_stix_bundle(session)
    b2 = session_to_stix_bundle(session)
    merged = merge_stix_bundles([b1, b2])
    ids = [o.get('id') for o in merged.get('objects', []) if o.get('id')]
    assert len(ids) == len(set(ids))
