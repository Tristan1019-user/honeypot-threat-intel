def test_integrity_endpoint_exists(client):
    r = client.get('/api/v1/integrity')
    assert r.status_code == 200
    j = r.json()
    # v2: renamed from stix_bundle_sha256 (was misleading — only covered ≤500 sessions)
    assert 'dataset_fingerprint' in j
    assert 'coverage' in j
    assert j['coverage'] == 'all non-revoked indicators'
    assert 'generated_at' in j
    assert 'total_indicators' in j


def test_ip_and_hassh_404_on_empty_db(client):
    assert client.get('/api/v1/ip/1.2.3.4').status_code == 404
    assert client.get('/api/v1/hassh/notreal').status_code == 404
