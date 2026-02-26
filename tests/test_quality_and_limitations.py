def test_quality_endpoint_shape(client):
    r = client.get('/api/v1/quality')
    assert r.status_code == 200
    j = r.json()
    assert 'freshness' in j
    assert 'pipeline' in j
    assert 'window_24h' in j


def test_limitations_endpoint_shape(client):
    r = client.get('/api/v1/limitations')
    assert r.status_code == 200
    j = r.json()
    assert 'recommended_usage' in j
    assert 'not_recommended_as' in j
    assert 'known_biases' in j
