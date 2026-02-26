def test_taxii_discovery_and_collections(client):
    r = client.get('/taxii2/')
    assert r.status_code == 200
    assert 'api_roots' in r.json()

    r2 = client.get('/taxii2/collections')
    assert r2.status_code == 200
    assert 'collections' in r2.json()


def test_taxii_objects_bad_collection(client):
    r = client.get('/taxii2/collections/not-real/objects')
    assert r.status_code == 404
