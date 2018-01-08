import copy

import pyld_sig

ALYSSA = {"@context": ["https://www.w3.org/ns/activitystreams",
                       "https://w3id.org/identity/v1"],
          "type": "Person",
          "id": "https://dustycloud.org/tmp/alyssa.jsonld",
          "name": "Alyssa P. Hacker",
          "preferredUsername": "alyssa",
          "summary": "Lisp enthusiast hailing from MIT",
          "inbox": "https://social.example/alyssa/inbox/",
          "outbox": "https://social.example/alyssa/outbox/",
          "followers": "https://social.example/alyssa/followers/",
          "following": "https://social.example/alyssa/following/",
          "liked": "https://social.example/alyssa/liked/",
          "publicKey": "https://dustycloud.org/tmp/alyssas-key.jsonld"}
ALYSSAS_KEY = {"@context": "https://w3id.org/identity/v1",
               "id": "https://dustycloud.org/tmp/alyssas-key.jsonld",
               "owner": "https://dustycloud.org/tmp/alyssa.jsonld",
               "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzTCeT3jImdupMCdzEk2G\ns75KFz0NielLPsZC+htt0U0NGDF6FqHNE3ab2c6F4pX8s0MbB92oE0pY5qooNQQS\nGimynm2PDgvv2lxViOUH5/iwraUuxgyy0wxWBPXKo7qtL47gZeWlJp6tWmRDo8oy\nA30mnJCNo4YHh11Tl85hE5RCIwBIL0VZiezcMUxSlHCSzOea04xSQxkCo+9a1y/E\nPPuT+D1OZ2weLxqM4I5k3BKdbTehbcPd/iUrS21k2NT0q0ga+q3Gar8cYTg0k/Le\nyJ4VbXijJPJbztTMTWV5BMugtCYJWRXzQ9t1dknIJ/WB8f3ZZufOJ0aP5rKLs+DL\n/psqu8yc0GNKoHrOe6zoBOnsuys6wUN3SgTioC9+wdMasVoRsHWBHr5NgBDxjCZF\nSgS2smVoe0reb7vSK+1bXRdIH27Bjsi/TrQjvPmSkZ/MUyL3JPpt08deQNl5ue8W\nSAyC1KMUfiBndIOIBTXXEB6pe4q0xrD/PK6FVZmOSUMgBH6jKWJzUft6hMWWVD4i\nognhWpl91uxOpGfasksvncN36gOpfGGjJ5S2QG4iafqdo/JA6ltiyc7JYYoLFLne\nIY0d5//ahq05QxAlAhkEDYCQhgqWJr6P60FAdDfv3ULXcuJRsy8m3qz0HZeNsddx\nIMZxsMU+ECsl/UwYdEs7K2MCAwEAAQ==\n-----END PUBLIC KEY-----\n"}

ALYSSAS_PUBLIC_KEY_PEM = ALYSSAS_KEY["publicKeyPem"].encode("utf-8")
ALYSSAS_PRIVATE_KEY_PEM = b"-----BEGIN PRIVATE KEY-----\n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\njWyYg2LxmH5ce6jd8OWJbaSTPrOBfwk=\n-----END PRIVATE KEY-----\n"

EXAMPLE_DOC = {
    '@context': {
        'description': 'http://schema.org/description',
        'geo': 'http://schema.org/geo',
        'image': {'@id': 'http://schema.org/image', '@type': '@id'},
        'latitude': {'@id': 'http://schema.org/latitude',
                     '@type': 'xsd:float'},
        'longitude': {'@id': 'http://schema.org/longitude',
                      '@type': 'xsd:float'},
        'name': 'http://schema.org/name',
        'xsd': 'http://www.w3.org/2001/XMLSchema#'},
    'description': 'The Empire State Building is a 102-story landmark in New York '
    'City.',
    'geo': {'latitude': '40.75', 'longitude': '73.98'},
    'image': 'http://www.civil.usherbrooke.ca/cours/gci215a/empire-state-building.jpg',
    'name': 'The Empire State Building'}

EXAMPLE_DOC_SIGNED = {
    '@context': {'description': 'http://schema.org/description',
                 'geo': 'http://schema.org/geo',
                 'image': {'@id': 'http://schema.org/image', '@type': '@id'},
                 'latitude': {'@id': 'http://schema.org/latitude',
                              '@type': 'xsd:float'},
                 'longitude': {'@id': 'http://schema.org/longitude',
                               '@type': 'xsd:float'},
                 'name': 'http://schema.org/name',
                 'xsd': 'http://www.w3.org/2001/XMLSchema#'},
    'description': 'The Empire State Building is a 102-story landmark in New York '
    'City.',
    'geo': {'latitude': '40.75', 'longitude': '73.98'},
    'https://w3id.org/security#signature': {
        '@type': 'https://w3id.org/security#GraphSignature2012',
        'http://purl.org/dc/terms/created': {
            '@type': 'xsd:dateTime',
            '@value': '2018-01-08T18:29:51Z'},
        'http://purl.org/dc/terms/creator': {'@id': 'https://dustycloud.org/tmp/alyssa.jsonld'},
        'https://w3id.org/security#signatureValue': 'R/8ZT/Abdn44Pk9IDiSmw8a7TDepEugwSmhgJvL/5pnUg57RJGiUn1dwjCHgiv2q28WH9zhpFb8lBKW2V82FIGll/iTrW4JgMNpnfyjUvv04R3RoUl5gYPUY870R0gxmwxi+YPpVpuIZLrZ2B5xWxMe6RgrzFdVOWwy+6x20QVUK2hz8VmIef0P/vVBDcBJEUEtVn36LRiXWy3gInRASMxwPmTxsTuFcDnjW9sBQ1oM+Lib758j+3R7e9lUC11B53oZskYXYevYqEBM+ujsLtSFTTuqG/9Egvh1fV+pZY9H7/kdi+6aXFGQfFN8JRhGZ5i1MMKfq8ZE5vx2yyxPzCgNM3Z2NMhSMgiq7yzi3BIUt+dYJI9i095klSFt1cvYe1jnI8GUAURNHLbvZFbbhqbKEPApSrOg0lA6kwm4Bwy2SCpjIILIbGnCnqP6Rw3/QVLUPFBOJr87rEfYGwNxveVxQcuvpkxlEjSLYukWh8NBgEFiVzw/CQbv4bdwfA3eroiHPFwUHyBAEhuaX7QqzNRkermHJ5cid4HeL0y4IzH83f2ixfS3nli98t4FSyXhJ88iOe5X45Q+rMfSFi1Uo6GbK3cP1S5WDAYk4wnwgL0wRnt1JW6k2cFiyjVmfkh+PUj8B9MT0l7jKSOD73wUtWbl8j/Bo9KDsbu/XsDF72BY='},
    'image': 'http://www.civil.usherbrooke.ca/cours/gci215a/empire-state-building.jpg',
    'name': 'The Empire State Building'}

def _identity(obj):
    return lambda *args, **kwargs: obj
def test_check_known_signature():
    assert(pyld_sig.verify(
        EXAMPLE_DOC_SIGNED,
        {"publicKey": _identity(ALYSSAS_KEY)}))

def test_check_wrong_signature():
    wrong_doc = copy.deepcopy(EXAMPLE_DOC_SIGNED)
    # Mess up the signature
    wrong_doc["https://w3id.org/security#signature"][
        "https://w3id.org/security#signatureValue"] = (
            "nopenope" +
            wrong_doc["https://w3id.org/security#signature"][
                "https://w3id.org/security#signatureValue"][8:])
    assert(not(
        pyld_sig.verify(
            wrong_doc,
            {"publicKey": _identity(ALYSSAS_KEY)})))

def test_fresh_signature():
    fresh_sig = pyld_sig.sign(
        EXAMPLE_DOC,
        {"privateKeyPem": ALYSSAS_PRIVATE_KEY_PEM,
         "creator": "https://dustycloud.org/tmp/alyssa.jsonld"})
    assert(pyld_sig.verify(
        fresh_sig,
        {"publicKey": _identity(ALYSSAS_KEY)}))
