"""JWKS fetching/caching/rotation and reloadable directory trust store."""
import json
import sys

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_gateway.auth import AuthError, JWTVerifier, PrincipalAuth
from agent_gateway.keys import DirectoryKeyStore, JWKSKeyStore
from agent_gateway.signing import HTTPRequest, MessageSigner, MessageVerifier, NonceStore, SignatureError

URL = "https://idp.enterprise.com/.well-known/jwks.json"


def jwk_of(key, kid):
    return json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key())) | {"kid": kid, "use": "sig"}


class FakeIdP:
    def __init__(self):
        self.keys = {}
        self.fail = None
        self.hits = 0
        self.extra = []

    def add(self, kid):
        k = Ed25519PrivateKey.generate()
        self.keys[kid] = k
        return k

    def handler(self, request):
        self.hits += 1
        if self.fail:
            return httpx.Response(self.fail) if isinstance(self.fail, int) else (_ for _ in ()).throw(self.fail)
        return httpx.Response(200, json={"keys": [jwk_of(k, kid) for kid, k in self.keys.items()] + self.extra})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def idp():
    i = FakeIdP()
    i.add("k1")
    return i


def sign(key, kid, clock, **extra):
    now = int(clock())
    claims = {"iss": "https://idp.enterprise.com", "aud": "agent-gateway", "sub": "user:a", "iat": now, "exp": now + 600, **extra}
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid})


def mk(idp, clock, **kw):
    return JWKSKeyStore(URL, idp.client(), clock=clock, **kw)


def test_fetch_cache_and_ttl_refresh(idp, clock):
    store = mk(idp, clock, ttl=300)
    assert store.get("k1") is not None and store.get("k1") is not None
    assert idp.hits == 1  # cached
    clock.advance(301)
    store.get("k1")
    assert idp.hits == 2


def test_rotation_new_kid_picked_up_and_old_key_dropped(idp, clock):
    store = mk(idp, clock, ttl=300, min_refresh_interval=30)
    verifier = PrincipalAuth(JWTVerifier(store, "https://idp.enterprise.com", "agent-gateway", clock=clock), clock=clock)
    old = idp.keys["k1"]
    assert verifier.authenticate(sign(old, "k1", clock)).subject == "user:a"
    new = idp.add("k2")  # IdP rotates: publishes k2 ...
    clock.advance(31)
    assert verifier.authenticate(sign(new, "k2", clock)).subject == "user:a"  # unknown kid triggers refresh
    del idp.keys["k1"]  # ... and later retires k1
    clock.advance(301)
    with pytest.raises(AuthError):
        verifier.authenticate(sign(old, "k1", clock))  # revoked key no longer trusted
    assert verifier.authenticate(sign(new, "k2", clock))


def test_unknown_kid_flood_cannot_hammer_idp(idp, clock):
    store = mk(idp, clock, min_refresh_interval=30)
    store.get("k1")
    base = idp.hits
    for i in range(200):
        assert store.get(f"random-{i}") is None
    assert idp.hits - base <= 1
    clock.advance(31)
    store.get("another")
    assert idp.hits - base <= 2


def test_idp_outage_serves_stale_then_fails_closed(idp, clock):
    store = mk(idp, clock, ttl=300, stale_ttl=3600, min_refresh_interval=10)
    assert store.get("k1")
    idp.fail = 503
    clock.advance(400)
    assert store.get("k1") is not None  # IdP down: stale keys keep logins working for a while
    assert store.refresh_failures >= 1
    clock.advance(4000)
    assert store.get("k1") is None  # ... but not forever


def test_garbage_or_empty_jwks_never_replaces_good_keys(idp, clock):
    store = mk(idp, clock, ttl=300, min_refresh_interval=1)
    assert store.get("k1")
    idp.keys.clear()  # IdP returns an empty set (misconfig / attack)
    clock.advance(301)
    assert store.get("k1") is not None and store.refresh_failures == 1


def test_unsafe_keys_are_skipped(idp, clock):
    weak = rsa.generate_private_key(65537, 1024)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key())) | {"kid": "ec1"}
    weak_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(weak.public_key())) | {"kid": "weak"}
    private_leak = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(idp.keys["k1"])) | {"kid": "priv"}  # contains 'd'
    enc = jwk_of(Ed25519PrivateKey.generate(), "enc1") | {"use": "enc"}
    idp.extra = [ec_jwk, weak_jwk, private_leak, enc, {"kid": "junk", "kty": "oct", "k": "AAAA"}, {"nokid": 1}]
    store = mk(idp, clock)
    store.get("k1")
    assert store.key_ids() == {"k1", "ec1"}


def test_https_required_and_redirects_not_followed(idp, clock):
    with pytest.raises(ValueError):
        JWKSKeyStore("http://idp/jwks", idp.client())
    redirect = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "https://evil/"})))
    assert JWKSKeyStore(URL, redirect, clock=clock).get("k1") is None


def test_oversized_response_rejected(idp, clock):
    assert mk(idp, clock, max_bytes=50).get("k1") is None


# ------------------------------------------------------------ agent key directory
def write_pub(path, key):
    path.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))


def test_directory_store_adds_rotates_and_revokes_without_restart(tmp_path, clock):
    store = DirectoryKeyStore(tmp_path, clock=clock, reload_interval=15)
    a = MessageSigner("agent:a", Ed25519PrivateKey.generate(), clock=clock)
    v = MessageVerifier(store, NonceStore(clock), clock, recipient_id="agent:b")
    mkmsg = lambda s=a: s.sign(HTTPRequest("POST", "https://b/x", {}, b"{}"), recipient="agent:b")
    with pytest.raises(SignatureError, match="unknown sender"):
        v.verify(mkmsg())
    write_pub(tmp_path / "agent%3Aa.pem", a._key)  # onboard (URL-quoted name: ":" is illegal in Windows file names)
    clock.advance(16)
    v.verify(mkmsg())
    a2 = MessageSigner("agent:a", Ed25519PrivateKey.generate(), clock=clock)  # rotate key
    write_pub(tmp_path / "agent%3Aa.pem", a2._key)
    clock.advance(16)
    with pytest.raises(SignatureError, match="invalid signature"):
        v.verify(mkmsg(a))
    v.verify(mkmsg(a2))
    (tmp_path / "agent%3Aa.pem").unlink()  # revoke
    clock.advance(16)
    with pytest.raises(SignatureError, match="unknown sender"):
        v.verify(mkmsg(a2))


def test_directory_store_ignores_corrupt_files(tmp_path, clock):
    (tmp_path / "bad.pem").write_text("not a key")
    write_pub(tmp_path / "good.pem", Ed25519PrivateKey.generate())
    store = DirectoryKeyStore(tmp_path, clock=clock)
    assert store.get("good") is not None and store.get("bad") is None


def test_directory_store_accepts_quoted_names_and_fails_closed_on_conflicting_files(tmp_path, clock):
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    write_pub(tmp_path / "agent%3Ax.pem", a)
    store = DirectoryKeyStore(tmp_path, clock=clock, reload_interval=0)
    assert store.get("agent:x") is not None and store.get("agent%3Ax") is None
    if sys.platform == "win32":
        return  # ':' cannot name a file on Windows (it silently creates an alternate data stream), so no conflict can exist
    write_pub(tmp_path / "agent:x.pem", b)  # a second file decoding to the same id
    store.reload()
    assert store.get("agent:x") is None  # ambiguous: disabled, not "last one wins"
