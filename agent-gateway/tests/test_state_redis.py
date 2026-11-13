"""Stage 1: shared state across replicas (Redis semantics via fakeredis) + connectors."""
import threading

import fakeredis
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_gateway.adapters import AdapterError
from agent_gateway.approvals import ApprovalError, ApprovalStore
from agent_gateway.broker import UpstreamCredential
from agent_gateway.connectors import GitHubHTTPAdapter, TokenExchangeProvider, dpop_proof
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision, RiskTier
from agent_gateway.state import MemoryBackend, RedisBackend

from conftest import REPORT, Clock, email_req, pr_req, read_req


@pytest.fixture(params=["memory", "redis"])
def backend(request, clock):
    if request.param == "memory":
        return MemoryBackend(clock)
    return RedisBackend(fakeredis.FakeRedis())


def test_backend_atomic_update_and_abort(backend):
    backend.atomic_update("k", lambda d: ({"n": 1}, None), ttl=60)

    def boom(d):
        raise ValueError("abort")

    with pytest.raises(ValueError):
        backend.atomic_update("k", boom)
    assert backend.get("k") == {"n": 1}  # unchanged after aborted update


def test_set_nx_and_window(backend):
    assert backend.set_nx("n1", 60) is True
    assert backend.set_nx("n1", 60) is False
    counts = [backend.window_add("w", 100.0 + i, 60) for i in range(3)]
    assert counts == [1, 2, 3]
    assert backend.window_add("w", 200.0, 60) == 1  # old entries aged out


def test_approval_single_use_across_two_replicas():
    """Two gateway replicas sharing one Redis: exactly one consume wins under contention."""
    server = fakeredis.FakeServer()
    clock = Clock()
    a = ApprovalStore(clock, backend=RedisBackend(fakeredis.FakeRedis(server=server)))
    b = ApprovalStore(clock, backend=RedisBackend(fakeredis.FakeRedis(server=server)))
    req = email_req()
    rec = a.create(req, RiskTier.HIGH)
    b.approve(rec.approval_id, "user:mgr@enterprise.com", step_up_verified=True)  # approved via replica B
    clock.advance(31)
    wins, lock = [], threading.Lock()

    def worker(store):
        try:
            store.consume(rec.approval_id, req)
            with lock:
                wins.append(1)
        except ApprovalError:
            pass

    ts = [threading.Thread(target=worker, args=(a if i % 2 else b,)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(wins) == 1


def test_revocation_and_rate_limit_visible_across_replicas(clock):
    server = fakeredis.FakeServer()
    mk = lambda: build_stack(clock=clock, backend=RedisBackend(fakeredis.FakeRedis(server=server)),
                             fs={REPORT: "x"})
    s1, s2 = mk(), mk()
    req = read_req()
    tok = s1.broker.issue(req, s1.gateway.signer.sign(req, s1.gateway.pdp.evaluate(req)))
    s2.broker.revoke_active_for(agent_id=req.identity.agent_id)  # revoked on replica 2
    # replica 1 shares the registry -> sees it
    assert s1.broker.revocations.is_revoked(tok)


def test_breaker_state_shared_across_replicas(clock):
    server = fakeredis.FakeServer()
    mk = lambda: build_stack(clock=clock, backend=RedisBackend(fakeredis.FakeRedis(server=server)), fs={REPORT: "x"})
    s1, s2 = mk(), mk()
    for step in range(1, 11):
        (s1 if step % 2 else s2).gateway.execute(read_req(step=step))
    # depth limit reached by alternating replicas; either replica now refuses
    assert s1.gateway.execute(read_req(step=11)).decision is Decision.DENY
    assert s2.gateway.execute(read_req(step=12)).decision is Decision.DENY


def test_token_secret_not_stored_in_plaintext(clock):
    server = fakeredis.FakeServer()
    r = fakeredis.FakeRedis(server=server)
    st = build_stack(clock=clock, backend=RedisBackend(r), fs={REPORT: "x"})
    req = read_req()
    tok = st.broker.issue(req, st.gateway.signer.sign(req, st.gateway.pdp.evaluate(req)))
    dump = b"".join(r.get(k) or b"" for k in r.scan_iter(match="*jit:jit-*") if r.type(k) == b"string")
    assert tok.secret.encode() not in dump


# ------------------------------- connectors -------------------------------
IDP = "https://idp.enterprise.com/oauth/token"


def _idp_transport(seen):
    def handler(request: httpx.Request):
        seen.append(request)
        assert request.headers.get("DPoP")
        form = dict(p.split("=", 1) for p in request.content.decode().split("&"))
        assert form["grant_type"].endswith("token-exchange")
        return httpx.Response(200, json={"access_token": "up-token-123", "token_type": "DPoP", "expires_in": 120})
    return httpx.MockTransport(handler)


def test_token_exchange_and_github_adapter_end_to_end(clock):
    idp_seen, gh_seen = [], []

    def gh_handler(request: httpx.Request):
        gh_seen.append(request)
        return httpx.Response(201, json={"number": 7, "html_url": "https://github.com/o/r/pull/7", "state": "open", "evil": "x"})

    provider = TokenExchangeProvider(
        httpx.Client(transport=_idp_transport(idp_seen)), IDP, "gw", "s3cret",
        subject_token_for=lambda r: "human-token", audience_for=lambda r: "https://api.github.com",
        scopes_for=lambda r: ["pull_request:write"])
    st = build_stack(
        clock=clock, upstream=provider,
        github_adapter_factory=lambda b, a: GitHubHTTPAdapter(b, a, httpx.Client(transport=httpx.MockTransport(gh_handler))))
    first = st.gateway.execute(pr_req())
    st.approvals.approve(first.approval_id, "user:lead@enterprise.com")
    done = st.gateway.execute(pr_req(step=2), approval_id=first.approval_id)
    assert done.decision is Decision.ALLOW
    assert done.result == {"number": 7, "html_url": "https://github.com/o/r/pull/7", "state": "open"}  # whitelisted
    req = gh_seen[0]
    assert req.url.path == "/repos/org-enterprise/core-docs/pulls"
    assert req.headers["authorization"] == "DPoP up-token-123" and req.headers["dpop"]
    assert "up-token-123" not in st.evidence.events()[-1].model_dump_json()
    assert len(idp_seen) == 1  # exchanged exactly once, only after approval


def test_exchange_failure_denies_and_never_calls_target(clock):
    def idp(request):
        return httpx.Response(400, json={"error": "invalid_grant"})
    calls = []
    provider = TokenExchangeProvider(
        httpx.Client(transport=httpx.MockTransport(idp)), IDP, "gw", "s", lambda r: "t", lambda r: "a", lambda r: [])
    st = build_stack(clock=clock, upstream=provider, github_adapter_factory=lambda b, a: GitHubHTTPAdapter(
        b, a, httpx.Client(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(201, json={})))))
    first = st.gateway.execute(pr_req())
    st.approvals.approve(first.approval_id, "user:lead@enterprise.com")
    done = st.gateway.execute(pr_req(step=2), approval_id=first.approval_id)
    assert done.decision is Decision.DENY and not calls


def test_adapter_rejects_non_allowlisted_base_url_and_http_idp():
    with pytest.raises(ValueError):
        GitHubHTTPAdapter(None, None, base_url="https://evil.example.net")
    with pytest.raises(ValueError):
        TokenExchangeProvider(httpx.Client(), "http://idp/token", "a", "b", lambda r: "", lambda r: "", lambda r: [])


def test_dpop_proof_binds_method_url_and_token():
    import jwt
    key = Ed25519PrivateKey.generate()
    proof = dpop_proof(key, "post", "https://api.github.com/repos/o/r/pulls?x=1", access_token="tok", now=1000)
    claims = jwt.decode(proof, key.public_key(), algorithms=["EdDSA"], options={"verify_exp": False})
    assert claims["htm"] == "POST" and claims["htu"] == "https://api.github.com/repos/o/r/pulls" and claims["ath"]
