"""Credential Broker: short-lived, narrowly-scoped JIT tokens + revocation registry.

Tokens never enter the LLM context; they flow broker -> adapter directly. The broker only
mints tokens against a PDP-signed grant. The token registry and revocation lists live in the
shared StateBackend so any gateway replica can validate or revoke. Only a SHA-256 of the
token secret is stored.

Optionally the broker exchanges for a real upstream credential (RFC 8693 token exchange,
see connectors.py). The upstream credential is held only in the in-process JITToken handed
to the adapter; it is never persisted or logged.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .models import ActionRequest, Decision, DecisionResult
from .state import MemoryBackend, StateBackend

MAX_TOKEN_TTL = 300
REVOCATION_RETENTION = 24 * 3600


class BrokerError(Exception):
    pass


@dataclass(frozen=True)
class PolicyGrant:
    """PDP-signed authorization the broker verifies before minting."""

    request_fingerprint: str
    decision: str
    expires_at: float
    signature: str


def _fingerprint(request: ActionRequest) -> str:
    i = request.identity
    raw = "|".join([i.actor_user_id, i.agent_id, i.task_id, i.session_id,
                    request.capability, request.resource, request.args_hash()])
    return hashlib.sha256(raw.encode()).hexdigest()


class GrantSigner:
    """Shared by PDP side (sign) and broker (verify). Key lives outside the agent runtime."""

    def __init__(self, key: bytes, clock: Callable[[], float] = time.time):
        self._key = key
        self._clock = clock

    def sign(self, request: ActionRequest, result: DecisionResult, ttl: int = 60) -> PolicyGrant:
        fp = _fingerprint(request)
        exp = self._clock() + ttl
        sig = hmac.new(self._key, f"{fp}|{result.decision.value}|{exp}".encode(), hashlib.sha256).hexdigest()
        return PolicyGrant(fp, result.decision.value, exp, sig)

    def verify(self, request: ActionRequest, grant: PolicyGrant) -> bool:
        expected = hmac.new(
            self._key,
            f"{grant.request_fingerprint}|{grant.decision}|{grant.expires_at}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return (
            hmac.compare_digest(expected, grant.signature)
            and grant.request_fingerprint == _fingerprint(request)
            and grant.decision in (Decision.ALLOW.value,)
            and self._clock() < grant.expires_at
        )


@dataclass(frozen=True)
class UpstreamCredential:
    """Credential for the target system (e.g. an OAuth access token). Never logged."""

    access_token: str = field(repr=False)
    expires_in: int
    token_type: str = "Bearer"
    dpop_key: Any = field(default=None, repr=False)


class UpstreamProvider(Protocol):
    def mint(self, request: ActionRequest, ttl: int) -> UpstreamCredential: ...


@dataclass(frozen=True)
class JITToken:
    token_id: str
    secret: str = field(repr=False)
    agent_id: str
    session_id: str
    actor_user_id: str
    capability: str
    resource: str
    scope: tuple[str, ...]
    expires_at: float
    upstream: UpstreamCredential | None = field(default=None, repr=False, compare=False)

    def __repr__(self) -> str:  # never leak the secret into logs/prompts
        return f"JITToken(id={self.token_id}, cap={self.capability}, res={self.resource})"


class RevocationRegistry:
    """Real-time revocation without redeploys or secret rotation (shared across replicas)."""

    def __init__(self, backend: StateBackend | None = None) -> None:
        self._b: StateBackend = backend or MemoryBackend()

    def revoke_token(self, token_id: str) -> None:
        self._b.set_add("revoked:tokens", token_id, ttl=REVOCATION_RETENTION)

    def revoke_agent(self, agent_id: str) -> None:
        self._b.set_add("revoked:agents", agent_id)

    def revoke_session(self, session_id: str) -> None:
        self._b.set_add("revoked:sessions", session_id)

    def is_identity_revoked(self, agent_id: str, session_id: str) -> bool:
        return self._b.set_contains("revoked:agents", agent_id) or \
            self._b.set_contains("revoked:sessions", session_id)

    def is_revoked(self, token: JITToken) -> bool:
        return self._b.set_contains("revoked:tokens", token.token_id) or \
            self.is_identity_revoked(token.agent_id, token.session_id)


def _secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class CredentialBroker:
    def __init__(
        self,
        signer: GrantSigner,
        revocations: RevocationRegistry | None = None,
        clock: Callable[[], float] = time.time,
        backend: StateBackend | None = None,
        upstream: UpstreamProvider | None = None,
    ):
        self._signer = signer
        self._b: StateBackend = backend or MemoryBackend(clock)
        self.revocations = revocations or RevocationRegistry(self._b)
        self._clock = clock
        self._upstream = upstream

    def issue(
        self,
        request: ActionRequest,
        grant: PolicyGrant,
        scope: tuple[str, ...] = (),
        ttl: int = MAX_TOKEN_TTL,
    ) -> JITToken:
        if ttl > MAX_TOKEN_TTL:
            raise BrokerError("token TTL may not exceed 300 seconds")
        if self.revocations.is_identity_revoked(request.identity.agent_id, request.identity.session_id):
            raise BrokerError("agent or session revoked")
        if not self._signer.verify(request, grant):
            raise BrokerError("missing or invalid PDP authorization grant")

        upstream = None
        if self._upstream is not None:
            try:
                upstream = self._upstream.mint(request, ttl)
            except Exception as exc:
                raise BrokerError(f"upstream credential exchange failed: {type(exc).__name__}") from exc
            ttl = min(ttl, int(upstream.expires_in))
            if ttl <= 0:
                raise BrokerError("upstream credential already expired")

        tok = JITToken(
            token_id="jit-" + secrets.token_hex(6),
            secret=secrets.token_urlsafe(32),
            agent_id=request.identity.agent_id,
            session_id=request.identity.session_id,
            actor_user_id=request.identity.actor_user_id,
            capability=request.capability,
            resource=request.resource,
            scope=scope or (request.capability,),
            expires_at=self._clock() + ttl,
            upstream=upstream,
        )
        record = {
            "secret_sha256": _secret_hash(tok.secret),
            "agent_id": tok.agent_id,
            "session_id": tok.session_id,
            "actor_user_id": tok.actor_user_id,
            "capability": tok.capability,
            "resource": tok.resource,
            "scope": list(tok.scope),
            "expires_at": tok.expires_at,
        }
        self._b.atomic_update(f"jit:{tok.token_id}", lambda d: (record, None), ttl=ttl + 60)
        self._b.set_add(f"jit:agent:{tok.agent_id}", tok.token_id, ttl=ttl + 60)
        self._b.set_add(f"jit:session:{tok.session_id}", tok.token_id, ttl=ttl + 60)
        return tok

    def validate(self, token: JITToken, request: ActionRequest) -> None:
        """Called by the adapter. Raises BrokerError unless token is live, in scope and unrevoked."""
        rec = self._b.get(f"jit:{token.token_id}")
        if rec is None or not hmac.compare_digest(rec["secret_sha256"], _secret_hash(token.secret)):
            raise BrokerError("unknown token")
        if self._clock() >= rec["expires_at"]:
            raise BrokerError("token expired")
        if self.revocations.is_revoked(token):
            raise BrokerError("token revoked")
        if rec["capability"] != request.capability or rec["resource"] != request.resource:
            raise BrokerError("token not valid for this capability/resource")
        if rec["agent_id"] != request.identity.agent_id:
            raise BrokerError("token bound to a different agent")

    def revoke_active_for(self, agent_id: str | None = None, session_id: str | None = None) -> int:
        ids: set[str] = set()
        if agent_id:
            ids |= self._b.set_members(f"jit:agent:{agent_id}")
        if session_id:
            ids |= self._b.set_members(f"jit:session:{session_id}")
        for tid in ids:
            self.revocations.revoke_token(tid)
        if agent_id:
            self.revocations.revoke_agent(agent_id)
        if session_id:
            self.revocations.revoke_session(session_id)
        return len(ids)
