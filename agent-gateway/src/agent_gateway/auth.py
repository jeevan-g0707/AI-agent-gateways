"""Authentication for humans (approvers, security admins, requesting users).

OIDC-style JWT verification with a pinned key set (JWKS you fetch and cache out-of-band),
strict claim requirements, role checks, and step-up evaluation from `acr` + `auth_time`
so step-up status is *derived from the verified token*, never asserted by the caller.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import jwt

ALLOWED_ALGS = ("EdDSA", "ES256", "RS256")
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]


class AuthError(Exception):
    pass


class JWTVerifier:
    def __init__(
        self,
        keys: dict[str, Any],  # kid -> public key object
        issuer: str,
        audience: str,
        algorithms: tuple[str, ...] = ALLOWED_ALGS,
        leeway: int = 30,
        max_lifetime: int = 3600,
        clock: Callable[[], float] = time.time,
    ):
        self._keys = keys
        self._iss = issuer
        self._aud = audience
        self._algs = list(algorithms)
        self._leeway = leeway
        self._max_lifetime = max_lifetime
        self._clock = clock

    def verify(self, token: str) -> dict:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed token") from exc
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in self._algs:  # blocks alg=none and HS/RS confusion
            raise AuthError("algorithm not allowed")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise AuthError("unknown signing key")
        try:
            claims = jwt.decode(
                token, key, algorithms=[alg], audience=self._aud, issuer=self._iss,
                leeway=self._leeway, options={"require": REQUIRED_CLAIMS, "verify_exp": False, "verify_iat": False},
            )
        except jwt.PyJWTError as exc:
            raise AuthError("token rejected") from exc
        # time checks against our injectable clock
        now = self._clock()
        if now >= claims["exp"] + self._leeway:
            raise AuthError("token expired")
        if claims["iat"] - now > self._leeway:
            raise AuthError("token issued in the future")
        if claims["exp"] - claims["iat"] > self._max_lifetime:
            raise AuthError("token lifetime too long")
        return claims


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    step_up_verified: bool


class PrincipalAuth:
    """Turns a verified JWT into a Principal with roles and step-up status."""

    def __init__(
        self,
        verifier: JWTVerifier,
        step_up_acr: str = "urn:enterprise:acr:mfa",
        max_auth_age: int = 300,
        clock: Callable[[], float] = time.time,
    ):
        self._v = verifier
        self._acr = step_up_acr
        self._max_age = max_auth_age
        self._clock = clock

    def authenticate(self, token: str | None) -> Principal:
        if not token:
            raise AuthError("credentials required")
        claims = self._v.verify(token)
        roles = claims.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
            raise AuthError("malformed roles claim")
        auth_time = claims.get("auth_time")
        step_up = (
            claims.get("acr") == self._acr
            and isinstance(auth_time, (int, float))
            and 0 <= self._clock() - auth_time <= self._max_age  # fresh MFA, not a stale session
        )
        return Principal(subject=claims["sub"], roles=frozenset(roles), step_up_verified=bool(step_up))

    def require_role(self, token: str | None, role: str) -> Principal:
        p = self.authenticate(token)
        if role not in p.roles:
            raise AuthError(f"missing role '{role}'")
        return p


def bearer_token(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    scheme, _, value = authorization_header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None
