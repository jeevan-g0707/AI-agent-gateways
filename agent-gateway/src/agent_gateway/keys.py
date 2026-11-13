"""Trust-key sources that rotate.

`JWKSKeyStore`     fetches an IdP's JWKS over https, caches it, refreshes on schedule and on an
                   unknown `kid` (rate-limited so random kids can't be used to hammer the IdP),
                   survives IdP outages on stale keys for a bounded time, then fails closed.
                   A successful refresh REPLACES the key set, so a key the IdP removes is
                   distrusted at the next refresh (worst-case lag = `ttl`).
`DirectoryKeyStore` same idea for PEM files (agent public keys): add/rotate/revoke by
                   adding or deleting files; picked up within `reload_interval` without restart.

Both expose `.get(key_id) -> public key | None`, so they drop into JWTVerifier / MessageVerifier.
"""
from __future__ import annotations

import logging
import threading
from urllib.parse import unquote
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

log = logging.getLogger("agent_gateway.keys")
ALLOWED_KTY = ("OKP", "EC", "RSA")
MIN_RSA_BITS = 2048


class JWKSKeyStore:
    def __init__(
        self,
        url: str,
        http: Any,
        *,
        clock: Callable[[], float] = time.time,
        ttl: float = 300,
        stale_ttl: float = 24 * 3600,
        min_refresh_interval: float = 30,
        max_bytes: int = 256 * 1024,
        max_keys: int = 50,
        allow_insecure: bool = False,
    ):
        if urlparse(url).scheme != "https" and not allow_insecure:
            raise ValueError("JWKS URL must be https")
        self._url, self._http, self._clock = url, http, clock
        self._ttl, self._stale_ttl, self._min_refresh = ttl, stale_ttl, min_refresh_interval
        self._max_bytes, self._max_keys = max_bytes, max_keys
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_attempt = float("-inf")
        self._lock = threading.Lock()
        self.refresh_failures = 0

    # ------------------------------------------------------------------
    def get(self, kid: str) -> Any | None:
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at >= self._ttl
            if (stale or kid not in self._keys) and now - self._last_attempt >= self._min_refresh:
                self._refresh_locked(now)
            if self._fetched_at is None or now - self._fetched_at > self._stale_ttl:
                return None  # never loaded, or the IdP has been unreachable too long: fail closed
            return self._keys.get(kid)

    def refresh(self) -> bool:
        """Force a refresh (e.g. from an admin endpoint after an emergency key rotation)."""
        with self._lock:
            return self._refresh_locked(self._clock())

    def key_ids(self) -> set[str]:
        with self._lock:
            return set(self._keys)

    # ------------------------------------------------------------------
    def _refresh_locked(self, now: float) -> bool:
        self._last_attempt = now
        try:
            r = self._http.get(self._url, timeout=5.0, follow_redirects=False,
                               headers={"Accept": "application/json"})
            if r.status_code != 200 or len(r.content) > self._max_bytes:
                raise ValueError(f"unusable JWKS response (HTTP {r.status_code}, {len(r.content)} bytes)")
            keys = self._parse(r.json())
            if not keys:
                raise ValueError("JWKS contained no usable keys")  # never replace good keys with nothing
        except Exception as exc:
            self.refresh_failures += 1
            log.warning("JWKS refresh failed (%s); keeping cached keys", type(exc).__name__)
            return False
        self._keys, self._fetched_at = keys, now  # replace: removed keys are distrusted
        return True

    def _parse(self, doc: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        entries = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(entries, list):
            raise ValueError("malformed JWKS")
        for jwk in entries[: self._max_keys]:
            try:
                kid, kty = jwk.get("kid"), jwk.get("kty")
                if not isinstance(kid, str) or kty not in ALLOWED_KTY or jwk.get("use") == "enc":
                    continue
                if "d" in jwk:  # a private key in a public JWKS: never load it
                    continue
                key = jwt.PyJWK.from_dict(jwk).key
                if kty == "RSA" and key.key_size < MIN_RSA_BITS:
                    continue
                out[kid] = key
            except Exception:
                continue  # one bad key must not take down the set
        return out


class DirectoryKeyStore:
    """`<key_id>.pem` public keys in a directory. Add/replace/delete files to rotate or revoke.

    The key id is the URL-decoded file stem, so ids containing ':' or '/' can be stored on every OS:
    `agent%3Arepo-helper%3Av2.pem` is key id `agent:repo-helper:v2` (Windows forbids ':' in file names).
    A plain `agent:repo-helper:v2.pem` still works on Linux/macOS. If two files decode to the same id, that id is
    disabled entirely (fail closed) rather than guessing which one is meant."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time,
                 reload_interval: float = 15):
        self._dir = Path(path)
        self._clock, self._interval = clock, reload_interval
        self._keys: dict[str, Any] = {}
        self._sig: tuple | None = None
        self._checked = float("-inf")
        self._lock = threading.Lock()
        self.reload()

    def _signature(self) -> tuple:
        return tuple(sorted((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in self._dir.glob("*.pem")))

    def reload(self) -> None:
        with self._lock:
            self._reload_locked()

    def _reload_locked(self) -> None:
        keys: dict[str, Any] = {}
        conflicts: set[str] = set()
        for p in sorted(self._dir.glob("*.pem")):
            kid = unquote(p.stem)
            try:
                key = load_pem_public_key(p.read_bytes())
            except Exception:
                log.warning("ignoring unreadable key file %s", p.name)
                continue
            if kid in keys:
                conflicts.add(kid)
            keys[kid] = key
        for kid in conflicts:
            log.error("key id %r is defined by more than one file: disabled until resolved", kid)
            keys.pop(kid, None)
        self._keys, self._sig, self._checked = keys, self._signature(), self._clock()

    def get(self, key_id: str) -> Any | None:
        with self._lock:
            if self._clock() - self._checked >= self._interval:
                if self._signature() != self._sig:
                    self._reload_locked()
                else:
                    self._checked = self._clock()
            return self._keys.get(key_id)
