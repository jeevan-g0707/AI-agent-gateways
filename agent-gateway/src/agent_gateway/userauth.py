"""Cryptographic attestation that a HUMAN approved a message: closes the "front end is trusted" gap as far as software can.

Without this, `trusted-input` is a claim by the front end ("the user typed this"). With it, the front end must present a
signature made by a key that only the user's device holds, over (session, message id, user, hash of the typed text, time):

  * scheme "webauthn" - a FIDO2/WebAuthn assertion (passkey / security key). The authenticator requires user presence
                        (a touch) and usually user verification (biometric/PIN), and the key never leaves the device.
                        We verify the challenge, origin, RP-ID hash, flags, signature (ES256 or EdDSA) and the sign
                        counter (a counter that does not increase indicates a cloned authenticator).
  * scheme "ed25519"  - a raw Ed25519 signature for native/CLI clients that hold a device key.

What this DOES prove: a registered device of that user was used, with presence, for exactly this text hash, now, once.
A compromised front end or gateway cannot mint such a signature, replay an old one, move it to another session or user, or
swap the text afterwards.
What it does NOT prove: that the user SAW the text they signed. WebAuthn has no trusted display, so a malicious front end
could ask the user to touch their key for text the user never read. Mitigations are on the front-end side (show the
destinations being granted next to the prompt); the gateway additionally records the signed hash in the audit log.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .state import MemoryBackend, StateBackend

CONTEXT = b"agent-gateway/typed-input/v1"
FLAG_UP, FLAG_UV = 0x01, 0x04


class UserAttestationError(Exception):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception as exc:
        raise UserAttestationError("malformed base64") from exc


def canonical_message(session_id: str, message_id: str, actor: str, typed_text: str, signed_at: int) -> bytes:
    """The bytes a user's device signs. Binds text, session, message, person and time.
    JSON-encoded list: unambiguous for any field contents (a delimiter-joined form let ("a\\nb","c") collide with ("a","b\\nc"))."""
    sha = hashlib.sha256(typed_text.encode()).hexdigest()
    return json.dumps([CONTEXT.decode(), session_id, message_id, actor, sha, int(signed_at)],
                      separators=(",", ":"), ensure_ascii=True).encode()


class UserCredentialStore:
    """user id -> {credential id -> public key}. In-memory; see DirectoryUserCredentialStore for files."""

    def __init__(self):
        self._c: dict[tuple[str, str], Any] = {}

    def add(self, user: str, credential_id: str, public_key: Any) -> None:
        self._c[(user, credential_id)] = public_key

    def remove(self, user: str, credential_id: str) -> None:
        self._c.pop((user, credential_id), None)

    def get(self, user: str, credential_id: str) -> Any | None:
        return self._c.get((user, credential_id))


class DirectoryUserCredentialStore:
    """<root>/<url-quoted user>/<url-quoted credential id>.pem; re-read on every lookup, so enrolling or
    revoking a device (add/delete the file) takes effect immediately without a restart."""

    def __init__(self, root: str | Path):
        self._root = Path(root)

    def get(self, user: str, credential_id: str) -> Any | None:
        p = self._root / quote(user, safe="") / (quote(credential_id, safe="") + ".pem")
        try:
            if not p.resolve().is_relative_to(self._root.resolve()):
                return None
            return load_pem_public_key(p.read_bytes())
        except (OSError, ValueError):
            return None


class UserAttestationVerifier:
    def __init__(
        self,
        credentials: Any,
        *,
        rp_id: str,
        origins: list[str] | tuple[str, ...],
        backend: StateBackend | None = None,
        clock: Callable[[], float] = time.time,
        max_age: float = 120.0,
        require_user_verification: bool = True,
    ):
        self._creds, self._rp_id, self._origins = credentials, rp_id, tuple(origins)
        self._b: StateBackend = backend or MemoryBackend(clock)
        self._clock, self._max_age, self._require_uv = clock, max_age, require_user_verification

    # -- public ------------------------------------------------------------
    def verify(self, attestation: dict[str, Any], *, session_id: str, message_id: str, actor: str,
               typed_text: str) -> str:
        """Returns the credential id that signed. Raises UserAttestationError on ANY problem."""
        try:
            scheme = attestation["scheme"]
            cred_id = str(attestation["credential_id"])
            signed_at = int(attestation["signed_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise UserAttestationError("malformed attestation") from exc
        now = self._clock()
        if abs(now - signed_at) > self._max_age:
            raise UserAttestationError("attestation is stale or from the future")
        key = self._creds.get(actor, cred_id)
        if key is None:
            raise UserAttestationError("unknown credential for this user")
        message = canonical_message(session_id, message_id, actor, typed_text, signed_at)
        if scheme == "ed25519":
            if not isinstance(key, Ed25519PublicKey):
                raise UserAttestationError("credential type does not match scheme")
            self._check(lambda: key.verify(unb64u(attestation["signature"]), message))
        elif scheme == "webauthn":
            self._webauthn(key, attestation, hashlib.sha256(message).digest(), actor, cred_id)
        else:
            raise UserAttestationError("unsupported attestation scheme")
        return cred_id

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _check(fn) -> None:
        try:
            fn()
        except (InvalidSignature, KeyError, TypeError) as exc:
            raise UserAttestationError("signature invalid") from exc

    def _webauthn(self, key, att: dict, challenge: bytes, actor: str, cred_id: str) -> None:
        try:
            auth_data = unb64u(att["authenticator_data"])
            client_json = unb64u(att["client_data_json"])
            sig = unb64u(att["signature"])
            client = json.loads(client_json)
        except (KeyError, ValueError) as exc:
            raise UserAttestationError("malformed webauthn assertion") from exc
        if client.get("type") != "webauthn.get":
            raise UserAttestationError("not a webauthn.get assertion")
        if unb64u(client.get("challenge", "")) != challenge:
            raise UserAttestationError("challenge does not match this message")  # text/session/time swapped
        if client.get("origin") not in self._origins:
            raise UserAttestationError("assertion made for a different origin")
        if len(auth_data) < 37 or auth_data[:32] != hashlib.sha256(self._rp_id.encode()).digest():
            raise UserAttestationError("rp id hash mismatch")
        flags = auth_data[32]
        if not flags & FLAG_UP:
            raise UserAttestationError("user presence not asserted")
        if self._require_uv and not flags & FLAG_UV:
            raise UserAttestationError("user verification not asserted")
        signed = auth_data + hashlib.sha256(client_json).digest()
        if isinstance(key, ec.EllipticCurvePublicKey):
            self._check(lambda: key.verify(sig, signed, ec.ECDSA(hashes.SHA256())))
        elif isinstance(key, Ed25519PublicKey):
            self._check(lambda: key.verify(sig, signed))
        else:
            raise UserAttestationError("unsupported credential key type")
        self._advance_counter(actor, cred_id, int.from_bytes(auth_data[33:37], "big"))

    def _advance_counter(self, actor: str, cred_id: str, counter: int) -> None:
        """A non-increasing sign counter means the authenticator was cloned (WebAuthn L2 §6.1.1). Counters of 0
        mean the authenticator does not implement one (e.g. some passkeys); those are not checked."""
        if counter == 0:
            return

        def fn(d):
            last = (d or {}).get("n", 0)
            if counter <= last:
                raise UserAttestationError("authenticator sign counter did not increase (cloned authenticator?)")
            return {"n": counter}, None

        self._b.atomic_update(f"uacnt:{actor}:{cred_id}", fn, ttl=None)
