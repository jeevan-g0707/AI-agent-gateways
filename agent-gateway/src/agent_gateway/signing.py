"""HTTP Message Signatures per RFC 9421 (Ed25519) + Content-Digest per RFC 9530,
with single-use nonce enforcement (RFC 9449-style replay protection) on a shared store.

Implements the parts of RFC 9421 needed for service-to-service use: Signature-Input /
Signature structured-field dictionaries, derived components (@method, @target-uri,
@authority, @scheme, @request-target, @path, @query), header components, and the
created / expires / nonce / keyid / alg / tag parameters. Verified against the RFC's own
Ed25519 test vector (Appendix B.2.6) in the test suite.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field, replace
from typing import Callable
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .state import MemoryBackend, StateBackend

ACCEPTANCE_WINDOW = 300  # seconds
CLOCK_SKEW = 30
DEFAULT_COVERED = ("@method", "@target-uri", "content-digest", "x-agent-recipient")
REQUIRED_COMPONENTS = ("@method", "@target-uri")


class SignatureError(Exception):
    pass


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------
@dataclass
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        vals = [v for k, v in self.headers.items() if k.lower() == name.lower()]
        if not vals:
            return None
        return ", ".join(" ".join(v.split()) for v in vals)  # RFC 9421 2.1: strip + combine

    def with_headers(self, **updates: str) -> "HTTPRequest":
        h = {k: v for k, v in self.headers.items() if k.lower() not in {u.lower() for u in updates}}
        h.update(updates)
        return replace(self, headers=h)


def content_digest(body: bytes, alg: str = "sha-256") -> str:
    """RFC 9530 Content-Digest value."""
    h = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}[alg]
    return f"{alg}=:{base64.b64encode(h(body).digest()).decode()}:"


def _check_content_digest(header_value: str, body: bytes) -> bool:
    ok = False
    for member in header_value.split(","):
        m = re.fullmatch(r"\s*(sha-256|sha-512)=:([A-Za-z0-9+/=]+):\s*", member)
        if m and hmac.compare_digest(content_digest(body, m.group(1)), f"{m.group(1)}=:{m.group(2)}:"):
            ok = True
        elif m:
            return False  # a digest we understand that does not match: reject outright
    return ok


# ---------------------------------------------------------------------------
# Structured field helpers (RFC 8941 subset sufficient for RFC 9421)
# ---------------------------------------------------------------------------
def _sf_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _serialize_params(params: dict) -> str:
    out = ""
    for k, v in params.items():
        if v is True:
            out += f";{k}"
        elif isinstance(v, int):
            out += f";{k}={v}"
        else:
            out += f";{k}={_sf_string(str(v))}"
    return out


def serialize_signature_params(components: list[str], params: dict) -> str:
    inner = " ".join(_sf_string(c) for c in components)
    return f"({inner}){_serialize_params(params)}"


def _split_top_level(s: str, sep: str) -> list[str]:
    parts, cur, depth, in_q, esc = [], "", 0, False, False
    for ch in s:
        if in_q:
            cur += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_q = False
            continue
        if ch == '"':
            in_q = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(cur)
            cur = ""
            continue
        cur += ch
    if in_q or depth != 0:
        raise SignatureError("malformed structured field")
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def _parse_sf_string(tok: str) -> str:
    if len(tok) < 2 or tok[0] != '"' or tok[-1] != '"':
        raise SignatureError("malformed string")
    return re.sub(r"\\(.)", r"\1", tok[1:-1])


def _parse_params(s: str) -> dict:
    params: dict = {}
    for part in _split_top_level(s, ";"):
        if "=" not in part:
            params[part] = True
            continue
        k, v = part.split("=", 1)
        if v.startswith('"'):
            params[k] = _parse_sf_string(v)
        elif re.fullmatch(r"-?\d+", v):
            params[k] = int(v)
        else:
            params[k] = v
    return params


@dataclass
class ParsedSigInput:
    label: str
    components: list[str]  # serialized component identifiers, e.g. '"@method"' stripped to @method
    params: dict
    raw_params: str  # exact serialization used in the signature base


def parse_signature_input(header: str) -> dict[str, ParsedSigInput]:
    out: dict[str, ParsedSigInput] = {}
    for member in _split_top_level(header, ","):
        label, _, rest = member.partition("=")
        if not rest.startswith("("):
            raise SignatureError("Signature-Input member is not an inner list")
        close = rest.index(")")
        inner, after = rest[1:close], rest[close + 1:]
        comps = [_parse_sf_string(t) for t in _split_top_level(inner, " ")] if inner.strip() else []
        params = _parse_params(after.lstrip(";")) if after.startswith(";") else {}
        out[label.strip()] = ParsedSigInput(label.strip(), comps, params, rest)
    return out


def parse_signature(header: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for member in _split_top_level(header, ","):
        label, _, val = member.partition("=")
        m = re.fullmatch(r":([A-Za-z0-9+/=]*):", val.strip())
        if not m:
            raise SignatureError("malformed Signature member")
        try:
            out[label.strip()] = base64.b64decode(m.group(1), validate=True)
        except binascii.Error as exc:
            raise SignatureError("malformed Signature base64") from exc
    return out


# ---------------------------------------------------------------------------
# Signature base (RFC 9421 section 2.5)
# ---------------------------------------------------------------------------
def _component_value(req: HTTPRequest, comp: str) -> str:
    u = urlsplit(req.url)
    if comp.startswith("@"):
        if comp == "@method":
            return req.method.upper()
        if comp == "@target-uri":
            return req.url
        if comp == "@authority":
            host = (u.hostname or "").lower()
            default = {"http": 80, "https": 443}.get(u.scheme.lower())
            return f"{host}:{u.port}" if u.port and u.port != default else host
        if comp == "@scheme":
            return u.scheme.lower()
        if comp == "@request-target":
            return (u.path or "/") + (f"?{u.query}" if u.query else "")
        if comp == "@path":
            return u.path or "/"
        if comp == "@query":
            return "?" + u.query
        raise SignatureError(f"unsupported derived component {comp}")
    if comp != comp.lower():
        raise SignatureError("header component names must be lowercase")
    v = req.header(comp)
    if v is None:
        raise SignatureError(f"covered header '{comp}' is missing")
    return v


def signature_base(req: HTTPRequest, components: list[str], raw_params: str) -> bytes:
    lines = [f'{_sf_string(c)}: {_component_value(req, c)}' for c in components]
    lines.append(f'"@signature-params": {raw_params}')
    return "\n".join(lines).encode()


# ---------------------------------------------------------------------------
# Nonce store (shared across receivers)
# ---------------------------------------------------------------------------
class NonceStore:
    """Atomic single-use claim with TTL. Back with Redis (SET NX EX) across replicas."""

    def __init__(self, clock: Callable[[], float] = time.time, backend: StateBackend | None = None):
        self._b: StateBackend = backend or MemoryBackend(clock)

    def claim(self, nonce: str, ttl: int = ACCEPTANCE_WINDOW + CLOCK_SKEW) -> bool:
        return self._b.set_nx(f"nonce:{nonce}", ttl)


# ---------------------------------------------------------------------------
# Signer / verifier
# ---------------------------------------------------------------------------
class MessageSigner:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey | None = None,
                 clock: Callable[[], float] = time.time, tag: str | None = "agent-gateway"):
        self.key_id = key_id
        self._key = private_key or Ed25519PrivateKey.generate()
        self._clock = clock
        self._tag = tag

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def sign(
        self,
        req: HTTPRequest,
        *,
        recipient: str | None = None,
        covered: tuple[str, ...] = DEFAULT_COVERED,
        label: str = "sig1",
        expires_in: int | None = ACCEPTANCE_WINDOW,
    ) -> HTTPRequest:
        out = req
        if req.body or "content-digest" in covered:
            out = out.with_headers(**{"Content-Digest": content_digest(req.body)})
        if recipient is not None:
            out = out.with_headers(**{"X-Agent-Recipient": recipient})
        comps = [c for c in covered if c != "content-digest" or out.header("content-digest")]
        comps = [c for c in comps if c != "x-agent-recipient" or out.header("x-agent-recipient")]
        now = int(self._clock())
        params: dict = {"created": now}
        if expires_in is not None:
            params["expires"] = now + expires_in
        params.update({"nonce": secrets.token_urlsafe(16), "keyid": self.key_id, "alg": "ed25519"})
        if self._tag:
            params["tag"] = self._tag
        raw = serialize_signature_params(comps, params)
        sig = self._key.sign(signature_base(out, comps, raw))
        return out.with_headers(**{
            "Signature-Input": f"{label}={raw}",
            "Signature": f"{label}=:{base64.b64encode(sig).decode()}:",
        })

    def sign_with_params(self, req: HTTPRequest, components: list[str], params: dict, label: str) -> HTTPRequest:
        """Low-level: exact components/params (used for RFC test vectors)."""
        raw = serialize_signature_params(components, params)
        sig = self._key.sign(signature_base(req, components, raw))
        return req.with_headers(**{
            "Signature-Input": f"{label}={raw}",
            "Signature": f"{label}=:{base64.b64encode(sig).decode()}:",
        })


@dataclass
class VerifiedSignature:
    key_id: str
    label: str
    covered: list[str]
    created: int
    nonce: str | None


class MessageVerifier:
    def __init__(
        self,
        trust_store: dict[str, Ed25519PublicKey],
        nonces: NonceStore | None = None,
        clock: Callable[[], float] = time.time,
        *,
        recipient_id: str | None = None,
        tag: str | None = "agent-gateway",
        require_nonce: bool = True,
        max_age: int = ACCEPTANCE_WINDOW,
        required_components: tuple[str, ...] = REQUIRED_COMPONENTS,
        require_body_coverage: bool = True,
    ):
        self._require_body = require_body_coverage
        self._required = required_components
        self._trust = trust_store  # asymmetric keys registered in the enterprise trust store
        self._nonces = nonces
        self._clock = clock
        self._recipient = recipient_id
        self._tag = tag
        self._require_nonce = require_nonce
        self._max_age = max_age

    def verify(self, req: HTTPRequest, label: str | None = None) -> VerifiedSignature:
        sig_in = req.header("signature-input")
        sig_hdr = req.header("signature")
        if not sig_in or not sig_hdr:
            raise SignatureError("missing signature headers")
        inputs = parse_signature_input(sig_in)
        sigs = parse_signature(sig_hdr)

        candidates = [label] if label else [l for l, p in inputs.items() if self._tag is None or p.params.get("tag") == self._tag]
        if not candidates or candidates[0] not in inputs or candidates[0] not in sigs:
            raise SignatureError("no acceptable signature present")
        parsed, sig = inputs[candidates[0]], sigs[candidates[0]]
        params = parsed.params

        # algorithm / key
        if params.get("alg", "ed25519") != "ed25519":
            raise SignatureError("unsupported algorithm")
        key_id = params.get("keyid")
        pub = self._trust.get(key_id) if isinstance(key_id, str) else None
        if pub is None:
            raise SignatureError("unknown sender")

        # freshness
        now = self._clock()
        created = params.get("created")
        if not isinstance(created, int):
            raise SignatureError("signature must carry 'created'")
        if created - now > CLOCK_SKEW or now - created > self._max_age:
            raise SignatureError("message outside acceptance window")
        exp = params.get("expires")
        if exp is not None and (not isinstance(exp, int) or now >= exp):
            raise SignatureError("signature expired")
        nonce = params.get("nonce")
        if self._require_nonce and not isinstance(nonce, str):
            raise SignatureError("signature must carry 'nonce'")

        # coverage: the sender cannot choose to leave critical parts unsigned
        covered = parsed.components
        for need in self._required:
            if need not in covered:
                raise SignatureError(f"required component '{need}' not covered")
        if self._require_body and req.body and "content-digest" not in covered:
            raise SignatureError("body present but content-digest not covered")
        if self._recipient is not None:
            if "x-agent-recipient" not in covered:
                raise SignatureError("recipient not covered by signature")
            if req.header("x-agent-recipient") != self._recipient:
                raise SignatureError("message not addressed to this agent")

        # the signed Content-Digest header must actually match the body we received
        if "content-digest" in covered:
            cd = req.header("content-digest")
            if cd is None or not _check_content_digest(cd, req.body):
                raise SignatureError("content digest does not match body")

        try:
            pub.verify(sig, signature_base(req, covered, parsed.raw_params))
        except InvalidSignature as exc:
            raise SignatureError("invalid signature") from exc

        # Replay check LAST so forged messages cannot burn legitimate nonces.
        if self._require_nonce:
            if self._nonces is None:
                raise SignatureError("nonce store not configured")
            if not self._nonces.claim(f"{key_id}:{nonce}"):
                raise SignatureError("nonce replay detected")
        return VerifiedSignature(key_id, parsed.label, covered, created, nonce if isinstance(nonce, str) else None)


# ---------------------------------------------------------------------------
# Third-party execution evidence
# ---------------------------------------------------------------------------
def verify_execution_evidence(
    pub: Ed25519PublicKey,
    payload: bytes,
    signature_b64: str,
    *,
    expected_args_sha256: str,
    now: float,
    max_age: float = ACCEPTANCE_WINDOW,
) -> dict:
    """Verify a vendor-signed execution report. Everything checked is *inside* the signed payload:
    {"args_sha256": ..., "status": "success", "ts": <epoch>}. Raises SignatureError on any failure."""
    try:
        pub.verify(base64.b64decode(signature_b64, validate=True), payload)
    except (InvalidSignature, binascii.Error, ValueError) as exc:
        raise SignatureError("evidence signature invalid") from exc
    try:
        data = json.loads(payload)
        ts = float(data["ts"])
    except (ValueError, KeyError, TypeError) as exc:
        raise SignatureError("evidence payload malformed") from exc
    if abs(now - ts) > max_age:
        raise SignatureError("evidence timestamp outside window")
    if not hmac.compare_digest(str(data.get("args_sha256", "")), expected_args_sha256):
        raise SignatureError("evidence parameter hash mismatch")
    if data.get("status") != "success":
        raise SignatureError("evidence does not report success")
    return data
