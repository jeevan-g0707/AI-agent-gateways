"""Real connectors: RFC 8693 token exchange (+ RFC 9449 DPoP) and a hardened HTTP adapter.

The broker mints a *new, narrowly scoped* upstream credential per approved call by exchanging
the requesting human's delegated token at the enterprise IdP. The agent never sees it.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
import uuid
from typing import Callable
from urllib.parse import urlparse

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .adapters import AdapterError, GitHubCreatePRSchema, ToolAdapter
from .broker import UpstreamCredential
from .models import ActionRequest

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
MAX_RESPONSE_BYTES = 1_000_000


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def dpop_proof(key: Ed25519PrivateKey, method: str, url: str, access_token: str | None = None,
               now: float | None = None) -> str:
    """RFC 9449 DPoP proof JWT bound to method + URL (+ access token hash when presenting one)."""
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    parsed = urlparse(url)
    htu = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"  # no query/fragment per RFC 9449
    claims = {"jti": uuid.uuid4().hex, "htm": method.upper(), "htu": htu, "iat": int(now or time.time())}
    if access_token:
        claims["ath"] = _b64u(hashlib.sha256(access_token.encode()).digest())
    headers = {"typ": "dpop+jwt", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)}}
    return jwt.encode(claims, key, algorithm="EdDSA", headers=headers)


class TokenExchangeProvider:
    """UpstreamProvider that performs RFC 8693 exchange at the IdP's token endpoint."""

    def __init__(
        self,
        http: httpx.Client,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        subject_token_for: Callable[[ActionRequest], str],
        audience_for: Callable[[ActionRequest], str],
        scopes_for: Callable[[ActionRequest], list[str]],
        use_dpop: bool = True,
    ):
        if urlparse(token_endpoint).scheme != "https":
            raise ValueError("token endpoint must be https")
        self._http = http
        self._endpoint = token_endpoint
        self._cid = client_id
        self._secret = client_secret
        self._subject = subject_token_for
        self._aud = audience_for
        self._scopes = scopes_for
        self._dpop = use_dpop

    def mint(self, request: ActionRequest, ttl: int) -> UpstreamCredential:
        data = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": self._subject(request),
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": self._aud(request),
            "scope": " ".join(self._scopes(request)),
            "resource": request.resource,
        }
        headers = {}
        key = Ed25519PrivateKey.generate() if self._dpop else None
        if key is not None:
            headers["DPoP"] = dpop_proof(key, "POST", self._endpoint)
        resp = self._http.post(
            self._endpoint, data=data, headers=headers, auth=(self._cid, self._secret),
            follow_redirects=False, timeout=5.0,
        )
        if resp.status_code != 200 or len(resp.content) > MAX_RESPONSE_BYTES:
            raise AdapterError(f"token exchange rejected (HTTP {resp.status_code})")
        body = resp.json()
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        ttype = body.get("token_type", "")
        if not isinstance(token, str) or not token or not isinstance(expires_in, int) or expires_in <= 0:
            raise AdapterError("malformed token exchange response")
        if ttype not in ("Bearer", "DPoP") or (self._dpop and ttype != "DPoP"):
            raise AdapterError("unexpected token type")
        return UpstreamCredential(token, min(expires_in, ttl), ttype, dpop_key=key if ttype == "DPoP" else None)


_REPO_RE = re.compile(r"^repo:([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})$")


class GitHubHTTPAdapter(ToolAdapter):
    """Creates a pull request via the GitHub REST API with the brokered credential."""

    name = "github_pr"
    capability = "github:pull_request:create"
    schema = GitHubCreatePRSchema
    allowed_hosts = frozenset({"api.github.com"})

    def __init__(self, broker, approvals, http: httpx.Client | None = None,
                 base_url: str = "https://api.github.com"):
        super().__init__(broker, approvals)
        host = urlparse(base_url).hostname
        if urlparse(base_url).scheme != "https" or host not in self.allowed_hosts:
            raise ValueError("base_url must be https on an allowlisted host")
        self._http = http or httpx.Client()
        self._base = base_url.rstrip("/")

    def execute(self, args: GitHubCreatePRSchema, request: ActionRequest, token=None) -> dict:
        m = _REPO_RE.match(request.resource)
        if not m:
            raise AdapterError("resource is not a valid repository")
        if token is None or token.upstream is None:
            raise AdapterError("no upstream credential available")
        url = f"{self._base}/repos/{m.group(1)}/{m.group(2)}/pulls"
        up = token.upstream
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if up.dpop_key is not None:
            headers["Authorization"] = f"DPoP {up.access_token}"
            headers["DPoP"] = dpop_proof(up.dpop_key, "POST", url, access_token=up.access_token)
        else:
            headers["Authorization"] = f"Bearer {up.access_token}"
        try:
            resp = self._http.post(url, json=args.model_dump(), headers=headers,
                                   follow_redirects=False, timeout=10.0)
        except httpx.HTTPError as exc:
            raise AdapterError(f"upstream request failed: {type(exc).__name__}") from exc
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise AdapterError("upstream response too large")
        if resp.status_code != 201:
            raise AdapterError(f"upstream returned HTTP {resp.status_code}")  # never echo the body
        data = resp.json()
        return {"number": data.get("number"), "html_url": str(data.get("html_url", ""))[:300],
                "state": data.get("state")}  # whitelist fields: upstream payload is untrusted
