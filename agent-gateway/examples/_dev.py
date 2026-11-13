"""Throwaway local gateway for the examples: real HTTP service, generated keys, an in-memory sample report."""
from __future__ import annotations

import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import quote

import httpx
import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_gateway.api import create_app
from agent_gateway.auth import JWTVerifier, PrincipalAuth
from agent_gateway.factory import build_stack
from agent_gateway.keys import DirectoryKeyStore

AGENT_ID = "agent:repo-helper:v2.1:abc123"
USER = "user:shyam@enterprise.com"  # entitled in config/policy.json
ACTOR_ISS, STAFF_ISS = "https://idp.local", "https://admin-idp.local"
MFA = "urn:enterprise:acr:mfa"
SAMPLE_FILES = {"/app/reports/summary.csv": "region,total\nEMEA,100\nAPAC,80\n"}


def _write_pub(path: Path, key) -> None:
    path.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))


class DevServer:
    def __init__(self, files: dict[str, str] | None = None, policy_path: str | Path | None = None):
        self.work = Path(tempfile.mkdtemp(prefix="gateway-dev-"))
        dirs = {n: self.work / n for n in ("agents", "actors", "staff")}
        for d in dirs.values():
            d.mkdir()
        self.agent_key, self._actor_key, self._staff_key = (Ed25519PrivateKey.generate() for _ in range(3))
        _write_pub(dirs["agents"] / (quote(AGENT_ID, safe="") + ".pem"), self.agent_key)  # ':' is illegal on Windows
        _write_pub(dirs["actors"] / "k1.pem", self._actor_key)
        _write_pub(dirs["staff"] / "k1.pem", self._staff_key)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.base_url = f"http://127.0.0.1:{port}"
        stack = build_stack(policy_path, evidence_sinks=[], fs=files or SAMPLE_FILES)
        app = create_app(
            stack, agent_keys=DirectoryKeyStore(dirs["agents"]),
            actor_auth=PrincipalAuth(JWTVerifier(DirectoryKeyStore(dirs["actors"]), ACTOR_ISS, "agent-gateway")),
            staff_auth=PrincipalAuth(JWTVerifier(DirectoryKeyStore(dirs["staff"]), STAFF_ISS, "agent-gateway-admin")),
            public_base_url=self.base_url, gateway_id="gateway")
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        threading.Thread(target=self._server.run, daemon=True).start()
        for _ in range(100):
            if self._server.started:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("dev server did not start")

    # -- what your identity provider would do ------------------------------------------------
    def _token(self, key, iss, aud, sub, roles=(), mfa=False) -> str:
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + 600, "roles": list(roles)}
        if mfa:
            claims.update(acr=MFA, auth_time=now)
        return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k1"})

    def user_token(self, sub: str = USER) -> str:
        """The IdP token proving which human the agent is acting for."""
        return self._token(self._actor_key, ACTOR_ISS, "agent-gateway", sub)

    def approve(self, approval_id: str, approver: str = "user:manager@enterprise.com") -> httpx.Response:
        """What a reviewer's tool does (fresh multi-factor sign-in required for risky actions)."""
        tok = self._token(self._staff_key, STAFF_ISS, "agent-gateway-admin", approver, ["approver"], mfa=True)
        return httpx.post(f"{self.base_url}/v1/approvals/{approval_id}/approve", headers={"Authorization": f"Bearer {tok}"})

    def stop(self) -> None:
        self._server.should_exit = True
        time.sleep(0.3)
        shutil.rmtree(self.work, ignore_errors=True)
