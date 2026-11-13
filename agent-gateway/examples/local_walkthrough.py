"""Run the REAL HTTP service on your machine with throwaway keys, and drive it like a real agent would.

    python examples/local_walkthrough.py            # run the walkthrough, then exit
    python examples/local_walkthrough.py --keep     # ...then leave the server running (open /docs in a browser)

What it does
  1. Generates throwaway keys: one for the agent (signs every request, RFC 9421), one for the "identity provider" that
     vouches for the human user, and one for the staff IdP that vouches for approvers/auditors.
  2. Starts the service (uvicorn) on 127.0.0.1 with those public keys loaded from a directory.
  3. Plays an agent: allowed actions, blocked actions, an action that needs a human approval, and attacks.

Nothing here touches the network beyond localhost, and everything is deleted when it exits. In production the keys come
from your real IdP and secret manager; see the README "Configuration" table.
"""
from __future__ import annotations

import json
import shutil
import socket
import sys
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
from agent_gateway.models import ActionRequest, Identity
from agent_gateway.signing import HTTPRequest, MessageSigner

AGENT = "agent:repo-helper:v2.1:abc123"
USER = "user:shyam@enterprise.com"  # the human the agent works for (must be entitled in config/policy.json)
APPROVER, AUDITOR = "user:manager@enterprise.com", "user:auditor@enterprise.com"
ACTOR_ISS, STAFF_ISS = "https://idp.local", "https://admin-idp.local"
MFA = "urn:enterprise:acr:mfa"
REPORT = "/app/reports/summary.csv"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_pub(path: Path, private_key) -> None:
    path.write_bytes(private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))


def identity() -> Identity:
    return Identity(actor_user_id=USER, agent_id=AGENT, task_id="task:doc-update-789", session_id="sess-4f8a2b")


def main(keep: bool) -> int:
    work = Path(tempfile.mkdtemp(prefix="gateway-walkthrough-"))
    agents, actors, staff = work / "agents", work / "actors", work / "staff"
    for d in (agents, actors, staff):
        d.mkdir()
    agent_key, actor_key, staff_key = (Ed25519PrivateKey.generate() for _ in range(3))
    # Key ids contain ':' which Windows forbids in file names, so the directory store reads URL-quoted names.
    write_pub(agents / (quote(AGENT, safe="") + ".pem"), agent_key)
    write_pub(actors / "k1.pem", actor_key)
    write_pub(staff / "k1.pem", staff_key)

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    stack = build_stack(evidence_sinks=[], fs={REPORT: "region,total\nEMEA,100\nAPAC,80\n"})
    app = create_app(
        stack, agent_keys=DirectoryKeyStore(agents),
        actor_auth=PrincipalAuth(JWTVerifier(DirectoryKeyStore(actors), ACTOR_ISS, "agent-gateway")),
        staff_auth=PrincipalAuth(JWTVerifier(DirectoryKeyStore(staff), STAFF_ISS, "agent-gateway-admin")),
        public_base_url=base, gateway_id="gateway")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    else:
        print("server did not start")
        return 1
    print(f"service running at {base}   (keys in {work})\n")

    signer = MessageSigner(AGENT, agent_key)
    http = httpx.Client(timeout=10)

    def token(key, iss, aud, sub, roles=(), mfa=False):
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + 600, "roles": list(roles)}
        if mfa:
            claims.update(acr=MFA, auth_time=now)  # fresh multi-factor sign-in: required to approve risky actions
        return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": "k1"})

    def staff_headers(sub, role):
        return {"Authorization": "Bearer " + token(staff_key, STAFF_ISS, "agent-gateway-admin", sub, [role], mfa=True)}

    step = [0]

    def execute(req_args: dict, approval_id=None, *, sign=True, tamper=False):
        """Send one action as the agent. `req_args` are ActionRequest fields (step is filled in)."""
        step[0] += 1
        req = ActionRequest(identity=identity(), step=step[0], **req_args)
        body = json.dumps({"request": json.loads(req.model_dump_json()), "approval_id": approval_id}).encode()
        headers = {"Content-Type": "application/json"}
        if sign:
            headers = dict(signer.sign(HTTPRequest("POST", f"{base}/v1/execute", headers, body), recipient="gateway").headers)
            headers["X-Actor-Token"] = token(actor_key, ACTOR_ISS, "agent-gateway", USER)
        if tamper:  # change the action AFTER it was signed
            body = body.replace(b"files:read", b"iam:modify_policy")
        return http.post(f"{base}/v1/execute", content=body, headers=headers)

    def show(title: str, r: httpx.Response) -> dict:
        d = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        outcome = d.get("decision") or f"HTTP {r.status_code}"
        why = d.get("reason") or d.get("detail") or ""
        print(f"{title:<46} -> {str(outcome):<17} {str(why)[:78]}")
        return d

    read = dict(tool="file_reader", capability="files:read", resource=f"file:{REPORT}",
                arguments={"path": REPORT, "operation": "read"})
    pr = dict(tool="github_pr", capability="github:pull_request:create", resource="repo:org-enterprise/core-docs",
              arguments={"title": "Update docs", "head": "feature/docs-402", "base": "main", "body": "Draft PR"},
              justification="DOC-402")
    evil_mail = dict(tool="email_send", capability="email:send_external", resource="mailbox:outbound-docs",
                     arguments={"to": "bob@evil.net", "subject": "numbers", "body": "here you go"})

    print("== what the gateway does with an agent's requests ==")
    show("health check", http.get(f"{base}/healthz"))
    show("1. request with no signature", execute(read, sign=False))
    show("2. read an allowed report", execute(read))
    show("3. read a secrets file (blocked pattern)", execute({**read, "resource": "file:/app/reports/prod.env",
                                                                 "arguments": {"path": "/app/reports/prod.env", "operation": "read"}}))
    show("4. action changed after signing (tampered)", execute(read, tamper=True))
    show("5. email to a stranger (exfiltration)", execute(evil_mail))

    print("\n== an action that needs a human ==")
    d = show("6. open a pull request", execute(pr))
    approval_id = d["approval_id"]
    show("7. the requester tries to approve it", http.post(f"{base}/v1/approvals/{approval_id}/approve",
                                                           headers=staff_headers(USER, "approver")))
    show("8. a different person approves it", http.post(f"{base}/v1/approvals/{approval_id}/approve",
                                                        headers=staff_headers(APPROVER, "approver")))
    show("9. agent retries WITH the approval", execute(pr, approval_id))
    show("10. agent replays the same approval", execute(pr, approval_id))

    print("\n== the audit trail ==")
    r = http.get(f"{base}/v1/evidence/verify", headers=staff_headers(AUDITOR, "auditor"))
    print(f"11. tamper-evident log: {r.json()}")

    if keep:
        print(f"\nServer left running at {base}  (interactive API docs: {base}/docs). Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    server.should_exit = True
    time.sleep(0.3)
    shutil.rmtree(work, ignore_errors=True)  # the throwaway keys are not kept
    return 0


if __name__ == "__main__":
    sys.exit(main("--keep" in sys.argv))
