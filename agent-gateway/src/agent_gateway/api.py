"""HTTP surface (FastAPI). Run:  uvicorn --factory agent_gateway.api:app_from_env

Authentication model
  * Agent calls (/v1/execute): RFC 9421-signed requests. The signing key id must equal the
    request's agent_id, so an agent can only ever act as itself. Replays are rejected via a
    shared nonce store. Transport should additionally be mTLS (terminate at your ingress).
  * Requesting human: `X-Actor-Token` JWT whose `sub` must equal identity.actor_user_id
    (this is what makes the dual-bound identity *verified* instead of merely asserted).
  * Approvers / admins: `Authorization: Bearer <JWT>` with a role claim. Step-up status is
    derived from the token's acr + auth_time, never from the request body.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Body, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, ValidationError

from .approvals import ApprovalError
from .audit_sinks import AuditUnavailable
from .auth import AuthError, JWTVerifier, PrincipalAuth, bearer_token
from .dataflow import TrustedInputRejected
from .factory import Stack, build_stack
from .incident import contain
from .models import ActionRequest
from .signing import HTTPRequest, MessageVerifier, NonceStore, SignatureError

log = logging.getLogger("agent_gateway.api")
MAX_BODY_BYTES = 256 * 1024

ROLE_APPROVER = "approver"
ROLE_SECURITY_ADMIN = "security-admin"
ROLE_AUDITOR = "auditor"
ROLE_FRONTEND = "frontend"  # the user-facing chat/UI service identity (trusted; not the agent)


class RationaleBody(BaseModel):
    rationale: str = ""


class ExecuteBody(BaseModel):
    request: ActionRequest
    approval_id: str | None = None


class TrustedInputBody(BaseModel):
    typed_text: str  # ONLY what the human typed by hand this turn
    message_id: str  # unique per human message
    attachments: list[str] = []  # pasted/uploaded/fetched content: screened as untrusted, never trusted
    actor_user_id: str | None = None  # the human this session belongs to
    attestation: dict[str, Any] | None = None  # user-device signature over this text (see userauth)


class ClearTaintBody(BaseModel):
    reason: str


class DeclassifyBody(BaseModel):
    to_label: str
    reason: str


class ContainBody(BaseModel):
    agent_id: str
    session_id: str
    disable_capabilities: list[str] = []


def create_app(
    stack: Stack,
    *,
    agent_keys: Any,  # dict or rotating key store exposing .get(key_id)
    actor_auth: PrincipalAuth,
    staff_auth: PrincipalAuth,
    public_base_url: str,
    gateway_id: str = "gateway",
    nonce_store: NonceStore | None = None,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    import time as _t

    clock = clock or _t.time
    nonces = nonce_store or NonceStore(clock, backend=stack.backend)
    agent_verifier = MessageVerifier(agent_keys, nonces, clock, recipient_id=gateway_id)
    base = public_base_url.rstrip("/")
    app = FastAPI(title="Agent Execution Gateway", version="0.2.0")

    def unauthorized(reason: str, exc: Exception | None = None) -> HTTPException:
        log.warning("auth failure: %s (%s)", reason, exc)  # detail to logs, never to the caller
        return HTTPException(status_code=401, detail="authentication failed")

    def staff(authorization: str | None, role: str):
        try:
            return staff_auth.require_role(bearer_token(authorization), role)
        except AuthError as exc:
            raise unauthorized("staff", exc)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "policy_version": stack.gateway.pdp.policy_version}

    @app.post("/v1/execute")
    async def execute(request: Request, x_actor_token: str | None = Header(default=None)) -> dict[str, Any]:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="body too large")
        query = f"?{request.url.query}" if request.url.query else ""
        signed = HTTPRequest(request.method, f"{base}{request.url.path}{query}", dict(request.headers), raw)
        try:
            verified = agent_verifier.verify(signed)
        except SignatureError as exc:
            raise unauthorized("agent signature", exc)
        try:
            body = ExecuteBody.model_validate(json.loads(raw))
        except (ValueError, ValidationError):
            raise HTTPException(status_code=422, detail="invalid request body")

        ident = body.request.identity
        if verified.key_id != ident.agent_id:
            raise unauthorized("agent identity mismatch")
        try:
            actor = actor_auth.authenticate(x_actor_token)
        except AuthError as exc:
            raise unauthorized("actor token", exc)
        if actor.subject != ident.actor_user_id:
            raise unauthorized("actor mismatch")

        r = stack.gateway.execute(body.request, approval_id=body.approval_id)
        return {
            "decision": r.decision.value,
            "reason": r.reason,
            "risk_tier": r.risk_tier.value if r.risk_tier else None,
            "approval_id": r.approval_id,
            "approval_preview": r.approval_preview,
            "result": r.result,
        }

    @app.post("/v1/approvals/{approval_id}/approve")
    def approve(approval_id: str, body: RationaleBody = Body(default_factory=RationaleBody),
                authorization: str | None = Header(default=None)) -> dict[str, Any]:
        who = staff(authorization, ROLE_APPROVER)
        try:
            rec = stack.approvals.approve(approval_id, who.subject, body.rationale,
                                          step_up_verified=who.step_up_verified)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"approved": rec.approved, "approvers": rec.approvers, "required": rec.required_approvers}

    @app.post("/v1/approvals/{approval_id}/reject")
    def reject(approval_id: str, body: RationaleBody = Body(default_factory=RationaleBody),
               authorization: str | None = Header(default=None)) -> dict[str, Any]:
        who = staff(authorization, ROLE_APPROVER)
        try:
            stack.approvals.reject(approval_id, who.subject, body.rationale)
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return {"rejected": True}

    @app.get("/v1/evidence/verify")
    def verify_evidence(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        staff(authorization, ROLE_AUDITOR)
        ok, bad = stack.evidence.verify_chain()
        return {"intact": ok, "first_bad_index": bad, "entries": len(stack.evidence.events())}

    @app.post("/v1/sessions/{session_id}/trusted-input")
    def trusted_input(session_id: str, body: TrustedInputBody,
                      authorization: str | None = Header(default=None)) -> dict[str, Any]:
        """Front end reports what the human typed, so destinations they named become usable."""
        who = staff(authorization, ROLE_FRONTEND)
        try:
            found = stack.gateway.register_trusted_input(
                session_id, body.typed_text, message_id=body.message_id, registrar=who.subject,
                attachments=body.attachments, actor_user_id=body.actor_user_id, attestation=body.attestation)
        except AuditUnavailable:
            raise HTTPException(status_code=503, detail="audit log unavailable; refused")
        except TrustedInputRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"registered": sorted(found)}

    @app.post("/v1/sessions/{session_id}/canary")
    def canary(session_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
        staff(authorization, ROLE_FRONTEND)
        return {"canary": stack.gateway.issue_canary(session_id)}

    @app.post("/v1/sessions/{session_id}/clear-taint")
    def clear_taint(session_id: str, body: ClearTaintBody,
                    authorization: str | None = Header(default=None)) -> dict[str, Any]:
        who = staff(authorization, ROLE_SECURITY_ADMIN)
        if not who.step_up_verified:
            raise HTTPException(status_code=409, detail="step-up authentication required")
        try:
            stack.gateway.clear_taint(session_id, who.subject, body.reason)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"cleared": True}

    @app.post("/v1/sessions/{session_id}/declassify")
    def declassify(session_id: str, body: DeclassifyBody,
                   authorization: str | None = Header(default=None)) -> dict[str, Any]:
        who = staff(authorization, ROLE_SECURITY_ADMIN)
        if not who.step_up_verified:
            raise HTTPException(status_code=409, detail="step-up authentication required")
        try:
            stack.gateway.declassify(session_id, who.subject, body.to_label, body.reason)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"declassified_to": body.to_label}

    @app.post("/v1/audit/watchdog/run")
    def watchdog_run(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        staff(authorization, ROLE_AUDITOR)
        problems = stack.watchdog.run_once() if stack.watchdog else []
        return {"intact": not problems, "problems": problems, "halted": stack.guard.global_halt()}

    @app.post("/v1/audit/global-halt/clear")
    def clear_global_halt(body: ClearTaintBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        """Only after a human has investigated the alarm. Re-runs the integrity check first; refuses if it still fails."""
        who = staff(authorization, ROLE_SECURITY_ADMIN)
        if not who.step_up_verified:
            raise HTTPException(status_code=409, detail="step-up authentication required")
        if not body.reason.strip():
            raise HTTPException(status_code=422, detail="reason required")
        if stack.watchdog:
            stack.guard.clear_halt_all()  # lift so the check itself can run; re-halts if still broken
            problems = stack.watchdog.run_once()
            if problems:
                raise HTTPException(status_code=409, detail={"still_failing": problems})
        else:
            stack.guard.clear_halt_all()
        return {"cleared": True}

    @app.post("/v1/incident/contain")
    def incident(body: ContainBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        staff(authorization, ROLE_SECURITY_ADMIN)
        rep = contain(stack.gateway, agent_id=body.agent_id, session_id=body.session_id,
                      memory=stack.memory, disable_capabilities=body.disable_capabilities)
        return {
            "revoked_tokens": rep.revoked_tokens,
            "quarantined_memory_entries": rep.quarantined_memory_entries,
            "disabled_capabilities": rep.disabled_capabilities,
            "timeline_events": len(rep.timeline),
        }

    return app


def app_from_env() -> FastAPI:  # pragma: no cover - deployment wiring
    """Trust material is rotatable, no restart needed:
      GATEWAY_ACTOR_JWKS_URL / GATEWAY_STAFF_JWKS_URL   fetched, cached and rotated automatically
      (or) GATEWAY_ACTOR_JWKS_DIR / GATEWAY_STAFF_JWKS_DIR   PEM files, reloaded when they change
      GATEWAY_AGENT_KEYS_DIR   <agent_id>.pem Ed25519 public keys (URL-quote ':' as %3A on Windows); delete a file to revoke an agent
    """
    import httpx

    from .keys import DirectoryKeyStore, JWKSKeyStore

    def store(url_var: str, dir_var: str):
        if os.environ.get(url_var):
            return JWKSKeyStore(os.environ[url_var], httpx.Client())
        return DirectoryKeyStore(os.environ[dir_var])

    actor = PrincipalAuth(JWTVerifier(store("GATEWAY_ACTOR_JWKS_URL", "GATEWAY_ACTOR_JWKS_DIR"),
                                      os.environ["GATEWAY_ACTOR_ISSUER"], "agent-gateway"))
    staff_auth = PrincipalAuth(JWTVerifier(store("GATEWAY_STAFF_JWKS_URL", "GATEWAY_STAFF_JWKS_DIR"),
                                           os.environ["GATEWAY_STAFF_ISSUER"], "agent-gateway-admin"))
    stack = build_stack()
    if stack.watchdog is not None:
        stack.watchdog.start(float(os.environ.get("GATEWAY_WATCHDOG_INTERVAL", "30")))
    return create_app(stack, agent_keys=DirectoryKeyStore(os.environ["GATEWAY_AGENT_KEYS_DIR"]),
                      actor_auth=actor, staff_auth=staff_auth,
                      public_base_url=os.environ["GATEWAY_PUBLIC_URL"])
