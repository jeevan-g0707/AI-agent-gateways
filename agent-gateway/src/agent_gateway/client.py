"""Client for the agent runtime: put the gateway between an AI agent and its tools.

The agent never calls a tool itself. Its runtime calls `GatewayTools.call(name, input)`, which signs the request and sends
it to the gateway; only on `allow` does anything happen (the gateway runs the tool, with a short-lived credential it mints
itself). The agent sees one of three plain-text outcomes:

    OK: {...}                         the action ran
    DENIED by security policy: ...    it did not run, and retrying the same thing will not help
    PENDING HUMAN APPROVAL (id ...)   nothing ran; a person must approve it

Approvals are made by people through the gateway's staff API, never by the agent. After a person has approved, the
RUNTIME (not the agent) calls `GatewayTools.resume(approval_id)` to run the exact action that was approved.

    client = GatewayClient(base_url, agent_id, agent_private_key, actor_token=lambda: current_user_jwt(),
                           user_id="user:shyam@enterprise.com", task_id="task:42", session_id="sess-abc")
    tools = GatewayTools(client, default_tool_specs(repo="org-enterprise/core-docs"))
    tools.definitions()                       # give these to your LLM as its tools
    text = tools.call("read_file", {"path": "/app/reports/summary.csv"})   # run when the LLM asks for a tool
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import ActionRequest, Identity
from .signing import HTTPRequest, MessageSigner


class GatewayError(Exception):
    """The gateway could not be reached, or refused to authenticate/understand the call (not a policy decision)."""


@dataclass(frozen=True)
class GatewayResult:
    status_code: int
    decision: str  # allow | deny | require_approval
    reason: str
    risk_tier: str | None = None
    approval_id: str | None = None
    approval_preview: dict | None = None
    result: Any = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def pending_approval(self) -> bool:
        return self.decision == "require_approval"


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        agent_id: str,
        signing_key: Ed25519PrivateKey,
        actor_token: Callable[[], str],
        *,
        user_id: str,
        task_id: str,
        session_id: str,
        gateway_id: str = "gateway",
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ):
        """`actor_token` returns a fresh JWT from your identity provider proving which human this agent acts for;
        its `sub` must equal `user_id`. `signing_key` is the agent's own key (its public half is on the gateway)."""
        self._base = base_url.rstrip("/")
        self._signer = MessageSigner(agent_id, signing_key, clock=clock)
        self._identity = Identity(actor_user_id=user_id, agent_id=agent_id, task_id=task_id, session_id=session_id)
        self._actor_token = actor_token
        self._gateway_id = gateway_id
        self._http = http or httpx.Client(timeout=120)  # must exceed the gateway's upstream timeouts (GitHub adapter: 60s), so a slow upstream shows up as an adapter error
        self._step = 0

    def execute(self, tool: str, capability: str, resource: str, arguments: dict[str, Any], *,
                justification: str = "", approval_id: str | None = None,
                idempotency_key: str | None = None) -> GatewayResult:
        self._step += 1  # every call is a new step; the gateway rejects a repeated (task, step) as a replay
        req = ActionRequest(identity=self._identity, tool=tool, capability=capability, resource=resource,
                            arguments=arguments, justification=justification, idempotency_key=idempotency_key,
                            step=self._step)
        body = json.dumps({"request": json.loads(req.model_dump_json()), "approval_id": approval_id}).encode()
        url = f"{self._base}/v1/execute"
        signed = self._signer.sign(HTTPRequest("POST", url, {"Content-Type": "application/json"}, body),
                                   recipient=self._gateway_id)
        headers = {**signed.headers, "X-Actor-Token": self._actor_token()}
        try:
            r = self._http.post(url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise GatewayError(f"gateway unreachable: {type(exc).__name__}") from exc
        if r.status_code != 200:
            detail = r.json().get("detail") if r.headers.get("content-type", "").startswith("application/json") else ""
            raise GatewayError(f"gateway returned HTTP {r.status_code}: {detail}")
        d = r.json()
        return GatewayResult(r.status_code, d["decision"], d.get("reason", ""), d.get("risk_tier"),
                             d.get("approval_id"), d.get("approval_preview"), d.get("result"))


# --------------------------------------------------------------------------- tools for an LLM
@dataclass(frozen=True)
class ToolSpec:
    """One tool the LLM may ask for, and how it maps onto a gateway capability."""

    name: str  # what the LLM calls it
    description: str
    input_schema: dict[str, Any]  # JSON Schema for the LLM
    tool: str  # gateway adapter name
    capability: str
    build: Callable[[dict[str, Any]], tuple[str, dict[str, Any]]]  # LLM input -> (exact resource, arguments)


def default_tool_specs(repo: str = "org-enterprise/core-docs", mailbox: str = "outbound-docs") -> list[ToolSpec]:
    return [
        ToolSpec(
            "read_file", "Read a report file under /app/reports.",
            {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            "file_reader", "files:read",
            lambda i: (f"file:{i['path']}", {"path": i["path"], "operation": "read"})),
        ToolSpec(
            "open_pull_request", "Open a pull request in the documentation repository. A person must approve it.",
            {"type": "object", "properties": {"title": {"type": "string"}, "head": {"type": "string"},
                                              "base": {"type": "string"}, "body": {"type": "string"}},
             "required": ["title", "head", "base"]},
            "github_pr", "github:pull_request:create",
            lambda i: (f"repo:{repo}", {"title": i["title"], "head": i["head"], "base": i["base"],
                                        "body": i.get("body", "")})),
        ToolSpec(
            "send_email", "Send an email to an external recipient. A person must approve it.",
            {"type": "object", "properties": {"to": {"type": "string"}, "subject": {"type": "string"},
                                              "body": {"type": "string"}}, "required": ["to", "subject", "body"]},
            "email_send", "email:send_external",
            lambda i: (f"mailbox:{mailbox}", {"to": i["to"], "subject": i["subject"], "body": i["body"]})),
    ]


@dataclass
class GatewayTools:
    client: GatewayClient
    specs: list[ToolSpec]
    pending: dict[str, tuple[str, dict]] = field(default_factory=dict)  # approval id -> the exact call awaiting a human

    def definitions(self) -> list[dict[str, Any]]:
        """Tool definitions in the shape Anthropic's Messages API expects (name, description, input_schema)."""
        return [{"name": s.name, "description": s.description, "input_schema": s.input_schema} for s in self.specs]

    def _spec(self, name: str) -> ToolSpec:
        for s in self.specs:
            if s.name == name:
                return s
        raise KeyError(name)

    def call(self, name: str, tool_input: dict[str, Any], *, justification: str = "") -> str:
        """Run a tool the LLM asked for. Always returns text for the LLM; never raises on a policy decision."""
        try:
            spec = self._spec(name)
        except KeyError:
            return f"ERROR: unknown tool '{name}'."
        try:
            resource, args = spec.build(tool_input)
        except (KeyError, TypeError) as exc:
            return f"ERROR: bad input for {name}: missing or invalid {exc}."
        try:
            res = self.client.execute(spec.tool, spec.capability, resource, args, justification=justification)
        except GatewayError as exc:
            return f"ERROR: the security gateway could not process this ({exc}). Nothing was executed."
        return self._render(res, name, tool_input)

    def resume(self, approval_id: str) -> str:
        """Called by the RUNTIME after a person approved. Re-submits the exact action that was approved (any change
        would be rejected by the gateway: approvals are bound to the action's exact content)."""
        if approval_id not in self.pending:
            return f"ERROR: no pending action for approval {approval_id}."
        name, tool_input = self.pending[approval_id]
        spec = self._spec(name)
        resource, args = spec.build(tool_input)
        try:
            res = self.client.execute(spec.tool, spec.capability, resource, args, approval_id=approval_id)
        except GatewayError as exc:
            return f"ERROR: the security gateway could not process this ({exc})."
        if res.allowed:  # keep it until it has actually run: a too-early resume must not lose the pending action
            self.pending.pop(approval_id, None)
        return self._render(res, name, tool_input)

    def _render(self, res: GatewayResult, name: str, tool_input: dict) -> str:
        if res.allowed:
            return "OK: " + json.dumps(res.result, default=str)
        if res.pending_approval:
            self.pending[res.approval_id] = (name, tool_input)
            return (f"PENDING HUMAN APPROVAL (id {res.approval_id}): {res.reason}. Nothing has been executed yet. "
                    "Tell the user what you want to do and that a reviewer must approve it, then stop and wait.")
        return (f"DENIED by security policy: {res.reason}. This was NOT executed. Do not retry the same action or try "
                "to work around it; tell the user it was blocked.")
