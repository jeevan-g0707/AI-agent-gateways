"""Tool/Connector adapters: hardened proxies in front of target systems.

Every invocation, in order:
  1. validates the JIT token (live, unrevoked, bound to this capability+resource)
  2. validates arguments against a strict Pydantic schema
  3. for approval-gated actions, atomically consumes the approval token
  4. executes against the target (mocked here)
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .approvals import ApprovalError, ApprovalStore
from .broker import BrokerError, CredentialBroker, JITToken
from .models import ActionRequest


class AdapterError(Exception):
    pass


class ToolAdapter(ABC):
    name: str
    capability: str
    schema: type[BaseModel]
    # Arguments that name an outbound destination: {arg_name: 'email' | 'url'}. The gateway checks
    # each one against the allowlist / user-supplied destinations (dataflow.check_destinations).
    egress_params: dict[str, str] = {}

    def __init__(self, broker: CredentialBroker, approvals: ApprovalStore):
        self._broker = broker
        self._approvals = approvals

    def invoke(
        self,
        request: ActionRequest,
        token: JITToken,
        approval_id: str | None = None,
        require_approval: bool = False,
    ) -> Any:
        try:
            self._broker.validate(token, request)
        except BrokerError as exc:
            raise AdapterError(f"credential check failed: {exc}") from exc

        try:
            parsed = self.schema(**request.arguments)
        except ValidationError as exc:
            raise AdapterError(f"argument validation failed: {exc.error_count()} error(s)") from exc

        self.check_resource(request.resource, parsed)

        if require_approval:
            if not approval_id:
                raise AdapterError("approval token required")
            try:
                self._approvals.consume(approval_id, request)  # atomic, single-use
            except ApprovalError as exc:
                raise AdapterError(f"approval check failed: {exc}") from exc

        return self.execute(parsed, request, token)

    def check_resource(self, resource: str, parsed: BaseModel) -> None:  # optional hook
        return None

    @abstractmethod
    def execute(self, args: BaseModel, request: ActionRequest, token: JITToken | None = None) -> Any: ...


# --------------------------------------------------------------------------
# GitHub PR adapter (schema from the standard)
# --------------------------------------------------------------------------
class GitHubCreatePRSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=100)
    head: str = Field(..., max_length=50)
    base: str = Field(..., max_length=50)
    body: str = Field(..., max_length=2000)

    @field_validator("head", "base")
    @classmethod
    def validate_branch_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-\/]+$", v):
            raise ValueError("Branch name contains forbidden characters")
        return v

    @field_validator("base")
    @classmethod
    def validate_permitted_base_branches(cls, v: str) -> str:
        if v not in {"main", "develop"}:
            raise ValueError(f"Target base branch '{v}' is not permitted")
        return v


class GitHubPRAdapter(ToolAdapter):
    name = "github_pr"
    capability = "github:pull_request:create"
    schema = GitHubCreatePRSchema
    is_mock = True  # in-memory stand-in; see adapters_real.GitHubPRRealAdapter

    def __init__(self, broker, approvals):
        super().__init__(broker, approvals)
        self.created: list[dict] = []  # stands in for the real API

    def execute(self, args: GitHubCreatePRSchema, request: ActionRequest, token=None) -> dict:
        pr = {"number": len(self.created) + 1, "repo": request.resource, **args.model_dump()}
        self.created.append(pr)
        return pr


# --------------------------------------------------------------------------
# Hardened file reader (scoped allowlist, blocked patterns, traversal-safe)
# --------------------------------------------------------------------------
class FileReadSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., min_length=1, max_length=512)
    operation: str = "read"


class FileReaderAdapter(ToolAdapter):
    name = "file_reader"
    capability = "files:read"
    schema = FileReadSchema

    allowed_paths = ("/app/reports/*",)
    allowed_operations = ("read",)
    blocked_patterns = ("*.env", "*.key", "*.pem", "*secret*", "*.credentials")

    def __init__(self, broker, approvals, fs: dict[str, str] | None = None):
        super().__init__(broker, approvals)
        self._fs = fs if fs is not None else {}

    def check_resource(self, resource: str, parsed: FileReadSchema) -> None:
        if parsed.operation not in self.allowed_operations:
            raise AdapterError(f"operation '{parsed.operation}' not allowed")
        norm = posixpath.normpath(parsed.path)
        if norm != parsed.path.rstrip("/") or ".." in parsed.path.split("/"):
            raise AdapterError("non-canonical or traversal path rejected")
        if not any(fnmatch.fnmatchcase(norm, p) for p in self.allowed_paths):
            raise AdapterError("path outside allowed directory")
        base = posixpath.basename(norm).lower()
        if any(fnmatch.fnmatchcase(base, p) or fnmatch.fnmatchcase(norm.lower(), p)
               for p in self.blocked_patterns):
            raise AdapterError("path matches blocked pattern")
        if resource != f"file:{norm}":
            raise AdapterError("argument path does not match authorized resource")

    def execute(self, args: FileReadSchema, request: ActionRequest, token=None) -> str:
        return self._fs.get(posixpath.normpath(args.path), "")


# --------------------------------------------------------------------------
# Generic high-risk adapters (mocked) so approval flows can be exercised
# --------------------------------------------------------------------------
class EmailSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254)
    subject: str = Field(..., max_length=200)
    body: str = Field(..., max_length=5000)


class EmailAdapter(ToolAdapter):
    name = "email_send"
    capability = "email:send_external"
    schema = EmailSchema
    egress_params = {"to": "email"}
    is_mock = True  # in-memory stand-in: refused by the production profile; see adapters_real.SMTPEmailAdapter

    def __init__(self, broker, approvals):
        super().__init__(broker, approvals)
        self.sent: list[dict] = []

    def execute(self, args: EmailSchema, request: ActionRequest, token=None) -> dict:
        self.sent.append(args.model_dump())
        return {"status": "queued"}


class DropTableSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")
    table: str = Field(..., pattern=r"^[a-z_][a-z0-9_]{0,62}$")


class DropTableAdapter(ToolAdapter):
    name = "db_drop_table"
    capability = "db:drop_table"
    schema = DropTableSchema
    is_mock = True  # refused by the production profile; see adapters_real.SQLDropTableAdapter

    def __init__(self, broker, approvals):
        super().__init__(broker, approvals)
        self.dropped: list[tuple[str, str]] = []
        self._seen_idempotency: set[str] = set()

    def execute(self, args: DropTableSchema, request: ActionRequest, token=None) -> dict:
        key = request.idempotency_key
        if not key:
            raise AdapterError("idempotency_key required for critical actions")
        if key in self._seen_idempotency:
            return {"status": "duplicate_ignored"}
        self._seen_idempotency.add(key)
        self.dropped.append((request.resource, args.table))
        return {"status": "dropped"}
