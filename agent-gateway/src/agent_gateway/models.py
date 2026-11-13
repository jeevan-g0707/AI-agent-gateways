"""Core data models shared across the gateway."""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Identity(BaseModel):
    """Dual-bound agent identity: human actor + agent instance + task scope."""

    model_config = ConfigDict(frozen=True)

    actor_user_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)  # e.g. agent:repo-helper:v2.1:abc123
    task_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    environment: str = "production"


class ActionRequest(BaseModel):
    """A tool call proposed by the (untrusted) agent orchestrator."""

    identity: Identity
    tool: str
    capability: str  # e.g. "github:pull_request:create"
    resource: str  # exact resource, e.g. "repo:org-enterprise/core-docs"
    arguments: dict[str, Any] = Field(default_factory=dict)
    justification: str = ""
    idempotency_key: str | None = None
    step: int = 1

    def args_hash(self) -> str:
        return hash_arguments(self.arguments)


class DecisionResult(BaseModel):
    decision: Decision
    risk_tier: RiskTier | None = None
    reason: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    policy_version: str = ""
    latency_ms: float = 0.0
    approval_id: str | None = None
    failure_mode: str | None = None


def hash_arguments(arguments: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON (sorted keys, no whitespace)."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()
