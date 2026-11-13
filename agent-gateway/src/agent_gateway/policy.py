"""Policy Decision Point (PDP).

Runs outside the agent's context window. Deterministic, rule-based, fail-closed:
any exception, missing rule, ambiguity or corrupt config yields DENY.
"""
from __future__ import annotations

import fnmatch
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ActionRequest, Decision, DecisionResult, RiskTier

WILDCARD_CHARS = ("*", "?", "[")
# What a session that has seen suspected prompt injection may still do, per risk tier.
DEFAULT_TAINT_POLICY = {"low": "require_approval", "medium": "require_approval", "high": "deny", "critical": "deny"}


@dataclass(frozen=True)
class CapabilityRule:
    capability: str
    risk: RiskTier
    resource_patterns: tuple[str, ...]
    rule_id: str


@dataclass
class PolicyConfig:
    version: str
    capabilities: dict[str, CapabilityRule]
    user_entitlements: dict[str, frozenset[str]]
    # Spec reconciliation: the decision flowchart denies CRITICAL, the risk table
    # allows it behind dual approval. Default follows the table; flip to "deny"
    # to follow the flowchart strictly.
    critical_mode: str = "require_dual_approval"
    approval_cooldowns: dict[str, int] = field(default_factory=dict)
    egress_allowed_domains: tuple[str, ...] = ()
    taint_policy: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TAINT_POLICY))
    # information-flow control
    data_labels: tuple[tuple[str, str], ...] = ()  # (resource pattern, label) of data a tool call returns
    default_data_label: str = "internal"
    egress_clearance: dict[str, str] = field(default_factory=dict)  # allowlisted domain -> max label it may receive
    default_egress_clearance: str = "public"
    trusted_destination_clearance: str = "internal"  # for destinations the human typed
    egress_limits: dict[str, int] = field(default_factory=dict)
    # destination domain -> source-resource patterns it may EVER receive data derived from (allowlist, deny otherwise)
    release_rules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # egress from a session at/above this label (or any tainted session) needs two distinct approvers
    egress_dual_approval_label: str = "confidential"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyConfig":
        caps = {}
        for name, spec in raw["capabilities"].items():
            caps[name] = CapabilityRule(
                capability=name,
                risk=RiskTier(spec["risk"]),
                resource_patterns=tuple(spec["resource_patterns"]),
                rule_id=spec["rule_id"],
            )
        ent = {u: frozenset(c) for u, c in raw["user_entitlements"].items()}
        return cls(
            version=raw["version"],
            capabilities=caps,
            user_entitlements=ent,
            critical_mode=raw.get("critical_mode", "require_dual_approval"),
            approval_cooldowns={k: int(v) for k, v in raw.get("approval", {}).get("cooldown_seconds", {}).items()},
            egress_allowed_domains=tuple(d.lower() for d in raw.get("egress_allowed_domains", [])),
            taint_policy={**DEFAULT_TAINT_POLICY, **raw.get("taint_policy", {})},
            data_labels=tuple((d["pattern"], d["label"]) for d in raw.get("data_labels", [])),
            default_data_label=raw.get("default_data_label", "internal"),
            egress_clearance={k.lower(): v for k, v in raw.get("egress_clearance", {}).items()},
            default_egress_clearance=raw.get("default_egress_clearance", "public"),
            trusted_destination_clearance=raw.get("trusted_destination_clearance", "internal"),
            egress_limits={k: int(v) for k, v in raw.get("egress_limits", {}).items()},
            release_rules={k.lower(): tuple(v) for k, v in raw.get("release_rules", {}).items()},
            egress_dual_approval_label=raw.get("egress_dual_approval_label", "confidential"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))


class PolicyDecisionPoint:
    def __init__(self, config: PolicyConfig | None, supported_tools: dict[str, str] | None = None):
        """
        config: loaded policy. None simulates missing/corrupt config -> fail closed.
        supported_tools: optional map tool_name -> capability the tool may exercise.
        """
        self._config = config
        self._tool_caps = supported_tools or {}

    @property
    def policy_version(self) -> str:
        return self._config.version if self._config else "unavailable"

    def evaluate(self, request: ActionRequest) -> DecisionResult:
        start = time.perf_counter()
        try:
            result = self._evaluate(request)
        except Exception as exc:  # fail closed on ANY internal error
            result = self._deny(
                f"policy evaluation error: {type(exc).__name__}",
                ["R-FAILCLOSED"],
                failure_mode="exception",
            )
        result.latency_ms = round((time.perf_counter() - start) * 1000, 3)
        return result

    # ------------------------------------------------------------------
    def _evaluate(self, request: ActionRequest) -> DecisionResult:
        cfg = self._config
        if cfg is None:
            return self._deny("policy configuration unavailable", ["R-FAILCLOSED"], "no_config")

        rule = cfg.capabilities.get(request.capability)
        if rule is None:
            return self._deny(f"capability '{request.capability}' not in allowlist", ["R-NO-RULE"])

        if self._tool_caps and self._tool_caps.get(request.tool) != request.capability:
            return self._deny(
                f"tool '{request.tool}' is not permitted to exercise '{request.capability}'",
                ["R-TOOL-CAP-MISMATCH"],
            )

        # Exact resource binding: the REQUEST may never carry wildcards.
        if any(ch in request.resource for ch in WILDCARD_CHARS) or not request.resource.strip():
            return self._deny("resource must be exact (no wildcards)", ["R-EXACT-RESOURCE"])
        if ".." in request.resource:
            return self._deny("path traversal in resource", ["R-EXACT-RESOURCE"])

        if not any(fnmatch.fnmatchcase(request.resource, p) for p in rule.resource_patterns):
            return self._deny(
                f"resource '{request.resource}' outside allowed scope", [rule.rule_id], tier=rule.risk
            )

        # Human baseline entitlement (dual-bound identity check).
        entitled = cfg.user_entitlements.get(request.identity.actor_user_id)
        if entitled is None or request.capability not in entitled:
            return self._deny(
                "requesting user lacks entitlement for capability",
                [rule.rule_id, "R-ENTITLEMENT"],
                tier=rule.risk,
            )

        if rule.risk is RiskTier.LOW:
            return DecisionResult(
                decision=Decision.ALLOW,
                risk_tier=rule.risk,
                reason="low risk, within scope",
                rule_ids=[rule.rule_id],
                policy_version=cfg.version,
            )
        if rule.risk is RiskTier.CRITICAL and cfg.critical_mode == "deny":
            return self._deny("critical actions are denied by policy", [rule.rule_id], tier=rule.risk)

        return DecisionResult(
            decision=Decision.REQUIRE_APPROVAL,
            risk_tier=rule.risk,
            reason=f"{rule.risk.value} risk requires human approval",
            rule_ids=[rule.rule_id],
            policy_version=cfg.version,
        )

    def _deny(
        self,
        reason: str,
        rule_ids: list[str],
        failure_mode: str | None = None,
        tier: RiskTier | None = None,
    ) -> DecisionResult:
        return DecisionResult(
            decision=Decision.DENY,
            risk_tier=tier,
            reason=reason,
            rule_ids=rule_ids,
            policy_version=self.policy_version,
            failure_mode=failure_mode,
        )
