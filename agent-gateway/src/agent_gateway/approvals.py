"""Human-in-the-loop approvals.

Approvals are bound to an exact normalized action payload, expire in <=300s, and are
consumed atomically exactly once by the tool adapter. All mutations are compare-and-swap
operations on the shared StateBackend, so they are safe across threads *and* gateway replicas.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

from .models import ActionRequest, RiskTier
from .state import MemoryBackend, StateBackend

MAX_APPROVAL_TTL = 300
REQUIRED_APPROVERS = {
    RiskTier.LOW: 1,  # only reached when a tainted session upgrades a low-risk action
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 1,
    RiskTier.CRITICAL: 2,
}
STEP_UP_TIERS = {RiskTier.HIGH, RiskTier.CRITICAL}
# Delay between final approval and earliest execution. It is a recall window: the requester or any
# approver can cancel while the action is cooling down. Overridable via policy.json ("approval").
DEFAULT_COOLDOWN_SECONDS = {RiskTier.LOW: 0, RiskTier.MEDIUM: 0, RiskTier.HIGH: 30, RiskTier.CRITICAL: 120}
RECORD_RETENTION = 3600  # keep consumed/expired records briefly for forensics


class ApprovalError(Exception):
    pass


def binding_hash(request: ActionRequest) -> str:
    """Hash over every field an approval is bound to. Any change invalidates it."""
    ident = request.identity
    parts = [
        ident.actor_user_id,
        ident.agent_id,
        ident.task_id,
        request.tool,
        request.capability,
        request.resource,
        request.args_hash(),
        request.idempotency_key or "",
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


@dataclass
class ApprovalRecord:
    approval_id: str
    binding: str
    tier: RiskTier
    summary: dict
    created_at: float
    expires_at: float
    required_approvers: int
    approvers: list[str] = field(default_factory=list)
    rationales: list[str] = field(default_factory=list)
    approved_at: float | None = None
    consumed: bool = False
    rejected: bool = False
    actor_user_id: str = ""
    executable_at: float | None = None  # earliest execution time (approved_at + cooldown)

    @property
    def approved(self) -> bool:
        return len(set(self.approvers)) >= self.required_approvers and not self.rejected

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tier"] = self.tier.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ApprovalRecord":
        d = dict(d)
        d["tier"] = RiskTier(d["tier"])
        return cls(**d)


class ApprovalStore:
    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        ttl: int = MAX_APPROVAL_TTL,
        backend: StateBackend | None = None,
        cooldowns: dict[RiskTier, int] | None = None,
    ):
        if ttl > MAX_APPROVAL_TTL:
            raise ValueError("approval TTL may not exceed 300 seconds")
        self._cooldowns = {**DEFAULT_COOLDOWN_SECONDS, **(cooldowns or {})}
        for tier, cd in self._cooldowns.items():
            if cd < 0 or cd >= ttl:
                raise ValueError(f"cooldown for {tier.value} must be >= 0 and shorter than the {ttl}s approval window")
        self._clock = clock
        self._ttl = ttl
        self._b: StateBackend = backend or MemoryBackend(clock)

    @staticmethod
    def _key(approval_id: str) -> str:
        return f"approval:{approval_id}"

    def _mutate(self, approval_id: str, mutator):
        """Atomic read-modify-write of one record. `mutator(rec)` may raise to abort."""

        def fn(d):
            if d is None:
                raise ApprovalError("unknown approval")
            rec = ApprovalRecord.from_dict(d)
            result = mutator(rec)
            return rec.to_dict(), result

        return self._b.atomic_update(self._key(approval_id), fn, ttl=self._ttl + RECORD_RETENTION)

    # -- request side -------------------------------------------------------
    def create(self, request: ActionRequest, tier: RiskTier, context: dict | None = None,
               required_approvers: int | None = None) -> ApprovalRecord:
        now = self._clock()
        rec = ApprovalRecord(
            approval_id="appr-" + secrets.token_hex(8),
            binding=binding_hash(request),
            tier=tier,
            summary={
                "actor_user_id": request.identity.actor_user_id,
                "agent_id": request.identity.agent_id,
                "tool": request.tool,
                "capability": request.capability,
                "resource": request.resource,
                "arguments": request.arguments,  # diff/preview for the reviewer
                "arguments_sha256": request.args_hash(),
                "justification": request.justification,
                "cooldown_seconds": self._cooldowns[tier],
                # what the reviewer needs to judge *where this content came from and where it goes*
                "context": context or {},
            },
            created_at=now,
            expires_at=now + self._ttl,
            required_approvers=max(REQUIRED_APPROVERS[tier], required_approvers or 0),
            actor_user_id=request.identity.actor_user_id,
        )
        self._b.atomic_update(self._key(rec.approval_id), lambda d: (rec.to_dict(), None),
                              ttl=self._ttl + RECORD_RETENTION)
        return rec

    def get(self, approval_id: str) -> ApprovalRecord | None:
        d = self._b.get(self._key(approval_id))
        return ApprovalRecord.from_dict(d) if d else None

    # -- reviewer side ------------------------------------------------------
    def approve(
        self,
        approval_id: str,
        approver_id: str,
        rationale: str = "",
        step_up_verified: bool = False,
    ) -> ApprovalRecord:
        def mut(rec: ApprovalRecord):
            now = self._clock()
            if now >= rec.expires_at:
                raise ApprovalError("approval request expired")
            if rec.consumed or rec.rejected:
                raise ApprovalError("approval no longer open")
            if approver_id == rec.actor_user_id:
                raise ApprovalError("requester cannot approve their own action")
            if approver_id in rec.approvers:
                raise ApprovalError("approver already recorded; dual approval needs distinct approvers")
            if rec.tier in STEP_UP_TIERS and not step_up_verified:
                raise ApprovalError("step-up authentication required")
            rec.approvers.append(approver_id)
            rec.rationales.append(rationale)
            if rec.approved:
                rec.approved_at = now
                rec.expires_at = now + self._ttl  # execution window runs from final approval
                rec.executable_at = now + self._cooldowns[rec.tier]
            return rec

        return self._mutate(approval_id, mut)

    def reject(self, approval_id: str, approver_id: str, rationale: str = "") -> ApprovalRecord:
        def mut(rec: ApprovalRecord):
            if rec.consumed:
                raise ApprovalError("approval already consumed; too late to cancel")
            rec.rejected = True
            rec.rationales.append(f"rejected/cancelled by {approver_id}: {rationale}")
            return rec

        return self._mutate(approval_id, mut)

    # -- adapter side -------------------------------------------------------
    def consume(self, approval_id: str, request: ActionRequest) -> ApprovalRecord:
        """Atomically validate and burn the approval. Raises ApprovalError on any failure."""

        def mut(rec: ApprovalRecord):
            now = self._clock()
            if rec.consumed:
                raise ApprovalError("approval token already consumed (replay)")
            if now >= rec.expires_at:
                raise ApprovalError("approval token expired")
            if not rec.approved:
                raise ApprovalError("approval not granted")
            if rec.binding != binding_hash(request):
                raise ApprovalError("request does not match approved parameters")
            if rec.rejected:
                raise ApprovalError("approval was cancelled")
            if rec.executable_at is not None and now < rec.executable_at:
                raise ApprovalError(f"cooldown period not elapsed ({rec.executable_at - now:.0f}s remaining)")
            rec.consumed = True
            return rec

        return self._mutate(approval_id, mut)

    def status(self, approval_id: str, request: ActionRequest) -> tuple[str, str, float]:
        """Non-consuming check. Returns (state, reason, retry_after) where state is
        'ok' | 'cooling' | 'invalid'. The adapter still performs the authoritative atomic consume."""
        rec = self.get(approval_id)
        if rec is None:
            return "invalid", "unknown approval token", 0.0
        now = self._clock()
        if rec.rejected:
            return "invalid", "approval was cancelled", 0.0
        if rec.consumed:
            return "invalid", "approval token already consumed", 0.0
        if now >= rec.expires_at:
            return "invalid", "approval token expired", 0.0
        if not rec.approved:
            return "invalid", "approval not granted", 0.0
        if rec.binding != binding_hash(request):
            return "invalid", "request does not match approved parameters", 0.0
        if rec.executable_at is not None and now < rec.executable_at:
            wait = rec.executable_at - now
            return "cooling", f"approved; cooldown in effect, retry in {wait:.0f}s", wait
        return "ok", "ok", 0.0

    def peek_valid(self, approval_id: str, request: ActionRequest) -> tuple[bool, str]:
        state, why, _ = self.status(approval_id, request)
        return state == "ok", why
