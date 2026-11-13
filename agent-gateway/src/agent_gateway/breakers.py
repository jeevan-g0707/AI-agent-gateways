"""Execution-state integrity: rate limits, SIEM anomaly alerts, circuit breakers, replay tracking.

All per-session state lives in the shared StateBackend, so limits hold across gateway
replicas (an agent cannot dodge the 100 calls/min throttle by hitting different instances).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .state import UNCHANGED, MemoryBackend, StateBackend

GATEWAY_RATE_LIMIT = 100  # hard throttle: calls / 60s / session
SIEM_ANOMALY_THRESHOLD = 30  # alert: calls / 60s (fires before the hard limit)
WINDOW_SECONDS = 60
MAX_DEPTH = 10
MAX_CONSECUTIVE_FAILURES = 5
MAX_COST_USD = 10.00
SESSION_STATE_TTL = 7 * 24 * 3600


def check_execution_timeout(start_time: datetime, max_allowed_seconds: float, now: datetime | None = None) -> bool:
    """True if the window is exceeded. Uses total_seconds(); `.seconds` drops whole days."""
    now = now or datetime.now(timezone.utc)
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    elapsed = now - start_time
    return elapsed.total_seconds() > max_allowed_seconds


@dataclass
class SessionState:
    depth: int = 0
    consecutive_failures: int = 0
    cost_usd: float = 0.0
    tripped: str | None = None
    completed_steps: list[str] = field(default_factory=list)  # "task_id:step"
    anomaly_raised: bool = False
    tainted: bool = False  # untrusted content has entered this session's context
    data_label: int = 0  # high-water mark of data sensitivity this session has seen (0 public..3 restricted)
    label_sources: list[str] = field(default_factory=list)  # what raised it (most recent 20)
    egress_messages: int = 0
    egress_bytes: int = 0
    egress_dests: list[str] = field(default_factory=list)


class ExecutionGuard:
    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        on_alert: Callable[[str, str], None] | None = None,
        backend: StateBackend | None = None,
    ):
        self._clock = clock
        self._b: StateBackend = backend or MemoryBackend(clock)
        self._alert = on_alert or (lambda session, msg: None)

    # -- state helpers -----------------------------------------------------
    @staticmethod
    def _key(session_id: str) -> str:
        return f"guard:{session_id}"

    def _update(self, session_id: str, mutator):
        def fn(d):
            st = SessionState(**d) if d else SessionState()
            result = mutator(st)
            return st.__dict__.copy(), result

        return self._b.atomic_update(self._key(session_id), fn, ttl=SESSION_STATE_TTL)

    def state(self, session_id: str) -> SessionState:
        d = self._b.get(self._key(session_id))
        return SessionState(**d) if d else SessionState()

    # -- pre-execution gate ------------------------------------------------
    # -- gateway-wide emergency stop (audit integrity alarm, operator action) --------------------
    def halt_all(self, reason: str) -> None:
        self._b.atomic_update("guard:global", lambda d: ({"reason": reason, "at": self._clock()}, None))

    def clear_halt_all(self) -> None:
        self._b.atomic_update("guard:global", lambda d: (None, None))

    def global_halt(self) -> str | None:
        d = self._b.get("guard:global")
        return d["reason"] if d else None

    def pre_check(self, session_id: str, task_id: str, step: int) -> tuple[bool, str]:
        """Returns (allowed, reason). Every attempt counts against the rate window."""
        halted = self.global_halt()
        if halted:
            return False, f"gateway halted: {halted}"
        st = self.state(session_id)
        if st.tripped:
            return False, f"circuit breaker open: {st.tripped}"

        now = self._clock()
        count = self._b.window_add(f"rate:{session_id}", now, WINDOW_SECONDS)
        if count > GATEWAY_RATE_LIMIT:
            return False, "gateway throttle: 100 calls/60s exceeded"

        if count >= SIEM_ANOMALY_THRESHOLD:
            def raise_once(s: SessionState):
                first = not s.anomaly_raised
                s.anomaly_raised = True
                return first

            if self._update(session_id, raise_once):
                self._alert(session_id, f"{count} tool calls in {WINDOW_SECONDS}s (possible runaway)")

        def check(s: SessionState):
            if s.depth >= MAX_DEPTH:
                s.tripped = "execution depth limit (10)"
            elif s.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                s.tripped = "retry threshold (5 consecutive failures)"
            elif s.cost_usd > MAX_COST_USD:
                s.tripped = "cost cap ($10.00)"
            if s.tripped:
                return False, s.tripped
            if f"{task_id}:{step}" in s.completed_steps:
                return False, f"step {step} already executed (replay blocked)"
            return True, "ok"

        return self._update(session_id, check)

    def record_result(self, session_id: str, task_id: str, step: int, success: bool, cost_usd: float = 0.0) -> None:
        def mut(s: SessionState):
            s.depth += 1
            s.cost_usd += cost_usd
            if success:
                s.consecutive_failures = 0
                s.completed_steps.append(f"{task_id}:{step}")
            else:
                s.consecutive_failures += 1
            if s.cost_usd > MAX_COST_USD and not s.tripped:
                s.tripped = "cost cap ($10.00)"
            if s.consecutive_failures >= MAX_CONSECUTIVE_FAILURES and not s.tripped:
                s.tripped = "retry threshold (5 consecutive failures)"

        self._update(session_id, mut)

    def halt(self, session_id: str, reason: str) -> None:
        """Hard stop (incident response / orchestrator pause)."""
        self._update(session_id, lambda s: setattr(s, "tripped", reason))

    def add_cost(self, session_id: str, cost_usd: float) -> None:
        def mut(s: SessionState):
            s.cost_usd += cost_usd
            if s.cost_usd > MAX_COST_USD and not s.tripped:
                s.tripped = "cost cap ($10.00)"

        self._update(session_id, mut)

    # -- taint tracking ----------------------------------------------------
    def mark_tainted(self, session_id: str) -> None:
        self._update(session_id, lambda s: setattr(s, "tainted", True))

    # -- information-flow label (monotonic: it only rises, except by audited declassification) --
    def raise_label(self, session_id: str, rank: int, source: str) -> None:
        def mut(s: SessionState):
            if rank > s.data_label:
                s.data_label = rank
                s.label_sources = (s.label_sources + [source])[-20:]
            elif rank == s.data_label and rank > 0 and source not in s.label_sources:
                s.label_sources = (s.label_sources + [source])[-20:]

        self._update(session_id, mut)

    def set_label(self, session_id: str, rank: int) -> None:
        def mut(s: SessionState):
            s.data_label = rank
            s.label_sources = []

        self._update(session_id, mut)

    def record_egress(self, session_id: str, nbytes: int, dests: list[str]) -> None:
        def mut(s: SessionState):
            s.egress_messages += 1
            s.egress_bytes += nbytes
            for d in dests:
                if d not in s.egress_dests:
                    s.egress_dests.append(d)

        self._update(session_id, mut)

    def clear_taint(self, session_id: str) -> None:
        self._update(session_id, lambda s: setattr(s, "tainted", False))

    def is_tainted(self, session_id: str) -> bool:
        return self.state(session_id).tainted
