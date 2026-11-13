"""Making local log deletion survivable.

A root user on the gateway host can delete or rewrite local files; no code can prevent that. What we can do:

  1. DETECT AT WRITE TIME   FileWORMSink refuses to write if its file was unlinked, replaced or edited
                            (see audit_sinks), so the next action is refused immediately (fail closed).
  2. DETECT CONTINUOUSLY    AuditWatchdog compares every replica against the in-memory chain, checks sealed
                            segments against their manifest and, on any discrepancy, HALTS THE WHOLE GATEWAY.
  3. RECOVER                reconcile_sinks() on startup treats the S3 Object Lock copy (which not even the
                            account root can delete during retention) as authoritative: a deleted or truncated
                            local log is quarantined (kept as evidence) and rebuilt from it; a lagging replica
                            is caught up; a *diverging* replica is refused (needs a human).
  4. REFUSE TO RUN BLIND    validate_production_profile() refuses to start in production without an immutable
                            remote sink, so "local files only" cannot be deployed by accident.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .audit import EvidenceStore, verify_entries, verify_log
from .audit_sinks import AuditSink, AuditTampered, AuditUnavailable, FileWORMSink, ObjectLockSink
from .breakers import ExecutionGuard

log = logging.getLogger("agent_gateway.audit_guard")


class ProductionProfileError(RuntimeError):
    pass


def reconcile_sinks(
    sinks: Sequence[AuditSink],
    hmac_key: bytes,
    checkpoint_public_key: Ed25519PublicKey | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Startup reconciliation across all readable required sinks. Returns (authoritative chain, actions)."""
    readable = [s for s in sinks if s.required and hasattr(s, "entries")]
    if not readable:
        return [], {}
    # keyed by position, NOT by sink name: two sinks of the same type (two buckets) must never shadow each other
    chains: dict[int, list[dict[str, Any]]] = {}
    for i, s in enumerate(readable):
        try:
            chain = list(s.entries())
        except AuditTampered:
            chains[i] = []  # unreadable/truncated line: handled below as a damaged replica
            continue
        ok, bad = verify_entries(chain, hmac_key)
        if not ok:
            if isinstance(s, FileWORMSink):  # a damaged LOCAL copy is recoverable if another replica is intact
                chains[i] = []
                continue
            raise AuditTampered(f"{s.name}: stored chain fails verification at index {bad}")
        chains[i] = chain

    longest = max(chains.values(), key=len)
    ok, bad = verify_entries(longest, hmac_key)
    if not ok:
        raise AuditTampered(f"no intact replica: chain fails verification at index {bad}")

    def label(i: int) -> str:
        n = readable[i].name
        return n if sum(1 for x in readable if x.name == n) == 1 else f"{n}#{i}"

    actions: dict[str, str] = {}
    for i, s in enumerate(readable):
        c = chains[i]
        if longest[: len(c)] != c and c:
            if isinstance(s, FileWORMSink) and len(readable) > 1:
                chains[i] = c = []  # local diverges from the others: treat as damaged, rebuild
            else:
                raise AuditTampered(f"{label(i)} diverges from the other audit replicas")
        # signed checkpoints prove the authoritative chain was not truncated
        if checkpoint_public_key is not None and hasattr(s, "checkpoints"):
            problems = verify_log(longest, s.checkpoints(), hmac_key, checkpoint_public_key)
            if problems:
                raise AuditTampered("; ".join(problems))

    for i, s in enumerate(readable):
        c = chains[i]
        if len(c) == len(longest):
            actions[label(i)] = "in sync"
            continue
        if isinstance(s, FileWORMSink):
            damaged = bool(s.verify_manifest()) or not c
            if damaged and (s.entry_count() > 0):
                q = s.reset_quarantine()
                actions[label(i)] = f"local log damaged/deleted: quarantined at {q.name}, rebuilt from replica"
                c = []
            else:
                actions[label(i)] = f"caught up {len(longest) - len(c)} entries from replica"
        else:
            actions[label(i)] = f"caught up {len(longest) - len(c)} entries from replica"
        for e in longest[len(c):]:
            s.write(e)
    return longest, actions


class AuditWatchdog:
    """Periodic integrity check. Any problem halts the entire gateway until a human clears it."""

    def __init__(
        self,
        evidence: EvidenceStore,
        sinks: Sequence[AuditSink],
        guard: ExecutionGuard,
        *,
        hmac_key: bytes,
        checkpoint_public_key: Ed25519PublicKey | None = None,
        on_alarm: Callable[[list[str]], None] | None = None,
        config_check_every: int = 120,
        min_retention_days: int | None = None,
    ):
        self._cfg_every, self._min_days, self._runs = config_check_every, min_retention_days, 0
        self._ev, self._sinks, self._guard = evidence, list(sinks), guard
        self._key, self._pub = hmac_key, checkpoint_public_key
        self._alarm = on_alarm or (lambda problems: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> list[str]:
        problems: list[str] = []
        ok, bad = self._ev.verify_chain()
        if not ok:
            problems.append(f"in-memory chain broken at index {bad}")
        expected = len(self._ev._entries)
        for s in self._sinks:
            if not s.required or not hasattr(s, "entry_count"):
                continue
            try:
                if isinstance(s, FileWORMSink):
                    problems += [f"{s.name}: {p}" for p in s.verify_manifest()]
                n = s.entry_count()
                lag = self._ev._pos.get(s.name, expected)
                if n != lag:
                    problems.append(f"{s.name}: holds {n} entries but {lag} were written "
                                    f"({'entries removed' if n < lag else 'unexpected extra entries'})")
                if self._pub is not None and hasattr(s, "checkpoints") and n == lag and lag == expected:
                    problems += [f"{s.name}: {p}" for p in
                                 verify_log(list(s.entries()), s.checkpoints(), self._key, self._pub)]
            except AuditUnavailable as exc:
                problems.append(f"{s.name}: unreadable ({exc})")
            except Exception as exc:
                problems.append(f"{s.name}: check failed ({type(exc).__name__})")
        self._runs += 1
        if self._cfg_every and (self._runs - 1) % self._cfg_every == 0:  # configuration drift: someone loosened the bucket/IAM
            for s in self._sinks:
                if s.required and getattr(s, "immutable", False) and hasattr(s, "verify_bucket"):
                    problems += [f"{s.name}: configuration drift: {p}"
                                 for p in s.verify_bucket(min_retention_days=self._min_days, probe=False)]
        if problems:
            self._guard.halt_all("audit integrity alarm: " + "; ".join(problems)[:500])
            log.error("audit watchdog alarm: %s", problems)
            self._alarm(problems)
        return problems

    def start(self, interval: float = 30.0) -> None:
        def loop():
            while not self._stop.wait(interval):
                try:
                    self.run_once()
                except Exception:  # the watchdog itself failing is an alarm
                    self._guard.halt_all("audit watchdog failure")

        self._thread = threading.Thread(target=loop, name="audit-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


def validate_production_profile(sinks: Sequence[AuditSink], adapters: dict[str, Any], *,
                                min_retention_days: int | None = None, probe: bool = True) -> None:
    """Raise ProductionProfileError listing everything that makes this deployment unsafe for production.
    Immutable sinks are not taken on trust: their bucket configuration is inspected (and probed)."""
    problems: list[str] = []
    for s in sinks:
        if s.required and getattr(s, "immutable", False) and hasattr(s, "verify_bucket"):
            problems += [f"{s.name}: {p}" for p in s.verify_bucket(min_retention_days=min_retention_days, probe=probe)]
    if not any(s.required and getattr(s, "immutable", False) for s in sinks):
        problems.append("no required IMMUTABLE audit sink (S3 Object Lock in COMPLIANCE mode): local files "
                        "alone can be deleted by a privileged user")
    mocks = sorted(n for n, a in adapters.items() if getattr(a, "is_mock", False))
    if mocks:
        problems.append(f"mock adapters configured: {', '.join(mocks)}")
    if problems:
        raise ProductionProfileError("; ".join(problems))
