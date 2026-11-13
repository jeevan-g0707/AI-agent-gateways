"""Tamper-evident evidence store: HMAC hash-chained AgentSecurityEvent records."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import base64
from typing import Any, Callable, Sequence

from pydantic import BaseModel, Field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .audit_sinks import AuditSink, AuditTampered, AuditUnavailable
from .dlp import DataProtectionPolicy, Operation


class AgentSecurityEvent(BaseModel):
    # Actor context
    agent_id: str
    actor_user_id: str
    task_id: str
    session_id: str
    environment: str = "production"
    # Request context
    capability: str
    resource: str
    arguments_redacted: dict[str, Any] = Field(default_factory=dict)
    arguments_sha256: str = ""
    risk_tier: str | None = None
    justification: str = ""
    # Decision context
    policy_version: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    decision: str = ""
    evaluation_latency_ms: float = 0.0
    failure_mode: str | None = None
    reason: str = ""
    # Execution context
    timestamp: float = 0.0
    event_type: str = "decision"  # decision | execution | security
    execution_status: str | None = None
    execution_duration_ms: float | None = None
    payload_bytes: int | None = None
    dlp_applied: bool = False
    # Human context
    approver_ids: list[str] = Field(default_factory=list)
    approval_decided_at: float | None = None
    approval_rationale: list[str] = Field(default_factory=list)
    approval_token_id: str | None = None
    approval_expires_at: float | None = None


GENESIS = "0" * 64


def _mac(key: bytes, prev: str, payload: str) -> str:
    return hmac.new(key, (prev + payload).encode(), hashlib.sha256).hexdigest()


def verify_entries(entries: Sequence[dict[str, Any]], key: bytes) -> tuple[bool, int | None]:
    """Pure chain check over stored entries (sequence, linkage, HMAC). Returns (ok, first_bad_index)."""
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i or e.get("prev") != prev or \
                not hmac.compare_digest(_mac(key, prev, e.get("payload", "")), e.get("mac", "")):
            return False, i
        prev = e["mac"]
    return True, None


def _cp_bytes(cp: dict[str, Any]) -> bytes:
    body = {k: cp[k] for k in ("seq", "head_mac", "count", "ts")}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def verify_log(
    entries: Sequence[dict[str, Any]],
    checkpoints: Sequence[dict[str, Any]],
    hmac_key: bytes,
    checkpoint_public_key: Ed25519PublicKey,
) -> list[str]:
    """Independent audit of a stored log. Returns a list of problems (empty = intact).

    Detects: edited or reordered entries, a deleted *tail* (the log is shorter than a signed
    checkpoint says it was), and forged checkpoints. Checkpoints should live on different
    storage than entries (separate bucket / WORM volume) so one compromise cannot rewrite both."""
    problems: list[str] = []
    ok, bad = verify_entries(entries, hmac_key)
    if not ok:
        problems.append(f"entry chain broken at index {bad}")
    for cp in checkpoints:
        try:
            checkpoint_public_key.verify(base64.b64decode(cp["sig"]), _cp_bytes(cp))
        except (InvalidSignature, KeyError, ValueError):
            problems.append(f"checkpoint at seq {cp.get('seq')} has an invalid signature")
            continue
        if cp["seq"] >= len(entries):
            problems.append(f"log truncated: checkpoint covers seq {cp['seq']} but only {len(entries)} entries exist")
        elif entries[cp["seq"]]["mac"] != cp["head_mac"]:
            problems.append(f"checkpoint at seq {cp['seq']} does not match the stored entry")
    return problems


class EvidenceStore:
    GENESIS = GENESIS

    def __init__(
        self,
        key: bytes,
        clock: Callable[[], float] = time.time,
        *,
        sinks: Sequence[AuditSink] = (),
        checkpoint_every: int = 0,
        checkpoint_key: Ed25519PrivateKey | None = None,
    ):
        if checkpoint_every and checkpoint_key is None:
            raise ValueError("checkpoint_every requires checkpoint_key")
        self._key = key
        self._clock = clock
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._dlp = DataProtectionPolicy()
        self._sinks = list(sinks)
        self._cp_every = checkpoint_every
        self._cp_key = checkpoint_key
        self._cp_due = False
        self.sink_errors: dict[str, int] = {}
        self._pos: dict[str, int] = {}  # per required sink: how many chain entries it durably holds
        self._lag_seqs: list[int] = []

    # -- recovery -----------------------------------------------------------
    def restore(self, entries: Sequence[dict[str, Any]]) -> int:
        """Load previously persisted entries after a restart. Refuses to start on a broken chain."""
        entries = list(entries)
        ok, bad = verify_entries(entries, self._key)
        if not ok:
            raise AuditTampered(f"persisted audit log fails verification at index {bad}")
        with self._lock:
            self._entries = entries
            for sink in self._sinks:
                if sink.required:
                    self._pos[sink.name] = len(entries)
        return len(entries)

    # -- writing --------------------------------------------------------------
    def _mac(self, prev: str, payload: str) -> str:
        return _mac(self._key, prev, payload)

    def redact_args(self, arguments: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in arguments.items():
            if isinstance(v, str):
                out[k] = self._dlp.protect(v, Operation.LOG)[0]
            else:
                text = json.dumps(v, default=str)
                out[k] = self._dlp.protect(text, Operation.LOG)[0] if v is not None else None
        return out

    def set_sink_position(self, sink_name: str, count: int) -> None:
        """Tell the store how many chain entries a required sink already holds (after reconciliation)."""
        self._pos[sink_name] = count

    def _catch_up(self, sink: AuditSink) -> None:
        """Required sinks are replicas of one chain. Before a sink accepts a new entry it must hold every
        earlier one; if it missed some (it was down), replay them first, in order."""
        for i in range(self._pos.get(sink.name, 0), len(self._entries)):
            sink.write(self._entries[i])
            self._pos[sink.name] = i + 1

    def append(self, event: AgentSecurityEvent) -> str:
        """Record an event on every required sink (as replicas of one chain) before the caller proceeds.

        * No required sink accepted it  -> nothing is committed; AuditUnavailable.
        * Some accepted, some failed    -> the entry IS committed (it durably exists somewhere, and
          discarding it would leave an orphan that breaks the chain), the lagging sink is caught up on the
          next append, a marker records that the decision was not acted on, and AuditUnavailable is raised
          so the caller still refuses the action."""
        with self._lock:
            if not event.timestamp:
                event.timestamp = self._clock()
            if self._lag_seqs:  # leave an honest trace of decisions that were refused for lack of audit
                marker_seqs, self._lag_seqs = self._lag_seqs, []
                self._append_locked(AgentSecurityEvent(
                    agent_id="gateway", actor_user_id="-", task_id="-", session_id="-", capability="audit:lag",
                    resource="audit-log", decision="deny", event_type="security", timestamp=self._clock(),
                    reason=f"entries {marker_seqs} were recorded while a required sink was failing; the "
                           f"corresponding actions were NOT executed", rule_ids=["R-AUDIT-LAG"]))
            return self._append_locked(event)

    def _append_locked(self, event: AgentSecurityEvent) -> str:
        payload = event.model_dump_json()
        prev = self._entries[-1]["mac"] if self._entries else GENESIS
        entry = {"seq": len(self._entries), "prev": prev, "payload": payload, "mac": self._mac(prev, payload)}
        accepted, failure = 0, None
        for sink in self._sinks:
            if not sink.required:
                continue
            try:
                self._catch_up(sink)
                sink.write(entry)
                self._pos[sink.name] = entry["seq"] + 1
                accepted += 1
            except Exception as exc:  # keep going: the other replicas should still get the entry
                failure = failure or exc
        required = [s for s in self._sinks if s.required]
        if required and accepted == 0:
            raise (failure if isinstance(failure, AuditUnavailable) else
                   AuditUnavailable(f"{type(failure).__name__}")) from failure
        self._entries.append(entry)
        for sink in self._sinks:
            if not sink.required:
                try:
                    sink.write(entry)
                except Exception:
                    self.sink_errors[sink.name] = self.sink_errors.get(sink.name, 0) + 1
        if self._cp_every and (entry["seq"] + 1) % self._cp_every == 0:
            self._cp_due = True
        if self._cp_due:
            self._emit_checkpoint_locked()
        if failure is not None:
            self._lag_seqs.append(entry["seq"])
            raise (failure if isinstance(failure, AuditUnavailable) else
                   AuditUnavailable(f"{type(failure).__name__}")) from failure
        return entry["mac"]

    def checkpoint(self) -> dict[str, Any] | None:
        """Force a signed checkpoint of the current chain head."""
        with self._lock:
            self._cp_due = True
            return self._emit_checkpoint_locked()

    def _emit_checkpoint_locked(self) -> dict[str, Any] | None:
        if not self._entries or self._cp_key is None:
            return None
        head = self._entries[-1]
        cp = {"seq": head["seq"], "head_mac": head["mac"], "count": len(self._entries), "ts": self._clock()}
        cp["sig"] = base64.b64encode(self._cp_key.sign(_cp_bytes(cp))).decode()
        ok = True
        for sink in self._sinks:
            try:
                sink.write_checkpoint(cp)
            except Exception:
                ok = False
                self.sink_errors[sink.name] = self.sink_errors.get(sink.name, 0) + 1
        self._cp_due = not ok  # retry on the next append if any sink missed it
        return cp

    # -- reading ----------------------------------------------------------------
    def verify_chain(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_index)."""
        return verify_entries(self._entries, self._key)

    def events(self) -> list[AgentSecurityEvent]:
        return [AgentSecurityEvent.model_validate_json(e["payload"]) for e in self._entries]

    def trace(self, *, session_id: str | None = None, agent_id: str | None = None) -> list[AgentSecurityEvent]:
        return [
            e for e in self.events()
            if (session_id is None or e.session_id == session_id)
            and (agent_id is None or e.agent_id == agent_id)
        ]
