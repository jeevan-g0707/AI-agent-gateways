"""Governed Execution Gateway: wires every control into one fail-closed pipeline.

Pipeline per proposed tool call:
  1. throttle / circuit breakers / step replay      (breakers.ExecutionGuard)
  2. schema pre-validation                          (adapter schema)
  3. egress DLP + exfiltration pattern detection    (dlp, exfil)
  4. Policy Decision Point                          (policy)
  5. approval flow (require_approval)               (approvals)
  6. JIT credential issuance                        (broker)
  7. adapter execution + output DLP                 (adapters, dlp)
  8. tamper-evident evidence                        (audit)

Any unexpected exception at any stage results in DENY (fail closed).
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import ValidationError

from .adapters import AdapterError, ToolAdapter
from .approvals import ApprovalStore
from .audit import AgentSecurityEvent, EvidenceStore
from .audit_sinks import AuditUnavailable
from .breakers import ExecutionGuard
from .dataflow import (LABEL_NAMES, LABELS, MAX_TYPED_CHARS, CanaryRegistry, FlowPolicy, TrustedInputRegistry,
                       TrustedInputRejected, UntrustedCorpus, SourceLedger, check_destinations, extract_entities,
                       label_rank, release_violation, walk_strings)
from .broker import BrokerError, CredentialBroker, GrantSigner
from .dlp import DataClassification, DataProtectionPolicy, Operation
from .exfil import ExfiltrationDetector
from .injection import InjectionDefense, ScanResult
from .models import ActionRequest, Decision, DecisionResult, RiskTier
from .policy import DEFAULT_TAINT_POLICY, PolicyDecisionPoint
from .userauth import UserAttestationError, UserAttestationVerifier

EGRESS_CAPABILITIES = {"email:send_external"}
EST_COST_PER_CALL_USD = 0.0


@dataclass
class GatewayResponse:
    decision: Decision
    reason: str
    risk_tier: RiskTier | None = None
    approval_id: str | None = None
    result: Any = None
    approval_preview: dict | None = None
    retry_after: float | None = None  # set while an approved action is in its cooldown window

    @property
    def executed(self) -> bool:
        return self.decision is Decision.ALLOW and self.result is not None


class Gateway:
    def __init__(
        self,
        pdp: PolicyDecisionPoint,
        signer: GrantSigner,
        broker: CredentialBroker,
        approvals: ApprovalStore,
        evidence: EvidenceStore,
        guard: ExecutionGuard,
        adapters: dict[str, ToolAdapter],
        exfil: ExfiltrationDetector | None = None,
        dlp: DataProtectionPolicy | None = None,
        injection: InjectionDefense | None = None,
        clock: Callable[[], float] = time.time,
        *,
        trusted: TrustedInputRegistry | None = None,
        canaries: CanaryRegistry | None = None,
        egress_domains: tuple[str, ...] = (),
        taint_policy: dict[str, str] | None = None,
        flow: FlowPolicy | None = None,
        corpus: UntrustedCorpus | None = None,
        sources: SourceLedger | None = None,
        user_verifier: UserAttestationVerifier | None = None,
        require_user_signature: bool = False,
    ):
        self.user_verifier = user_verifier
        self.require_user_signature = require_user_signature
        self.sources = sources or SourceLedger()
        self.flow = flow or FlowPolicy()
        self.corpus = corpus or UntrustedCorpus()
        self.pdp = pdp
        self.signer = signer
        self.broker = broker
        self.approvals = approvals
        self.evidence = evidence
        self.guard = guard
        self.adapters = adapters
        self.exfil = exfil or ExfiltrationDetector()
        self.dlp = dlp or DataProtectionPolicy()
        self.injection = injection or InjectionDefense()
        self.trusted = trusted or TrustedInputRegistry()
        self.canaries = canaries or CanaryRegistry()
        self.egress_domains = egress_domains
        self.taint_policy = taint_policy or dict(DEFAULT_TAINT_POLICY)
        self.disabled_capabilities: set[str] = set()
        self.unlogged: list[AgentSecurityEvent] = []  # events whose audit write failed AFTER the action ran
        self._clock = clock

    # ------------------------------------------------------------------ public
    def execute(self, request: ActionRequest, approval_id: str | None = None) -> GatewayResponse:
        """Single entry point for every proposed tool call. Never raises; fails closed."""
        try:
            return self._execute(request, approval_id)
        except AuditUnavailable:  # audit-before-execute: if we cannot record it, we do not do it
            return GatewayResponse(Decision.DENY, "audit log unavailable; action refused")
        except Exception as exc:  # fail closed
            resp = GatewayResponse(Decision.DENY, f"gateway error: {type(exc).__name__}")
            try:
                self._log_decision(request, DecisionResult(
                    decision=Decision.DENY, reason=resp.reason, rule_ids=["R-FAILCLOSED"],
                    policy_version=self.pdp.policy_version, failure_mode="exception"))
            except Exception:
                pass  # already denying; a failing audit sink must not turn a deny into a crash
            return resp

    def reconcile_audit(self) -> int:
        """Retry events that could not be written after execution. Returns how many remain."""
        remaining: list[AgentSecurityEvent] = []
        for ev in self.unlogged:
            try:
                self.evidence.append(ev)
            except Exception:
                remaining.append(ev)
        self.unlogged = remaining
        return len(remaining)

    def _audit_post(self, event: AgentSecurityEvent) -> None:
        """Record an event about something that ALREADY happened. We cannot undo it, so on failure we
        keep the event for reconciliation and halt the session so no further action runs unrecorded."""
        try:
            self.evidence.append(event)
        except Exception:
            self.unlogged.append(event)
            self.guard.halt(event.session_id, "audit sink unavailable")

    # -- trusted-side API (called by the user-facing front end, never by the agent) -----------
    def register_trusted_input(self, session_id: str, typed_text: str, *, message_id: str, registrar: str,
                               attachments: tuple[str, ...] | list[str] = (),
                               actor_user_id: str | None = None, attestation: dict | None = None) -> set[str]:
        """Record destinations the human TYPED. Contract for the front end:
          * `typed_text` is only what the person entered by hand in this turn.
          * Anything pasted, uploaded, fetched or generated goes in `attachments`; those are screened as
            untrusted content and can never make a destination trusted.
          * `message_id` is unique per human message (replays are refused).
        The gateway does not just trust the caller: it refuses text that overlaps content it already saw
        as untrusted (retrieved docs, tool output, the agent's own writing), enforces a size and rate
        limit, and audits every registration (with a hash of the text) before it takes effect."""
        if not registrar:
            raise TrustedInputRejected("registrar identity required")
        if not message_id or len(message_id) > 128:
            raise TrustedInputRejected("message_id required (max 128 chars)")
        if len(typed_text) > MAX_TYPED_CHARS:
            raise TrustedInputRejected(f"typed text over {MAX_TYPED_CHARS} characters: this is not a typed message")
        sha = hashlib.sha256(typed_text.encode()).hexdigest()
        signed, cred = False, ""
        if attestation is not None or self.require_user_signature:
            # A claim by the front end is not enough: a device key of THIS user must have signed THIS text now.
            try:
                if not (self.user_verifier and actor_user_id and attestation is not None):
                    raise UserAttestationError("a user-device attestation and actor_user_id are required")
                cred = self.user_verifier.verify(attestation, session_id=session_id, message_id=message_id,
                                                 actor=actor_user_id, typed_text=typed_text)
                signed = True
            except UserAttestationError as exc:
                self._session_audit(session_id, registrar, "session:register_trusted_input",
                                    f"REFUSED: user attestation rejected ({exc})", ["R-USER-ATTESTATION"],
                                    decision="deny", sha=sha)
                raise TrustedInputRejected(f"user attestation rejected: {exc}") from exc
        if actor_user_id and not self.trusted.bind_actor(session_id, actor_user_id):
            self._session_audit(session_id, registrar, "session:register_trusted_input",
                                f"REFUSED: session already belongs to a different user than {actor_user_id}",
                                ["R-TRUSTED-INPUT-ACTOR"], decision="deny", sha=sha)
            raise TrustedInputRejected("this session is bound to a different user")
        overlap = self.corpus.overlap(session_id, typed_text)
        if overlap:
            self._session_audit(session_id, registrar, "session:register_trusted_input",
                                f"REFUSED: typed text shares {overlap} passage(s) with untrusted content "
                                f"(front end forwarding non-typed text?)", ["R-TRUSTED-INPUT-OVERLAP"],
                                decision="deny", sha=sha)
            raise TrustedInputRejected("typed text overlaps content previously seen as untrusted; "
                                       "pasted or retrieved text must be sent as an attachment")
        if not self.trusted.rate_ok(session_id):
            raise TrustedInputRejected("too many trusted-input registrations for this session")
        if not self.trusted.claim_message(session_id, message_id):
            raise TrustedInputRejected("message_id already registered (replay)")
        for att in attachments:  # screened, fingerprinted as untrusted, never trusted
            self.ingest_untrusted(att, source="attachment", session_id=session_id)
        entities = extract_entities(typed_text)
        self._session_audit(session_id, registrar, "session:register_trusted_input",
                            f"registered {len(entities)} destination(s): {', '.join(sorted(entities)) or '-'}"
                            + (f" [user-signed, credential {cred}]" if signed else " [front-end asserted, unsigned]"),
                            ["R-TRUSTED-INPUT"], sha=sha)
        self.trusted.register(session_id, typed_text, signed=signed)
        # what the human typed also counts as data in the session (they may have typed something sensitive)
        rank = LABELS[self.dlp.classify_data(typed_text).value]
        if rank:
            self.guard.raise_label(session_id, rank, f"user_input:{LABEL_NAMES[rank]}")
        return entities

    def declassify(self, session_id: str, reviewer: str, to_label: str, reason: str) -> None:
        """Reviewer-gated: lower a session's data-label high-water mark after a human has judged that the
        session's context no longer carries data above `to_label`. Audited before it takes effect."""
        target = label_rank(to_label)
        current = self.guard.state(session_id).data_label
        if not reviewer or not reason.strip():
            raise ValueError("reviewer and reason are required to declassify")
        if target >= current:
            raise ValueError("declassification can only lower the label")
        self._session_audit(session_id, reviewer, "session:declassify",
                            f"label {LABEL_NAMES[current]} -> {to_label} by {reviewer}: {reason}", ["R-DECLASSIFY"])
        self.guard.set_label(session_id, target)

    def _session_audit(self, session_id: str, actor: str, capability: str, reason: str, rules: list[str],
                       decision: str = "allow", sha: str = "") -> None:
        """Audit-before-effect for session-level administrative actions (raises AuditUnavailable)."""
        self.evidence.append(AgentSecurityEvent(
            agent_id="gateway", actor_user_id=actor, task_id="-", session_id=session_id,
            capability=capability, resource=f"session:{session_id}", decision=decision, event_type="security",
            reason=reason, rule_ids=rules, timestamp=self._clock(), approver_ids=[actor], arguments_sha256=sha))

    def issue_canary(self, session_id: str) -> str:
        """Returns a token to embed in the system prompt. Seeing it in any outbound argument = exfiltration."""
        return self.canaries.issue(session_id)

    def clear_taint(self, session_id: str, reviewer: str, reason: str) -> None:
        """Reviewer-gated: lift taint after a human has inspected the session. Audited before it takes effect."""
        if not reviewer or not reason.strip():
            raise ValueError("reviewer and reason are required to clear taint")
        self._session_audit(session_id, reviewer, "session:clear_taint",
                            f"taint cleared by {reviewer}: {reason}", ["R-TAINT-CLEAR"])
        self.guard.clear_taint(session_id)

    def ingest_untrusted(self, text: str, request_ctx: ActionRequest | None = None, source: str = "external",
                         session_id: str | None = None) -> ScanResult:
        """Wrap and screen external content (web, email, RAG, API responses) before it reaches the LLM.

        A suspicious or malicious verdict TAINTS the session: from then on every action, even
        low-risk ones, needs human approval until the session is cleared by a reviewer."""
        scan = self.injection.scan(text)
        sid = session_id or (request_ctx.identity.session_id if request_ctx else None)
        if sid:
            self.corpus.add(sid, text)
        if not scan.clean:
            if sid:
                self.guard.mark_tainted(sid)
            if request_ctx is not None:
                self._audit_post(self._event(
                    request_ctx, event_type="security", decision="deny",
                    reason=f"prompt injection ({scan.verdict}) in {source}: {','.join(scan.matches)}",
                    rule_ids=["R-INJECTION"]))
        return scan

    # ---------------------------------------------------------------- internals
    def _execute(self, req: ActionRequest, approval_id: str | None) -> GatewayResponse:
        ident = req.identity

        # 1. throttle, breakers, replay
        ok, why = self.guard.pre_check(ident.session_id, ident.task_id, req.step)
        if not ok:
            try:
                return self._deny(req, why, ["R-CIRCUIT"])
            except AuditUnavailable:  # the halt itself may be caused by a broken log; keep the real reason visible
                return GatewayResponse(Decision.DENY, f"{why}; audit log unavailable")

        if req.capability in self.disabled_capabilities:
            return self._deny(req, "capability disabled by incident response", ["R-TOOL-DISABLED"])
        if self.broker.revocations.is_identity_revoked(ident.agent_id, ident.session_id):
            return self._deny(req, "agent or session revoked", ["R-REVOKED"])

        adapter = self.adapters.get(req.tool)
        if adapter is None or adapter.capability != req.capability:
            return self._deny(req, "unknown tool or capability mismatch", ["R-NO-ADAPTER"])

        # 2. schema pre-validation (reject malformed payloads before anything else)
        try:
            adapter.schema(**req.arguments)
        except ValidationError as exc:
            return self._deny(req, f"schema validation failed ({exc.error_count()} errors)", ["R-SCHEMA"])

        for t in walk_strings(req.arguments):  # agent-written text is never "typed by the human"
            self.corpus.add(ident.session_id, t)

        # 2b. deterministic data-flow checks (hold even if every detector misses)
        leaked = self.canaries.leaked(ident.session_id, walk_strings(req.arguments))
        if leaked:
            self.guard.mark_tainted(ident.session_id)
            return self._deny(req, "canary token found in outbound arguments: context exfiltration attempt",
                              ["R-CANARY"])
        st = self.guard.state(ident.session_id)
        bad_dest, dest_infos = check_destinations(
            adapter.egress_params, req.arguments, ident.session_id, self.egress_domains, self.trusted,
            session_label=st.data_label, clearances=self.flow.clearances,
            default_clearance=self.flow.default_clearance, trusted_clearance=self.flow.trusted_clearance)
        if bad_dest:
            rule = "R-LABEL" if bad_dest.startswith("data-flow violation") else "R-DESTINATION"
            return self._deny(req, bad_dest, [rule])
        if any(d["origin"] != "allowlist" for d in dest_infos):
            owner = self.trusted.bound_actor(ident.session_id)
            if owner is not None and owner != ident.actor_user_id:
                return self._deny(req, "destination was granted by a different user than the one making this request",
                                  ["R-DESTINATION"])
        egress_bytes, egress_trace, egress_text = 0, {}, ""
        if adapter.egress_params:
            egress_bytes = sum(len(t.encode()) for t in walk_strings(req.arguments))
            over = self._egress_budget_violation(st, egress_bytes, dest_infos)
            if over:
                return self._deny(req, over, ["R-EGRESS-BUDGET"])
            rel = release_violation(dest_infos, self.sources.sources(ident.session_id), self.flow.release_rules)
            if rel:
                return self._deny(req, rel, ["R-RELEASE"])
            egress_text = "\n".join(walk_strings(req.arguments))
            egress_trace = self.sources.trace(ident.session_id, egress_text)
            bulk = self._bulk_copy_violation(egress_trace)
            if bulk:
                return self._deny(req, bulk, ["R-BULK-COPY"])

        # 3. DLP + exfiltration detection on outbound arguments
        arg_text = repr(req.arguments)
        if req.capability in EGRESS_CAPABILITIES and \
                self.dlp.classify_data(arg_text) is DataClassification.RESTRICTED:
            return self._deny(req, "restricted data in outbound arguments", ["R-DLP"])
        findings = self.exfil.scan(req.arguments)
        if findings:
            kinds = ",".join(sorted({f.kind for f in findings}))
            return self._deny(req, f"suspected exfiltration ({kinds})", ["R-EXFIL"])

        # 4. Policy Decision Point
        decision = self.pdp.evaluate(req)

        if decision.decision is Decision.DENY:
            self._log_decision(req, decision)
            self.guard.record_result(ident.session_id, ident.task_id, req.step, success=False)
            return GatewayResponse(Decision.DENY, decision.reason, decision.risk_tier)

        # 4b. tainted session: injection signals were seen, so what may still run is restricted per tier.
        # (taint_policy: 'deny' removes the capability outright; otherwise a human must approve.)
        if self.guard.is_tainted(ident.session_id):
            tier = decision.risk_tier.value if decision.risk_tier else "critical"
            if self.taint_policy.get(tier, "deny") == "deny":
                return self._deny(
                    req, f"session tainted by suspected prompt injection; {tier}-risk actions are blocked",
                    decision.rule_ids + ["R-TAINT-DENY"])
            if decision.decision is Decision.ALLOW:
                decision = decision.model_copy(update={
                    "decision": Decision.REQUIRE_APPROVAL,
                    "reason": "session tainted by suspected prompt injection; human approval required",
                    "rule_ids": decision.rule_ids + ["R-TAINT"]})

        # 5. approval flow
        approval_rec = None
        if decision.decision is Decision.REQUIRE_APPROVAL:
            if approval_id is None:
                st_now = self.guard.state(ident.session_id)
                rec = self.approvals.create(req, decision.risk_tier, context={  # type: ignore[arg-type]
                    "session_data_label": LABEL_NAMES[st_now.data_label],
                    "label_sources": st_now.label_sources,
                    "session_tainted": st_now.tainted,
                    "destinations": dest_infos,
                    "egress_so_far": {"messages": st_now.egress_messages, "bytes": st_now.egress_bytes,
                                      "destinations": st_now.egress_dests},
                    "content_trace": egress_trace,  # how much of this message is copied from which source
                    "new_destinations": sorted({d["destination"] for d in dest_infos} - set(st_now.egress_dests)),
                    "user_typed_destinations": [d["destination"] for d in dest_infos if d["origin"] != "allowlist"],
                }, required_approvers=self._egress_approvers(adapter, st_now))
                decision.approval_id = rec.approval_id
                self._log_decision(req, decision)
                return GatewayResponse(
                    Decision.REQUIRE_APPROVAL, decision.reason, decision.risk_tier,
                    approval_id=rec.approval_id, approval_preview=rec.summary,
                )
            state, why, wait = self.approvals.status(approval_id, req)
            if state == "cooling":  # approved but not yet executable: not a failure, just wait
                return GatewayResponse(Decision.REQUIRE_APPROVAL, why, decision.risk_tier,
                                       approval_id=approval_id, retry_after=round(wait, 1))
            if state != "ok":
                self._log_decision(req, DecisionResult(
                    decision=Decision.DENY, risk_tier=decision.risk_tier, reason=why,
                    rule_ids=decision.rule_ids + ["R-APPROVAL"], policy_version=decision.policy_version))
                return GatewayResponse(Decision.DENY, f"approval invalid: {why}", decision.risk_tier)
            approval_rec = self.approvals.get(approval_id)
            decision = decision.model_copy(update={"decision": Decision.ALLOW,
                                                   "reason": "approved by human reviewer(s)",
                                                   "approval_id": approval_id})

        # 6. JIT credentials (only against a PDP-signed ALLOW)
        grant = self.signer.sign(req, decision)
        try:
            token = self.broker.issue(req, grant)
        except BrokerError as exc:
            return self._deny(req, f"credential issuance refused: {exc}", ["R-BROKER"])

        # 7. execute through the hardened adapter
        self._log_decision(req, decision, approval_rec=approval_rec)
        t0 = time.perf_counter()
        needs_approval = approval_rec is not None
        try:
            raw = adapter.invoke(req, token, approval_id=approval_id, require_approval=needs_approval)
        except AdapterError as exc:
            self.guard.record_result(ident.session_id, ident.task_id, req.step, success=False)
            self._audit_post(self._event(
                req, event_type="execution", decision="deny", reason=str(exc),
                rule_ids=["R-ADAPTER"], execution_status="failed",
                execution_duration_ms=(time.perf_counter() - t0) * 1000))
            return GatewayResponse(Decision.DENY, str(exc), decision.risk_tier)

        # output guardrail
        out_text = raw if isinstance(raw, str) else repr(raw)
        if out_text:
            self.corpus.add(ident.session_id, out_text)
        out_scan = self.injection.scan(out_text) if out_text else None
        if out_scan is not None and not out_scan.clean:  # tool output is untrusted: taint, don't block
            self.guard.mark_tainted(ident.session_id)
            self._audit_post(self._event(
                req, event_type="security", decision="deny",
                reason=f"injection signals in tool output ({out_scan.verdict})", rule_ids=["R-INJECTION-OUTPUT"]))
        protected, cls = self.dlp.protect(out_text, Operation.OUTPUT)
        dlp_applied = protected != out_text
        if adapter.egress_params:  # data leaving: account for it against the session's egress budget
            self.guard.record_egress(ident.session_id, egress_bytes, [d["destination"] for d in dest_infos])
            self.sources.mark_sent(ident.session_id, egress_text)
        else:  # data entering the agent's context: the session now carries at least this sensitivity
            rank = max(self.flow.source_label(req.resource), LABELS[cls.value])
            self.sources.record(ident.session_id, req.resource, out_text)
            self.guard.raise_label(ident.session_id, rank, f"{req.resource}:{LABEL_NAMES[rank]}")
        result: Any = protected if isinstance(raw, str) else (raw if not dlp_applied else protected)

        self.guard.record_result(ident.session_id, ident.task_id, req.step, success=True,
                                 cost_usd=EST_COST_PER_CALL_USD)
        self._audit_post(self._event(
            req, event_type="execution", decision="allow", reason="executed",
            rule_ids=decision.rule_ids, execution_status="success",
            execution_duration_ms=(time.perf_counter() - t0) * 1000,
            payload_bytes=len(out_text.encode()), dlp_applied=dlp_applied,
            approval_rec=approval_rec, risk_tier=decision.risk_tier))
        if result is None:
            result = ""
        return GatewayResponse(Decision.ALLOW, decision.reason, decision.risk_tier,
                               approval_id=approval_id, result=result if result != "" else "")

    def _egress_approvers(self, adapter, st) -> int | None:
        """Data leaving a tainted session, or one that has handled data at/above the configured label, needs two people."""
        if adapter.egress_params and (st.tainted or st.data_label >= self.flow.dual_approval_label):
            return 2
        return None

    def _bulk_copy_violation(self, trace: dict) -> str | None:
        lim = self.flow.limits
        pct, min_sh = lim.get("max_source_coverage_pct"), lim.get("min_source_shingles", 5)
        if pct is None:
            return None
        for row in trace.get("verbatim_from", []):
            if row["source_shingles"] >= min_sh and row["pct_of_source_cumulative"] >= pct and \
                    self.flow.source_label(row["source"]) > 0:
                return (f"bulk copy: {row['pct_of_source_cumulative']}% of '{row['source']}' would have been sent verbatim "
                        f"in this session including this message (limit {pct}% for non-public sources)")
        return None

    def _egress_budget_violation(self, st, nbytes: int, dest_infos: list[dict]) -> str | None:
        lim = self.flow.limits
        if "max_bytes_per_message" in lim and nbytes > lim["max_bytes_per_message"]:
            return f"egress budget: message of {nbytes} bytes exceeds the {lim['max_bytes_per_message']}-byte limit"
        if "max_messages_per_session" in lim and st.egress_messages + 1 > lim["max_messages_per_session"]:
            return f"egress budget: session already sent {st.egress_messages} messages (limit {lim['max_messages_per_session']})"
        if "max_bytes_per_session" in lim and st.egress_bytes + nbytes > lim["max_bytes_per_session"]:
            return f"egress budget: session byte limit {lim['max_bytes_per_session']} would be exceeded"
        new = {d["destination"] for d in dest_infos} - set(st.egress_dests)
        if "max_new_destinations_per_session" in lim and \
                len(st.egress_dests) + len(new) > lim["max_new_destinations_per_session"]:
            return f"egress budget: at most {lim['max_new_destinations_per_session']} distinct destinations per session"
        return None

    # ----------------------------------------------------------------- logging
    def _deny(self, req: ActionRequest, reason: str, rules: list[str]) -> GatewayResponse:
        res = DecisionResult(decision=Decision.DENY, reason=reason, rule_ids=rules,
                             policy_version=self.pdp.policy_version)
        self._log_decision(req, res)
        self.guard.record_result(req.identity.session_id, req.identity.task_id, req.step, success=False)
        return GatewayResponse(Decision.DENY, reason)

    def _log_decision(self, req: ActionRequest, res: DecisionResult, approval_rec=None) -> None:
        self.evidence.append(self._event(
            req, event_type="decision", decision=res.decision.value, reason=res.reason,
            rule_ids=res.rule_ids, risk_tier=res.risk_tier, latency=res.latency_ms,
            failure_mode=res.failure_mode, approval_rec=approval_rec, policy_version=res.policy_version))

    def _event(self, req: ActionRequest, *, event_type: str, decision: str, reason: str,
               rule_ids: list[str], risk_tier: RiskTier | None = None, latency: float = 0.0,
               failure_mode: str | None = None, approval_rec=None, policy_version: str | None = None,
               execution_status: str | None = None, execution_duration_ms: float | None = None,
               payload_bytes: int | None = None, dlp_applied: bool = False) -> AgentSecurityEvent:
        i = req.identity
        return AgentSecurityEvent(
            agent_id=i.agent_id, actor_user_id=i.actor_user_id, task_id=i.task_id,
            session_id=i.session_id, environment=i.environment,
            capability=req.capability, resource=req.resource,
            arguments_redacted=self.evidence.redact_args(req.arguments),
            arguments_sha256=req.args_hash(),
            risk_tier=risk_tier.value if risk_tier else None, justification=req.justification,
            policy_version=policy_version or self.pdp.policy_version, rule_ids=rule_ids,
            decision=decision, evaluation_latency_ms=latency, failure_mode=failure_mode,
            reason=reason, timestamp=self._clock(), event_type=event_type,
            execution_status=execution_status, execution_duration_ms=execution_duration_ms,
            payload_bytes=payload_bytes, dlp_applied=dlp_applied,
            approver_ids=list(approval_rec.approvers) if approval_rec else [],
            approval_decided_at=approval_rec.approved_at if approval_rec else None,
            approval_rationale=list(approval_rec.rationales) if approval_rec else [],
            approval_token_id=approval_rec.approval_id if approval_rec else None,
            approval_expires_at=approval_rec.expires_at if approval_rec else None,
        )
