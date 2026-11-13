from datetime import datetime, timedelta, timezone

import pytest

from agent_gateway.adapters import AdapterError, GitHubCreatePRSchema
from agent_gateway.audit import AgentSecurityEvent, EvidenceStore
from agent_gateway.breakers import ExecutionGuard, check_execution_timeout
from agent_gateway.broker import BrokerError
from agent_gateway.dlp import DataClassification, DataProtectionPolicy
from agent_gateway.incident import contain
from agent_gateway.memory import Provenance, SecureMemoryStore, compute_checksum
from agent_gateway.models import Decision, RiskTier
from agent_gateway.policy import PolicyConfig, PolicyDecisionPoint

from conftest import REPORT, drop_req, pr_req, read_req, email_req


# ------------------------------- policy / fail-closed -------------------------------
def test_pdp_fails_closed_without_config():
    pdp = PolicyDecisionPoint(None)
    res = pdp.evaluate(read_req())
    assert res.decision is Decision.DENY and res.failure_mode == "no_config"


def test_pdp_fails_closed_on_internal_error(stack):
    pdp = stack.gateway.pdp
    pdp._config.capabilities = None  # corrupt state
    assert pdp.evaluate(read_req()).decision is Decision.DENY


def test_wildcard_and_traversal_resources_denied(stack):
    pdp = stack.gateway.pdp
    wild = read_req().model_copy(update={"resource": "file:/app/reports/*"})
    trav = read_req().model_copy(update={"resource": "file:/app/reports/../etc/passwd"})
    assert pdp.evaluate(wild).decision is Decision.DENY
    assert pdp.evaluate(trav).decision is Decision.DENY


def test_resource_outside_scope_denied(stack):
    other = read_req().model_copy(update={"resource": "file:/etc/passwd"})
    assert stack.gateway.pdp.evaluate(other).decision is Decision.DENY


def test_risk_tiers_map_to_decisions(stack):
    pdp = stack.gateway.pdp
    assert pdp.evaluate(read_req()).decision is Decision.ALLOW
    assert pdp.evaluate(pr_req()).decision is Decision.REQUIRE_APPROVAL
    assert pdp.evaluate(email_req()).risk_tier is RiskTier.HIGH
    assert pdp.evaluate(drop_req()).risk_tier is RiskTier.CRITICAL


def test_critical_mode_deny_follows_flowchart(stack):
    cfg = stack.gateway.pdp._config
    cfg.critical_mode = "deny"
    assert stack.gateway.pdp.evaluate(drop_req()).decision is Decision.DENY


# ------------------------------- adapters -------------------------------
def test_low_risk_read_executes_and_logs(gw, stack):
    r = gw.execute(read_req())
    assert r.decision is Decision.ALLOW and "EMEA" in r.result
    assert stack.evidence.verify_chain()[0]


@pytest.mark.parametrize("path", ["/app/reports/.env", "/app/reports/db.key", "/app/reports/my_secret.txt"])
def test_blocked_file_patterns(gw, path):
    assert gw.execute(read_req(path=path)).decision is Decision.DENY


def test_traversal_path_rejected_at_adapter(gw):
    req = read_req().model_copy(update={"arguments": {"path": "/app/reports/../../etc/passwd", "operation": "read"}})
    assert gw.execute(req).decision is Decision.DENY


def test_write_operation_rejected_by_reader(gw):
    req = read_req().model_copy(update={"arguments": {"path": REPORT, "operation": "write"}})
    assert gw.execute(req).decision is Decision.DENY


def test_extra_argument_fields_rejected(gw):
    req = read_req().model_copy(update={"arguments": {"path": REPORT, "operation": "read", "sudo": True}})
    assert gw.execute(req).decision is Decision.DENY


def test_output_dlp_redacts_restricted_content(gw):
    r = gw.execute(read_req(path="/app/reports/leaky.csv", step=1))
    assert r.decision is Decision.ALLOW and r.result == "[REDACTED_RESTRICTED_DATA]"


def test_pr_schema_rules():
    with pytest.raises(ValueError):
        GitHubCreatePRSchema(title="t", head="a b", base="main", body="")
    with pytest.raises(ValueError):
        GitHubCreatePRSchema(title="t", head="feat", base="release", body="")
    GitHubCreatePRSchema(title="t", head="feat/x", base="develop", body="")


def test_medium_pr_flow_end_to_end(stack, gw):
    first = gw.execute(pr_req())
    assert first.decision is Decision.REQUIRE_APPROVAL
    stack.approvals.approve(first.approval_id, "user:lead@enterprise.com")
    done = gw.execute(pr_req(step=2), approval_id=first.approval_id)
    assert done.decision is Decision.ALLOW and done.result["number"] == 1
    ev = [e for e in stack.evidence.events() if e.event_type == "execution"][-1]
    assert ev.approver_ids == ["user:lead@enterprise.com"] and ev.approval_token_id == first.approval_id


# ------------------------------- broker -------------------------------
def test_broker_refuses_without_pdp_grant(stack):
    from agent_gateway.broker import PolicyGrant
    forged = PolicyGrant("x", "allow", 9e12, "bad")
    with pytest.raises(BrokerError):
        stack.broker.issue(read_req(), forged)


def test_broker_ttl_cap_and_no_deny_grants(stack):
    req = read_req()
    res = stack.gateway.pdp.evaluate(req)
    grant = stack.gateway.signer.sign(req, res)
    with pytest.raises(BrokerError):
        stack.broker.issue(req, grant, ttl=301)
    deny_grant = stack.gateway.signer.sign(req, res.model_copy(update={"decision": Decision.DENY}))
    with pytest.raises(BrokerError):
        stack.broker.issue(req, deny_grant)


def test_token_scoped_to_resource_expiry_and_revocation(stack, clock):
    req = read_req()
    grant = stack.gateway.signer.sign(req, stack.gateway.pdp.evaluate(req))
    tok = stack.broker.issue(req, grant)
    stack.broker.validate(tok, req)
    with pytest.raises(BrokerError):
        stack.broker.validate(tok, read_req(path="/app/reports/other.csv"))
    stack.broker.revoke_active_for(agent_id=req.identity.agent_id)
    with pytest.raises(BrokerError, match="revoked"):
        stack.broker.validate(tok, req)
    assert "secret" not in repr(tok)


def test_token_expires(stack, clock):
    req = read_req()
    tok = stack.broker.issue(req, stack.gateway.signer.sign(req, stack.gateway.pdp.evaluate(req)))
    clock.advance(301)
    with pytest.raises(BrokerError, match="expired"):
        stack.broker.validate(tok, req)


# ------------------------------- DLP -------------------------------
@pytest.mark.parametrize("text,cls", [
    ("ssn 123-45-6789", DataClassification.RESTRICTED),
    ("password = hunter2", DataClassification.RESTRICTED),
    ("employee salary review", DataClassification.CONFIDENTIAL),
    ("mail bob@enterprise.com", DataClassification.INTERNAL),
    ("hello world", DataClassification.PUBLIC),
])
def test_classification(text, cls):
    assert DataProtectionPolicy().classify_data(text) is cls


def test_protection_matrix():
    p = DataProtectionPolicy()
    c = DataClassification
    assert p.apply_protection("x", c.RESTRICTED, "log") == "[REDACTED_RESTRICTED_DATA]"
    assert p.apply_protection("salary info", c.CONFIDENTIAL, "log") == "[REDACTED_CONFIDENTIAL_LOG]"
    assert p.apply_protection("salary info", c.CONFIDENTIAL, "output") == "sa*******fo"
    assert p.apply_protection("bob@enterprise.com", c.INTERNAL, "log").startswith("bo")
    assert p.apply_protection("bob@enterprise.com", c.INTERNAL, "output") == "bob@enterprise.com"


# ------------------------------- memory -------------------------------
KW = dict(actor_user_id="u1", tenant_id="t1", session_id="s1")


def test_memory_partitioning(stack):
    stack.memory.write("mine", provenance=Provenance.USER, origin="chat", **KW)
    assert stack.memory.read(actor_user_id="u2", tenant_id="t1", session_id="s1") == []
    assert stack.memory.read(actor_user_id="u1", tenant_id="t2", session_id="s1") == []
    assert stack.memory.read(actor_user_id="u1", tenant_id="t1", session_id="s2") == []
    assert len(stack.memory.read(**KW)) == 1


def test_memory_checksum_format_and_tamper_detection(stack):
    rec = stack.memory.write("fact", provenance=Provenance.TOOL_OUTPUT, origin="/app/reports/x", **KW)
    assert len(rec.checksum) == 16 and int(rec.checksum, 16) >= 0
    rec.content = "poisoned fact"  # tamper at rest
    assert stack.memory.read(**KW) == [] and rec.quarantined


def test_memory_redaction_ttl_and_provenance(stack, clock):
    rec = stack.memory.write("card 4111111111111111 ok", provenance=Provenance.RETRIEVED_DOC, origin="web", ttl=10**9, **KW)
    assert "4111111111111111" not in rec.content
    assert rec.expires_at - rec.created_at == 24 * 3600  # TTL clamped
    assert rec.trust.value == "untrusted"
    clock.advance(24 * 3600 + 1)
    assert stack.memory.read(**KW) == []


def test_checksum_formula():
    import hashlib, hmac
    expect = hmac.new(b"k", b"hellou1", hashlib.sha256).hexdigest()[:16]
    assert compute_checksum("hello", "u1", b"k") == expect


# ------------------------------- breakers -------------------------------
def test_timeout_uses_total_seconds_not_seconds_attr():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    now = start + timedelta(days=1, seconds=10)
    assert (now - start).seconds == 10  # the trap
    assert check_execution_timeout(start, 3600, now=now) is True


def test_throttle_and_siem_alert_thresholds(clock):
    alerts = []
    g = ExecutionGuard(clock=clock, on_alert=lambda s, m: alerts.append(m))
    for i in range(1, 100 + 1):
        assert g.pre_check("s", "t", i)[0]
        if i == 29:
            assert not alerts
        if i == 30:
            assert len(alerts) == 1  # alert fires well before the hard limit
    assert not g.pre_check("s", "t", 101)[0]
    clock.advance(61)
    assert g.pre_check("s", "t", 102)[0]
    assert len(alerts) == 1  # no alert spam


# ------------------------------- audit -------------------------------
def test_evidence_chain_detects_tampering(stack, gw):
    gw.execute(read_req(step=1))
    gw.execute(read_req(step=2))
    assert stack.evidence.verify_chain() == (True, None)
    stack.evidence._entries[1]["payload"] = stack.evidence._entries[1]["payload"].replace("allow", "deny")
    ok, bad = stack.evidence.verify_chain()
    assert not ok and bad == 1


def test_audit_redacts_arguments(stack, gw):
    gw.execute(email_req(body="password = hunter2"))
    logged = [e for e in stack.evidence.events()][-1]
    assert "hunter2" not in logged.model_dump_json()


# ------------------------------- incident response -------------------------------
def test_containment_playbook(stack, gw):
    req = read_req()
    tok = stack.broker.issue(req, gw.signer.sign(req, gw.pdp.evaluate(req)))
    stack.memory.write("note", provenance=Provenance.TOOL_OUTPUT, origin="x", actor_user_id="u", tenant_id="t", session_id=req.identity.session_id)
    halted = []
    rep = contain(gw, agent_id=req.identity.agent_id, session_id=req.identity.session_id,
                  memory=stack.memory, disable_capabilities=["email:send_external"],
                  halt_orchestrator=halted.append)
    assert rep.revoked_tokens >= 1 and rep.quarantined_memory_entries == 1 and halted
    with pytest.raises(BrokerError):
        stack.broker.validate(tok, req)
    assert gw.execute(read_req(step=9)).decision is Decision.DENY  # session halted
    assert rep.timeline is not None
