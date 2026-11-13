"""Information-flow control: data labels, destination clearance (no write-down), egress budgets."""
import json
from pathlib import Path

import pytest

from agent_gateway.factory import build_stack
from agent_gateway.models import Decision
from agent_gateway.policy import PolicyConfig

from conftest import REPORT, Clock, email_req, read_req

MGR = "user:manager@enterprise.com"
BOARD = "/app/reports/board-minutes.csv"
POLICY = json.loads((Path(__file__).resolve().parents[1] / "config" / "policy.json").read_text())


def make(clock, fs=None, **overrides):
    raw = json.loads(json.dumps(POLICY))
    for k, v in overrides.items():
        raw[k] = {**raw.get(k, {}), **v} if isinstance(v, dict) else v
    files = {REPORT: "region,total\nEMEA,100\n", BOARD: "Board minutes: acquisition plan", **(fs or {})}
    return build_stack(clock=clock, policy=PolicyConfig.from_dict(raw), fs=files)


def mail(to="ext@partner.com", step=1, body="figures attached"):
    r = email_req(body=body, step=step)
    return r.model_copy(update={"arguments": {**r.arguments, "to": to}})


def send(st, clock, req, approver=MGR):
    first = st.gateway.execute(req)
    assert first.decision is Decision.REQUIRE_APPROVAL, first.reason
    st.approvals.approve(first.approval_id, approver, step_up_verified=True)
    clock.advance(31)
    return st.gateway.execute(req.model_copy(update={"step": req.step + 50}), approval_id=first.approval_id)


@pytest.fixture
def clk():
    return Clock()


def label_conf(clock, **kw):
    return make(clock, data_labels=[{"pattern": "file:/app/reports/board-*", "label": "confidential"},
                                    {"pattern": "file:/app/reports/*", "label": "internal"}], **kw)


def test_internal_data_can_go_to_internal_cleared_partner(clk):
    st = make(clk)
    assert st.gateway.execute(read_req(path=REPORT, step=1)).decision is Decision.ALLOW
    assert st.guard.state("sess-4f8a2b").data_label == 1  # internal
    assert send(st, clk, mail(step=2)).decision is Decision.ALLOW


def test_confidential_data_cannot_flow_to_partner_even_when_agent_is_convinced(clk):
    st = label_conf(clk)
    assert st.gateway.execute(read_req(path=BOARD, step=1)).decision is Decision.ALLOW
    assert st.guard.state("sess-4f8a2b").data_label == 2
    r = st.gateway.execute(mail("ext@partner.com", step=2))
    assert r.decision is Decision.DENY and "data-flow violation" in r.reason
    # ... but the enterprise's own domain is cleared for confidential
    assert st.gateway.execute(mail("cfo@enterprise.com", step=3)).decision is Decision.REQUIRE_APPROVAL


def test_label_is_session_wide_high_water_mark_not_per_message(clk):
    st = label_conf(clk)
    st.gateway.execute(read_req(path=BOARD, step=1))
    st.gateway.execute(read_req(path=REPORT, step=2))  # reading a lower-label file does not lower it
    assert st.guard.state("sess-4f8a2b").data_label == 2


def test_dlp_content_classification_raises_label_beyond_resource_label(clk):
    st = make(clk, fs={"/app/reports/hr.csv": "team salary bands: L3 120k"})
    r = st.gateway.execute(read_req(path="/app/reports/hr.csv", step=1))
    assert r.decision is Decision.ALLOW
    assert st.guard.state("sess-4f8a2b").data_label == 2  # content said 'salary' -> confidential
    assert st.gateway.execute(mail(step=2)).decision is Decision.DENY


def test_restricted_data_can_never_leave_to_any_destination(clk):
    st = make(clk, fs={"/app/reports/pii.csv": "ssn 123-45-6789"})
    st.gateway.execute(read_req(path="/app/reports/pii.csv", step=1))
    assert st.guard.state("sess-4f8a2b").data_label == 3
    for to in ("ext@partner.com", "cfo@enterprise.com"):
        assert st.gateway.execute(mail(to, step=hash(to) % 500 + 2)).decision is Decision.DENY


def test_user_typed_destination_gets_trusted_clearance_not_blank_check(clk):
    st = label_conf(clk)
    st.gateway.register_trusted_input("sess-4f8a2b", "send the numbers to carol@client-co.org",
                                      message_id="m1", registrar="svc:chat")
    st.gateway.execute(read_req(path=REPORT, step=1))  # internal
    assert st.gateway.execute(mail("carol@client-co.org", step=2)).decision is Decision.REQUIRE_APPROVAL
    st.gateway.execute(read_req(path=BOARD, step=3))  # now confidential
    r = st.gateway.execute(mail("carol@client-co.org", step=4))
    assert r.decision is Decision.DENY and "data-flow violation" in r.reason


def test_reviewer_declassification_is_audited_and_only_lowers(clk):
    st = label_conf(clk)
    st.gateway.execute(read_req(path=BOARD, step=1))
    with pytest.raises(ValueError):
        st.gateway.declassify("sess-4f8a2b", "sec@enterprise.com", "restricted", "x")
    with pytest.raises(ValueError):
        st.gateway.declassify("sess-4f8a2b", "sec@enterprise.com", "internal", "  ")
    st.gateway.declassify("sess-4f8a2b", "sec@enterprise.com", "internal", "board data purged from context")
    assert st.guard.state("sess-4f8a2b").data_label == 1
    assert any(e.capability == "session:declassify" for e in st.evidence.events())
    assert st.gateway.execute(mail(step=2)).decision is Decision.REQUIRE_APPROVAL


def test_sending_does_not_raise_label_and_failed_reads_do_not(clk):
    st = label_conf(clk)
    send(st, clk, mail())
    assert st.guard.state("sess-4f8a2b").data_label == 0
    st.gateway.execute(read_req(path="/app/reports/.env", step=9))  # denied read
    assert st.guard.state("sess-4f8a2b").data_label == 0


# ------------------------------------------------------------ egress budgets
def test_message_count_budget(clk):
    st = make(clk, egress_limits={"max_messages_per_session": 2})
    assert send(st, clk, mail(step=1)).decision is Decision.ALLOW
    assert send(st, clk, mail(step=2)).decision is Decision.ALLOW
    r = st.gateway.execute(mail(step=3))
    assert r.decision is Decision.DENY and "egress budget" in r.reason


def test_per_message_and_total_byte_budgets(clk):
    st = make(clk, egress_limits={"max_bytes_per_message": 300, "max_bytes_per_session": 450})
    assert st.gateway.execute(mail(body="x" * 500)).decision is Decision.DENY
    assert send(st, clk, mail(step=2, body="y" * 200)).decision is Decision.ALLOW
    assert st.gateway.execute(mail(step=3, body="z" * 250)).decision is Decision.DENY  # total would pass 450


def test_distinct_destination_budget_stops_spraying(clk):
    st = make(clk, egress_limits={"max_new_destinations_per_session": 2})
    assert send(st, clk, mail("a@partner.com", step=1)).decision is Decision.ALLOW
    assert send(st, clk, mail("b@partner.com", step=2)).decision is Decision.ALLOW
    assert st.gateway.execute(mail("c@partner.com", step=3)).decision is Decision.DENY
    assert send(st, clk, mail("a@partner.com", step=4)).decision is Decision.ALLOW  # reuse is fine


# --------------------------------------------------------- reviewer context
def test_approval_preview_shows_lineage_and_destination_origin(clk):
    st = label_conf(clk)
    st.gateway.register_trusted_input("sess-4f8a2b", "mail carol@client-co.org", message_id="m1", registrar="svc")
    st.gateway.execute(read_req(path=REPORT, step=1))
    resp = st.gateway.execute(mail("carol@client-co.org", step=2))
    ctx = resp.approval_preview["context"]
    assert ctx["session_data_label"] == "internal" and ctx["session_tainted"] is False
    assert ctx["label_sources"] == [f"file:{REPORT}:internal"]
    assert ctx["destinations"] == [{"destination": "email:carol@client-co.org", "origin": "user_typed", "clearance": "internal"}]
