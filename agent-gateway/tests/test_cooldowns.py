"""Approval cooldowns: recall window, retry_after, cancel, execution window."""
import pytest

from agent_gateway.approvals import ApprovalError, ApprovalStore
from agent_gateway.models import Decision, RiskTier

from conftest import drop_req, email_req, pr_req

MGR, MGR2 = "user:manager@enterprise.com", "user:director@enterprise.com"


def test_high_risk_blocked_during_cooldown_then_allowed(stack, gw, clock):
    first = gw.execute(email_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    early = gw.execute(email_req(step=2), approval_id=first.approval_id)
    assert early.decision is Decision.REQUIRE_APPROVAL and 0 < early.retry_after <= 30
    assert "cooldown" in early.reason
    clock.advance(31)
    assert gw.execute(email_req(step=3), approval_id=first.approval_id).decision is Decision.ALLOW


def test_cooldown_wait_is_not_a_failure_and_does_not_burn_approval(stack, gw, clock):
    first = gw.execute(email_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    for i in range(8):  # an impatient agent polling must not trip the retry breaker
        assert gw.execute(email_req(step=2 + i), approval_id=first.approval_id).decision is Decision.REQUIRE_APPROVAL
    assert stack.guard.state("sess-4f8a2b").consecutive_failures == 0
    clock.advance(31)
    assert gw.execute(email_req(step=20), approval_id=first.approval_id).decision is Decision.ALLOW


def test_critical_cooldown_longer_and_counts_from_final_approval(stack, gw, clock):
    first = gw.execute(drop_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    clock.advance(100)  # first approver was slow; the clock must restart at the SECOND approval
    stack.approvals.approve(first.approval_id, MGR2, step_up_verified=True)
    clock.advance(60)
    assert gw.execute(drop_req(step=2), approval_id=first.approval_id).decision is Decision.REQUIRE_APPROVAL
    clock.advance(61)
    assert gw.execute(drop_req(step=3), approval_id=first.approval_id).decision is Decision.ALLOW


def test_cancel_during_cooldown_blocks_execution(stack, gw, clock):
    first = gw.execute(email_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    stack.approvals.reject(first.approval_id, "user:shyam@enterprise.com", "changed my mind")
    clock.advance(31)
    resp = gw.execute(email_req(step=2), approval_id=first.approval_id)
    assert resp.decision is Decision.DENY and "cancel" in resp.reason


def test_cannot_cancel_after_consumption(stack, gw, clock):
    first = gw.execute(email_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    clock.advance(31)
    assert gw.execute(email_req(step=2), approval_id=first.approval_id).decision is Decision.ALLOW
    with pytest.raises(ApprovalError, match="too late"):
        stack.approvals.reject(first.approval_id, MGR)


def test_execution_window_runs_from_final_approval(stack, gw, clock):
    first = gw.execute(email_req())
    clock.advance(250)  # slow review: still inside the 300s review window
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    clock.advance(31)  # 281s after creation: would have expired under a creation-based window
    assert gw.execute(email_req(step=2), approval_id=first.approval_id).decision is Decision.ALLOW


def test_unused_approval_expires_300s_after_grant(stack, gw, clock):
    first = gw.execute(email_req())
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    clock.advance(301)
    assert gw.execute(email_req(step=2), approval_id=first.approval_id).decision is Decision.DENY


def test_medium_has_no_cooldown_and_config_is_validated(stack, gw):
    first = gw.execute(pr_req())
    stack.approvals.approve(first.approval_id, "user:lead@enterprise.com")
    assert gw.execute(pr_req(step=2), approval_id=first.approval_id).decision is Decision.ALLOW
    with pytest.raises(ValueError):
        ApprovalStore(cooldowns={RiskTier.HIGH: 300})  # cooldown must leave an execution window
    with pytest.raises(ValueError):
        ApprovalStore(cooldowns={RiskTier.HIGH: -1})


def test_policy_file_sets_cooldowns(stack):
    assert stack.approvals._cooldowns[RiskTier.HIGH] == 30
    assert stack.approvals._cooldowns[RiskTier.CRITICAL] == 120
