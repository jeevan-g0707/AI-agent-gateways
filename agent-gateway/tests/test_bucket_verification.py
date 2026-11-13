"""The gateway checks the audit bucket itself instead of trusting that it was configured as documented."""
import pytest

from agent_gateway.audit_guard import AuditWatchdog, ProductionProfileError, validate_production_profile
from agent_gateway.audit_sinks import ObjectLockSink
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision

from conftest import Clock, read_req
from s3fake import FakeS3


def sink(s3=None, **kw):
    return ObjectLockSink(s3 or FakeS3(), "bkt", "gw", clock=Clock(), **kw)


def test_correctly_configured_bucket_has_no_problems():
    assert sink().verify_bucket(min_retention_days=30) == []


def test_object_lock_not_enabled_on_bucket():
    s3 = FakeS3()
    s3.lock_enabled = False
    assert any("Object Lock" in p for p in sink(s3).verify_bucket())


def test_governance_mode_sink_and_governance_bucket_default_are_flagged():
    assert any("GOVERNANCE" in p for p in sink(mode="GOVERNANCE").verify_bucket())
    s3 = FakeS3()
    s3.default_mode = "GOVERNANCE"
    assert any("default retention is GOVERNANCE" in p for p in sink(s3).verify_bucket())


def test_short_retention_is_flagged_on_sink_and_on_bucket():
    assert any("below the required 365" in p for p in sink(retention_days=7).verify_bucket(min_retention_days=365))
    s3 = FakeS3()
    s3.default_days = 1
    assert any("bucket default retention is 1 days" in p for p in sink(s3).verify_bucket(min_retention_days=30))


def test_versioning_must_be_enabled():
    s3 = FakeS3()
    s3.versioning = None
    assert any("versioning" in p for p in sink(s3).verify_bucket())


def test_probe_detects_a_bucket_that_lets_locked_objects_be_deleted_or_shortened():
    s3 = FakeS3()
    s3.enforce_lock = False  # lock "enabled" on paper, but IAM/bucket policy lets someone delete or shorten
    probs = sink(s3).verify_bucket()
    assert any("DELETED" in p for p in probs) and any("SHORTENED" in p for p in probs)


def test_probe_only_ever_touches_its_own_object_never_audit_entries():
    s3 = FakeS3()
    s = sink(s3)
    from agent_gateway.audit import AgentSecurityEvent, EvidenceStore
    ev = EvidenceStore(b"k" * 32, sinks=[s])
    for i in range(3):
        ev.append(AgentSecurityEvent(agent_id="a", actor_user_id="u", task_id="t", session_id="s",
                                     capability="files:read", resource=f"file:/app/reports/{i}", decision="allow"))
    before = {k for k in s3.objects if "/entries/" in k}
    s3.enforce_lock = False  # worst case: the probe really does delete what it touches
    s.verify_bucket()
    assert {k for k in s3.objects if "/entries/" in k} == before and s.entry_count() == 3  # entries untouched
    assert not [k for k in s3.objects if "_probe" in k]  # the (deletable) probe cleaned itself up
    assert len(list(s.entries())) == 3  # and probes never appear as audit entries


def test_probe_write_failure_and_unreadable_config_are_reported_not_raised():
    s3 = FakeS3()
    s3.fail_puts = True
    assert any("probe write failed" in p for p in sink(s3).verify_bucket())
    class NoApi:
        pass
    assert any("cannot read" in p for p in ObjectLockSink(NoApi(), "b").verify_bucket())


def test_probe_can_be_disabled():
    s3 = FakeS3()
    s3.enforce_lock = False
    assert sink(s3).verify_bucket(probe=False) == []  # config looks fine; only the probe reveals enforcement
    assert not s3.calls


def test_production_profile_refuses_a_misconfigured_bucket_with_reasons():
    s3 = FakeS3()
    s3.lock_enabled = False
    with pytest.raises(ProductionProfileError, match="Object Lock"):
        validate_production_profile([sink(s3)], {})
    s3 = FakeS3()
    s3.enforce_lock = False
    with pytest.raises(ProductionProfileError, match="DELETED"):
        build_stack(clock=Clock(), evidence_sinks=[sink(s3)], production=True)
    validate_production_profile([sink()], {}, min_retention_days=30)  # a good bucket passes


def test_watchdog_halts_gateway_when_someone_later_loosens_the_bucket():
    s3 = FakeS3()
    st = build_stack(clock=Clock(), evidence_sinks=[sink(s3)], fs={"/app/reports/summary.csv": "x"})
    wd = st.watchdog  # the real watchdog, with the real chain key
    wd._cfg_every = 1  # check configuration on every run
    assert st.gateway.execute(read_req()).decision is Decision.ALLOW
    assert wd.run_once() == []  # healthy bucket: quiet
    s3.default_mode = "GOVERNANCE"  # an admin quietly weakens the default retention
    problems = wd.run_once()
    assert any("configuration drift" in p for p in problems) and st.guard.global_halt()
    assert st.gateway.execute(read_req(step=9)).decision is Decision.DENY


def test_config_check_runs_on_the_first_run_and_then_at_the_configured_interval():
    s3 = FakeS3()
    st = build_stack(clock=Clock(), evidence_sinks=[sink(s3)])
    wd = st.watchdog
    wd._cfg_every = 3
    s3.default_mode = "GOVERNANCE"
    hits = [bool([p for p in wd.run_once() if "drift" in p]) for _ in range(4)]
    assert hits == [True, False, False, True]  # runs 1 and 4
