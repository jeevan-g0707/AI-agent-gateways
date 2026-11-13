"""ObjectLockSink + the anti-deletion machinery against a REAL S3 API over HTTP (boto3 -> moto server by default,
or any S3-compatible endpoint / real bucket via GATEWAY_TEST_S3_ENDPOINT).

NOTE on fidelity: moto enforces conditional writes, delete-denial and bypass-denial, but (as of 5.2) allows SHORTENING a
COMPLIANCE retention, which real S3 forbids. Tests below that depend on that are written to hold on both."""
import os

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.exceptions import ClientError

from agent_gateway.audit import verify_log
from agent_gateway.audit_guard import ProductionProfileError, reconcile_sinks, validate_production_profile
from agent_gateway.audit_sinks import AuditUnavailable, FileWORMSink, ObjectLockSink
from agent_gateway.models import Decision

from conftest import Clock, read_req
from svc_fixtures import s3_bucket, s3_client, s3_endpoint  # noqa: F401
from test_audit_survival import KEY, Env, run

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _audit_key():
    yield
    os.environ.pop("GATEWAY_AUDIT_KEY", None)


def entry(i, **kw):
    return {"seq": i, "mac": f"{i:064x}", **kw}


def test_write_read_roundtrip_and_every_object_carries_compliance_retention(s3_bucket):
    c, b = s3_bucket
    s = ObjectLockSink(c, b, "gw")
    for i in range(3):
        s.write(entry(i))
    assert [e["seq"] for e in s.entries()] == [0, 1, 2] and s.entry_count() == 3
    head = c.head_object(Bucket=b, Key="gw/entries/000000000001.json")
    assert head["ObjectLockMode"] == "COMPLIANCE" and head["ObjectLockRetainUntilDate"]


def test_identical_rewrite_is_idempotent_and_a_different_entry_at_same_seq_is_refused_over_http(s3_bucket):
    c, b = s3_bucket
    s = ObjectLockSink(c, b, "gw")
    s.write(entry(0))
    s.write(entry(0))  # real 412 PreconditionFailed from the server -> read-back -> identical -> ok
    with pytest.raises(AuditUnavailable, match="DIFFERENT"):
        s.write(entry(0, mac="f" * 64))
    assert [e["mac"] for e in s.entries()] == [f"{0:064x}"]  # original intact


def test_listing_more_than_one_page_follows_continuation_tokens(s3_bucket):
    c, b = s3_bucket
    s = ObjectLockSink(c, b, "gw")
    for i in range(1005):  # S3 returns at most 1000 keys per page
        s.write(entry(i))
    assert s.entry_count() == 1005
    assert [e["seq"] for e in s.entries()][-3:] == [1002, 1003, 1004]


def test_locked_objects_cannot_be_deleted_even_by_the_writer_credentials(s3_bucket):
    c, b = s3_bucket
    s = ObjectLockSink(c, b, "gw")
    s.write(entry(0))
    ver = c.head_object(Bucket=b, Key="gw/entries/000000000000.json")["VersionId"]
    for kw in ({}, {"BypassGovernanceRetention": True}):
        with pytest.raises(ClientError) as e:
            c.delete_object(Bucket=b, Key="gw/entries/000000000000.json", VersionId=ver, **kw)
        assert e.value.response["Error"]["Code"] == "AccessDenied"
    assert s.entry_count() == 1


def test_bucket_without_object_lock_is_reported(s3_client):
    import uuid
    name = f"gw-plain-{uuid.uuid4().hex[:10]}"
    s3_client.create_bucket(Bucket=name)  # created WITHOUT Object Lock (cannot be enabled later)
    probs = ObjectLockSink(s3_client, name, "gw").verify_bucket(probe=False)
    assert any("Object Lock" in p for p in probs)


def test_verify_bucket_on_a_lock_enabled_bucket(s3_bucket):
    c, b = s3_bucket
    s = ObjectLockSink(c, b, "gw")
    assert s.verify_bucket(min_retention_days=30, probe=False) == []
    probs = s.verify_bucket(min_retention_days=30)  # with the destructive-capability probe
    assert not any("DELETED" in p for p in probs), probs  # the server really refuses deletes
    # A server that lets retention be shortened (moto) is correctly flagged; real S3 COMPLIANCE returns no problems.
    assert all("SHORTENED" in p for p in probs), probs
    assert s.entry_count() == 0  # the probe left no audit entries


def test_production_profile_with_real_client(s3_bucket):
    c, b = s3_bucket
    sink = ObjectLockSink(c, b, "gw")
    validate_production_profile([sink], {}, min_retention_days=30, probe=False)
    try:
        validate_production_profile([sink], {}, min_retention_days=30, probe=True)
    except ProductionProfileError as exc:  # only acceptable reason: the server's weaker lock implementation
        assert "SHORTENED" in str(exc)


# ------------------------------------------------- the whole deletion-survival story over real S3
def test_deleted_local_log_is_rebuilt_from_real_s3_and_chain_verifies(tmp_path, s3_bucket):
    c, b = s3_bucket
    env = Env(tmp_path, s3=c, bucket=b)
    stack = env.start()
    run(stack, 4)
    remote_macs = [e["mac"] for e in env.remote.entries()]
    env.stop()
    import shutil
    shutil.rmtree(tmp_path / "log")  # root wipes the local log
    stack = env.start()
    assert [e["mac"] for e in env.file.entries()] == remote_macs
    assert stack.evidence.verify_chain() == (True, None)
    assert stack.gateway.execute(read_req(step=1)).decision is Decision.ALLOW
    assert verify_log(list(env.remote.entries()), env.remote.checkpoints(), KEY, env.ck.public_key()) == []
    env.stop()


def test_local_truncation_is_caught_by_watchdog_and_halts_gateway_with_real_s3(tmp_path, s3_bucket):
    from agent_gateway.audit_guard import AuditWatchdog
    c, b = s3_bucket
    env = Env(tmp_path, s3=c, bucket=b)
    stack = env.start()
    run(stack, 3)
    wd = AuditWatchdog(stack.evidence, [env.file, env.remote], stack.guard, hmac_key=KEY,
                       checkpoint_public_key=env.ck.public_key())
    assert wd.run_once() == []
    f = next(iter((tmp_path / "log").glob("audit-*.jsonl")))
    lines = f.read_bytes().splitlines(keepends=True)
    f.write_bytes(b"".join(lines[:-2]))
    assert any("entries removed" in p for p in wd.run_once()) and stack.guard.global_halt()
    env.stop()


def test_s3_outage_midway_refuses_actions_then_recovers_and_replicas_converge(tmp_path, s3_bucket):
    """Break the connection for real (bad endpoint), not by a flag in a fake."""
    c, b = s3_bucket
    env = Env(tmp_path, s3=c, bucket=b)
    stack = env.start()
    run(stack, 2)
    good = env.remote._c
    broken = boto3.client("s3", endpoint_url="http://127.0.0.1:9", region_name="us-east-1",
                          aws_access_key_id="x", aws_secret_access_key="x",
                          config=boto3.session.Config(retries={"max_attempts": 0}, connect_timeout=1))
    env.remote._c = broken
    r = stack.gateway.execute(read_req(step=3))
    assert r.decision is Decision.DENY and "audit log unavailable" in r.reason
    env.remote._c = good
    assert stack.gateway.execute(read_req(step=4)).decision is Decision.ALLOW
    assert [e["mac"] for e in env.file.entries()] == [e["mac"] for e in env.remote.entries()]
    env.stop()
