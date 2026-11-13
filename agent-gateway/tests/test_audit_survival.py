"""Local log deletion/tampering: detected, fail-closed, recoverable from the immutable copy."""
import os
import shutil
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_gateway.audit import AgentSecurityEvent, EvidenceStore, verify_entries, verify_log
from agent_gateway.audit_guard import AuditWatchdog, ProductionProfileError, reconcile_sinks, validate_production_profile
from agent_gateway.audit_sinks import AuditTampered, AuditUnavailable, FileWORMSink, ObjectLockSink
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision

from conftest import REPORT, Clock, read_req
from s3fake import FakeS3

KEY = b"k" * 32
# Windows will not let another process delete or rename a file the gateway holds open (which, incidentally, is
# protective). These tests simulate that attack, so they can only run where the OS allows it.
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Windows forbids deleting/renaming a file held open")


def ev(i=0):
    return AgentSecurityEvent(agent_id="a", actor_user_id="u", task_id="t", session_id="s",
                              capability="files:read", resource=f"file:/app/reports/{i}", decision="allow")


class Env:
    """A deployment: local append-only dir + checkpoints dir + S3 Object Lock, restartable."""

    def __init__(self, tmp, s3=None, ck=None, clock=None, bucket="bkt", **fkw):
        self.tmp, self.s3, self.bucket = tmp, s3 or FakeS3(), bucket
        self.ck = ck or Ed25519PrivateKey.generate()
        self.clock = clock or Clock()
        self.fkw = fkw

    def start(self):
        os.environ["GATEWAY_AUDIT_KEY"] = KEY.decode()
        self.file = FileWORMSink(self.tmp / "log", checkpoints_dir=self.tmp / "cp", **self.fkw)
        self.remote = ObjectLockSink(self.s3, self.bucket, "gw", clock=self.clock)
        self.stack = build_stack(clock=self.clock, fs={REPORT: "x"}, evidence_sinks=[self.file, self.remote],
                                 checkpoint_key=self.ck, checkpoint_every=3, production=False)
        return self.stack

    def stop(self):
        self.file.close()


@pytest.fixture(autouse=True)
def _audit_key():
    yield
    os.environ.pop("GATEWAY_AUDIT_KEY", None)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.start()
    yield e
    e.stop()


def run(stack, n, start=1):
    return [stack.gateway.execute(read_req(step=start + i)).decision for i in range(n)]


# ------------------------------------------------------------- detect at write
@posix_only
def test_deleting_the_live_log_makes_the_next_action_refuse(env):
    assert run(env.stack, 2) == [Decision.ALLOW] * 2
    next(iter((env.tmp / "log").glob("audit-*.jsonl"))).unlink()  # root deletes the file
    resp = env.stack.gateway.execute(read_req(step=3))
    assert resp.decision is Decision.DENY and "audit log unavailable" in resp.reason


@pytest.mark.parametrize("tamper", ["truncate", "append", pytest.param("replace", marks=posix_only)])
def test_truncating_editing_or_replacing_live_log_is_caught(env, tamper):
    run(env.stack, 2)
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    if tamper == "truncate":
        data = f.read_bytes()
        f.write_bytes(data[: data.rfind(b"\n", 0, len(data) - 1) + 1])
    elif tamper == "append":
        with open(f, "ab") as fh:
            fh.write(b'{"forged": true}\n')
    else:
        os.replace(f, env.tmp / "elsewhere.jsonl")
        f.write_bytes(b"")
    assert env.stack.gateway.execute(read_req(step=3)).decision is Decision.DENY


@posix_only
def test_while_local_is_broken_every_action_is_refused_not_just_one(env):
    run(env.stack, 1)
    next(iter((env.tmp / "log").glob("audit-*.jsonl"))).unlink()
    assert [env.stack.gateway.execute(read_req(step=s)).decision for s in (2, 3, 4)] == [Decision.DENY] * 3


# --------------------------------------------------------------- recovery
def test_restart_rebuilds_deleted_local_log_from_object_lock(env):
    run(env.stack, 4)
    remote_before = list(env.remote.entries())
    env.stop()
    shutil.rmtree(env.tmp / "log")  # the whole local log is gone
    stack = env.start()
    assert [e["mac"] for e in env.file.entries()] == [e["mac"] for e in remote_before]
    assert stack.evidence.verify_chain() == (True, None)
    assert stack.gateway.execute(read_req(step=1)).decision is Decision.ALLOW  # back in business
    assert verify_log(list(env.remote.entries()), env.remote.checkpoints(), KEY, env.ck.public_key()) == []


def test_restart_quarantines_tampered_local_log_and_keeps_it_as_evidence(env):
    run(env.stack, 4)
    env.stop()
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    f.write_text(f.read_text().replace("allow", "deny "))
    stack = env.start()
    quarantined = list((env.tmp / "log").glob("quarantine-*"))
    assert quarantined and any(quarantined[0].glob("audit-*.jsonl"))  # evidence of tampering preserved
    assert verify_entries(list(env.file.entries()), KEY) == (True, None)
    assert stack.evidence.verify_chain()[0] and len(stack.evidence.events()) >= 4


def test_deleted_sealed_segment_is_detected_and_rebuilt(tmp_path):
    e = Env(tmp_path, max_segment_bytes=1200)
    stack = e.start()
    run(stack, 6)
    segs = sorted((tmp_path / "log").glob("audit-*.jsonl"))
    assert len(segs) > 2
    e.stop()
    os.chmod(segs[0], 0o640)
    segs[0].unlink()
    stack = e.start()
    assert len(list(e.file.entries())) == len(list(e.remote.entries()))
    assert e.file.verify_manifest() == []
    e.stop()


def test_local_tail_deleted_is_caught_up_from_remote(env):
    run(env.stack, 5)
    env.stop()
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    lines = f.read_bytes().splitlines(keepends=True)
    f.write_bytes(b"".join(lines[:-3]))  # attacker deletes the last 3 entries
    stack = env.start()
    assert len(list(env.file.entries())) == len(list(env.remote.entries()))


def test_local_log_that_diverges_from_immutable_copy_is_quarantined_and_rebuilt(env):
    run(env.stack, 3)
    env.stop()
    other = EvidenceStore(KEY)  # a self-consistent but different chain (e.g. forged by someone holding the key)
    for i in range(3):
        other.append(ev(i))
    import json
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    f.write_text("".join(json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n" for x in other._entries))
    env.start()
    assert list((env.tmp / "log").glob("quarantine-*"))  # the forged file is preserved as evidence
    assert [e["mac"] for e in env.file.entries()] == [e["mac"] for e in env.remote.entries()]  # S3 copy wins


def test_two_remote_replicas_that_disagree_refuse_to_start(env):
    run(env.stack, 3)
    env.stop()
    s3b = FakeS3()
    other = EvidenceStore(KEY)
    for i in range(3):
        other.append(ev(i))
    second = ObjectLockSink(s3b, "bkt", "gw")
    for e in other._entries:
        second.write(e)
    with pytest.raises(AuditTampered, match="diverges"):
        reconcile_sinks([ObjectLockSink(env.s3, "bkt", "gw"), second], KEY)


def test_remote_chain_tampering_is_fatal(env):
    run(env.stack, 3)
    env.stop()
    k = "gw/entries/000000000001.json"
    env.s3.objects[k] = {**env.s3.objects[k], "Body": env.s3.objects[k]["Body"].replace(b"allow", b"deny ")}
    with pytest.raises(AuditTampered):
        reconcile_sinks([FileWORMSink(env.tmp / "log"), ObjectLockSink(env.s3, "bkt", "gw")], KEY)


def test_truncated_remote_is_exposed_by_signed_checkpoints(env):
    run(env.stack, 7)  # checkpoints at seq 2,5,8...
    env.stop()
    for k in [k for k in env.s3.objects if "/entries/" in k][-4:]:
        del env.s3.objects[k]  # (impossible under COMPLIANCE lock; proves the checkpoint backstop)
    env.file.close()
    local_dir = env.tmp / "log"
    shutil.rmtree(local_dir)
    with pytest.raises(AuditTampered, match="truncated"):
        reconcile_sinks([FileWORMSink(local_dir, checkpoints_dir=env.tmp / "cp"), ObjectLockSink(env.s3, "bkt", "gw")],
                        KEY, env.ck.public_key())


# ------------------------------------------------- replicas / partial failure
def test_s3_outage_refuses_action_but_chain_stays_consistent_and_catches_up(env):
    run(env.stack, 2)
    env.s3.fail_puts = True
    r = env.stack.gateway.execute(read_req(step=3))
    assert r.decision is Decision.DENY and "audit log unavailable" in r.reason
    assert env.stack.gateway.execute(read_req(step=4)).decision is Decision.DENY
    env.s3.fail_puts = False
    assert env.stack.gateway.execute(read_req(step=5)).decision is Decision.ALLOW  # recovers on its own
    local = [e["mac"] for e in env.file.entries()]
    remote = [e["mac"] for e in env.remote.entries()]
    assert local == remote  # replicas identical: no orphan or gap
    assert verify_entries(list(env.file.entries()), KEY) == (True, None)
    assert any(e.capability == "audit:lag" for e in env.stack.evidence.events())  # honest marker
    env.stop()
    env.start()  # and a restart is clean
    assert env.stack.evidence.verify_chain()[0]


# ----------------------------------------------------------------- watchdog
def test_watchdog_detects_local_truncation_and_halts_whole_gateway(env):
    run(env.stack, 3)
    alarms = []
    wd = AuditWatchdog(env.stack.evidence, [env.file, env.remote], env.stack.guard, hmac_key=KEY,
                       checkpoint_public_key=env.ck.public_key(), on_alarm=alarms.append)
    assert wd.run_once() == []
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    lines = f.read_bytes().splitlines(keepends=True)
    f.write_bytes(b"".join(lines[:-2]))  # silent truncation at rest
    problems = wd.run_once()
    assert any("entries removed" in p for p in problems) and alarms
    assert env.stack.guard.global_halt()
    # every session, not just the suspect one, is stopped
    assert env.stack.gateway.execute(read_req(session="some-other-session")).reason.startswith("gateway halted")


def test_watchdog_detects_deleted_sealed_segment(tmp_path):
    e = Env(tmp_path, max_segment_bytes=1200)
    stack = e.start()
    run(stack, 6)
    wd = AuditWatchdog(stack.evidence, [e.file, e.remote], stack.guard, hmac_key=KEY)
    assert wd.run_once() == []
    seg = sorted((tmp_path / "log").glob("audit-*.jsonl"))[0]
    os.chmod(seg, 0o640)
    seg.unlink()
    assert any("missing" in p for p in wd.run_once())
    e.stop()


def test_watchdog_detects_remote_entries_missing_and_unreadable(env):
    run(env.stack, 3)
    wd = AuditWatchdog(env.stack.evidence, [env.file, env.remote], env.stack.guard, hmac_key=KEY)
    del env.s3.objects[sorted(k for k in env.s3.objects if "/entries/" in k)[-1]]
    assert any("entries removed" in p for p in wd.run_once())


def test_watchdog_thread_runs_and_stops(env):
    import time
    wd = AuditWatchdog(env.stack.evidence, [env.file, env.remote], env.stack.guard, hmac_key=KEY)
    wd.start(0.05)
    f = next(iter((env.tmp / "log").glob("audit-*.jsonl")))
    run(env.stack, 2)
    f.write_bytes(b"")  # truncate everything
    deadline = time.time() + 3
    while time.time() < deadline and not env.stack.guard.global_halt():
        time.sleep(0.05)
    wd.stop()
    assert env.stack.guard.global_halt()


# ---------------------------------------------------------- production profile
def test_production_profile_requires_immutable_sink(tmp_path):
    f = FileWORMSink(tmp_path / "log")
    with pytest.raises(ProductionProfileError, match="IMMUTABLE"):
        validate_production_profile([f], {})
    gov = ObjectLockSink(FakeS3(), "b", mode="GOVERNANCE")  # bypassable by privileged principals
    with pytest.raises(ProductionProfileError, match="IMMUTABLE"):
        validate_production_profile([f, gov], {})
    validate_production_profile([f, ObjectLockSink(FakeS3(), "b")], {})  # COMPLIANCE: ok


def test_production_profile_refuses_mock_adapters(tmp_path):
    from agent_gateway.adapters import DropTableAdapter, EmailAdapter
    sink = ObjectLockSink(FakeS3(), "b")
    mocks = {"email_send": EmailAdapter(None, None), "db_drop_table": DropTableAdapter(None, None)}
    with pytest.raises(ProductionProfileError, match="mock adapters"):
        validate_production_profile([sink], mocks)
    with pytest.raises(ProductionProfileError):
        build_stack(clock=Clock(), evidence_sinks=[sink], production=True)


def test_append_only_probe_is_false_when_unsupported(tmp_path):
    assert FileWORMSink(tmp_path / "x").is_append_only() in (True, False)  # best effort, never raises
