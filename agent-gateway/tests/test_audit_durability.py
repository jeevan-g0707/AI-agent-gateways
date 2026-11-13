"""Durable, tamper-evident, fail-closed audit."""
import json
import os
import stat
from datetime import datetime

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_gateway.audit import AgentSecurityEvent, EvidenceStore, verify_entries, verify_log
from agent_gateway.audit_sinks import (AuditTampered, AuditUnavailable, FileWORMSink, HTTPEventSink,
                                       ObjectLockSink)
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision

from conftest import REPORT, read_req
from s3fake import FakeS3

KEY = b"k" * 32


def ev(i=0, session="s1"):
    return AgentSecurityEvent(agent_id="a", actor_user_id="u", task_id="t", session_id=session,
                              capability="files:read", resource=f"file:/app/reports/{i}", decision="allow")


def store(tmp_path, **kw):
    sink = FileWORMSink(tmp_path / "log", checkpoints_dir=tmp_path / "cp", **kw.pop("sink_kw", {}))
    ck = Ed25519PrivateKey.generate()
    return EvidenceStore(KEY, sinks=[sink], checkpoint_every=kw.pop("every", 3), checkpoint_key=ck), sink, ck


# ----------------------------------------------------------------- file sink
def test_entries_survive_restart_and_chain_continues(tmp_path):
    s1, sink1, ck = store(tmp_path)
    for i in range(5):
        s1.append(ev(i))
    sink1.close()
    sink2 = FileWORMSink(tmp_path / "log", checkpoints_dir=tmp_path / "cp")
    s2 = EvidenceStore(KEY, sinks=[sink2], checkpoint_every=3, checkpoint_key=ck)
    assert s2.restore(list(sink2.entries())) == 5
    s2.append(ev(5))
    assert s2.verify_chain() == (True, None)
    assert [e.resource for e in s2.events()][-1].endswith("/5")
    assert len(list(sink2.entries())) == 6


def test_restart_refuses_tampered_log(tmp_path):
    s1, sink1, _ = store(tmp_path)
    for i in range(3):
        s1.append(ev(i))
    sink1.close()
    seg = next((tmp_path / "log").glob("audit-*.jsonl"))
    seg.write_text(seg.read_text().replace('"allow"', '"deny "').replace("allow", "deny "), )
    sink2 = FileWORMSink(tmp_path / "log")
    with pytest.raises(AuditTampered):
        EvidenceStore(KEY, sinks=[sink2]).restore(list(sink2.entries()))


def test_partial_write_from_crash_is_dropped_not_fatal(tmp_path):
    s1, sink1, _ = store(tmp_path)
    s1.append(ev(0)); s1.append(ev(1))
    sink1.close()
    seg = next((tmp_path / "log").glob("audit-*.jsonl"))
    with open(seg, "ab") as f:
        f.write(b'{"seq":2,"prev":"abc","paylo')  # crash mid-write, never acknowledged
    sink2 = FileWORMSink(tmp_path / "log")
    assert len(list(sink2.entries())) == 2
    assert verify_entries(list(sink2.entries()), KEY) == (True, None)


def test_rotation_seals_segments_and_detects_later_modification(tmp_path):
    sink = FileWORMSink(tmp_path / "log", max_segment_bytes=1500)
    st = EvidenceStore(KEY, sinks=[sink])
    for i in range(12):
        st.append(ev(i))
    segs = sorted((tmp_path / "log").glob("audit-*.jsonl"))
    assert len(segs) > 2
    assert all(not (p.stat().st_mode & stat.S_IWUSR) for p in segs[:-1])  # sealed read-only
    assert sink.verify_manifest() == []
    assert verify_entries(list(sink.entries()), KEY) == (True, None)  # chain spans segments
    os.chmod(segs[0], 0o640)
    segs[0].write_bytes(segs[0].read_bytes().replace(b"allow", b"alloW"))
    assert any("modified" in p for p in sink.verify_manifest())
    os.chmod(segs[1], 0o640)  # sealed segments are read-only; Windows refuses to delete read-only files
    segs[1].unlink()
    assert any("missing" in p for p in sink.verify_manifest())


# ---------------------------------------------------- checkpoints / truncation
def test_deleted_tail_is_detected_via_signed_checkpoint(tmp_path):
    s1, sink, ck = store(tmp_path, every=3)
    for i in range(7):
        s1.append(ev(i))
    entries, cps = list(sink.entries()), sink.checkpoints()
    assert len(cps) == 2  # at seq 2 and 5
    assert verify_log(entries, cps, KEY, ck.public_key()) == []
    # attacker deletes the last 3 entries (and the chain still verifies by itself!)
    cut = entries[:4]
    assert verify_entries(cut, KEY) == (True, None)
    problems = verify_log(cut, cps, KEY, ck.public_key())
    assert any("truncated" in p for p in problems)


def test_forged_or_mismatched_checkpoint_detected(tmp_path):
    s1, sink, ck = store(tmp_path, every=2)
    for i in range(4):
        s1.append(ev(i))
    entries, cps = list(sink.entries()), sink.checkpoints()
    evil = Ed25519PrivateKey.generate()
    assert any("invalid signature" in p for p in verify_log(entries, cps, KEY, evil.public_key()))
    rewritten = [dict(e) for e in entries]
    assert verify_log(rewritten, [{**cps[0], "head_mac": "0" * 64}], KEY, ck.public_key())


def test_checkpoint_retried_after_sink_failure(tmp_path):
    s1, sink, ck = store(tmp_path, every=2)
    real = sink.write_checkpoint
    sink.write_checkpoint = lambda cp: (_ for _ in ()).throw(OSError("disk"))
    s1.append(ev(0)); s1.append(ev(1))  # checkpoint due, fails
    assert s1.sink_errors.get("file") == 1 and sink.checkpoints() == []
    sink.write_checkpoint = real
    s1.append(ev(2))  # retried on next append
    assert len(sink.checkpoints()) == 1


# --------------------------------------------------------------- fail closed
class BrokenSink:
    name, required = "broken", True
    def write(self, entry): raise OSError("disk full")
    def write_checkpoint(self, cp): pass


def test_required_sink_failure_commits_nothing_and_raises():
    st = EvidenceStore(KEY, sinks=[BrokenSink()])
    with pytest.raises(AuditUnavailable):
        st.append(ev())
    assert st.events() == []  # not committed: the chain never contains an unpersisted entry


def test_gateway_refuses_actions_when_audit_unavailable(clock):
    st = build_stack(clock=clock, fs={REPORT: "x"}, evidence_sinks=[BrokenSink()])
    resp = st.gateway.execute(read_req())
    assert resp.decision is Decision.DENY and "audit log unavailable" in resp.reason
    assert st.evidence.events() == []  # nothing recorded and, because logging precedes execution, nothing ran


def test_audit_failure_after_execution_halts_session_and_reconciles(clock, tmp_path):
    sink = FileWORMSink(tmp_path / "log")
    st = build_stack(clock=clock, fs={REPORT: "x"}, evidence_sinks=[sink])
    gw = st.gateway
    calls = {"n": 0}
    real = sink.write

    def flaky(entry):
        calls["n"] += 1
        if calls["n"] == 2:  # 1st = decision (ok), 2nd = execution event (fails)
            raise AuditUnavailable("transient")
        real(entry)

    sink.write = flaky
    assert gw.execute(read_req(step=1)).decision is Decision.ALLOW  # already executed, cannot undo
    assert len(gw.unlogged) == 1
    assert gw.execute(read_req(step=2)).decision is Decision.DENY  # session halted: no more unrecorded work
    assert gw.reconcile_audit() == 0 and not gw.unlogged
    assert any(e.event_type == "execution" for e in st.evidence.events())
    assert st.evidence.verify_chain()[0]


def test_deny_still_returned_if_audit_down_during_error_path(clock):
    st = build_stack(clock=clock, fs={}, evidence_sinks=[BrokenSink()])
    assert st.gateway.execute(read_req()).decision is Decision.DENY  # never raises


# ------------------------------------------------------------ S3 Object Lock
def test_object_lock_sink_writes_immutable_retained_objects(clock):
    c = FakeS3()
    sink = ObjectLockSink(c, "audit-bucket", "gw", retention_days=400, clock=clock)
    st = EvidenceStore(KEY, sinks=[sink], checkpoint_every=2, checkpoint_key=Ed25519PrivateKey.generate(), clock=clock)
    st.append(ev(0)); st.append(ev(1))
    keys = sorted(c.objects)
    assert keys == ["gw/checkpoints/000000000001.json", "gw/entries/000000000000.json", "gw/entries/000000000001.json"]
    first = c.objects["gw/entries/000000000000.json"]
    assert first["ObjectLockMode"] == "COMPLIANCE" and first["IfNoneMatch"] == "*"
    assert (first["ObjectLockRetainUntilDate"] - datetime.fromtimestamp(clock(), first["ObjectLockRetainUntilDate"].tzinfo)).days >= 399
    same = json.loads(c.objects["gw/entries/000000000000.json"]["Body"])
    sink.write(same)  # idempotent: re-sending the identical entry is a no-op
    with pytest.raises(AuditUnavailable, match="DIFFERENT"):  # a different entry at an existing seq is refused
        sink.write({**same, "mac": "f" * 64})


def test_object_lock_failure_is_fail_closed(clock):
    class Down:
        def put_object(self, **kw): raise ConnectionError("s3 down")
    st = EvidenceStore(KEY, sinks=[ObjectLockSink(Down(), "b")])
    with pytest.raises(AuditUnavailable):
        st.append(ev())


# ------------------------------------------------------------------- SIEM
def test_siem_spools_when_down_and_replays_in_order(tmp_path):
    state = {"up": False, "got": []}

    def handler(request):
        if not state["up"]:
            return httpx.Response(503)
        state["got"].append(json.loads(request.content)["event"]["seq"])
        return httpx.Response(200)

    siem = HTTPEventSink("https://siem.enterprise.com/hec", "tok", httpx.Client(transport=httpx.MockTransport(handler)),
                         spool_path=tmp_path / "siem.spool", sleep=lambda s: None)
    st = EvidenceStore(KEY, sinks=[siem])
    for i in range(3):
        st.append(ev(i))  # SIEM down: business continues, events spooled
    assert siem.backlog() == 3 and state["got"] == []
    state["up"] = True
    st.append(ev(3))  # recovery: backlog replayed BEFORE the new event
    assert state["got"] == [0, 1, 2, 3] and siem.backlog() == 0


def test_siem_requires_https_and_never_blocks_actions(tmp_path):
    with pytest.raises(ValueError):
        HTTPEventSink("http://siem/hec", "t", None, spool_path=tmp_path / "s")
    boom = httpx.Client(transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))
    siem = HTTPEventSink("https://siem/hec", "t", boom, spool_path=tmp_path / "s", sleep=lambda s: None)
    st = EvidenceStore(KEY, sinks=[siem])
    st.append(ev())  # does not raise
    assert siem.backlog() == 1


def test_persistent_audit_requires_persistent_key(monkeypatch, tmp_path):
    from agent_gateway.factory import audit_from_env
    monkeypatch.setenv("GATEWAY_AUDIT_DIR", str(tmp_path / "a"))
    monkeypatch.delenv("GATEWAY_AUDIT_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GATEWAY_AUDIT_KEY"):
        audit_from_env()
    monkeypatch.setenv("GATEWAY_AUDIT_KEY", "x" * 32)
    with pytest.raises(RuntimeError, match="CHECKPOINT"):
        audit_from_env()
