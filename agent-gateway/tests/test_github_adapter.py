"""The real GitHub adapter, exercised against a real local HTTP server that behaves like the GitHub pulls endpoint."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_gateway.adapters import AdapterError
from agent_gateway.adapters_real import GitHubPRRealAdapter, github_adapter_from_env
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision

from conftest import Clock, ident, pr_req

TOKEN = "ghp_test_secret_token"


class FakeGitHub:
    def __init__(self):
        self.calls, self.status, self.redirect = [], 201, None
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.calls.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                if outer.redirect:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect)
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    outer.status = 401
                payload = ({"number": 7, "html_url": f"http://x/{self.path}/7"} if outer.status == 201
                           else {"message": f"secret detail {TOKEN}"})
                data = json.dumps(payload).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()


@pytest.fixture
def gh():
    g = FakeGitHub()
    yield g
    g.stop()


def stack_for(gh, repos=("org-enterprise/core-docs",), token=TOKEN):
    return build_stack(clock=Clock(), evidence_sinks=[],
                       github_adapter_factory=lambda b, a: GitHubPRRealAdapter(
                           b, a, token=token, allowed_repos=repos, api_url=gh.url, allow_insecure=True))


def run_pr(stack, **kw):
    """Policy -> approval -> execution, as a client would."""
    req = pr_req(**kw)
    d = stack.gateway.execute(req)
    assert d.decision == Decision.REQUIRE_APPROVAL, d
    stack.approvals.approve(d.approval_id, "user:manager@enterprise.com", step_up_verified=True)
    return stack.gateway.execute(req, approval_id=d.approval_id)


def test_https_required_and_token_validated():
    with pytest.raises(ValueError):
        GitHubPRRealAdapter(None, None, token="t", allowed_repos=["o/r"], api_url="http://api.github.com")
    with pytest.raises(ValueError):
        GitHubPRRealAdapter(None, None, token="", allowed_repos=["o/r"])
    with pytest.raises(ValueError):
        GitHubPRRealAdapter(None, None, token="a b", allowed_repos=["o/r"])
    with pytest.raises(ValueError):
        GitHubPRRealAdapter(None, None, token="t", allowed_repos=[])


def test_env_factory(monkeypatch):
    assert github_adapter_from_env({}) is None
    with pytest.raises(RuntimeError):
        github_adapter_from_env({"GATEWAY_GITHUB_TOKEN": "t"})
    assert callable(github_adapter_from_env({"GATEWAY_GITHUB_TOKEN": "t", "GATEWAY_GITHUB_REPOS": "o/r"}))


def test_adapter_posts_to_the_policy_checked_repo(gh):
    stack = stack_for(gh)
    adapter = stack.adapters["github_pr"]
    assert adapter.is_mock is False
    out = run_pr(stack)
    assert out.decision == Decision.ALLOW, out
    assert gh.calls[0]["path"] == "/repos/org-enterprise/core-docs/pulls"
    assert gh.calls[0]["auth"] == f"Bearer {TOKEN}"
    assert gh.calls[0]["body"]["base"] == "main"


def test_repo_not_configured_on_adapter_is_refused_even_if_policy_allows(gh):
    stack = stack_for(gh, repos=("someone/else",))
    out = run_pr(stack)
    assert out.decision != Decision.ALLOW
    assert gh.calls == []


def test_github_errors_do_not_leak_token_or_response_body(gh):
    gh.status = 422
    stack = stack_for(gh)
    out = run_pr(stack)
    assert out.decision != Decision.ALLOW
    assert TOKEN not in repr(out) and "secret detail" not in repr(out)


def test_wrong_token_is_reported_without_leaking(gh):
    stack = stack_for(gh, token="wrong-token")
    out = run_pr(stack)
    assert out.decision != Decision.ALLOW
    assert "wrong-token" not in repr(out)


def test_redirect_is_not_followed(gh):
    gh.redirect = "http://127.0.0.1:1/steal"
    stack = stack_for(gh)
    out = run_pr(stack)
    assert out.decision != Decision.ALLOW
    assert len(gh.calls) == 1
