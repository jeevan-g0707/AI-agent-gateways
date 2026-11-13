import pytest

from agent_gateway.factory import build_stack
from agent_gateway.models import ActionRequest, Identity

REPORT = "/app/reports/summary.csv"


class Clock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def stack(clock):
    return build_stack(
        clock=clock,
        fs={REPORT: "region,total\nEMEA,100\n", "/app/reports/leaky.csv": "ssn 123-45-6789 total 5"},
    )


@pytest.fixture
def gw(stack):
    return stack.gateway


def ident(user="user:shyam@enterprise.com", agent="agent:repo-helper:v2.1:abc123",
          task="task:doc-update-789", session="sess-4f8a2b"):
    return Identity(actor_user_id=user, agent_id=agent, task_id=task, session_id=session)


def read_req(path=REPORT, step=1, **kw):
    return ActionRequest(
        identity=ident(**kw), tool="file_reader", capability="files:read",
        resource=f"file:{path}", arguments={"path": path, "operation": "read"}, step=step,
    )


def pr_req(step=1, base="main", **kw):
    return ActionRequest(
        identity=ident(**kw), tool="github_pr", capability="github:pull_request:create",
        resource="repo:org-enterprise/core-docs",
        arguments={"title": "Update docs", "head": "feature/docs-402", "base": base, "body": "Draft PR"},
        justification="DOC-402", step=step,
    )


def email_req(body="hello partner", step=1, **kw):
    return ActionRequest(
        identity=ident(**kw), tool="email_send", capability="email:send_external",
        resource="mailbox:outbound-docs",
        arguments={"to": "ext@partner.com", "subject": "Docs", "body": body}, step=step,
    )


def drop_req(table="old_logs", key="idem-1", step=1, **kw):
    kw.setdefault("user", "user:admin@enterprise.com")
    return ActionRequest(
        identity=ident(**kw), tool="db_drop_table", capability="db:drop_table",
        resource="db:staging/orders", arguments={"table": table}, idempotency_key=key, step=step,
    )
