"""Policy tour: run a fixed set of requests against config/policy.json (or a copy you edit) and print each decision.

    python examples/policy_tour.py                       # uses config/policy.json
    python examples/policy_tour.py my_policy.json        # uses a copy you edited

Every probe runs as a brand-new session, so one probe never affects another. Edit the policy, rerun, and compare.
"""
from __future__ import annotations

import sys
from itertools import count
from pathlib import Path

from _dev import AGENT_ID, USER, DevServer

from agent_gateway.client import GatewayClient, GatewayError

ADMIN = "user:admin@enterprise.com"
INTERN = "user:intern@enterprise.com"
REPORT = "/app/reports/summary.csv"


def mail(to):
    return ("email_send", "email:send_external", "mailbox:outbound-docs", {"to": to, "subject": "Report", "body": "hello"})


PROBES = [
    # (label, user, tool, capability, resource, arguments)
    ("read an allowed report", USER, "file_reader", "files:read", f"file:{REPORT}", {"path": REPORT, "operation": "read"}),
    ("read prod.env (secrets pattern)", USER, "file_reader", "files:read", "file:/app/reports/prod.env",
     {"path": "/app/reports/prod.env", "operation": "read"}),
    ("intern reads a report", INTERN, "file_reader", "files:read", f"file:{REPORT}", {"path": REPORT, "operation": "read"}),
    ("PR to the docs repo", USER, "github_pr", "github:pull_request:create", "repo:org-enterprise/core-docs",
     {"title": "Update docs", "head": "feature/x", "base": "main", "body": "Draft"}),
    ("PR to a different repo", USER, "github_pr", "github:pull_request:create", "repo:org-enterprise/payments",
     {"title": "Update", "head": "feature/x", "base": "main", "body": "Draft"}),
    ("email cfo@enterprise.com", USER, *mail("cfo@enterprise.com")),
    ("email ext@partner.com", USER, *mail("ext@partner.com")),
    ("email bob@acme-partner.org", USER, *mail("bob@acme-partner.org")),
    ("shyam drops a staging table", USER, "db_drop_table", "db:drop_table", "db:staging/old_logs", {"table": "old_logs"}),
    ("admin drops a staging table", ADMIN, "db_drop_table", "db:drop_table", "db:staging/old_logs", {"table": "old_logs"}),
]


def main(policy: str | None) -> None:
    dev = DevServer(policy_path=policy)
    ids = count(1)
    try:
        print(f"policy: {policy or 'config/policy.json (default)'}\n")
        print(f"{'request':<32} {'who':<9} {'decision':<17} {'risk':<9} reason")
        print("-" * 118)
        for label, user, tool, cap, resource, args in PROBES:
            n = next(ids)
            client = GatewayClient(dev.base_url, AGENT_ID, dev.agent_key, lambda u=user: dev.user_token(u),
                                   user_id=user, task_id=f"task:tour-{n}", session_id=f"sess-tour-{n}")
            try:
                r = client.execute(tool, cap, resource, args, justification="policy tour")
                row = (r.decision, r.risk_tier or "-", r.reason)
            except GatewayError as exc:
                row = ("(rejected)", "-", str(exc))
            print(f"{label:<32} {user.split(':')[1].split('@')[0]:<9} {row[0]:<17} {row[1]:<9} {row[2][:60]}")
    finally:
        dev.stop()


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg and not Path(arg).is_file():
        sys.exit(f"policy file not found: {arg}")
    main(arg)
