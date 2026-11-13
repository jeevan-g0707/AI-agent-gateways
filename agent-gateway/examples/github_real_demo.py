"""Open a REAL pull request through the gateway (after a simulated human approval).

    $env:GITHUB_TOKEN = "github_pat_..."          # fine-grained token for ONE test repo: Pull requests = write
    python examples/github_real_demo.py --repo YOURNAME/gateway-test --head gateway-demo

Before running, the repo needs a branch (--head) that has at least one commit that `main` does not have;
GitHub refuses a pull request between identical branches. The token stays inside the gateway process: the "agent"
only ever sees OK / DENIED / PENDING text.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from _dev import AGENT_ID, USER, DevServer

from agent_gateway.client import GatewayClient, GatewayTools, default_tool_specs

POLICY = Path(__file__).resolve().parents[1] / "config" / "policy.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/name of your TEST repository")
    ap.add_argument("--head", required=True, help="existing branch with a commit that main lacks")
    ap.add_argument("--base", default="main", choices=["main", "develop"])
    a = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print('set your token first:  $env:GITHUB_TOKEN = "github_pat_..."')
        return 1
    if a.repo.count("/") != 1:
        print("--repo must look like owner/name")
        return 1

    policy = json.loads(POLICY.read_text())  # your repo replaces the sample repo in the policy
    policy["capabilities"]["github:pull_request:create"]["resource_patterns"] = [f"repo:{a.repo}"]
    tmp = Path(tempfile.mkdtemp()) / "policy.json"
    tmp.write_text(json.dumps(policy))
    os.environ.update(GATEWAY_GITHUB_TOKEN=token, GATEWAY_GITHUB_REPOS=a.repo)

    dev = DevServer(policy_path=tmp)
    try:
        client = GatewayClient(dev.base_url, AGENT_ID, dev.agent_key, dev.user_token, user_id=USER,
                               task_id="task:real-pr", session_id="sess-real-pr")
        tools = GatewayTools(client, default_tool_specs(repo=a.repo))
        pr = {"title": "Gateway demo PR", "head": a.head, "base": a.base,
              "body": "Opened by an agent through the gateway after human approval."}
        print("agent calls  : open_pull_request")
        print("agent sees   :", tools.call("open_pull_request", pr), "\n")
        (approval_id,) = tools.pending
        print(f"reviewer approves {approval_id}: HTTP {dev.approve(approval_id).status_code}\n")
        print("runtime resumes the approved action:")
        out = tools.resume(approval_id)
        print("agent sees   :", out)
        return 0 if out.startswith("OK") else 2
    finally:
        dev.stop()
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
