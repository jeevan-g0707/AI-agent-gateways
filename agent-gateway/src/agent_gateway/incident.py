"""Automated incident-response containment playbook."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .audit import AgentSecurityEvent
from .gateway import Gateway
from .memory import SecureMemoryStore


@dataclass
class ContainmentReport:
    revoked_tokens: int
    orchestrator_halted: bool
    quarantined_memory_entries: int
    disabled_capabilities: list[str]
    timeline: list[AgentSecurityEvent] = field(default_factory=list)


def contain(
    gateway: Gateway,
    *,
    agent_id: str,
    session_id: str,
    memory: SecureMemoryStore | None = None,
    disable_capabilities: list[str] | None = None,
    halt_orchestrator: Callable[[str], None] | None = None,
) -> ContainmentReport:
    # 1. revoke every live JIT grant for the agent/session
    revoked = gateway.broker.revoke_active_for(agent_id=agent_id, session_id=session_id)
    # 2. halt execution loops (gateway-side breaker + orchestrator signal)
    gateway.guard.halt(session_id, "incident response: halted")
    if halt_orchestrator:
        halt_orchestrator(session_id)
    # 3. quarantine memory written during the session
    quarantined = memory.quarantine_session(session_id) if memory else 0
    # 4. temporarily disable high-risk capabilities for the agent class
    caps = disable_capabilities or []
    gateway.disabled_capabilities.update(caps)
    # 5. forensic reconstruction from the evidence store
    timeline = gateway.evidence.trace(session_id=session_id)
    return ContainmentReport(revoked, True, quarantined, sorted(caps), timeline)
