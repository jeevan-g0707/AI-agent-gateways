"""Convenience wiring for a fully-configured gateway (used by tests, demo and API)."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .adapters import DropTableAdapter, EmailAdapter, FileReaderAdapter, GitHubPRAdapter
from .approvals import ApprovalStore
from .audit import EvidenceStore
from .audit_guard import AuditWatchdog, reconcile_sinks, validate_production_profile
from .audit_sinks import AuditSink, FileWORMSink, HTTPEventSink, ObjectLockSink
from .breakers import ExecutionGuard
from .broker import CredentialBroker, GrantSigner, RevocationRegistry, UpstreamProvider
from .dataflow import CanaryRegistry, FlowPolicy, SourceLedger, TrustedInputRegistry, UntrustedCorpus
from .exfil import ExfiltrationDetector
from .gateway import Gateway
from .memory import SecureMemoryStore
from .models import RiskTier
from .policy import PolicyConfig, PolicyDecisionPoint
from .state import MemoryBackend, RedisBackend, StateBackend
from .userauth import DirectoryUserCredentialStore, UserAttestationVerifier

def _env_key(name: str) -> bytes:
    """Key material from the environment (os.environb does not exist on Windows); random if unset."""
    v = os.environ.get(name)
    return os.fsencode(v) if v is not None else os.urandom(32)


DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "config" / "policy.json"
TOOL_CAPABILITIES = {
    "github_pr": "github:pull_request:create",
    "file_reader": "files:read",
    "email_send": "email:send_external",
    "db_drop_table": "db:drop_table",
}


@dataclass
class Stack:
    gateway: Gateway
    approvals: ApprovalStore
    broker: CredentialBroker
    evidence: EvidenceStore
    guard: ExecutionGuard
    memory: SecureMemoryStore
    adapters: dict
    backend: StateBackend
    watchdog: AuditWatchdog | None = None


def backend_from_env(clock: Callable[[], float] = time.time) -> StateBackend:
    """GATEWAY_REDIS_URL=rediss://... selects Redis; otherwise in-process memory."""
    url = os.environ.get("GATEWAY_REDIS_URL")
    if not url:
        return MemoryBackend(clock)
    import redis

    return RedisBackend(redis.Redis.from_url(url))


def audit_from_env(clock: Callable[[], float] = time.time):
    """Returns (sinks, checkpoint_key). Persistent audit requires persistent keys:
      GATEWAY_AUDIT_DIR            append-only segment directory (required sink)
      GATEWAY_CHECKPOINT_DIR       separate storage for signed checkpoints (recommended)
      GATEWAY_CHECKPOINT_KEY_FILE  PEM Ed25519 private key used to sign checkpoints
      GATEWAY_AUDIT_S3_BUCKET / _PREFIX / _RETENTION_DAYS   S3 Object Lock sink (required sink)
      GATEWAY_SIEM_URL / GATEWAY_SIEM_TOKEN / GATEWAY_SIEM_SPOOL   SIEM forwarder (optional sink)"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    sinks: list[AuditSink] = []
    env = os.environ
    if env.get("GATEWAY_AUDIT_DIR"):
        if "GATEWAY_AUDIT_KEY" not in os.environ:
            raise RuntimeError("GATEWAY_AUDIT_KEY must be set when audit is persisted, or the chain cannot be verified after restart")
        sinks.append(FileWORMSink(env["GATEWAY_AUDIT_DIR"], checkpoints_dir=env.get("GATEWAY_CHECKPOINT_DIR")))
    if env.get("GATEWAY_AUDIT_S3_BUCKET"):
        import boto3  # optional dependency

        sinks.append(ObjectLockSink(boto3.client("s3"), env["GATEWAY_AUDIT_S3_BUCKET"],
                                    env.get("GATEWAY_AUDIT_S3_PREFIX", "audit/"),
                                    retention_days=int(env.get("GATEWAY_AUDIT_RETENTION_DAYS", "365")), clock=clock))
    if env.get("GATEWAY_SIEM_URL"):
        import httpx

        sinks.append(HTTPEventSink(env["GATEWAY_SIEM_URL"], env["GATEWAY_SIEM_TOKEN"], httpx.Client(),
                                   spool_path=env.get("GATEWAY_SIEM_SPOOL", "/var/lib/agent-gateway/siem.spool")))
    ck = None
    if env.get("GATEWAY_CHECKPOINT_KEY_FILE"):
        with open(env["GATEWAY_CHECKPOINT_KEY_FILE"], "rb") as f:
            ck = load_pem_private_key(f.read(), None)
    elif any(s.required for s in sinks):
        raise RuntimeError("GATEWAY_CHECKPOINT_KEY_FILE required: signed checkpoints are what expose a deleted log tail")
    return sinks, ck


def build_stack(
    policy_path: str | Path | None = None,
    *,
    policy: PolicyConfig | None = None,
    clock: Callable[[], float] = time.time,
    fs: dict[str, str] | None = None,
    allowed_egress_hosts: frozenset[str] = frozenset({"api.github.com", "docs.enterprise.com"}),
    on_alert: Callable[[str, str], None] | None = None,
    backend: StateBackend | None = None,
    upstream: UpstreamProvider | None = None,
    github_adapter_factory: Callable | None = None,
    evidence_sinks: list[AuditSink] | None = None,
    checkpoint_key=None,
    checkpoint_every: int = 100,
    production: bool | None = None,
    email_adapter_factory: Callable | None = None,
    db_adapter_factory: Callable | None = None,
    user_verifier: UserAttestationVerifier | None = None,
    require_user_signature: bool | None = None,
) -> Stack:
    # Keys come from the environment / secret manager in production; never from the agent runtime.
    grant_key = _env_key("GATEWAY_GRANT_KEY")
    audit_key = _env_key("GATEWAY_AUDIT_KEY")
    memory_key = _env_key("GATEWAY_MEMORY_KEY")

    backend = backend or backend_from_env(clock)
    cfg = policy if policy is not None else PolicyConfig.from_file(policy_path or DEFAULT_POLICY)
    pdp = PolicyDecisionPoint(cfg, supported_tools=TOOL_CAPABILITIES)
    signer = GrantSigner(grant_key, clock=clock)
    broker = CredentialBroker(signer, RevocationRegistry(backend), clock=clock, backend=backend,
                              upstream=upstream)
    approvals = ApprovalStore(clock=clock, backend=backend,
                              cooldowns={RiskTier(k): v for k, v in cfg.approval_cooldowns.items()})
    if evidence_sinks is None:
        evidence_sinks, env_ck = audit_from_env(clock)
        checkpoint_key = checkpoint_key or env_ck
    evidence = EvidenceStore(audit_key, clock=clock, sinks=evidence_sinks,
                             checkpoint_every=checkpoint_every if checkpoint_key else 0,
                             checkpoint_key=checkpoint_key)
    # Restart recovery: reconcile every readable replica. A deleted/truncated local log is quarantined and rebuilt
    # from the immutable copy; a lagging replica is caught up; a diverging one refuses to start.
    chain, recovery = reconcile_sinks(evidence_sinks, audit_key,
                                      checkpoint_key.public_key() if checkpoint_key else None)
    evidence.restore(chain)
    for sink_name, action in recovery.items():
        if action != "in sync":
            import logging
            logging.getLogger("agent_gateway.audit_guard").warning("audit recovery [%s]: %s", sink_name, action)
    guard = ExecutionGuard(clock=clock, on_alert=on_alert, backend=backend)
    # Real adapters are selected by configuration (GATEWAY_SMTP_*, GATEWAY_DB_*); mocks only when nothing is configured.
    from .adapters_real import github_adapter_from_env, smtp_adapter_from_env, sql_adapter_from_env

    email_adapter_factory = email_adapter_factory or smtp_adapter_from_env(os.environ)
    db_adapter_factory = db_adapter_factory or sql_adapter_from_env(os.environ)
    github_adapter_factory = github_adapter_factory or github_adapter_from_env(os.environ)
    github = (github_adapter_factory or GitHubPRAdapter)(broker, approvals)
    adapters = {
        "github_pr": github,
        "file_reader": FileReaderAdapter(broker, approvals, fs=fs),
        "email_send": (email_adapter_factory or EmailAdapter)(broker, approvals),
        "db_drop_table": (db_adapter_factory or DropTableAdapter)(broker, approvals),
    }
    if production is None:
        production = os.environ.get("GATEWAY_ENV") == "production"
    if production:
        validate_production_profile(
            evidence_sinks, adapters, probe=os.environ.get("GATEWAY_AUDIT_PROBE", "1") != "0",
            min_retention_days=int(os.environ.get("GATEWAY_AUDIT_MIN_RETENTION_DAYS", "30")))
    # Human-input attestation: GATEWAY_USER_CREDENTIALS_DIR (+ GATEWAY_WEBAUTHN_RP_ID, GATEWAY_WEBAUTHN_ORIGINS)
    env = os.environ
    if user_verifier is None and env.get("GATEWAY_USER_CREDENTIALS_DIR"):
        user_verifier = UserAttestationVerifier(
            DirectoryUserCredentialStore(env["GATEWAY_USER_CREDENTIALS_DIR"]), rp_id=env["GATEWAY_WEBAUTHN_RP_ID"],
            origins=[o for o in env["GATEWAY_WEBAUTHN_ORIGINS"].split(",") if o], backend=backend, clock=clock)
    if require_user_signature is None:
        require_user_signature = env.get("GATEWAY_REQUIRE_USER_SIGNATURE") == "1"
    if require_user_signature and user_verifier is None:
        raise RuntimeError("require_user_signature needs a user credential store (GATEWAY_USER_CREDENTIALS_DIR)")
    if production and not require_user_signature:
        import logging
        logging.getLogger("agent_gateway").warning(
            "production without GATEWAY_REQUIRE_USER_SIGNATURE=1: destinations the user 'typed' are asserted by the "
            "front end, not cryptographically attested")
    gateway = Gateway(
        pdp, signer, broker, approvals, evidence, guard, adapters,
        exfil=ExfiltrationDetector(allowed_hosts=allowed_egress_hosts), clock=clock,
        trusted=TrustedInputRegistry(backend, clock), canaries=CanaryRegistry(backend),
        corpus=UntrustedCorpus(backend), sources=SourceLedger(backend),
        user_verifier=user_verifier, require_user_signature=require_user_signature,
        egress_domains=cfg.egress_allowed_domains, taint_policy=cfg.taint_policy,
        flow=FlowPolicy.from_config(cfg),
    )
    memory = SecureMemoryStore(memory_key, clock=clock)
    watchdog = AuditWatchdog(evidence, evidence_sinks, guard, hmac_key=audit_key,
                             checkpoint_public_key=checkpoint_key.public_key() if checkpoint_key else None,
                             min_retention_days=int(os.environ.get("GATEWAY_AUDIT_MIN_RETENTION_DAYS", "30")) if production else None)
    return Stack(gateway, approvals, broker, evidence, guard, memory, adapters, backend, watchdog)
