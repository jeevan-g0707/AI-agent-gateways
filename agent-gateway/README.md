# Agent Execution Gateway

Reference implementation of the *Secure Policy-Bounded Autonomous AI Agent Execution Gateway* standard.
The agent runtime is **untrusted**: it can only *propose* tool calls. Every call is intercepted, evaluated by an
external Policy Decision Point, optionally approved by a human, executed with a short-lived credential through a
hardened adapter, and recorded in a tamper-evident evidence store. Everything fails closed.

## Quick start

```bash
pip install -e ".[api,redis,aws,dev]"
pytest                      # 216 tests: abuse matrix, RFC 9421 vector, Redis semantics, API auth, evasions, audit durability, key rotation
python examples/demo.py     # walkthrough
uvicorn --factory agent_gateway.api:app_from_env   # see "Configuration"
```

## Request pipeline

```
ActionRequest ─► throttle / circuit breakers / step replay      breakers.py
              ─► schema pre-validation (Pydantic, extra=forbid) adapters.py
              ─► egress DLP + exfiltration detector             dlp.py, exfil.py
              ─► Policy Decision Point (allow|deny|require_approval)  policy.py
              ─► approval (bound, single-use, ≤300s)            approvals.py
              ─► Credential Broker: JIT token ≤300s, PDP-signed grant only   broker.py
              ─► Tool adapter: token check → schema → atomic approval consume → execute   adapters.py
              ─► output DLP                                     dlp.py
              ─► HMAC hash-chained evidence                     audit.py
```

## Standard → code map

| Requirement | Where |
|---|---|
| Fail-closed PDP (missing/corrupt config, exceptions) | `policy.py`, `Gateway.execute` |
| Exact resource binding, no wildcards, no traversal | `policy.py`, `adapters.FileReaderAdapter` |
| Per-task least privilege / per-step re-evaluation | `policy.py`, every `execute` call re-runs the PDP |
| Dual-bound identity (`actor_user_id`, `agent_id`, `task_id`/`session_id`) | `models.Identity` |
| JIT tokens ≤300s, bound to capability+resource+agent | `broker.py` |
| Revocation without redeploy | `broker.RevocationRegistry` |
| Risk tiers + HITL (step-up, dual approver for critical, idempotency) | `approvals.py`, `adapters.DropTableAdapter` |
| Parameter-bound approvals, SHA-256 args hash, single-use atomic consume | `approvals.binding_hash/consume` |
| Capability allowlists + blocked patterns | `adapters.FileReaderAdapter` |
| Pydantic argument schemas | `adapters.GitHubCreatePRSchema` etc. |
| 4-tier DLP × (context/log/output) | `dlp.py` |
| Exfiltration detection (base64 URLs, untrusted hosts, oversize) | `exfil.py` |
| Prompt-injection delimiters, hardening, secondary validator hook | `injection.py` |
| Memory partitioning, provenance, 16-char HMAC checksum, TTL ≤24h, quarantine | `memory.py` |
| Throttle 100/60s, SIEM alert at 30/60s, depth 10, retries 5, cost $10 | `breakers.py` |
| `total_seconds()` not `.seconds` | `breakers.check_execution_timeout` |
| `AgentSecurityEvent` with 5 metadata categories, tamper-evident | `audit.py` |
| RFC 9421-style signatures + single-use nonces (RFC 9449 replay model) | `signing.py` |
| Third-party execution evidence verification | `signing.verify_execution_evidence` |
| Incident-response containment playbook | `incident.py` |

## What changed in v0.2 (production-readiness pass)

| Area | Before | Now |
|---|---|---|
| Shared state | in-process dicts | `state.py`: `StateBackend` with Memory and **Redis** implementations. Approvals, nonces, revocations, JIT-token registry, rate windows and breaker state all live there, so limits and single-use guarantees hold across replicas. Check-and-consume is a WATCH/MULTI compare-and-swap (tested with 40 racing threads over two replicas). Token secrets are stored only as SHA-256. |
| Connectors | mocks only | `connectors.py`: RFC 8693 **token exchange** at the IdP (https-only, DPoP-bound per RFC 9449), `GitHubHTTPAdapter` (host allowlist, no redirects, response size cap, field whitelist, never echoes upstream bodies). Exchange happens only after PDP allow / approval; failure denies and the target is never called. |
| Signatures | custom Ed25519 scheme | `signing.py`: real **RFC 9421** (`Signature-Input`/`Signature`, derived components, `created`/`expires`/`nonce`/`keyid`/`alg`/`tag`) plus RFC 9530 `Content-Digest`. Reproduces the RFC's Appendix B.2.6 Ed25519 vector byte-for-byte (`tests/test_rfc9421.py`). Receivers refuse messages that leave method, URI, recipient or body uncovered. |
| API auth | `X-Approver-Id` header, no caller auth | `api.py` + `auth.py`: agent calls must be RFC 9421-signed and the key id must equal `identity.agent_id`; the requesting human's JWT `sub` must equal `identity.actor_user_id` (dual-bound identity is now *verified*). Approvers/admins authenticate with role-bearing JWTs; **step-up is derived from `acr` + fresh `auth_time`**, never from the request. alg=none, wrong key, expiry, audience and issuer are all enforced; failures return a uniform 401. |
| DLP | 5 regexes | `dlp.py`: Luhn + issuer-prefix cards, mod-97 IBANs, SSN structural rules, provider secret formats (AWS, GitHub, Slack, Stripe, Google, JWT, PEM, URL credentials, bearer tokens), run over raw **and decoded views** (URL/HTML escapes, base64, hex, zero-width splitting). |
| Injection | 9 regexes | `injection.py`: canonicalization (NFKC, invisible chars, lookalike folding, spacing collapse), decoding views incl. ROT13, category-weighted scoring across 10 attack families (incl. 6 languages), optional **LLM judge** that fails toward caution when unavailable, and **session taint**: a hit forces human approval for every later action in that session, even low-risk ones. Tool output is scanned too. |

## What changed in v0.3

### 1. Detection is probabilistic, so security no longer depends on it
Filters still run (they catch the lazy and the common). But the controls below hold **even when every detector misses**;
`tests/test_dataflow.py` first proves a stealth instruction evades the detector, then shows the attack is still stopped.

| Control | How it works |
|---|---|
| **Origin-checked destinations** | Email recipients / URL hosts must be on the policy allowlist (`egress_allowed_domains`, exact or subdomain, lookalikes rejected) **or** have been typed by the human in this session. The front end reports human input via `register_trusted_input` (`POST /v1/sessions/{id}/trusted-input`, role `frontend`). An injection can't name a new destination no matter how it is phrased. Adapters declare their destination arguments (`egress_params`). |
| **Canaries** | `issue_canary(session)` returns a token to embed in the system prompt. Appearing in any outbound argument (also base64/hex/URL-encoded, any case) = context exfiltration: deny + taint. |
| **Taint policy** | After any injection signal, `taint_policy` in `policy.json` decides per tier: default `low/medium -> require_approval`, `high/critical -> deny`. Enforced even for an approval granted *before* the taint. |
| **Reviewer-gated clear** | `clear_taint` / `POST /v1/sessions/{id}/clear-taint` needs role `security-admin`, fresh MFA and a written reason; audited before it takes effect. |

### 2. Key rotation (`keys.py`)
- `JWKSKeyStore`: https-only JWKS fetch, cached (`ttl` 300s), refresh on unknown `kid` (rate-limited, so random kids can't hammer your IdP),
  serves stale keys through an IdP outage for `stale_ttl` (default 24h) then **fails closed**, never replaces good keys with an empty/garbage set,
  skips weak RSA (<2048), private-key leaks, `use=enc` and unsupported types. A key the IdP retires is distrusted at the next refresh (worst-case lag = `ttl`).
- `DirectoryKeyStore`: agent public keys as `<agent_id>.pem` (URL-quote the id so it works on Windows too: `agent%3Arepo-helper%3Av2.pem`); add, replace or **delete a file to rotate/revoke**, picked up within 15s, no restart.
- Set `GATEWAY_ACTOR_JWKS_URL` / `GATEWAY_STAFF_JWKS_URL` (or the `_DIR` variants).

### 3. Durable audit (`audit_sinks.py`, `audit.py`)
- **Audit-before-execute**: required sinks are written *before* the entry joins the chain and before the action runs. If the log can't be written, the action is refused.
  If the write fails *after* execution, the event is queued (`gateway.unlogged`), the session is halted, and `reconcile_audit()` replays it.
- `FileWORMSink`: append-only JSONL, fsync per entry, crash-safe (partial last line dropped), rotation with read-only sealed segments + SHA-256 `MANIFEST`.
  Restart reloads and **verifies** the chain, refusing to start on tampering. Put it on an append-only (`chattr +a`) or WORM volume.
- `ObjectLockSink`: one immutable S3 Object Lock (COMPLIANCE) object per entry, `IfNoneMatch=*` so nothing is overwritten.
- `HTTPEventSink`: SIEM (Splunk HEC-style), https-only, retries, **disk spool + ordered replay** when the SIEM is down; never blocks business actions.
- **Signed checkpoints** (Ed25519) every N entries, stored on separate storage. `verify_log(entries, checkpoints, hmac_key, pubkey)` detects edits,
  reordering, forged checkpoints **and a deleted tail** (which a bare hash chain cannot see).

### 4. Approval cooldowns
Per-tier delay between final approval and earliest execution (default high 30s, critical 120s; `policy.json` -> `approval.cooldown_seconds`).
It is a recall window: `reject` cancels until the action is consumed. While cooling, the gateway answers `require_approval` with `retry_after`
(not a failure: polling does not trip the retry breaker or burn the approval). The 300s execution window now runs from the *final* approval, so slow reviewers don't eat it.

## Try the HTTP service locally

```bash
python examples/local_walkthrough.py          # starts the real service with throwaway keys and plays an agent against it
python examples/local_walkthrough.py --keep   # same, then leave it running; open the printed URL + /docs in a browser
```
It shows signed requests, an allowed read, a blocked secrets file, a tampered request (rejected), an exfiltration attempt
(denied), a human approval (including the requester failing to approve their own action), approval replay (denied) and the
tamper-evident audit check. Server-side `auth failure:` log lines are expected: the caller only ever sees a generic 401.

## Connecting an AI agent

`agent_gateway.client` is what the agent's runtime uses: `GatewayTools.call(name, input)` signs the request, sends it to the
gateway and returns one plain-text outcome the model can act on (`OK: ...`, `DENIED by security policy: ...`, or
`PENDING HUMAN APPROVAL (id ...)`). The model never touches a tool directly, and approvals are made by people through the
staff API, never by the agent; after approval the *runtime* calls `GatewayTools.resume(approval_id)`.

```bash
python examples/agent_demo.py                              # scripted "model", no API key: shows what the agent sees
python examples/ollama_agent_template.py "your task"       # real LLM tool-use loop via Ollama (free; local or cloud key)
python examples/claude_agent_template.py "your task"       # same loop with Claude (needs ANTHROPIC_API_KEY; see note)
```
The Ollama example was run end to end with a live local model (`llama3.1`): the model read a file, the pull-request call was held
for human approval, and it resumed after approval. Set `OLLAMA_HOST`, `OLLAMA_MODEL` and (cloud only) `OLLAMA_API_KEY`; Ollama cloud
models can need paid credits (HTTP 402), the local server is free. The Claude template is **untested against the live API**
(no key was available); the gateway side is covered by `tests/test_client.py` and `examples/agent_demo.py`. In production, replace the throwaway `DevServer` with your
gateway URL, the agent's own signing key, and a function returning the current user's identity-provider token.

## Real GitHub pull requests

Set `GATEWAY_GITHUB_TOKEN` (or `_TOKEN_FILE`) and `GATEWAY_GITHUB_REPOS=owner/name` and the gateway opens real PRs
(`GitHubPRRealAdapter`) instead of the in-memory mock. HTTPS only, no redirects, the repo must be both in policy and
in `GATEWAY_GITHUB_REPOS`, errors never echo the token. Try it with `examples/github_real_demo.py`.
Tested against a local HTTP server that mimics the pulls endpoint, and once by hand against github.com (a real PR was opened after approval over a slow link, hence the 60 s default; set `GATEWAY_GITHUB_TIMEOUT` to change it). There is no automated test against github.com.

Common GitHub errors: 403 = the fine-grained token lacks *Pull requests: Read and write*; 404 = the token cannot see the repo; 422 = the head branch does not exist, has no new commit, or a PR already exists.


## Policy tour

`examples/policy_tour.py` sends ten fixed requests (each in a fresh session) and prints the decision for each.
Copy `config/policy.json`, edit the copy, and rerun to see decisions change:

    python examples/policy_tour.py                    # the shipped policy
    python examples/policy_tour.py my_policy.json     # your edited copy


## What changed in v0.4

1. **Allowed-destination misuse is bounded, deterministically** (`dataflow.py`). Data carries a label
   (public < internal < confidential < restricted) from `policy.json`; a session's high-water mark can never flow to a
   destination with lower clearance (no write-down), so confidential data cannot reach `partner.com` however the agent was
   steered. Per-session egress budgets (messages, bytes, new destinations) cap volume. Approvers see the data lineage.
   Declassification needs a step-up security-admin and is audited.
2. **Trusted-input boundary is verified, not assumed.** Registrations are replay-protected (`message_id`), rate/size limited,
   checked against fingerprints of everything untrusted in the session (retrieved text, tool output, the agent's own text), and
   attachments are screened as untrusted. A front end that mis-forwards non-human text is rejected and audited.
3. **Local log deletion is detected, fail-closed and recoverable** (`audit_sinks.py`, `audit_guard.py`). The file sink notices
   deletion/replacement/edit on the next write and the gateway refuses to act; a watchdog halts the *whole* gateway on any
   discrepancy; on restart a deleted/diverging local log is quarantined (kept as evidence) and rebuilt from the S3 Object Lock
   copy. Two replicas that disagree refuse to start. Production mode requires an immutable sink. See `deploy/`.
4. **Real adapters** (`adapters_real.py`): SMTP (mandatory verified TLS, fixed sender, header-injection rejection, idempotent)
   and SQL DB-API (soft drop by default and restorable, resource must match table, protected tables, idempotency ledger in
   the same transaction as the DDL). Select with `GATEWAY_SMTP_*` / `GATEWAY_DB_*`; the production profile rejects mocks.

## What changed in v0.5

1. **Allowed-destination misuse: from "a human approves" to "a human approves with evidence, under hard limits".**
   - *Release rules* (`release_rules`): a destination lists the sources it may ever receive from; if the session has read
     anything else, sending is refused whatever the message says. Keys on what was read, so rewording cannot dodge it.
   - *Content tracing*: approvers see which sources the message is copied from (verbatim windows), what share of each source
     is leaving, which destinations are new, and which were typed by the user. Bulk copies of non-public sources are denied,
     **cumulatively across the session** (a source cannot be sent out in several small pieces).
   - *Dual approval* for egress from a tainted session or one that has handled data at/above `egress_dual_approval_label`.
2. **The front end is no longer simply trusted for "the human typed this".** `trusted-input` can require a signature from the
   user's own device key (WebAuthn/passkey, ES256 or EdDSA, with presence + verification, origin, RP-ID and sign-counter
   checks; or raw Ed25519 for native clients). A compromised front end cannot mint, replay, retarget or alter it. A session is
   bound to one user, so one user's typed destinations cannot be used by another. Destinations show `user_signed` vs
   `user_typed` to approvers. Enable with `GATEWAY_USER_CREDENTIALS_DIR` + `GATEWAY_REQUIRE_USER_SIGNATURE=1`.
3. **The audit bucket is verified, not assumed.** At production startup the gateway checks Object Lock is enabled, versioning
   is on, default retention is COMPLIANCE and long enough, and **probes** the bucket with a throwaway object to prove it can be
   neither deleted nor have its retention shortened. The watchdog re-checks for configuration drift and halts on change.
   `deploy/audit-bucket.cloudformation.yaml` (cfn-lint clean) creates the bucket, KMS key, deny-delete policy and IAM policies.
4. **Real-service integration tests** (`pytest -m integration`): real Redis 7 (atomicity under contention, TTL, two-replica
   exactly-once approval consumption), real PostgreSQL 16 (soft/hard drop, concurrency, lock timeouts), real S3 API over HTTP
   (moto; MinIO/real S3 via `GATEWAY_TEST_S3_ENDPOINT`), and a SIEM sink against a real HTTP server. They found and fixed a
   PostgreSQL first-use ledger race and an unbounded lock wait, neither visible against SQLite or fakes. Compose file and CI
   workflow included.

Independent re-check of the new code found two further flaws, now fixed with regression tests: an ambiguous encoding of the
signed bytes, and a per-message (not cumulative) bulk-copy limit.

## Configuration

| Variable | Purpose |
|---|---|
| `GATEWAY_REDIS_URL` | `rediss://...` selects the Redis backend (otherwise in-memory, single process) |
| `GATEWAY_GRANT_KEY`, `GATEWAY_AUDIT_KEY`, `GATEWAY_MEMORY_KEY` | HMAC keys from your KMS. `GATEWAY_AUDIT_KEY` is **mandatory** when audit is persisted |
| `GATEWAY_AUDIT_DIR` / `GATEWAY_CHECKPOINT_DIR` | append-only audit segments / checkpoints on separate storage |
| `GATEWAY_CHECKPOINT_KEY_FILE` | PEM Ed25519 private key that signs checkpoints (mandatory with a required sink) |
| `GATEWAY_AUDIT_S3_BUCKET`, `_PREFIX`, `GATEWAY_AUDIT_RETENTION_DAYS` | S3 Object Lock sink (bucket must have Object Lock enabled) |
| `GATEWAY_SIEM_URL`, `GATEWAY_SIEM_TOKEN`, `GATEWAY_SIEM_SPOOL` | SIEM forwarder |
| `GATEWAY_AGENT_KEYS_DIR` | `<agent_id>.pem` Ed25519 public keys (hot-reloaded) |
| `GATEWAY_ACTOR_JWKS_URL`/`_DIR`, `GATEWAY_ACTOR_ISSUER` | requesting-human tokens (audience `agent-gateway`) |
| `GATEWAY_STAFF_JWKS_URL`/`_DIR`, `GATEWAY_STAFF_ISSUER` | staff tokens (audience `agent-gateway-admin`; roles `approver`, `auditor`, `security-admin`, `frontend`) |
| `GATEWAY_PUBLIC_URL` | external URL agents sign against |
| `GATEWAY_ENV=production` | refuse to start without an immutable audit sink or with mock adapters |
| `GATEWAY_USER_CREDENTIALS_DIR`, `GATEWAY_WEBAUTHN_RP_ID`, `GATEWAY_WEBAUTHN_ORIGINS` | where user device public keys live (`<user>/<credential>.pem`, add/delete to enrol/revoke) |
| `GATEWAY_REQUIRE_USER_SIGNATURE=1` | trusted input must carry a valid user-device attestation |
| `GATEWAY_AUDIT_MIN_RETENTION_DAYS`, `GATEWAY_AUDIT_PROBE=0` | production bucket check: required retention (default 30); skip the delete/shorten probe |
| `GATEWAY_WATCHDOG_INTERVAL` | seconds between audit integrity checks (default 30) |
| `GATEWAY_SMTP_HOST`, `_PORT`, `_FROM`, `_USER`, `_PASSWORD`/`_PASSWORD_FILE`, `_TLS` (`starttls`/`implicit`), `_CA_FILE` | real email adapter |
| `GATEWAY_DB_URL` (`sqlite:///path` or `postgresql://`), `GATEWAY_DB_ENV`, `GATEWAY_DB_MODE` (`soft`/`hard`), `GATEWAY_DB_PROTECTED` | real DB adapter |

## Design decisions to review

1. **Critical tier.** The standard's flowchart says critical -> DENY; its risk table says critical -> step-up + dual approval.
   Default follows the table (`critical_mode: require_dual_approval`). Set `"critical_mode": "deny"` in `policy.json` for the flowchart reading.
2. **Approval binding excludes `step`.** Approvals bind to actor, agent, task, tool, capability, resource, args hash and idempotency key,
   so an approved action can run in a later step, but only once and only with identical parameters.
3. **Taint upgrades low-risk actions to approval.** This is stricter than the standard (which auto-allows low risk). It is the main defense
   against detection misses: a missed injection still can't act silently once *any* signal fires in the session.

## Remaining limitations (what is NOT solved)

- **Approved, allowed, non-traceable disclosure.** A human can still approve sending data to an allowed destination. The
  gateway guarantees the destination is permitted for every source read, the label clearance holds, volume is bounded and the
  approver sees the evidence. It cannot see meaning: a *paraphrase* is not traced (verbatim windows only), and an approver can
  still approve the wrong thing. This is bounded, not eliminated.
- **The attestation proves a registered device of that user signed this exact text, once, now. It does not prove the user read
  it.** WebAuthn has no trusted display, so a malicious front end can still ask the user to touch their key for text shown
  differently. It also cannot defend a user whose own device or key is compromised, and unsigned mode (the default) is still
  front-end-asserted. Require signatures in production.
- **Root on the gateway host** can still delete local files and read in-memory keys. That is now detected immediately, halts
  the gateway, and is recoverable from the S3 copy; and the gateway refuses to start in production if that bucket is not
  actually immutable. An attacker who also holds AWS administrator rights on the audit account, or controls the bucket's KMS
  key, is out of scope: use a separate account.
- **What was tested against what.** Real services: Redis 7.0, PostgreSQL 16, an SMTP server (aiosmtpd), SQLite, HTTP (SIEM),
  and the S3 *API* via moto. NOT real: AWS S3 itself. moto lets COMPLIANCE retention be shortened, which real S3 forbids, so the
  probe correctly flags moto; the IAM/bucket-policy semantics in `deploy/` are cfn-lint clean but have not been applied to a
  real AWS account here. Not run at all here: Docker compose, MinIO, the GitHub Actions workflow, managed Redis/RDS,
  Redis Cluster, TLS to Redis/Postgres, real mail providers, real WebAuthn authenticators (a software authenticator was used).
  Run `pytest -m integration` against your staging infrastructure before relying on it.
- **Detection is probabilistic**; nothing dangerous relies on it, but injection-driven misuse of low-risk entitled actions remains.
- **SMTP idempotency is in-process** (plus a deterministic Message-ID); the DB ledger is durable.
- Soft-dropped tables accumulate until an operator purges them; there is no automatic purge by design.
- Key-retirement lag equals the JWKS `ttl` (default 5 min); call `JWKSKeyStore.refresh()` after an emergency rotation.
- Object Lock sink writes one object per entry synchronously: correct and simple, not high-throughput.
- mTLS and edge rate-limiting are expected from your ingress.
- Run `pytest` as a CI release gate on any change to prompts, tool policies, memory config or model version.


## Testing against your real services (`examples/live_checks.py`)

The test suite and CI run against a **real Redis and a real PostgreSQL**, and S3 through a local moto server. To check your own
infrastructure (managed Redis, RDS, a real Object Lock bucket, a real mail provider) set the variables you have and run:

```
python examples/live_checks.py
```

Each check reports PASS, FAIL or SKIP (see the header of the file for the variables). The S3 check writes in COMPLIANCE mode for
one day, so use a bucket made for testing. The existing pytest suite can also point at real services with
`GATEWAY_TEST_REDIS_URL`, `GATEWAY_TEST_PG_DSN` and `GATEWAY_TEST_S3_ENDPOINT` (see `tests/svc_fixtures.py`).

Known limits: moto lets retention be shortened, so the S3 check **fails against moto by design** and can only pass on a real
bucket. Hardware security keys (WebAuthn) need a browser and a physical key and are not covered by this script.
