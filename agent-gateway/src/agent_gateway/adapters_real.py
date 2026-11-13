"""Real (non-mock) adapters: SMTP email and SQL (DB-API 2.0) table drop.

Both keep the ToolAdapter contract: credential check -> schema -> resource check -> atomic approval
consume -> execute. What they add is *their own* safety, independent of the gateway in front of them:

SMTPEmailAdapter
  * TLS is mandatory. STARTTLS (default) or implicit TLS, certificate and hostname verified. Plaintext is
    refused at construction unless `allow_insecure=True`, and credentials are never sent without TLS.
  * The envelope sender is fixed by configuration; the agent can only choose recipient, subject and body.
  * CR/LF in any header value is rejected (header injection), and the recipient must be a single address.
  * A deterministic Message-ID derived from the idempotency key lets the receiving side de-duplicate; an
    in-process ledger also suppresses a retried send.

SQLDropTableAdapter
  * SOFT DROP by default: the table is renamed into a trash name, so a mistaken or malicious approval is
    recoverable (`restore()`); `mode="hard"` must be chosen explicitly.
  * The resource authorised by policy must name exactly the table being dropped (db:<env>/<table>).
  * Protected tables can never be dropped; unknown tables are an error.
  * Idempotency is a ledger row written in the SAME transaction as the DDL, so a retry or a second gateway
    replica cannot drop twice, and a failed drop leaves no ledger row (the retry can succeed).
"""
from __future__ import annotations

import contextlib
import hashlib
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any, Callable, Iterable

from .adapters import AdapterError, DropTableSchema, EmailSchema, GitHubCreatePRSchema, ToolAdapter
from .models import ActionRequest

TLS_MODES = ("starttls", "implicit", "none")
LEDGER_LOCK_ID = 0x41475741  # arbitrary constant for the postgres advisory lock that serialises ledger creation


# --------------------------------------------------------------------------
# SMTP
# --------------------------------------------------------------------------
class SMTPEmailAdapter(ToolAdapter):
    name = "email_send"
    capability = "email:send_external"
    schema = EmailSchema
    egress_params = {"to": "email"}
    is_mock = False

    def __init__(
        self,
        broker,
        approvals,
        *,
        host: str,
        sender: str,
        port: int = 587,
        username: str | None = None,
        password: str | None = None,
        tls: str = "starttls",
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 15.0,
        allow_insecure: bool = False,
        smtp_factory: Callable[..., smtplib.SMTP] | None = None,
    ):
        super().__init__(broker, approvals)
        if tls not in TLS_MODES:
            raise ValueError(f"tls must be one of {TLS_MODES}")
        if tls == "none" and not allow_insecure:
            raise ValueError("plaintext SMTP refused: use tls='starttls' or 'implicit' (allow_insecure is for tests only)")
        if tls == "none" and username:
            raise ValueError("refusing to send SMTP credentials without TLS")
        if "@" not in sender or any(c in sender for c in "\r\n"):
            raise ValueError("sender must be a single mailbox address")
        self._host, self._port, self._sender = host, port, sender
        self._user, self._pw, self._tls = username, password, tls
        self._ctx = ssl_context or ssl.create_default_context()  # verifies chain and hostname
        self._timeout = timeout
        self._smtp_factory = smtp_factory
        self._domain = sender.rsplit("@", 1)[1]
        self._sent: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- helpers -----------------------------------------------------------
    @contextlib.contextmanager
    def _connect(self):
        if self._tls == "implicit":
            s = (self._smtp_factory or smtplib.SMTP_SSL)(self._host, self._port, timeout=self._timeout,
                                                         context=self._ctx)
        else:
            s = (self._smtp_factory or smtplib.SMTP)(self._host, self._port, timeout=self._timeout)
        try:
            s.ehlo()
            if self._tls == "starttls":
                s.starttls(context=self._ctx)  # raises if the server does not offer it: we never fall back to plaintext
                s.ehlo()
            if self._user:
                s.login(self._user, self._pw or "")
            yield s
        finally:
            try:
                s.quit()
            except Exception:
                s.close()

    def _message(self, args: EmailSchema, key: str | None) -> EmailMessage:
        for label, value in (("to", args.to), ("subject", args.subject)):
            if "\r" in value or "\n" in value or "\x00" in value:
                raise AdapterError(f"header injection rejected in '{label}'")
        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = args.to
        msg["Subject"] = args.subject
        msg["Date"] = formatdate(localtime=False)
        digest = hashlib.sha256(key.encode()).hexdigest()[:32] if key else hashlib.sha256(
            f"{args.to}{args.subject}{args.body}{time.time_ns()}".encode()).hexdigest()[:32]
        msg["Message-ID"] = f"<{digest}@{self._domain}>"
        msg.set_content(args.body)
        return msg

    # -- ToolAdapter -------------------------------------------------------
    def execute(self, args: EmailSchema, request: ActionRequest, token=None) -> dict:
        key = request.idempotency_key
        with self._lock:
            if key and key in self._sent:
                return {"status": "duplicate_ignored", "message_id": self._sent[key]["message_id"]}
        msg = self._message(args, key)
        try:
            with self._connect() as s:
                refused = s.send_message(msg, from_addr=self._sender, to_addrs=[args.to])
        except (smtplib.SMTPException, OSError) as exc:  # includes ssl.SSLError / certificate failures
            raise AdapterError(f"smtp delivery failed: {type(exc).__name__}") from exc  # never echo server text/creds
        if refused:
            raise AdapterError("recipient refused by the mail server")
        out = {"status": "sent", "message_id": msg["Message-ID"]}
        if key:
            with self._lock:
                self._sent[key] = out
        return out


# --------------------------------------------------------------------------
# GitHub
# --------------------------------------------------------------------------
class GitHubPRRealAdapter(ToolAdapter):
    """Opens a REAL pull request through the GitHub REST API (POST /repos/{owner}/{repo}/pulls).

      * The token lives only in the gateway process; the agent never sees it. Use a fine-grained token limited to
        one repository with only "Pull requests: write" (and "Contents: read").
      * The repository comes from the policy-checked resource (repo:<owner>/<name>), never from the arguments, and
        must be one of `allowed_repos` configured here as well (a second, independent check).
      * HTTPS only (allow_insecure is for tests). Redirects are not followed, so the token cannot be sent elsewhere.
      * A retried idempotency key returns the first PR instead of opening a second one.
      * Errors never echo the token or GitHub's response body to the agent.
    """

    name = "github_pr"
    capability = "github:pull_request:create"
    schema = GitHubCreatePRSchema
    is_mock = False

    def __init__(self, broker, approvals, *, token: str, allowed_repos: Iterable[str],
                 api_url: str = "https://api.github.com", http=None, timeout: float = 60.0,
                 allow_insecure: bool = False):
        super().__init__(broker, approvals)
        import httpx

        if not token or any(c in token for c in "\r\n "):
            raise ValueError("a GitHub token is required (no whitespace)")
        if not api_url.startswith("https://") and not allow_insecure:
            raise ValueError("GitHub API URL must be https (allow_insecure is for tests only)")
        self._repos = frozenset(allowed_repos)
        if not self._repos:
            raise ValueError("allowed_repos must name at least one owner/name")
        self._token, self._api = token, api_url.rstrip("/")
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self._done: dict[str, dict] = {}
        self._lock = threading.Lock()

    def check_resource(self, resource: str, parsed) -> None:
        if not resource.startswith("repo:") or resource[5:] not in self._repos:
            raise AdapterError("repository is not configured for this adapter")

    def execute(self, args: GitHubCreatePRSchema, request: ActionRequest, token=None) -> dict:
        import httpx

        key = request.idempotency_key
        with self._lock:
            if key and key in self._done:
                return {**self._done[key], "status": "duplicate_ignored"}
        repo = request.resource[5:]
        try:
            r = self._http.post(
                f"{self._api}/repos/{repo}/pulls",
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "agent-gateway"},
                json={"title": args.title, "head": args.head, "base": args.base, "body": args.body})
        except httpx.HTTPError as exc:
            raise AdapterError(f"github request failed: {type(exc).__name__}") from exc
        if r.status_code == 201:
            d = r.json()
            out = {"status": "created", "repo": repo, "number": d.get("number"), "url": d.get("html_url")}
            if key:
                with self._lock:
                    self._done[key] = out
            return out
        reasons = {401: "token rejected", 403: "token not permitted for this repository or rate limited",
                   404: "repository not found or token cannot see it",
                   422: "GitHub refused it (branch missing, no commits between branches, or a PR already exists)"}
        raise AdapterError(f"github returned HTTP {r.status_code}: {reasons.get(r.status_code, 'unexpected response')}")


# --------------------------------------------------------------------------
# SQL
# --------------------------------------------------------------------------
class SQLDropTableAdapter(ToolAdapter):
    name = "db_drop_table"
    capability = "db:drop_table"
    schema = DropTableSchema
    is_mock = False

    LEDGER = "_gateway_ops"

    def __init__(
        self,
        broker,
        approvals,
        *,
        connect: Callable[[], Any],
        environment: str = "staging",
        mode: str = "soft",
        dialect: str = "sqlite",
        protected_tables: Iterable[str] = (),
        clock: Callable[[], float] = time.time,
        lock_timeout_ms: int = 5000,
    ):
        super().__init__(broker, approvals)
        if lock_timeout_ms <= 0:
            raise ValueError("lock_timeout_ms must be positive: an unbounded wait for a table lock can hang the gateway")
        self._lock_timeout_ms = int(lock_timeout_ms)
        if mode not in ("soft", "hard"):
            raise ValueError("mode must be 'soft' or 'hard'")
        if dialect not in ("sqlite", "postgres"):
            raise ValueError("dialect must be 'sqlite' or 'postgres'")
        self._connect, self._env, self._mode, self._dialect = connect, environment, mode, dialect
        self._protected = {t.lower() for t in protected_tables} | {self.LEDGER}
        self._clock = clock
        self._ph = "?" if dialect == "sqlite" else "%s"

    # -- SQL helpers (identifiers are schema-validated AND quoted) ----------
    @staticmethod
    def _q(ident: str) -> str:
        return '"' + ident.replace('"', '""') + '"'

    def _exists(self, cur, table: str) -> bool:
        if self._dialect == "sqlite":
            cur.execute(f"SELECT 1 FROM sqlite_master WHERE type='table' AND name={self._ph}", (table,))
        else:
            cur.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() "
                        f"AND table_name={self._ph}", (table,))
        return cur.fetchone() is not None

    def _ensure_ledger(self, cur) -> None:
        cur.execute(f"CREATE TABLE IF NOT EXISTS {self.LEDGER} ("
                    "idempotency_key TEXT PRIMARY KEY, action TEXT NOT NULL, table_name TEXT NOT NULL, "
                    "trash_name TEXT, at DOUBLE PRECISION NOT NULL)" if self._dialect == "postgres" else
                    f"CREATE TABLE IF NOT EXISTS {self.LEDGER} ("
                    "idempotency_key TEXT PRIMARY KEY, action TEXT NOT NULL, table_name TEXT NOT NULL, "
                    "trash_name TEXT, at REAL NOT NULL)")

    def _trash_name(self, table: str) -> str:
        return f"_trash_{int(self._clock())}_{table}"[:63]

    # -- ToolAdapter -------------------------------------------------------
    def check_resource(self, resource: str, parsed: DropTableSchema) -> None:
        if resource != f"db:{self._env}/{parsed.table}":
            raise AdapterError("table does not match the authorized resource")
        if parsed.table.lower() in self._protected or parsed.table.startswith("_trash_"):
            raise AdapterError("table is protected")

    def execute(self, args: DropTableSchema, request: ActionRequest, token=None) -> dict:
        key = request.idempotency_key
        if not key:
            raise AdapterError("idempotency_key required for critical actions")
        conn = self._connect()
        try:
            cur = conn.cursor()
            if self._dialect == "postgres":
                # CREATE TABLE IF NOT EXISTS is not race-free on PostgreSQL (concurrent first use raises UniqueViolation)
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (LEDGER_LOCK_ID,))
            self._ensure_ledger(cur)
            conn.commit()  # ledger creation is not part of the drop transaction (this also releases the advisory lock)
            if self._dialect == "postgres":  # bounded wait for the table lock; applies to this transaction only
                cur.execute(f"SET LOCAL lock_timeout = {self._lock_timeout_ms}")
            try:
                cur.execute(f"INSERT INTO {self.LEDGER} (idempotency_key, action, table_name, trash_name, at) "
                            f"VALUES ({self._ph},{self._ph},{self._ph},{self._ph},{self._ph})",
                            (key, self._mode + "_drop", args.table, None, self._clock()))
            except Exception as exc:  # unique violation: this exact operation already happened
                conn.rollback()
                cur = conn.cursor()
                cur.execute(f"SELECT 1 FROM {self.LEDGER} WHERE idempotency_key={self._ph}", (key,))
                if cur.fetchone() is not None:
                    return {"status": "duplicate_ignored"}
                raise AdapterError(f"ledger write failed: {type(exc).__name__}") from exc
            if not self._exists(cur, args.table):
                conn.rollback()
                raise AdapterError(f"table '{args.table}' does not exist")
            if self._mode == "soft":
                trash = self._trash_name(args.table)
                cur.execute(f"ALTER TABLE {self._q(args.table)} RENAME TO {self._q(trash)}")
                cur.execute(f"UPDATE {self.LEDGER} SET trash_name={self._ph} WHERE idempotency_key={self._ph}",
                            (trash, key))
                result = {"status": "soft_dropped", "recoverable_as": trash}
            else:
                cur.execute(f"DROP TABLE {self._q(args.table)}")
                result = {"status": "dropped"}
            conn.commit()  # DDL and ledger row become durable together
            return result
        except AdapterError:
            raise
        except Exception as exc:
            with contextlib.suppress(Exception):
                conn.rollback()
            raise AdapterError(f"database operation failed: {type(exc).__name__}") from exc
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    # -- recovery (operator tooling, not exposed to the agent) -------------
    def list_trash(self) -> list[str]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            if self._dialect == "sqlite":
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '\\_trash\\_%' ESCAPE '\\'")
            else:
                cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() "
                            "AND table_name LIKE '\\_trash\\_%'")
            return sorted(r[0] for r in cur.fetchall())
        finally:
            conn.close()

    def restore(self, trash_name: str) -> str:
        """Undo a soft drop. Refuses if the original name has since been re-created."""
        if not trash_name.startswith("_trash_"):
            raise AdapterError("not a trash table")
        original = trash_name.split("_", 3)[3]
        conn = self._connect()
        try:
            cur = conn.cursor()
            if not self._exists(cur, trash_name):
                raise AdapterError("no such trash table")
            if self._exists(cur, original):
                raise AdapterError(f"'{original}' already exists; refusing to overwrite")
            cur.execute(f"ALTER TABLE {self._q(trash_name)} RENAME TO {self._q(original)}")
            conn.commit()
            return original
        finally:
            conn.close()


# --------------------------------------------------------------------------
# environment wiring
# --------------------------------------------------------------------------
def smtp_adapter_from_env(env: dict[str, str]) -> Callable | None:
    """GATEWAY_SMTP_HOST [_PORT _FROM _USER _PASSWORD|_PASSWORD_FILE _TLS _CA_FILE]. Returns a factory or None."""
    if not env.get("GATEWAY_SMTP_HOST"):
        return None
    password = env.get("GATEWAY_SMTP_PASSWORD")
    if env.get("GATEWAY_SMTP_PASSWORD_FILE"):
        with open(env["GATEWAY_SMTP_PASSWORD_FILE"]) as f:
            password = f.read().strip()
    ctx = ssl.create_default_context(cafile=env.get("GATEWAY_SMTP_CA_FILE"))
    tls = env.get("GATEWAY_SMTP_TLS", "starttls")

    def factory(broker, approvals):
        return SMTPEmailAdapter(
            broker, approvals, host=env["GATEWAY_SMTP_HOST"],
            port=int(env.get("GATEWAY_SMTP_PORT", "465" if tls == "implicit" else "587")),
            sender=env["GATEWAY_SMTP_FROM"], username=env.get("GATEWAY_SMTP_USER"), password=password,
            tls=tls, ssl_context=ctx)

    return factory


def github_adapter_from_env(env: dict[str, str]) -> Callable | None:
    """GATEWAY_GITHUB_TOKEN (or _TOKEN_FILE) + GATEWAY_GITHUB_REPOS=owner/name[,owner/name] [GATEWAY_GITHUB_API_URL]."""
    token = env.get("GATEWAY_GITHUB_TOKEN")
    if env.get("GATEWAY_GITHUB_TOKEN_FILE"):
        with open(env["GATEWAY_GITHUB_TOKEN_FILE"]) as f:
            token = f.read().strip()
    if not token:
        return None
    repos = [r.strip() for r in env.get("GATEWAY_GITHUB_REPOS", "").split(",") if r.strip()]
    if not repos:
        raise RuntimeError("GATEWAY_GITHUB_REPOS (owner/name, comma separated) is required with a GitHub token")
    api = env.get("GATEWAY_GITHUB_API_URL", "https://api.github.com")

    def factory(broker, approvals):
        return GitHubPRRealAdapter(broker, approvals, token=token.strip(), allowed_repos=repos, api_url=api,
                                   timeout=float(env.get("GATEWAY_GITHUB_TIMEOUT", "60")),
                                   allow_insecure=env.get("GATEWAY_GITHUB_ALLOW_INSECURE") == "1")

    return factory


def sql_adapter_from_env(env: dict[str, str]) -> Callable | None:
    """GATEWAY_DB_URL (sqlite:///path | postgresql://...) [GATEWAY_DB_ENV GATEWAY_DB_MODE GATEWAY_DB_PROTECTED]."""
    url = env.get("GATEWAY_DB_URL")
    if not url:
        return None
    if url.startswith("sqlite:///"):
        import sqlite3

        path, dialect = url[len("sqlite:///"):], "sqlite"

        def connect():
            return sqlite3.connect(path, timeout=10)
    elif url.startswith(("postgresql://", "postgres://")):
        import psycopg  # optional dependency: pip install 'agent-gateway[postgres]'

        dialect = "postgres"

        def connect():
            return psycopg.connect(url, connect_timeout=10)
    else:
        raise RuntimeError("GATEWAY_DB_URL must be sqlite:///path or postgresql://...")

    def factory(broker, approvals):
        return SQLDropTableAdapter(
            broker, approvals, connect=connect, dialect=dialect, environment=env.get("GATEWAY_DB_ENV", "staging"),
            mode=env.get("GATEWAY_DB_MODE", "soft"),
            protected_tables=[t for t in env.get("GATEWAY_DB_PROTECTED", "").split(",") if t])

    return factory
