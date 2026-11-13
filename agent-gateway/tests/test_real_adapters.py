"""Real SMTP (against an actual aiosmtpd server) and real SQL (against actual sqlite) adapters."""
import datetime
import ipaddress
import socket
import sqlite3
import ssl

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent_gateway.adapters import AdapterError, DropTableSchema, EmailSchema
from agent_gateway.adapters_real import GitHubPRRealAdapter, SMTPEmailAdapter, SQLDropTableAdapter
from agent_gateway.audit_sinks import ObjectLockSink
from agent_gateway.factory import build_stack
from agent_gateway.models import ActionRequest, Decision

from conftest import REPORT, Clock, drop_req, email_req, ident
from s3fake import FakeS3

MGR, MGR2 = "user:manager@enterprise.com", "user:director@enterprise.com"
SENDER = "gateway@enterprise.com"


# ============================================================ SMTP fixtures
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=2))
         .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
         .sign(key, hashes.SHA256()))
    cert_p, key_p = d / "cert.pem", d / "key.pem"
    cert_p.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    return cert_p, key_p


class Capture:
    def __init__(self):
        self.messages, self.auth_attempts = [], []

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if address.startswith("blocked@"):
            return "550 5.7.1 recipient rejected"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        return "250 OK"

    def authenticator(self, server, session, envelope, mechanism, auth_data):
        self.auth_attempts.append((auth_data.login, auth_data.password))
        ok = auth_data.login == b"gw" and auth_data.password == b"s3cret-pw"
        return AuthResult(success=ok, handled=False if not ok else True)


@pytest.fixture
def smtp_server(cert):
    """factory: smtp_server(mode='plain'|'starttls'|'implicit', auth=False) -> (cap, port)"""
    started = []

    def make(mode="plain", auth=False):
        cap, port = Capture(), free_port()
        kw = {}
        if mode != "plain":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            kw = {"tls_context": ctx, "require_starttls": True} if mode == "starttls" else {"ssl_context": ctx}
        if auth:
            kw.update(authenticator=cap.authenticator, auth_required=True, auth_require_tls=(mode != "plain"))
        ctl = Controller(cap, hostname="127.0.0.1", port=port, **kw)
        ctl.start()
        started.append(ctl)
        return cap, port

    yield make
    for c in started:
        c.stop()


def adapter(port, cert=None, **kw):
    ctx = ssl.create_default_context(cafile=str(cert[0])) if cert else None
    kw.setdefault("sender", SENDER)
    return SMTPEmailAdapter(None, None, host="127.0.0.1", port=port, ssl_context=ctx, **kw)


def mail_req(key=None, to="ext@partner.com", subject="Docs", body="hello partner"):
    return ActionRequest(identity=ident(), tool="email_send", capability="email:send_external",
                         resource="mailbox:outbound-docs", arguments={"to": to, "subject": subject, "body": body},
                         idempotency_key=key)


def send(a, req):
    return a.execute(EmailSchema(**req.arguments), req)


# ================================================================== SMTP
def test_plain_relay_delivers_with_fixed_sender(smtp_server):
    cap, port = smtp_server("plain")
    out = send(adapter(port, tls="none", allow_insecure=True), mail_req(key="k1"))
    assert out["status"] == "sent"
    env = cap.messages[0]
    assert env.mail_from == SENDER and env.rcpt_tos == ["ext@partner.com"]
    assert b"hello partner" in env.content and b"Message-ID: <" in env.content


def test_starttls_with_auth_delivers_and_credentials_only_after_tls(smtp_server, cert):
    cap, port = smtp_server("starttls", auth=True)  # server itself refuses AUTH before TLS
    out = send(adapter(port, cert, username="gw", password="s3cret-pw"), mail_req())
    assert out["status"] == "sent" and len(cap.messages) == 1
    assert cap.auth_attempts == [(b"gw", b"s3cret-pw")]


def test_wrong_password_fails_and_secret_is_not_echoed(smtp_server, cert):
    cap, port = smtp_server("starttls", auth=True)
    with pytest.raises(AdapterError) as e:
        send(adapter(port, cert, username="gw", password="WRONG-pw"), mail_req())
    assert not cap.messages and "WRONG-pw" not in str(e.value)


def test_server_without_starttls_is_refused_never_downgraded(smtp_server, cert):
    cap, port = smtp_server("plain", auth=False)
    with pytest.raises(AdapterError, match="SMTPNotSupportedError"):
        send(adapter(port, cert, username="gw", password="s3cret-pw"), mail_req())
    assert not cap.messages and not cap.auth_attempts  # credentials never left the gateway


def test_untrusted_certificate_is_refused(smtp_server):
    cap, port = smtp_server("starttls")
    with pytest.raises(AdapterError):  # default trust store does not know the self-signed cert
        send(adapter(port), mail_req())
    assert not cap.messages


def test_implicit_tls(smtp_server, cert):
    cap, port = smtp_server("implicit")
    assert send(adapter(port, cert, tls="implicit"), mail_req())["status"] == "sent"
    assert len(cap.messages) == 1


def test_plaintext_and_cleartext_credentials_refused_at_construction():
    with pytest.raises(ValueError, match="plaintext"):
        SMTPEmailAdapter(None, None, host="h", sender=SENDER, tls="none")
    with pytest.raises(ValueError, match="credentials"):
        SMTPEmailAdapter(None, None, host="h", sender=SENDER, tls="none", allow_insecure=True, username="u")


@pytest.mark.parametrize("field,value", [("subject", "Hi\r\nBcc: evil@x.com"), ("subject", "a\nb"), ("to", "a@b.com\r\nBcc: e@x.com")])
def test_header_injection_is_rejected_and_nothing_is_sent(smtp_server, field, value):
    cap, port = smtp_server("plain")
    req = mail_req()
    args = {**req.arguments, field: value}
    a = adapter(port, tls="none", allow_insecure=True)
    with pytest.raises((AdapterError, ValueError)):
        a.execute(EmailSchema.model_construct(**args), req)  # model_construct: bypass schema to hit the adapter's own guard
    assert not cap.messages


def test_idempotent_send_delivers_once_with_stable_message_id(smtp_server):
    cap, port = smtp_server("plain")
    a = adapter(port, tls="none", allow_insecure=True)
    first, second = send(a, mail_req(key="same")), send(a, mail_req(key="same"))
    assert first["status"] == "sent" and second["status"] == "duplicate_ignored"
    assert len(cap.messages) == 1 and first["message_id"] == second["message_id"]


def test_recipient_rejected_by_server_is_an_error(smtp_server):
    cap, port = smtp_server("plain")
    with pytest.raises(AdapterError, match="SMTPRecipientsRefused|refused"):
        send(adapter(port, tls="none", allow_insecure=True), mail_req(to="blocked@partner.com"))
    assert not cap.messages


def test_unreachable_server_is_an_error_not_a_crash():
    with pytest.raises(AdapterError, match="smtp delivery failed"):
        send(adapter(free_port(), tls="none", allow_insecure=True, timeout=1), mail_req())


def test_end_to_end_through_gateway_with_approval(smtp_server, cert):
    cap, port = smtp_server("starttls", auth=True)
    clock = Clock()
    stack = build_stack(clock=clock, evidence_sinks=[], fs={REPORT: "x"},
                        email_adapter_factory=lambda b, a: SMTPEmailAdapter(
                            b, a, host="127.0.0.1", port=port, sender=SENDER, username="gw", password="s3cret-pw",
                            ssl_context=ssl.create_default_context(cafile=str(cert[0]))))
    gw = stack.gateway
    first = gw.execute(email_req())
    assert first.decision is Decision.REQUIRE_APPROVAL and not cap.messages  # nothing sent before a human approves
    stack.approvals.approve(first.approval_id, MGR, step_up_verified=True)
    clock.advance(31)
    done = gw.execute(email_req(step=2), approval_id=first.approval_id)
    assert done.decision is Decision.ALLOW and done.result["status"] == "sent"
    assert len(cap.messages) == 1


def test_destination_control_still_stops_unlisted_recipient_before_any_network_io(smtp_server, cert):
    cap, port = smtp_server("plain")
    stack = build_stack(clock=Clock(), evidence_sinks=[], fs={REPORT: "x"},
                        email_adapter_factory=lambda b, a: adapter_for(b, a, port))
    bad = ActionRequest(identity=ident(), tool="email_send", capability="email:send_external",
                        resource="mailbox:outbound-docs", step=1,
                        arguments={"to": "bob@evil.net", "subject": "s", "body": "b"})
    assert stack.gateway.execute(bad).decision is Decision.DENY and not cap.messages


def adapter_for(b, a, port):
    return SMTPEmailAdapter(b, a, host="127.0.0.1", port=port, sender=SENDER, tls="none", allow_insecure=True)


# ==================================================================== SQL
@pytest.fixture
def dbfile(tmp_path):
    p = tmp_path / "staging.db"
    c = sqlite3.connect(p)
    for t in ("orders", "customers", "old_logs"):
        c.execute(f"CREATE TABLE {t} (id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany(f"INSERT INTO {t} (v) VALUES (?)", [("a",), ("b",), ("c",)])
    c.commit()
    c.close()
    return p


def tables(p):
    c = sqlite3.connect(p)
    try:
        return {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        c.close()


def sql_adapter(p, **kw):
    kw.setdefault("protected_tables", ["customers"])
    return SQLDropTableAdapter(None, None, connect=lambda: sqlite3.connect(p), **kw)


def dreq(table, key="k1"):
    return ActionRequest(identity=ident(user="user:admin@enterprise.com"), tool="db_drop_table",
                         capability="db:drop_table", resource=f"db:staging/{table}",
                         arguments={"table": table}, idempotency_key=key)


def run_drop(a, table, key="k1"):
    return a.execute(DropTableSchema(table=table), dreq(table, key))


def db_stack(p, clock, **kw):
    kw.setdefault("protected_tables", ["customers"])
    return build_stack(clock=clock, evidence_sinks=[], fs={REPORT: "x"},
                       db_adapter_factory=lambda b, a: SQLDropTableAdapter(
                           b, a, connect=lambda: sqlite3.connect(p), clock=clock, **kw))


def approved_drop(stack, clock, table, key="idem-1"):
    gw = stack.gateway
    req = lambda step: ActionRequest(  # noqa: E731
        identity=ident(user="user:admin@enterprise.com"), tool="db_drop_table", capability="db:drop_table",
        resource=f"db:staging/{table}", arguments={"table": table}, idempotency_key=key, step=step)
    first = gw.execute(req(1))
    assert first.decision is Decision.REQUIRE_APPROVAL
    for who in (MGR, MGR2):
        stack.approvals.approve(first.approval_id, who, step_up_verified=True)
    clock.advance(121)
    return gw.execute(req(2), approval_id=first.approval_id)


def test_soft_drop_through_gateway_is_recoverable(dbfile):
    clock = Clock()
    stack = db_stack(dbfile, clock)
    r = approved_drop(stack, clock, "orders")
    assert r.decision is Decision.ALLOW and r.result["status"] == "soft_dropped"
    trash = r.result["recoverable_as"]
    assert "orders" not in tables(dbfile) and trash in tables(dbfile)
    assert stack.adapters["db_drop_table"].restore(trash) == "orders"
    c = sqlite3.connect(dbfile)
    assert c.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 3  # data intact after restore


def test_hard_drop_when_explicitly_configured(dbfile):
    a = sql_adapter(dbfile, mode="hard")
    assert run_drop(a, "orders")["status"] == "dropped"
    assert "orders" not in tables(dbfile) and not a.list_trash()


def test_default_mode_is_soft(dbfile):
    assert run_drop(sql_adapter(dbfile), "old_logs")["status"] == "soft_dropped"


def test_idempotency_survives_new_adapter_and_never_drops_a_recreated_table(dbfile):
    assert run_drop(sql_adapter(dbfile), "orders", "same")["status"] == "soft_dropped"
    c = sqlite3.connect(dbfile)
    c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY)")
    c.commit()
    c.close()
    again = run_drop(sql_adapter(dbfile), "orders", "same")  # a different replica / after restart
    assert again["status"] == "duplicate_ignored" and "orders" in tables(dbfile)


def test_resource_and_table_must_match(dbfile):
    a = sql_adapter(dbfile)
    req = dreq("orders")  # authorized for orders...
    with pytest.raises(AdapterError, match="authorized resource"):
        a.check_resource(req.resource, DropTableSchema(table="old_logs"))  # ...but asks to drop old_logs
    assert tables(dbfile) >= {"orders", "old_logs"}


def test_gateway_flow_with_mismatched_resource_drops_nothing(dbfile):
    clock = Clock()
    stack = db_stack(dbfile, clock)
    gw = stack.gateway
    first = gw.execute(drop_req(table="old_logs"))  # conftest's request authorizes db:staging/orders
    for who in (MGR, MGR2):
        stack.approvals.approve(first.approval_id, who, step_up_verified=True)
    clock.advance(121)
    r = gw.execute(drop_req(table="old_logs", step=2), approval_id=first.approval_id)
    assert r.decision is Decision.DENY and tables(dbfile) >= {"orders", "old_logs"}


def test_protected_table_cannot_be_dropped_even_with_approval(dbfile):
    clock = Clock()
    stack = db_stack(dbfile, clock)
    r = approved_drop(stack, clock, "customers")
    assert r.decision is Decision.DENY and "customers" in tables(dbfile)


def test_ledger_and_trash_tables_are_protected(dbfile):
    a = sql_adapter(dbfile)
    run_drop(a, "old_logs")
    for t in ("_gateway_ops", a.list_trash()[0]):
        with pytest.raises(AdapterError, match="protected"):
            a.check_resource(f"db:staging/{t}", DropTableSchema(table=t))


def test_unknown_table_errors_and_leaves_no_ledger_row_so_retry_works(dbfile):
    a = sql_adapter(dbfile)
    with pytest.raises(AdapterError, match="does not exist"):
        run_drop(a, "ghost", "retry-me")
    c = sqlite3.connect(dbfile)
    assert c.execute("SELECT COUNT(*) FROM _gateway_ops").fetchone()[0] == 0
    c.execute("CREATE TABLE ghost (id INTEGER)")
    c.commit()
    c.close()
    assert run_drop(a, "ghost", "retry-me")["status"] == "soft_dropped"


def test_idempotency_key_is_required(dbfile):
    with pytest.raises(AdapterError, match="idempotency_key"):
        sql_adapter(dbfile).execute(DropTableSchema(table="orders"), dreq("orders", key=None))


class _FailingConn:
    """Wraps a real connection and raises when the DDL statement runs (after the ledger row was inserted)."""

    def __init__(self, conn):
        self._c = conn

    def cursor(self):
        outer = self
        cur = self._c.cursor()

        class Cur:
            def execute(self, sql, *a):
                if sql.startswith("ALTER TABLE"):
                    raise sqlite3.OperationalError("disk I/O error")
                return cur.execute(sql, *a)

            def __getattr__(self, n):
                return getattr(cur, n)

        return Cur()

    def __getattr__(self, n):
        return getattr(self._c, n)


def test_ddl_failure_rolls_back_the_ledger_row_too(dbfile):
    a = SQLDropTableAdapter(None, None, connect=lambda: _FailingConn(sqlite3.connect(dbfile)))
    with pytest.raises(AdapterError, match="OperationalError"):
        run_drop(a, "orders", "k-fail")
    c = sqlite3.connect(dbfile)
    assert c.execute("SELECT COUNT(*) FROM _gateway_ops").fetchone()[0] == 0 and "orders" in tables(dbfile)
    assert run_drop(sql_adapter(dbfile), "orders", "k-fail")["status"] == "soft_dropped"  # retry is possible


def test_restore_refuses_to_overwrite_a_recreated_table(dbfile):
    a = sql_adapter(dbfile)
    trash = run_drop(a, "orders")["recoverable_as"]
    c = sqlite3.connect(dbfile)
    c.execute("CREATE TABLE orders (x INTEGER)")
    c.commit()
    c.close()
    with pytest.raises(AdapterError, match="already exists"):
        a.restore(trash)
    with pytest.raises(AdapterError):
        a.restore("orders")  # not a trash table


def test_injection_in_identifier_is_impossible(dbfile):
    with pytest.raises(Exception):
        DropTableSchema(table='orders"; DROP TABLE customers; --')
    assert "customers" in tables(dbfile)


# ====================================================== wiring / production
def test_environment_selects_real_adapters(monkeypatch, dbfile):
    from agent_gateway.adapters_real import SMTPEmailAdapter as S, SQLDropTableAdapter as Q
    monkeypatch.setenv("GATEWAY_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("GATEWAY_SMTP_FROM", SENDER)
    monkeypatch.setenv("GATEWAY_DB_URL", f"sqlite:///{dbfile}")
    monkeypatch.setenv("GATEWAY_DB_MODE", "hard")
    monkeypatch.setenv("GATEWAY_DB_PROTECTED", "customers,payments")
    stack = build_stack(clock=Clock(), evidence_sinks=[])
    assert isinstance(stack.adapters["email_send"], S) and isinstance(stack.adapters["db_drop_table"], Q)
    assert stack.adapters["db_drop_table"]._mode == "hard" and "payments" in stack.adapters["db_drop_table"]._protected


def test_production_profile_accepts_real_adapters_and_rejects_mocks(dbfile):
    sink = ObjectLockSink(FakeS3(), "b")
    stack = build_stack(clock=Clock(), evidence_sinks=[sink], production=True,
                        email_adapter_factory=lambda b, a: SMTPEmailAdapter(b, a, host="h", sender=SENDER),
                        db_adapter_factory=lambda b, a: SQLDropTableAdapter(b, a, connect=lambda: sqlite3.connect(dbfile)),
                        github_adapter_factory=lambda b, a: GitHubPRRealAdapter(b, a, token="t", allowed_repos=["o/r"]))
    assert not any(getattr(a, "is_mock", False) for a in stack.adapters.values() if a.name != "file_reader")
    from agent_gateway.audit_guard import ProductionProfileError
    with pytest.raises(ProductionProfileError):
        build_stack(clock=Clock(), evidence_sinks=[ObjectLockSink(FakeS3(), "b")], production=True)
