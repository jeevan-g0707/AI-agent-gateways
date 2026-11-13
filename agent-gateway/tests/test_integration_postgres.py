"""SQLDropTableAdapter against a REAL PostgreSQL (dialect='postgres', psycopg 3)."""
import threading

import pytest

psycopg = pytest.importorskip("psycopg")

from agent_gateway.adapters import AdapterError, DropTableSchema
from agent_gateway.adapters_real import SQLDropTableAdapter
from agent_gateway.factory import build_stack
from agent_gateway.models import ActionRequest, Decision

from conftest import REPORT, Clock, ident
from svc_fixtures import pg_admin_dsn, pg_dsn  # noqa: F401

pytestmark = pytest.mark.integration
MGR, MGR2 = "user:manager@enterprise.com", "user:director@enterprise.com"


@pytest.fixture
def db(pg_dsn):
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        for t in ("orders", "customers", "old_logs"):
            c.execute(f"CREATE TABLE {t} (id serial PRIMARY KEY, v text)")
            c.execute(f"INSERT INTO {t} (v) SELECT 'row' || g FROM generate_series(1, 3) g")
    return pg_dsn


def tables(dsn, schema="public"):
    with psycopg.connect(dsn) as c:
        return {r[0] for r in c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (schema,))}


def adapter(dsn, **kw):
    kw.setdefault("protected_tables", ["customers"])
    return SQLDropTableAdapter(None, None, connect=lambda: psycopg.connect(dsn), dialect="postgres", **kw)


def req(table, key="k1"):
    return ActionRequest(identity=ident(user="user:admin@enterprise.com"), tool="db_drop_table",
                         capability="db:drop_table", resource=f"db:staging/{table}", arguments={"table": table},
                         idempotency_key=key)


def drop(a, table, key="k1"):
    return a.execute(DropTableSchema(table=table), req(table, key))


def run_threads(n, fn):
    out, errs = [None] * n, [None] * n

    def w(i):
        try:
            out[i] = fn(i)
        except Exception as exc:  # noqa: BLE001
            errs[i] = exc

    ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return out, errs


def test_soft_drop_is_recoverable_with_data_intact(db):
    a = adapter(db)
    r = drop(a, "orders")
    assert r["status"] == "soft_dropped" and "orders" not in tables(db) and r["recoverable_as"] in tables(db)
    assert a.list_trash() == [r["recoverable_as"]]  # LIKE ... ESCAPE works on postgres
    assert a.restore(r["recoverable_as"]) == "orders"
    with psycopg.connect(db) as c:
        assert c.execute("SELECT count(*) FROM orders").fetchone()[0] == 3


def test_hard_drop(db):
    a = adapter(db, mode="hard")
    assert drop(a, "old_logs")["status"] == "dropped" and "old_logs" not in tables(db) and not a.list_trash()


def test_idempotency_is_durable_and_never_drops_a_recreated_table(db):
    assert drop(adapter(db), "orders", "same")["status"] == "soft_dropped"
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("CREATE TABLE orders (id int)")
    assert drop(adapter(db), "orders", "same")["status"] == "duplicate_ignored"  # a fresh adapter / replica
    assert "orders" in tables(db)


def test_simultaneous_duplicate_requests_drop_once(db):
    """Eight workers race with the SAME idempotency key: the unique ledger row serialises them."""
    out, errs = run_threads(8, lambda i: drop(adapter(db), "orders", "race-key"))
    assert not any(errs), errs
    statuses = sorted(o["status"] for o in out)
    assert statuses.count("soft_dropped") == 1 and statuses.count("duplicate_ignored") == 7


def test_first_use_ledger_creation_race_does_not_break_concurrent_drops(pg_dsn):
    """Fresh database, no ledger yet, eight different drops at once (CREATE TABLE IF NOT EXISTS can race)."""
    with psycopg.connect(pg_dsn, autocommit=True) as c:
        for i in range(8):
            c.execute(f"CREATE TABLE t{i} (id int)")
    out, errs = run_threads(8, lambda i: drop(adapter(pg_dsn), f"t{i}", f"key-{i}"))
    assert not any(errs), errs
    assert all(o["status"] == "soft_dropped" for o in out)


def test_different_keys_same_table_only_one_wins(db):
    out, errs = run_threads(6, lambda i: drop(adapter(db), "orders", f"key-{i}"))
    ok = [o for o in out if o]
    assert len(ok) == 1 and all(isinstance(e, AdapterError) for e in errs if e)
    with psycopg.connect(db) as c:  # losers left no ledger rows behind
        assert c.execute("SELECT count(*) FROM _gateway_ops").fetchone()[0] == 1


def test_lock_held_by_another_session_times_out_instead_of_hanging_and_rolls_back(db):
    blocker = psycopg.connect(db)
    blocker.execute("LOCK TABLE orders IN ACCESS SHARE MODE")  # an open transaction reading the table
    try:
        a = adapter(db, lock_timeout_ms=500)
        with pytest.raises(AdapterError, match="LockNotAvailable"):
            drop(a, "orders", "locked")
        assert "orders" in tables(db)
        with psycopg.connect(db) as c:
            assert c.execute("SELECT count(*) FROM _gateway_ops").fetchone()[0] == 0  # no half-recorded drop
    finally:
        blocker.rollback()
        blocker.close()
    assert drop(adapter(db), "orders", "locked")["status"] == "soft_dropped"  # the same key now succeeds


def test_only_the_current_schema_is_touched(db):
    with psycopg.connect(db, autocommit=True) as c:
        c.execute("CREATE SCHEMA other")
        c.execute("CREATE TABLE other.only_there (id int)")
    with pytest.raises(AdapterError, match="does not exist"):
        drop(adapter(db), "only_there", "x")
    assert tables(db, "other") == {"only_there"}


def test_unknown_protected_and_mismatched_resource(db):
    a = adapter(db)
    with pytest.raises(AdapterError, match="does not exist"):
        drop(a, "ghost", "g1")
    with pytest.raises(AdapterError, match="protected"):
        a.check_resource("db:staging/customers", DropTableSchema(table="customers"))
    with pytest.raises(AdapterError, match="authorized resource"):
        a.check_resource("db:staging/orders", DropTableSchema(table="old_logs"))
    assert tables(db) >= {"orders", "customers", "old_logs"}


def test_full_gateway_flow_with_two_approvers_on_real_postgres(db):
    clock = Clock()
    st = build_stack(clock=clock, evidence_sinks=[], fs={REPORT: "x"},
                     db_adapter_factory=lambda b, a: SQLDropTableAdapter(
                         b, a, connect=lambda: psycopg.connect(db), dialect="postgres", clock=clock,
                         protected_tables=["customers"]))

    def r(step):
        return ActionRequest(identity=ident(user="user:admin@enterprise.com"), tool="db_drop_table",
                             capability="db:drop_table", resource="db:staging/old_logs",
                             arguments={"table": "old_logs"}, idempotency_key="idem-pg", step=step)

    first = st.gateway.execute(r(1))
    assert first.decision is Decision.REQUIRE_APPROVAL and "old_logs" in tables(db)  # nothing happened yet
    for who in (MGR, MGR2):
        st.approvals.approve(first.approval_id, who, step_up_verified=True)
    clock.advance(121)
    done = st.gateway.execute(r(2), approval_id=first.approval_id)
    assert done.decision is Decision.ALLOW and done.result["status"] == "soft_dropped"
    assert "old_logs" not in tables(db)
