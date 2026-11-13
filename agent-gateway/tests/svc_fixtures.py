"""Fixtures that run the integration tests against REAL services.

Each service is taken from the environment if you provide one, otherwise started locally, otherwise the test is skipped:
  GATEWAY_TEST_REDIS_URL=redis://host:6379/15
  GATEWAY_TEST_PG_DSN=postgresql://user:pw@host:5432/postgres      (needs CREATEDB)
  GATEWAY_TEST_S3_ENDPOINT=http://host:9000  + AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY  (MinIO / moto / real S3 if empty)
Pointing these at real infrastructure (a staging Redis, RDS, a real Object Lock bucket) is the intended use.
"""
from __future__ import annotations

import glob
import itertools
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

import pytest


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 20.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listening on {port}")


# ----------------------------------------------------------------------------- Redis
@pytest.fixture(scope="session")
def redis_url():
    url = os.environ.get("GATEWAY_TEST_REDIS_URL")
    if url:
        from urllib.parse import urlparse

        db = (urlparse(url).path or "/0").lstrip("/") or "0"
        if db == "0" and os.environ.get("GATEWAY_TEST_ALLOW_FLUSH") != "1":
            pytest.fail("refusing to FLUSHDB database 0 of an external Redis: use a dedicated database number "
                        "(e.g. redis://host:6379/15) or set GATEWAY_TEST_ALLOW_FLUSH=1")
        yield url
        return
    exe = shutil.which("redis-server")
    if not exe:
        pytest.skip("no redis-server available (set GATEWAY_TEST_REDIS_URL)")
    port, d = free_port(), tempfile.mkdtemp(prefix="gw-redis-")
    p = subprocess.Popen([exe, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no",
                          "--dir", d], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(port)
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        p.terminate()
        p.wait(10)
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def redis_client(redis_url):
    redis = pytest.importorskip("redis")
    c = redis.Redis.from_url(redis_url)
    c.flushdb()
    yield c
    c.flushdb()
    c.close()


# -------------------------------------------------------------------------- PostgreSQL
@pytest.fixture(scope="session")
def pg_admin_dsn():
    pytest.importorskip("psycopg")
    dsn = os.environ.get("GATEWAY_TEST_PG_DSN")
    if dsn:
        yield dsn
        return
    bins = sorted(glob.glob("/usr/lib/postgresql/*/bin"))
    if not bins:
        pytest.skip("no PostgreSQL binaries available (set GATEWAY_TEST_PG_DSN)")
    b = bins[-1]
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    if root:
        import pwd

        try:
            pwd.getpwnam("postgres")
        except KeyError:
            pytest.skip("running as root and no 'postgres' user to run the server as")
    pre = ["runuser", "-u", "postgres", "--"] if root else []
    d = tempfile.mkdtemp(prefix="gw-pg-")
    os.chmod(d, 0o755)
    if root:
        shutil.chown(d, "postgres")
    port = free_port()
    subprocess.run(pre + [f"{b}/initdb", "-D", f"{d}/data", "-A", "trust", "-U", "postgres"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(pre + [f"{b}/pg_ctl", "-D", f"{d}/data", "-w", "-l", f"{d}/log", "-o",
                          f"-p {port} -k {d} -c listen_addresses=127.0.0.1 -c fsync=off", "start"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run(pre + [f"{b}/pg_ctl", "-D", f"{d}/data", "-m", "fast", "stop"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(d, ignore_errors=True)


_db_counter = itertools.count()


@pytest.fixture
def pg_dsn(pg_admin_dsn):
    """A fresh, empty database per test."""
    import psycopg

    name = f"t_{os.getpid()}_{next(_db_counter)}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
    base, _, _ = pg_admin_dsn.rpartition("/")
    dsn = f"{base}/{name}"
    yield dsn
    with psycopg.connect(pg_admin_dsn, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# --------------------------------------------------------------------------------- S3
@pytest.fixture(scope="session")
def s3_endpoint():
    ep = os.environ.get("GATEWAY_TEST_S3_ENDPOINT")
    if ep:
        yield ep
        return
    pytest.importorskip("boto3")
    exe = shutil.which("moto_server")
    if not exe:
        pytest.skip("no moto_server available (pip install 'moto[server]') (or set GATEWAY_TEST_S3_ENDPOINT)")
    port = free_port()
    env = {**os.environ, "AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}
    p = subprocess.Popen([exe, "-p", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        wait_port(port)
        yield f"http://127.0.0.1:{port}"
    finally:
        p.terminate()
        p.wait(10)


@pytest.fixture
def s3_client(s3_endpoint):
    import boto3

    return boto3.client("s3", endpoint_url=s3_endpoint, region_name="us-east-1",
                        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
                        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"))


@pytest.fixture
def s3_bucket(s3_client):
    """A fresh Object-Lock-enabled, versioned bucket (default retention COMPLIANCE if the server supports setting it)."""
    name = f"gw-audit-{uuid.uuid4().hex[:12]}"
    s3_client.create_bucket(Bucket=name, ObjectLockEnabledForBucket=True)
    try:
        s3_client.put_object_lock_configuration(Bucket=name, ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}}})
    except Exception:
        pass
    return s3_client, name
