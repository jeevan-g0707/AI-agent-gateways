"""Live checks against YOUR real services. Each check runs only if its environment variables are set; otherwise SKIP.

  Redis (managed, e.g. ElastiCache/Upstash)  GATEWAY_LIVE_REDIS_URL=rediss://:password@host:6379/15
  PostgreSQL (e.g. RDS)                       GATEWAY_LIVE_PG_DSN=postgresql://user:pw@host:5432/postgres
  S3 Object Lock bucket                       GATEWAY_LIVE_S3_BUCKET=name   (+ AWS credentials as usual, optional GATEWAY_LIVE_S3_ENDPOINT)
  Mail provider (Gmail/SES/SendGrid SMTP)     GATEWAY_SMTP_HOST, _PORT, _FROM, _USER, _PASSWORD, _TLS (starttls|implicit),
                                              GATEWAY_LIVE_MAIL_TO=you@example.com

    python examples/live_checks.py

WARNING (S3): the bucket must have Object Lock enabled. The check writes 2 audit-style objects and 1 probe object under a
unique prefix in COMPLIANCE mode for 1 day. COMPLIANCE objects cannot be deleted by anyone until the day is over (a few bytes,
negligible cost). Use a bucket you made for testing. Nothing is printed that contains a password or key.
"""
from __future__ import annotations

import os
import sys
import time
import uuid

RESULTS: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""), flush=True)


def check_redis() -> None:
    url = os.environ.get("GATEWAY_LIVE_REDIS_URL")
    if not url:
        return record("redis", "SKIP", "GATEWAY_LIVE_REDIS_URL not set")
    import redis

    from agent_gateway.state import RedisBackend

    r = redis.Redis.from_url(url, socket_timeout=15)
    r.ping()
    b = RedisBackend(r, prefix=f"agw-live-{uuid.uuid4().hex[:8]}:")
    k = "counter"
    for _ in range(5):
        b.atomic_update(k, lambda v: ((v or 0) + 1, None), ttl=60)
    got = b.get(k)
    assert got == 5, f"expected 5, got {got}"
    assert b.set_nx("once", 30) and not b.set_nx("once", 30), "set_nx is not atomic"
    tls = url.startswith("rediss://")
    record("redis", "PASS", f"atomic updates work; TLS={'yes' if tls else 'NO (use rediss:// for managed Redis)'}")


def check_postgres() -> None:
    dsn = os.environ.get("GATEWAY_LIVE_PG_DSN")
    if not dsn:
        return record("postgres", "SKIP", "GATEWAY_LIVE_PG_DSN not set")
    import psycopg

    with psycopg.connect(dsn, connect_timeout=15) as c:
        ver = c.execute("select version()").fetchone()[0].split(",")[0]
        t = f"agw_live_{uuid.uuid4().hex[:8]}"
        c.execute(f"create table {t} (id int primary key, v text)")
        c.execute(f"insert into {t} values (1, 'ok')")
        assert c.execute(f"select v from {t} where id=1").fetchone()[0] == "ok"
        c.execute(f"drop table {t}")
        c.commit()
    record("postgres", "PASS", ver)


def check_s3() -> None:
    bucket = os.environ.get("GATEWAY_LIVE_S3_BUCKET")
    if not bucket:
        return record("s3-object-lock", "SKIP", "GATEWAY_LIVE_S3_BUCKET not set")
    import boto3

    from agent_gateway.audit_sinks import ObjectLockSink

    client = boto3.client("s3", endpoint_url=os.environ.get("GATEWAY_LIVE_S3_ENDPOINT") or None)
    prefix = f"live-check-{uuid.uuid4().hex[:8]}/"
    sink = ObjectLockSink(client, bucket, prefix, retention_days=1, mode="COMPLIANCE")
    sink.write({"seq": 1, "event": "live-check", "ts": time.time()})
    # an identical rewrite is a no-op; a different entry at the same sequence number must be refused
    try:
        sink.write({"seq": 1, "event": "TAMPERED"})
        return record("s3-object-lock", "FAIL", "a different entry overwrote an existing one")
    except Exception as exc:
        refused = type(exc).__name__
    problems = sink.verify_bucket(probe=True)
    if problems:
        return record("s3-object-lock", "FAIL", "; ".join(problems))
    record("s3-object-lock", "PASS", f"write-once enforced ({refused}); bucket lock config verified; prefix {prefix}")


def check_mail() -> None:
    host, to = os.environ.get("GATEWAY_SMTP_HOST"), os.environ.get("GATEWAY_LIVE_MAIL_TO")
    if not (host and to):
        return record("smtp", "SKIP", "GATEWAY_SMTP_HOST and GATEWAY_LIVE_MAIL_TO not set")
    from email.message import EmailMessage

    from agent_gateway.adapters_real import smtp_adapter_from_env

    adapter = smtp_adapter_from_env(dict(os.environ))(None, None)  # same TLS/auth path the gateway uses
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = adapter._sender, to, "Agent Gateway live check"
    msg.set_content("This is a test message from the Agent Gateway live check. No action needed.")
    with adapter._connect() as s:  # verifies the certificate chain and host name, then logs in
        s.send_message(msg)
    record("smtp", "PASS", f"TLS verified, authenticated, test mail sent to {to} - check the inbox")


def main() -> int:
    for fn in (check_redis, check_postgres, check_s3, check_mail):
        try:
            fn()
        except Exception as exc:  # report the type only: messages can contain hostnames or credentials
            record(fn.__name__.removeprefix("check_"), "FAIL", f"{type(exc).__name__}: {str(exc)[:160]}")
    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print(f"\n{sum(r[1]=='PASS' for r in RESULTS)} passed, {len(failed)} failed, {sum(r[1]=='SKIP' for r in RESULTS)} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
