"""HTTPEventSink against a real HTTP server using real httpx over real sockets."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from agent_gateway.audit_sinks import HTTPEventSink

pytestmark = pytest.mark.integration


class Collector:
    def __init__(self):
        self.received, self.mode = [], "ok"  # ok | down (503) | reject (400)
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                code = {"ok": 200, "down": 503, "reject": 400}[outer.mode]
                if code == 200:
                    outer.received.append((self.headers.get("Authorization"), body))
                self.send_response(code)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/event"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def seqs(self):
        return [b["event"]["seq"] for _, b in self.received]

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def siem():
    c = Collector()
    yield c
    c.stop()


def sink(siem, tmp_path, **kw):
    return HTTPEventSink(siem.url, "tok-123", httpx.Client(), spool_path=tmp_path / "spool", allow_insecure=True,
                         attempts=1, sleep=lambda s: None, **kw)


def test_delivers_with_token_and_payload_shape(siem, tmp_path):
    s = sink(siem, tmp_path)
    s.write({"seq": 0, "mac": "a"})
    auth, body = siem.received[0]
    assert auth == "Splunk tok-123" and body["event"]["kind"] == "entry" and body["event"]["seq"] == 0
    assert s.backlog() == 0


def test_outage_spools_in_order_and_replays_before_new_events(siem, tmp_path):
    s = sink(siem, tmp_path)
    s.write({"seq": 0})
    siem.mode = "down"
    for i in (1, 2, 3):
        s.write({"seq": i})  # does not raise: the SIEM being down must not stop the business
    assert s.backlog() == 3 and siem.seqs() == [0]
    siem.mode = "ok"
    s.write({"seq": 4})  # new event arrives: older ones must be delivered first
    assert siem.seqs() == [0, 1, 2, 3, 4] and s.backlog() == 0


def test_connection_refused_is_spooled_and_flush_recovers(siem, tmp_path):
    s = sink(siem, tmp_path)
    url = siem.url
    siem.stop()  # the server is really gone: connection refused
    s.write({"seq": 0})
    s.write({"seq": 1})
    assert s.backlog() == 2
    revived = Collector()
    s._url = revived.url
    try:
        assert s.flush() == 0 and revived.seqs() == [0, 1]
    finally:
        revived.stop()


def test_client_errors_are_not_retried_and_do_not_lose_the_event(siem, tmp_path):
    siem.mode = "reject"
    s = sink(siem, tmp_path)
    s.write({"seq": 0})
    assert s.backlog() == 1  # kept for operator attention rather than silently dropped


def test_siem_down_does_not_block_the_gateway(siem, tmp_path):
    from agent_gateway.factory import build_stack
    from agent_gateway.models import Decision
    from conftest import REPORT, Clock, read_req
    siem.mode = "down"
    st = build_stack(clock=Clock(), evidence_sinks=[sink(siem, tmp_path)], fs={REPORT: "x"})
    assert st.gateway.execute(read_req()).decision is Decision.ALLOW
    assert sink(siem, tmp_path).backlog() >= 2  # decision + execution events queued, none lost
