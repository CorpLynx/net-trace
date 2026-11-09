"""Cancelling a running trace: engine cancel token, POST /api/trace/cancel, audit entry, UI wiring, CLI Ctrl-C.
Everything is local: the demo lab's simulators are the transport, files live under tmp_path."""

import http.client
import json
import re
import threading
from http.server import ThreadingHTTPServer
from importlib import resources

import pytest
from click.testing import CliRunner

from nettrace import cli
from nettrace.demo import install
from nettrace.drivers.cisco_iosxe import CiscoClient
from nettrace.engine import Tracer
from nettrace.errors import CancelToken, Deadline
from nettrace.models import Flow, Outcome, Status
from nettrace.web import server

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
FLOW = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)
RUN_ID = "run-cancel-0001"


# ---- engine --------------------------------------------------------------------------------------
def test_deadline_check_honours_the_cancel_token():
    token = CancelToken()
    d = Deadline(60, token)
    d.check()
    token.cancel()
    from nettrace.errors import Cancelled

    with pytest.raises(Cancelled, match="cancelled by user"):
        d.check()


def test_cancel_before_start_of_next_hop_is_incomplete_with_partial_hops(monkeypatch):
    token = CancelToken()
    tracer = Tracer(install(), cancel=token)
    real, calls = Tracer._step, []

    def step_then_cancel(self, pos, flow):
        calls.append(pos)
        res = real(self, pos, flow)
        token.cancel()  # the user clicks Cancel while hop 1 is being evaluated
        return res

    monkeypatch.setattr(Tracer, "_step", step_then_cancel)
    r = tracer.trace(FLOW)
    assert len(calls) == 1, "no second hop may start after the cancel"
    assert r.cancelled and r.outcome == Outcome.INCOMPLETE and r.reason == "cancelled by user"
    assert len(r.hops) > 1 and r.hops[0].component == "source"
    assert not any(h.status == Status.UNKNOWN for h in r.hops), "a cancel is not a device failure"
    assert r.to_dict()["Cancelled"] is True


def test_cancel_stops_before_the_next_device_request(monkeypatch):
    """Faulty/slow transport seam: the cancel lands while a device command is in flight."""
    token = CancelToken()
    sent = []
    inner = CiscoClient.connection_override

    class Conn:
        def __init__(self, conn):
            self.conn = conn

        def send_command(self, command, read_timeout=60):
            sent.append(command)
            token.cancel()  # arrives mid-request; this request still finishes
            return self.conn.send_command(command, read_timeout=read_timeout)

        def disconnect(self):
            self.conn.disconnect()

    monkeypatch.setattr(CiscoClient, "connection_override", lambda device: Conn(inner(device)))
    r = Tracer(install(), cancel=token).trace(FLOW)
    assert len(sent) == 1, "exactly the in-flight request ran; nothing was sent after the cancel"
    assert r.cancelled and r.outcome == Outcome.INCOMPLETE and r.reason == "cancelled by user"
    assert r.hops[0].component == "source"


def test_cancel_before_the_trace_starts_sends_nothing(monkeypatch):
    token = CancelToken()
    token.cancel()
    monkeypatch.setattr(CiscoClient, "connection_override",
                        lambda device: pytest.fail("a device was contacted after cancel"))
    r = Tracer(install(), cancel=token).trace(FLOW)
    assert r.cancelled and r.outcome == Outcome.INCOMPLETE and r.reason == "cancelled by user"
    assert [h.component for h in r.hops] == ["source"]  # the local source lookup only


def test_a_normal_trace_is_not_marked_cancelled():
    r = Tracer(install()).trace(FLOW)
    assert not r.cancelled and "Cancelled" not in r.to_dict()


# ---- web: cancel route ---------------------------------------------------------------------------
@pytest.fixture
def live():
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port
    httpd.shutdown()
    httpd.server_close()
    app.close()


def _post(port, path, body, token=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["X-Nettrace-Token"] = token
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    c.request("POST", path, json.dumps(body), h)
    r = c.getresponse()
    raw = r.read()
    try:
        return r.status, json.loads(raw)
    except ValueError:
        return r.status, raw


def _audit(tmp_path):
    f = tmp_path / "audit" / "audit.log"
    return [json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []


def test_cancel_requires_the_token(live):
    app, port = live
    status, _ = _post(port, "/api/trace/cancel", {"id": RUN_ID})
    assert status == 401
    assert _post(port, "/api/trace/cancel", {"id": RUN_ID}, token="wrong")[0] == 401


def test_cancel_rejects_a_foreign_origin_and_host(live):
    app, port = live
    status, _ = _post(port, "/api/trace/cancel", {"id": RUN_ID}, app.token, {"Origin": "http://evil.example"})
    assert status == 403
    status, _ = _post(port, "/api/trace/cancel", {"id": RUN_ID}, app.token, {"Host": "evil.example"})
    assert status == 421


def test_cancel_unknown_id_is_404_json(live, tmp_path):
    app, port = live
    status, data = _post(port, "/api/trace/cancel", {"id": "does-not-exist"}, app.token)
    assert status == 404 and "error" in data
    assert not [r for r in _audit(tmp_path) if r["status"] == "cancelled"]


@pytest.mark.parametrize("bad", [None, 5, "short", "has space in it", "x" * 65, "semi;colon-id"])
def test_cancel_malformed_id_is_400(live, bad):
    app, port = live
    assert _post(port, "/api/trace/cancel", {"id": bad}, app.token)[0] == 400


def test_cancel_requires_json(live):
    app, port = live
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", "/api/trace/cancel", '{"id": "abcdefgh"}',
              {"Content-Type": "text/plain", "X-Nettrace-Token": app.token})
    assert c.getresponse().status == 415


def test_trace_id_must_have_a_safe_format(live):
    app, port = live
    flow = {"src": "10.1.10.25", "dst": "10.20.1.50", "protocol": "tcp", "port": 443}
    assert _post(port, "/api/trace", {**flow, "id": "../../etc"}, app.token)[0] == 400


def test_cancel_running_trace_end_to_end(live, tmp_path, monkeypatch):
    app, port = live
    started, release = threading.Event(), threading.Event()
    inner = CiscoClient.connection_override

    class SlowConn:
        def __init__(self, conn):
            self.conn = conn

        def send_command(self, command, read_timeout=60):
            started.set()
            assert release.wait(10)  # a slow device: the request is in flight until the test releases it
            return self.conn.send_command(command, read_timeout=read_timeout)

        def disconnect(self):
            self.conn.disconnect()

    monkeypatch.setattr(CiscoClient, "connection_override", lambda device: SlowConn(inner(device)))
    out = {}

    def run():
        out["resp"] = _post(port, "/api/trace", {"src": FLOW.src, "dst": FLOW.dst, "protocol": "tcp", "port": 443,
                                                 "id": RUN_ID}, app.token)

    t = threading.Thread(target=run)
    t.start()
    assert started.wait(10)
    assert _post(port, "/api/trace", {"src": FLOW.src, "dst": FLOW.dst, "protocol": "tcp", "port": 443,
                                      "id": RUN_ID}, app.token)[0] == 409  # id already running
    s1, d1 = _post(port, "/api/trace/cancel", {"id": RUN_ID}, app.token)
    s2, d2 = _post(port, "/api/trace/cancel", {"id": RUN_ID}, app.token)  # idempotent while still running
    assert (s1, d1["status"], d1["already"]) == (200, "cancelling", False)
    assert (s2, d2["status"], d2["already"]) == (200, "cancelling", True)
    release.set()
    t.join(15)
    status, entry = out["resp"]
    assert status == 200 and entry["cancelled"] is True and entry["run_id"] == RUN_ID
    assert entry["trace"]["Outcome"] == "INCOMPLETE" and entry["trace"]["Reason"] == "cancelled by user"
    assert entry["trace"]["Hops"] and entry["trace"]["Hops"][0]["component"] == "source"
    # a repeat after the trace stopped is still a clean 200 (idempotent); the run is no longer registered
    s3, d3 = _post(port, "/api/trace/cancel", {"id": RUN_ID}, app.token)
    assert (s3, d3["already"]) == (200, True) and RUN_ID not in app.runs
    # exactly one audit entry for the cancel, in trace mode, and no token anywhere in the log
    recs = [r for r in _audit(tmp_path) if r["status"] == "cancelled"]
    assert len(recs) == 1 and recs[0]["mode"] == "trace" and RUN_ID in recs[0]["request"]
    assert app.token not in (tmp_path / "audit" / "audit.log").read_text()


def test_cancel_after_finish_is_404(live):
    app, port = live
    flow = {"src": FLOW.src, "dst": FLOW.dst, "protocol": "tcp", "port": 443, "id": "finished-run-01"}
    status, entry = _post(port, "/api/trace", flow, app.token)
    assert status == 200 and entry["cancelled"] is False
    assert _post(port, "/api/trace/cancel", {"id": "finished-run-01"}, app.token)[0] == 404


def test_cancel_is_rate_limited():
    app = server.App(install(), demo=True)
    try:
        codes = []
        for _ in range(server.CANCEL_RATE[0] + 5):
            try:
                codes.append(app.cancel_trace({"id": "unknown-run-01"})[1])
            except server.BadRequest as exc:
                codes.append(int(exc.status))
        assert codes[0] == 404 and codes[-1] == 429
    finally:
        app.close()


def test_server_trace_that_is_cancelled_before_it_starts_builds_a_valid_entry():
    app = server.App(install(), demo=True)
    try:
        token = CancelToken()
        token.cancel()
        r = Tracer(install(), cancel=token).trace(FLOW)
        from nettrace.viz import build_map, render_svg
        from nettrace.web.topology import overlay

        trace = r.to_dict()
        overlay(app.topology, trace)
        render_svg(build_map(trace), header=False)
    finally:
        app.close()


# ---- UI (text-level; not run in a browser) -------------------------------------------------------
def test_ui_has_cancel_buttons_aria_and_escape_handler():
    assert 'id="cancel"' in APP_HTML and 'id="cancel2"' in APP_HTML
    assert "/api/trace/cancel" in APP_HTML
    assert "Cancelling…" in APP_HTML and "INCOMPLETE" in APP_HTML
    busy = re.search(r'<div id="busy"[^>]*>.*?id="busytxt"[^>]*>', APP_HTML, re.S).group(0)
    assert 'aria-live="polite"' in busy and 'role="status"' in busy
    assert re.search(r'\$\("#busy"\)\.addEventListener\("keydown".*?"Escape".*?cancelRun\(\)', APP_HTML, re.S)
    assert "disabled = true" in APP_HTML[APP_HTML.index("async function cancelRun"):]  # disabled after click
    assert "err.status === 404" in APP_HTML  # the finished-first race


def test_ui_cancel_keeps_the_hard_rules():
    for api in ("localStorage", "sessionStorage", "document.cookie", "indexedDB", "caches.open"):
        assert api not in APP_HTML
    assert not re.findall(r"https?://", APP_HTML.replace("http://www.w3.org/2000/svg", ""))
    assert "esc(t.Reason)" in APP_HTML and "newRunId" in APP_HTML


# ---- CLI Ctrl-C ----------------------------------------------------------------------------------
def test_cli_ctrl_c_exits_4_with_partial_hops_and_no_traceback(monkeypatch):
    real, calls = Tracer._step, []

    def interrupt_on_second(self, pos, flow):
        calls.append(pos)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return real(self, pos, flow)

    monkeypatch.setattr(Tracer, "_step", interrupt_on_second)
    res = CliRunner().invoke(cli.cli, ["--demo", "--output", "json", "trace", "run", "-s", "10.1.10.25",
                                       "-d", "10.20.1.50", "--port", "443"])
    assert res.exit_code == 4
    assert "Traceback" not in res.output and "KeyboardInterrupt" not in res.output
    data = json.loads(res.output[res.output.index("{"):])
    assert data["Outcome"] == "INCOMPLETE" and data["Reason"] == "cancelled by user" and data["Cancelled"] is True
    assert data["Hops"] and data["Hops"][0]["component"] == "source"
