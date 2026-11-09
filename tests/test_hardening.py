import http.client
import json
import logging
import re
import threading
from http.server import ThreadingHTTPServer
from importlib import resources

import pytest
from rich.console import Console

from nettrace.demo import install
from nettrace.drivers.panos import XmlApi
from nettrace.errors import ReadOnlyViolation
from nettrace.output import clean
from nettrace.readonly import check_panos_request
from nettrace.web import server

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")


def test_app_html_escapes_trace_values():
    # every ${h.status} or ${h.index} interpolation must be wrapped in esc()
    bad = re.findall(r"\$\{\s*(?:h\.status|h\.index|entry\.elapsed_ms)\s*\}", APP_HTML)
    assert bad == []


# L1: <test> on Panorama itself needs a target
def test_panorama_test_requires_target():
    cmd = "<test><routing/></test>"
    with pytest.raises(ReadOnlyViolation):
        check_panos_request({"type": "op", "cmd": cmd}, panorama=True)
    check_panos_request({"type": "op", "cmd": cmd, "target": "0070510"}, panorama=True)
    check_panos_request({"type": "op", "cmd": "<show><a/></show>"}, panorama=True)
    check_panos_request({"type": "op", "cmd": cmd})  # a firewall may run it directly


# L2: whole-config and mgt-config reads are refused
@pytest.mark.parametrize("xp", ["/config", "/config/mgt-config", "/config/mgt-config/users", ""])
def test_config_xpath_restricted(xp):
    with pytest.raises(ReadOnlyViolation):
        check_panos_request({"type": "config", "action": "get", "xpath": xp})


# L7: terminal control characters are stripped
def test_clean_strips_escape_sequences():
    assert clean("a\x1b]0;title\x07b\tc\nd") == "a]0;titleb\tc\nd"
    Console(record=True).print(clean("\x1b[2J"))


# TLS verification off must warn, naming the device but never a secret
def test_verify_tls_false_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="nettrace"):
        XmlApi("fw1", ["10.0.0.1"], None, "FW1_KEY", False)
        XmlApi("fw2", ["10.0.0.2"], None, "FW2_KEY", True)
    assert "DISABLED" in caplog.text and "fw1" in caplog.text
    assert "fw2" not in caplog.text and "FW1_KEY" not in caplog.text


# L4/L5: odd token / Content-Length values must not crash or hang the handler
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


def _post(port, headers, body=b"{}"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("POST", "/api/console", body, {"Content-Type": "application/json", **headers})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def test_non_ascii_token_is_401(live):
    _, port = live
    assert _post(port, {"X-Nettrace-Token": "é".encode("latin-1")})[0] == 401


@pytest.mark.parametrize("length", ["-1", "abc"])
def test_bad_content_length_is_rejected(live, length):
    app, port = live
    status, _ = _post(port, {"X-Nettrace-Token": app.token, "Content-Length": length}, b"")
    assert status in (400, 413)


# L6: the secret lives in the X-Nettrace-Token header or the session cookie, never the query string
def _get(port, path, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", path, headers=headers or {})
    return c.getresponse().status


def test_query_string_token_is_refused_header_works(live):
    app, port = live
    assert _get(port, f"/api/bootstrap?token={app.token}") == 401
    assert _get(port, "/api/bootstrap", {"X-Nettrace-Token": app.token}) == 200


def test_app_html_reads_fragment_and_clears_it():
    assert "location.hash" in APP_HTML and "history.replaceState" in APP_HTML
    assert "location.search" not in APP_HTML
    assert "sessionStorage" not in APP_HTML and "localStorage" not in APP_HTML and "prompt(" not in APP_HTML


def test_logs_contain_no_token(capsys):
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        _get(port, f"/api/bootstrap?token={app.token}")
        _get(port, "/api/bootstrap", {"X-Nettrace-Token": app.token})
    finally:
        httpd.shutdown()
        httpd.server_close()
        app.close()
    err = capsys.readouterr().err
    assert "/api/bootstrap" in err and app.token not in err
