"""One-time login code -> HttpOnly session cookie; the cookie needs X-Nettrace-Client (CSRF) on the API."""
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from importlib import resources

import pytest

from nettrace.demo import install
from nettrace.web import server

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
CLIENT = {"X-Nettrace-Client": "1"}


class Clock:
    now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def live(request, capsys):
    clock = Clock()
    app = server.App(install(), demo=True, code_ttl=60.0, clock=clock)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app, port, clock
    httpd.shutdown()
    httpd.server_close()
    app.close()


def _req(port, method, path, headers=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body, headers or {})
    r = c.getresponse()
    return r.status, r, r.read()


def _login(app, port):
    status, r, _ = _req(port, "GET", f"/?c={app.login_code}")
    assert status == 303
    return r


def _cookie(r):
    return r.getheader("Set-Cookie").split(";", 1)[0]


def test_code_works_once_then_401(live):
    app, port, _ = live
    code = app.login_code
    r = _login(app, port)
    assert r.getheader("Location") == "/"
    status, r2, body = _req(port, "GET", f"/?c={code}")
    assert status == 401 and b"run" in body.lower() and "default-src 'none'" in r2.getheader("Content-Security-Policy")
    assert app.login_code is None


def test_wrong_code_is_401_and_does_not_spend_the_real_one(live):
    app, port, _ = live
    assert _req(port, "GET", "/?c=nope")[0] == 401
    assert _req(port, "GET", f"/?c={app.login_code}")[0] == 303


def test_expired_code_is_401(live):
    app, port, clock = live
    code = app.login_code
    clock.now += 61
    assert _req(port, "GET", f"/?c={code}")[0] == 401
    assert app.login_code is None


def test_login_response_headers_and_cookie_flags(live):
    app, port, _ = live
    r = _login(app, port)
    assert r.getheader("Set-Cookie") == f"nettrace_session={app.token}; HttpOnly; SameSite=Strict; Path=/"
    assert r.getheader("Referrer-Policy") == "no-referrer" and r.getheader("Cache-Control") == "no-store"
    assert app.token not in r.getheader("Location") and app.login_code is None


def test_cookie_with_client_header_works_without_it_is_refused(live):
    app, port, _ = live
    cookie = _cookie(_login(app, port))
    assert _req(port, "GET", "/api/bootstrap", {"Cookie": cookie, **CLIENT})[0] == 200
    assert _req(port, "GET", "/api/bootstrap", {"Cookie": cookie})[0] == 403
    assert _req(port, "GET", "/api/bootstrap", {"Cookie": "nettrace_session=wrong", **CLIENT})[0] == 401
    assert _req(port, "GET", "/api/bootstrap", CLIENT)[0] == 401


def test_header_token_still_works_and_query_token_refused(live):
    app, port, _ = live
    assert _req(port, "GET", "/api/bootstrap", {"X-Nettrace-Token": app.token})[0] == 200
    assert _req(port, "GET", f"/api/bootstrap?token={app.token}", CLIENT)[0] == 401
    assert _req(port, "GET", f"/api/bootstrap?token={app.token}&c={app.token}")[0] == 401


def test_wrong_origin_with_valid_cookie_is_refused(live):
    app, port, _ = live
    cookie = _cookie(_login(app, port))
    h = {"Cookie": cookie, **CLIENT}
    assert _req(port, "GET", "/api/bootstrap", {**h, "Origin": "http://evil.example"})[0] == 403
    assert _req(port, "GET", "/api/bootstrap", {**h, "Host": "evil.example"})[0] == 421
    assert _req(port, "GET", "/api/bootstrap", {**h, "Origin": f"http://127.0.0.1:{port}"})[0] == 200


def test_cross_site_style_post_is_refused(live):
    app, port, _ = live
    cookie = _cookie(_login(app, port))
    body = json.dumps({"id": "abcdefgh1"})
    # a plain <form> / no-cors fetch: text/plain, no client header, cookie attached by the browser
    assert _req(port, "POST", "/api/trace/cancel", {"Cookie": cookie, "Content-Type": "text/plain"}, body)[0] == 403
    # with the header it gets past auth but is still JSON-only
    assert _req(port, "POST", "/api/trace/cancel", {"Cookie": cookie, "Content-Type": "text/plain", **CLIENT},
                body)[0] == 415
    assert _req(port, "POST", "/api/trace/cancel", {"Cookie": cookie, "Content-Type": "application/json", **CLIENT},
                body)[0] == 404  # authenticated; unknown run id


def test_logs_never_contain_the_query_string(live, capsys):
    app, port, _ = live
    code = app.login_code
    _req(port, "GET", f"/?c={code}")
    _req(port, "GET", f"/api/bootstrap?token={app.token}")
    err = capsys.readouterr().err
    assert "GET /" in err and code not in err and app.token not in err


def test_app_html_uses_cookie_session_and_client_header():
    assert "prompt(" not in APP_HTML and "localStorage" not in APP_HTML and "sessionStorage" not in APP_HTML
    assert "X-Nettrace-Token" not in APP_HTML and 'HASH.get("token")' not in APP_HTML
    assert '"X-Nettrace-Client": "1"' in APP_HTML and 'credentials: "same-origin"' in APP_HTML
    assert "Session ended (the server was restarted). Run `nettrace serve` again" in APP_HTML
