"""R18: console I/O off the global lock, thread-safe history, body deadline, validated + atomic discovery cache."""
import json
import socket
import threading
import time
import warnings
from http.server import ThreadingHTTPServer

import pytest

from nettrace import engine
from nettrace.demo import install
from nettrace.demo.lab import PRESETS
from nettrace.drivers.cisco_iosxe import CiscoClient
from nettrace.inventory import load_inventory
from nettrace.models import Flow, Outcome, Status
from nettrace.web import server

CMD = "show ip interface brief"


@pytest.fixture(autouse=True)
def _restore_demo_inventory():
    """install() returns one shared inventory; give back its discovery state."""
    inv = install()
    saved = ({k: dict(v) for k, v in inv.discovered.items()}, dict(inv.ambiguous))
    yield
    inv.discovered, inv.ambiguous = saved


@pytest.fixture
def app():
    a = server.App(install(), demo=True)
    yield a
    a.close()


# ---- 1. console lock -------------------------------------------------------------------------
def test_slow_device_does_not_block_other_devices(app, monkeypatch):
    other = "fw-dc1"
    monkeypatch.setattr(server, "CONSOLE_GAP", 0.0)
    started, release = threading.Event(), threading.Event()
    real = CiscoClient.show

    def show(self, command):
        if self.device.name == "core-rtr1":
            started.set()
            release.wait(10)
        return real(self, command)

    monkeypatch.setattr(CiscoClient, "show", show)
    slow = threading.Thread(target=lambda: app.console({"device": "core-rtr1", "command": CMD}))
    slow.start()
    assert started.wait(5)
    t0 = time.monotonic()
    assert app.console({"device": other, "command": "show system info"})["status"] == "ok"  # would hang on a global lock
    assert time.monotonic() - t0 < 5
    with pytest.raises(server.BadRequest, match="still running"):  # same device: refused, not queued
        app.console({"device": "core-rtr1", "command": "show version"})
    release.set()
    slow.join(10)
    assert not slow.is_alive()


def test_close_does_not_wait_for_stalled_device(app, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def show(self, command):
        started.set()
        release.wait(10)
        return ""

    monkeypatch.setattr(CiscoClient, "show", show)
    t = threading.Thread(target=lambda: app.console({"device": "core-rtr1", "command": CMD}), daemon=True)
    t.start()
    assert started.wait(5)
    t0 = time.monotonic()
    app.close()
    assert time.monotonic() - t0 < 2
    release.set()
    t.join(10)


# ---- 2. history ------------------------------------------------------------------------------
def test_history_bounded_unique_and_thread_safe(app):
    body = dict(PRESETS[0]["flow"])
    errors, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            try:
                app.history_list()
            except Exception as exc:  # e.g. "OrderedDict mutated during iteration"
                errors.append(exc)

    r = threading.Thread(target=reader)
    r.start()

    def work():
        for _ in range(8):
            try:
                app.run_trace(dict(body))
            except server.BadRequest:  # both trace slots busy
                pass

    ts = [threading.Thread(target=work) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    stop.set()
    r.join()
    assert not errors
    ids = [h["id"] for h in app.history_list()]
    assert len(ids) == len(set(ids)) <= 50


def test_trace_id_collision_is_retried(app, monkeypatch):
    body = dict(PRESETS[0]["flow"])
    first = app.run_trace(dict(body))["id"]
    ids = iter([first, first, "ffffffff"])
    monkeypatch.setattr(server.secrets, "token_hex", lambda n: next(ids) if n == 4 else "0" * 2 * n)
    assert app.run_trace(dict(body))["id"] == "ffffffff"
    assert len(app.history_list()) == 2


# ---- 3. body deadline ------------------------------------------------------------------------
def test_partial_body_gets_408(monkeypatch):
    monkeypatch.setattr(server, "BODY_DEADLINE", 0.5)
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, False)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=8)
        s.sendall((f"POST /api/trace HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Nettrace-Token: {app.token}\r\n"
                   "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"src\"").encode())
        t0 = time.monotonic()
        data = s.recv(4096)  # never send the rest
        assert data.startswith(b"HTTP/1.0 408") or data.startswith(b"HTTP/1.1 408"), data[:40]
        assert time.monotonic() - t0 < 5
        s.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        app.close()


# ---- 4. cache validation ---------------------------------------------------------------------
def _inv_with_cache(tmp_path, monkeypatch, content):
    inv = install()  # install() points NETTRACE_CACHE_DIR at its own dir; override after it
    monkeypatch.setenv("NETTRACE_CACHE_DIR", str(tmp_path / "cache"))
    (tmp_path / "cache").mkdir(exist_ok=True)
    (tmp_path / "cache" / "addresses.json").write_text(content if isinstance(content, str) else json.dumps(content))
    return load_inventory(inv.path)


def test_invalid_cache_entries_dropped_with_warning(tmp_path, monkeypatch):
    dev = next(iter(install().devices))
    cache = {"10.0.0.1": {"device": dev, "interface": "Gi0/0"},
             "not-an-ip": {"device": dev, "interface": "Gi0/0"},
             "10.0.0.2": {"device": "ghost", "interface": "Gi0/0"},
             "10.0.0.3": {"device": dev, "interface": "Gi0/0; reload"},
             "10.0.0.4": ["x"], "10.0.0.5": {"device": dev, "interface": "x" * 200}}
    with pytest.warns(UserWarning, match="discovery cache"):
        inv = _inv_with_cache(tmp_path, monkeypatch, cache)
    assert list(inv.discovered) == ["10.0.0.1"]


@pytest.mark.parametrize("content", ["[1, 2]", "42", "not json", '{"addresses": [1], "ambiguous": 5}'])
def test_malformed_cache_ignored(tmp_path, monkeypatch, content):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        inv = _inv_with_cache(tmp_path, monkeypatch, content)
    assert inv.discovered == {} and inv.ambiguous == {}


# ---- 5. merge, atomicity, ambiguity ----------------------------------------------------------
def _fresh(tmp_path, monkeypatch):
    inv = install()
    monkeypatch.setenv("NETTRACE_CACHE_DIR", str(tmp_path / "cache"))
    return inv


def test_merge_keeps_other_devices_and_is_0600(tmp_path, monkeypatch):
    inv = _fresh(tmp_path, monkeypatch)
    a, b = list(inv.devices)[:2]
    inv.merge_discovered({a: {"10.9.0.1": "Gi1"}})
    inv.merge_discovered({b: {"10.9.0.2": "Gi2"}})
    data = json.loads(inv.cache_file().read_text())
    assert set(data["addresses"]) == {"10.9.0.1", "10.9.0.2"}
    assert (inv.cache_file().stat().st_mode & 0o777) == 0o600
    assert not [p for p in inv.cache_file().parent.iterdir() if p.name.endswith(".tmp")]
    inv.merge_discovered({a: {}})  # a refresh replaces that device's entries
    assert set(json.loads(inv.cache_file().read_text())["addresses"]) == {"10.9.0.2"}


def test_concurrent_discover_runs_lose_nothing(tmp_path, monkeypatch):
    inv = _fresh(tmp_path, monkeypatch)
    names = list(inv.devices)[:6]
    ts = [threading.Thread(target=lambda n=n, i=i: inv.merge_discovered({n: {f"10.8.0.{i + 1}": "Gi1"}}))
          for i, n in enumerate(names)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(json.loads(inv.cache_file().read_text())["addresses"]) == len(names)


def test_duplicate_ip_is_ambiguous_for_neither(tmp_path, monkeypatch):
    inv = _fresh(tmp_path, monkeypatch)
    a, b = list(inv.devices)[:2]
    inv.merge_discovered({a: {"10.7.0.1": "Gi1"}})
    inv.merge_discovered({b: {"10.7.0.1": "Gi9"}})
    assert inv.device_by_address("10.7.0.1") is None
    assert inv.ambiguous_owners("10.7.0.1") == sorted([a, b])
    assert "10.7.0.1" not in inv.discovered
    reloaded = load_inventory(inv.path)  # persisted, and survives validation
    assert reloaded.device_by_address("10.7.0.1") is None and reloaded.ambiguous_owners("10.7.0.1") == sorted([a, b])
    inv.merge_discovered({b: {}})  # the collision resolves once one device stops claiming it
    assert inv.device_by_address("10.7.0.1")[0].name == a


def test_engine_reports_unknown_with_colliding_names(tmp_path, monkeypatch):
    inv = _fresh(tmp_path, monkeypatch)
    # find the device the first demo preset reaches via a discovered next hop and make that IP ambiguous
    preset = PRESETS[0]
    f = preset["flow"]
    flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"])
    seen: list[str] = []
    real = inv.device_by_address

    def spy(ip):
        hit = real(ip)
        if hit and ip in inv.discovered:
            seen.append(ip)
        return hit

    inv.device_by_address = spy
    engine.Tracer(inv).trace(flow, start_at=f.get("start_at"))
    assert seen, "preset never used a discovered next hop"
    ip = seen[0]
    owner = inv.discovered[ip]["device"]
    other = next(n for n in inv.devices if n != owner)
    inv.device_by_address = real
    inv.discovered.pop(ip)
    inv.ambiguous[ip] = [{"device": owner, "interface": "a"}, {"device": other, "interface": "b"}]
    res = engine.Tracer(inv).trace(flow, start_at=f.get("start_at"))
    assert res.outcome == Outcome.INCOMPLETE
    unk = [h for h in res.hops if h.status == Status.UNKNOWN]
    assert unk and all(n in unk[-1].summary for n in (owner, other)) and ip in unk[-1].summary
