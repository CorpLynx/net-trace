import sys
import time
import types

import pytest

from nettrace.demo import install
from nettrace.drivers import cisco_iosxe
from nettrace.drivers.cisco_iosxe import CiscoClient
from nettrace.errors import DeviceError
from nettrace.models import Evidence
from nettrace.web import server


@pytest.fixture
def app():
    a = server.App(install(), demo=True)
    yield a
    a.close()


def test_console_min_gap(app):
    cmd = {"device": "core-rtr1", "command": "show ip interface brief"}
    assert app.console(cmd)["status"] == "ok"
    with pytest.raises(server.BadRequest, match="between console commands"):
        app.console(cmd)


def test_console_idle_closes_session(app, monkeypatch):
    monkeypatch.setattr(server, "CONSOLE_IDLE", 0.05)
    app.console({"device": "core-rtr1", "command": "show ip interface brief"})
    client = app.console_clients._devices["core-rtr1"]
    assert client._conn is not None
    time.sleep(0.3)
    assert client._conn is None


def test_console_output_and_evidence_capped(app, monkeypatch):
    big = "x" * (300 * 1024)
    monkeypatch.setattr(CiscoClient, "show", lambda self, c: big)
    out = app.console({"device": "core-rtr1", "command": "show version"})["output"]
    assert out.endswith("[truncated]") and len(out) < 257 * 1024
    assert Evidence("d", "c", big).response.endswith("[truncated]")


def test_cisco_evidence_4000():
    c = CiscoClient(install().devices["core-rtr1"])
    c._connect = lambda: types.SimpleNamespace(send_command=lambda *a, **k: "y" * 10000)
    c.show("show version")
    assert len(c.evidence[0].response) < 4020 and c.evidence[0].response.endswith("[truncated]")


def test_auth_failure_cooldown(monkeypatch):
    calls = []

    class AuthErr(Exception):
        pass

    def handler(**kw):
        calls.append(kw)
        raise AuthErr()

    nm, exc = types.ModuleType("netmiko"), types.ModuleType("netmiko.exceptions")
    nm.ConnectHandler = handler
    exc.NetmikoAuthenticationException = AuthErr
    exc.NetmikoTimeoutException = TimeoutError
    monkeypatch.setitem(sys.modules, "netmiko", nm)
    monkeypatch.setitem(sys.modules, "netmiko.exceptions", exc)
    monkeypatch.setattr(CiscoClient, "connection_override", None)
    monkeypatch.setattr(CiscoClient, "_auth_failed", {})
    monkeypatch.setenv("U", "u")
    monkeypatch.setenv("P", "p")
    dev = install().devices["core-rtr1"]
    dev.username_env, dev.password_env, dev.secret_env = "U", "P", None
    with pytest.raises(DeviceError, match="SSH failed"):
        CiscoClient(dev).show("show version")
    for _ in range(2):
        with pytest.raises(DeviceError, match="cooldown"):
            CiscoClient(dev).show("show version")
    assert len(calls) == 1
    assert cisco_iosxe.AUTH_COOLDOWN == 300
