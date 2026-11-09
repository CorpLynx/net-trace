import json
import os
import stat

import pytest

from nettrace import audit
from nettrace.demo import PRESETS, install
from nettrace.drivers.panos import XmlApi
from nettrace.drivers.prisma import ScmClient
from nettrace.engine import Tracer
from nettrace.errors import DeviceError, ReadOnlyViolation
from nettrace.models import Flow
from nettrace.readonly import check_panos_request
from nettrace.web import server

TEST_MATCH = ("test security-policy-match from trust to untrust source 10.1.10.25 destination 8.8.8.8 "
              "protocol 6 destination-port 443")


def _records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit" / "audit.log").read_text().splitlines()]


@pytest.fixture
def app():
    a = server.App(install(), demo=True)
    yield a
    a.close()


# ---- O1: console scope --------------------------------------------------------------------------
@pytest.mark.parametrize("cmd", ["show running-config", "show startup-config", "show tech-support",
                                 "show crypto pki certificates", "show archive config differences",
                                 "show snmp user", "show logging", "show aaa servers"])
def test_console_denies_cisco_secrets(app, cmd):
    assert app.console({"device": "core-rtr1", "command": cmd})["status"] == "refused"


def test_console_allows_quick_cisco(app):
    assert app.console({"device": "core-rtr1", "command": "show ip interface brief"})["status"] == "ok"


@pytest.mark.parametrize("cmd", ["<show><config><running/></config></show>", "<test><vpn/></test>",
                                 "test authentication authentication-profile x", "show config running"])
def test_console_denies_panos_raw_xml_and_unlisted(app, cmd):
    assert app.console({"device": "fw-dc1", "command": cmd})["status"] == "refused"


def test_console_allows_panos_listed(app, monkeypatch):
    monkeypatch.setattr(server, "CONSOLE_GAP", 0)
    for cmd in ("show system info", "show interface all", TEST_MATCH):
        assert app.console({"device": "fw-dc1", "command": cmd})["status"] == "ok", cmd


@pytest.mark.parametrize("cmd", ["<test><authentication/></test>", "<test><vpn><ike-sa/></vpn></test>",
                                 "<test><routing><other/></routing></test>", "<test><a/><b/></test>"])
def test_guard_restricts_test_children(cmd):
    with pytest.raises(ReadOnlyViolation):
        check_panos_request({"type": "op", "cmd": cmd})


@pytest.mark.parametrize("cmd", ["<test><routing><fib-lookup/></routing></test>",
                                 "<test><advanced-routing><fib-lookup/></advanced-routing></test>",
                                 "<test><nat-policy-match/></test>", "<test><security-policy-match/></test>"])
def test_guard_allows_policy_and_fib_tests(cmd):
    check_panos_request({"type": "op", "cmd": cmd})


# ---- O2: audit log ------------------------------------------------------------------------------
def test_trace_and_console_are_audited(app, tmp_path):
    p = next(p for p in PRESETS if p["expect"] == "REACHABLE")
    f = dict(p["flow"])
    Tracer(app.inv).trace(Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"]),
                          start_at=f.get("start_at"))
    app.console({"device": "core-rtr1", "command": "show running-config"})
    recs = _records(tmp_path)
    assert {"ssh", "panos"} <= {r["kind"] for r in recs}
    for r in recs:
        assert set(r) - {"demo"} == {"ts", "pid", "user", "mode", "device", "kind", "request", "status"}
        assert r["pid"] == os.getpid() and r["status"] in ("ok", "refused", "error")
    assert any(r["mode"] == "trace" and r["status"] == "ok" for r in recs)
    assert any(r["mode"] == "console" and r["status"] == "refused" and "running-config" in r["request"] for r in recs)


def test_guard_refusal_is_logged_once(tmp_path):
    from nettrace.drivers.cisco_iosxe import CiscoClient

    client = CiscoClient(install().devices["core-rtr1"])
    with pytest.raises(ReadOnlyViolation):
        client.show("configure terminal")
    assert [r["status"] for r in _records(tmp_path)] == ["refused"]


def test_audit_file_permissions_and_no_secrets(tmp_path):
    audit.log("ssh", "r1", "show version", "ok")
    log = tmp_path / "audit" / "audit.log"
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert stat.S_IMODE(log.parent.stat().st_mode) == 0o700


def test_audit_failure_never_breaks_a_trace(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(blocker / "sub" / "audit.log"))  # parent is a file
    audit.log("ssh", "r1", "show version", "ok")  # must not raise
    p = next(p for p in PRESETS if p["expect"] == "REACHABLE")
    f = dict(p["flow"])
    r = Tracer(install()).trace(Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"]),
                                start_at=f.get("start_at"))
    assert r.outcome.value == "REACHABLE"


# ---- O3: no redirects ---------------------------------------------------------------------------
class _Redirect:
    verify = True
    kwargs: dict = {}

    def post(self, url, **kw):
        _Redirect.kwargs = kw

        class R:
            status_code = 307
            content = b""

        return R()


def test_panos_redirect_is_refused(monkeypatch):
    monkeypatch.setenv("FW_KEY", "secret-key")
    monkeypatch.setattr(XmlApi, "session_override", lambda api: _Redirect())
    api = XmlApi("fw", ["10.0.0.1"], None, "FW_KEY", True)
    with pytest.raises(DeviceError, match="redirect"):
        api.request({"type": "op", "cmd": "<show><system><info/></system></show>"}, "info")
    assert _Redirect.kwargs["allow_redirects"] is False


def test_scm_does_not_follow_redirects(monkeypatch):
    seen = {}

    class R:
        status_code = 302
        text = ""

    def fake_get(url, **kw):
        seen.update(kw)
        return R()

    monkeypatch.setattr(ScmClient, "transport_override", None)
    monkeypatch.setattr("nettrace.drivers.prisma.requests.get", fake_get)
    c = ScmClient()
    c._token, c._token_expiry = "t", 1e12
    with pytest.raises(DeviceError):
        c.get_all("/config/security/v1/security-rules", {"folder": "x"})
    assert seen["allow_redirects"] is False
