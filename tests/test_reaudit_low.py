"""Re-audit LOW findings R9-R17: each test reproduces the audit's proof of concept."""
import dataclasses
import http.client
import json
import os
import threading
import warnings
from importlib import resources
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from nettrace import audit
from nettrace.demo import install
from nettrace.drivers import cisco_iosxe, prisma
from nettrace.errors import InventoryError
from nettrace.inventory import load_inventory
from nettrace.models import Flow, Outcome, Status
from nettrace.steps import DeviceAt
from nettrace.web import server

from test_robustness import _prisma_step, _rule

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")


def _records(tmp_path):
    return [json.loads(x) for x in (tmp_path / "audit" / "audit.log").read_text().splitlines()]


# ---- R9: ingress inferred from the route back is not a clean PASS --------------------------------
def test_inferred_ingress_is_warn_with_reason():
    inv = install()
    client = cisco_iosxe.CiscoClient(inv.devices["core-rtr1"])
    res = cisco_iosxe.step(client, DeviceAt(device="core-rtr1"), Flow("10.1.1.10", "10.20.1.50", "tcp", dst_port=443))
    hop = res.hops[0]
    assert any("inferred" in d for d in hop.details)
    assert hop.status == Status.WARN and any("inferred" in w for w in res.warnings)


# ---- R10: Prisma allow below an uncertain rule; schedules ------------------------------------------
def test_prisma_allow_below_uncertain_rule_is_unknown():
    res = _prisma_step([_rule("needs-user", "deny", source_user=["alice"]), _rule("allow-all", "allow")])
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_prisma_scheduled_rule_is_uncertain():
    res = _prisma_step([_rule("office-hours", "allow", schedule="work-hours")])
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_prisma_allow_without_uncertainty_still_passes():
    res = _prisma_step([_rule("allow-all", "allow")])
    assert res.hops[0].status == Status.PASS


# ---- R11: token POST and Netmiko session prep are audited -------------------------------------------
def test_scm_token_post_is_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(prisma.ScmClient, "transport_override", None)
    for var in ("NETTRACE_SCM_CLIENT_ID", "NETTRACE_SCM_CLIENT_SECRET", "NETTRACE_SCM_TSG_ID"):
        monkeypatch.setenv(var, "canary-secret")
    monkeypatch.setattr(prisma.requests, "post", lambda *a, **k: SimpleNamespace(
        status_code=200, json=lambda: {"access_token": "t", "expires_in": 900}))
    prisma.ScmClient()._get_token()
    rec = [r for r in _records(tmp_path) if r["kind"] == "scm"]
    assert rec and rec[0]["request"].startswith("POST ") and rec[0]["status"] == "ok"
    assert "canary-secret" not in json.dumps(rec)


def test_netmiko_session_prep_is_audited(tmp_path, monkeypatch):
    import netmiko

    conn = SimpleNamespace(enable=lambda: None, disconnect=lambda: None,
                           send_command=lambda c, read_timeout=60: "ok")
    monkeypatch.setattr(netmiko, "ConnectHandler", lambda **kw: conn)
    monkeypatch.setattr(cisco_iosxe.CiscoClient, "connection_override", None)
    for var in ("T_USER", "T_PASS", "T_SECRET"):
        monkeypatch.setenv(var, "x")
    dev = dataclasses.replace(install().devices["core-rtr1"], username_env="T_USER", password_env="T_PASS",
                              secret_env="T_SECRET")
    cisco_iosxe.CiscoClient(dev)._connect()
    reqs = [(r["kind"], r["request"], r["status"]) for r in _records(tmp_path)]
    for cmd in ("terminal length 0", "terminal width 511", "enable"):
        assert ("ssh", cmd, "ok") in reqs


# ---- R12: ssh_strict: false -------------------------------------------------------------------------
DEV = "devices:\n  - {name: r1, platform: cisco_iosxe, host: 192.0.2.1%s}\n"


def _inv(tmp_path, text):
    p = tmp_path / "inv.yaml"
    p.write_text(text)
    return load_inventory(p)


def test_ssh_strict_false_per_device_warns_naming_the_device(tmp_path):
    with pytest.warns(UserWarning, match="r1.*NOT verified"):
        inv = _inv(tmp_path, DEV % ", ssh_strict: false")
    assert inv.devices["r1"].ssh_strict is False


def test_ssh_strict_false_in_defaults_is_refused_without_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NETTRACE_ALLOW_INSECURE_SSH", raising=False)
    text = "defaults:\n  cisco_iosxe: {ssh_strict: false}\n" + DEV % ""
    with pytest.raises(InventoryError, match="ssh_strict"):
        _inv(tmp_path, text)
    monkeypatch.setenv("NETTRACE_ALLOW_INSECURE_SSH", "1")
    with pytest.warns(UserWarning, match="r1"):
        assert _inv(tmp_path, text).devices["r1"].ssh_strict is False


def test_ssh_strict_default_is_silent(tmp_path):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert _inv(tmp_path, DEV % "").devices["r1"].ssh_strict is True


# ---- R13: audit log edges -----------------------------------------------------------------------------
def test_audit_symlinked_log_is_not_followed(tmp_path, monkeypatch):
    target = tmp_path / "victim.txt"
    target.write_text("keep\n")
    d = tmp_path / "alog"
    d.mkdir()
    (d / "audit.log").symlink_to(target)
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(d / "audit.log"))
    audit.log("ssh", "r1", "show version", "ok")  # must not raise
    assert target.read_text() == "keep\n"


def test_audit_symlinked_dir_is_not_followed(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(tmp_path / "link" / "audit.log"))
    audit.log("ssh", "r1", "show version", "ok")
    assert not (real / "audit.log").exists()


def test_audit_new_dir_0700_file_0600_and_old_file_tightened(tmp_path, monkeypatch):
    log = tmp_path / "fresh" / "sub" / "audit.log"
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(log))
    audit.log("ssh", "r1", "show version", "ok")
    assert oct(log.stat().st_mode & 0o777) == "0o600" and oct(log.parent.stat().st_mode & 0o777) == "0o700"
    old = tmp_path / "old.log"
    old.write_text("")
    old.chmod(0o644)
    monkeypatch.setenv("NETTRACE_AUDIT_LOG", str(old))
    audit.log("ssh", "r1", "show version", "ok")
    assert oct(old.stat().st_mode & 0o777) == "0o600"


def test_audit_demo_records_are_marked(tmp_path):
    install()  # the demo lab marks the process
    audit.log("ssh", "r1", "show version", "ok")
    assert _records(tmp_path)[0]["demo"] is True


# ---- R15: CSP and friends on non-page responses --------------------------------------------------------
def test_json_and_error_responses_carry_csp_nosniff_no_store():
    app = server.App(install(), demo=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lambda *a: None)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, port, False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        for path, headers in (("/api/bootstrap", {"X-Nettrace-Token": app.token}), ("/api/bootstrap", {}),
                              ("/nope", {})):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", path, headers=headers)
            r = c.getresponse()
            r.read()
            assert "default-src 'none'" in r.getheader("Content-Security-Policy"), path
            assert r.getheader("X-Content-Type-Options") == "nosniff" and r.getheader("Cache-Control") == "no-store"
    finally:
        httpd.shutdown()
        httpd.server_close()
        app.close()


# ---- R16: selectors and URL paths are escaped ------------------------------------------------------------
def test_viewer_and_app_escape_selectors_and_trace_path():
    assert 'data-hop="${hopIndex}"' not in APP_HTML and "CSS.escape(String(hopIndex))" in APP_HTML
    assert '"/api/traces/" + el.dataset.id' not in APP_HTML and 'encodeURIComponent(h.get("trace"))' in APP_HTML
    from nettrace.viz import html as viewer
    src = open(viewer.__file__).read()
    assert 'data-hop="${hop}"' not in src and src.count("CSS.escape(String(hop))") == 2


# ---- R17: scrubbed_env ---------------------------------------------------------------------------------------
def test_scrubbed_env_drops_credential_like_names(monkeypatch):
    bad = ["NETTRACE_X", "AWS_PROFILE", "GITHUB_TOKEN", "DB_SECRET", "DB_PASSWORD", "STRIPE_API_KEY", "MY_KEY",
           "SOME_CREDENTIALS_FILE", "cred_file"]
    for k in bad:
        monkeypatch.setenv(k, "x")
    monkeypatch.setenv("PATH_OK", "1")
    env = server.scrubbed_env()
    assert not [k for k in bad if k in env] and "PATH_OK" in env and "HOME" in os.environ and "HOME" in env
