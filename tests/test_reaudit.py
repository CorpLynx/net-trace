"""Re-audit fixes R1-R7: each test reproduces the audit's proof of concept."""
import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from rich.console import Console

from nettrace.demo import install
from nettrace.demo.sim_cisco import SimConnection
from nettrace.drivers import aws, cisco_iosxe, panos
from nettrace.errors import CredentialError, DeviceError, ReadOnlyViolation
from nettrace.models import Flow, Hop, Outcome, Status, TraceResult
from nettrace.output import _text_lines, emit
from nettrace.readonly import check_cisco_command, check_panos_request
from nettrace.web import server

ESC = "\x1b]0;PWNED\x07\x1b[2J\x9b2J"


@pytest.fixture
def app():
    a = server.App(install(), demo=True)
    yield a
    a.close()


# ---- R1: Cisco allowlist --------------------------------------------------------------------------
ABBREVIATED = ["show run", "show runn", "show ru", "show start", "show tech", "show cry pki certificates",
               "show snm user", "show arch", "show aa servers", "show vtp pass", "show derived-config",
               "show configuration", "show parser dump", "sh run", "show running-config",
               "show ip route 10.0.0.1 | include x", "show ip route 10.0.0.1; reload", "show ip route\nreload",
               "show ip route ?", "SHOW VERSION", "show Version", "show  version", "show\tversion", "show version ",
               "show\u00a0version", "show ip rou 10.0.0.1", "show ip int brief", "show int description",
               "show ip route 10.0.0.999", "show ip cef", "show ip route " + "1" * 400]


@pytest.mark.parametrize("cmd", ABBREVIATED)
def test_cisco_guard_rejects_abbreviations_and_tricks(cmd):
    with pytest.raises(ReadOnlyViolation):
        check_cisco_command(cmd)


@pytest.mark.parametrize("cmd", [c for c in ABBREVIATED if c not in ("show  version", "show version ") and len(c) < 400])
def test_cisco_console_refuses_abbreviations(app, cmd, monkeypatch):
    monkeypatch.setattr(server, "CONSOLE_GAP", 0)
    assert app.console({"device": "core-rtr1", "command": cmd})["status"] == "refused"


def test_simulator_accepts_ios_abbreviations_like_a_real_router():
    sim = SimConnection("core-rtr1")
    assert sim.send_command("show run") == sim.send_command("show running-config")
    assert "Invalid" not in sim.send_command("sh ip int br")
    assert sim.send_command("show s").startswith("% Ambiguous")


def test_cisco_console_allows_listed_commands(app, monkeypatch):
    monkeypatch.setattr(server, "CONSOLE_GAP", 0)
    for cmd in ("show ip route 10.20.1.50", "show ip interface brief", "show version", "show ip cef 10.20.1.50",
                "show ip arp", "show interfaces description", "show vrf", *server.QUICK["cisco_iosxe"]):
        assert app.console({"device": "core-rtr1", "command": cmd})["status"] == "ok", cmd


# ---- R2: PAN-OS xpath -----------------------------------------------------------------------------
@pytest.mark.parametrize("xp", [
    "/config/devices/../mgt-config/users", "/config/shared/../../mgt-config", "/config/devices/entry | /config/mgt-config",
    "/config/panorama/x|/config/mgt-config", "/config/devices/*/../../mgt-config", "/config/devices//mgt-config",
    "/config/devices/entry[@name='a' or 1=1]", "/config/devices/entry[@name='a'] | /config/mgt-config",
    "/config/devices", "/config/mgt-config", "/config/devices/entry/..", "/config/devices/entry[1]",
])
def test_panos_xpath_rejects_traversal_and_unions(xp):
    with pytest.raises(ReadOnlyViolation):
        check_panos_request({"type": "config", "action": "get", "xpath": xp})


def test_panos_xpath_allows_what_the_driver_sends():
    for xp in (panos.LOCAL_VSYS.format(vsys="vsys1") + "/rulebase/security/rules/entry[@name='allow web']",
               "/config/shared/address/entry[@name='h-1.2']", "/config/panorama/vsys/entry[@name='vsys1']/pre-rulebase/nat/rules",
               panos.PANORAMA_DG.format(dg="'DG-1'") + "/post-rulebase/security/rules/entry[@uuid='ab-12']"):
        check_panos_request({"type": "config", "action": "get", "xpath": xp})


# ---- R3: Cisco unparseable output is never "no route" ----------------------------------------------
class _Conn:
    def __init__(self, out):
        self.out = out

    def send_command(self, command, read_timeout=60):
        return self.out

    def disconnect(self):
        pass


@pytest.mark.parametrize("out", ["% Authorization failed.", "", "% Unrecognized host or address", "--More--",
                                 "Building configuration...", "% Invalid input detected"])
def test_cef_garbage_is_a_device_error(out, monkeypatch):
    monkeypatch.setattr(cisco_iosxe.CiscoClient, "connection_override", lambda dev: _Conn(out))
    client = cisco_iosxe.CiscoClient(install().devices["core-rtr1"])
    with pytest.raises(DeviceError):
        client.cef("10.20.1.50", None)


def test_cef_clear_no_route_still_blocks(monkeypatch):
    monkeypatch.setattr(cisco_iosxe.CiscoClient, "connection_override", lambda dev: _Conn("0.0.0.0/0\n  no route\n"))
    client = cisco_iosxe.CiscoClient(install().devices["core-rtr1"])
    assert client.cef("10.20.1.50", None).entries[0].kind == "drop"


@pytest.mark.parametrize("call", [lambda c: c.arp("10.1.1.1", None), lambda c: c.interface("Gi1"),
                                  lambda c: c.interfaces_brief(), lambda c: c.acl("A", Flow("10.0.0.1", "10.0.0.2"))])
def test_other_cisco_parsers_raise_on_authorization_failure(call, monkeypatch):
    monkeypatch.setattr(cisco_iosxe.CiscoClient, "connection_override", lambda dev: _Conn("% Authorization failed."))
    with pytest.raises(DeviceError):
        call(cisco_iosxe.CiscoClient(install().devices["core-rtr1"]))


# ---- R4: PAN-OS policy-match ------------------------------------------------------------------------
@pytest.mark.parametrize("xml", ["<result><unexpected/></result>", "<result><msg><line>something odd</line></msg></result>",
                                 "<result>junk</result>", "", "<result><rules><x/></rules></result>"])
def test_policy_match_unrecognised_reply_raises(xml):
    with pytest.raises(DeviceError):
        panos.parse_policy_match(ET.fromstring(f"<response status='success'>{xml}</response>"))


@pytest.mark.parametrize("xml", ["<result/>", "<result><rules/></result>",
                                 "<result><msg><line>no matching rule found</line></msg></result>"])
def test_policy_match_explicit_no_match(xml):
    assert panos.parse_policy_match(ET.fromstring(f"<response status='success'>{xml}</response>")) == (None, None)


def test_policy_match_rule_still_parsed():
    root = ET.fromstring("<response><result><rules><entry name='r1'><action>allow</action></entry></rules></result></response>")
    assert panos.parse_policy_match(root) == ("r1", "allow")


# ---- R5: AWS duplicate ENIs in one account+region ---------------------------------------------------
def _env(enis):
    env = object.__new__(aws.AwsEnv)
    env.targets = lambda: list(enis)

    def call(acct, region, op, **p):
        flt = {f["Name"]: f["Values"] for f in p["Filters"]}
        out = [e for e in enis[(acct, region)] if "vpc-id" not in flt or e["VpcId"] in flt["vpc-id"]]
        return {"NetworkInterfaces": out}

    env.call = call
    return env


def test_find_eni_two_vpcs_same_account_region_is_ambiguous():
    eni = lambda i, v: {"NetworkInterfaceId": i, "VpcId": v}  # noqa: E731
    env = _env({("1", "us-east-1"): [eni("eni-A", "vpc-a"), eni("eni-B", "vpc-b")]})
    with pytest.raises(aws.AmbiguousEni, match="eni-A.*eni-B"):
        env.find_eni("10.0.0.5")
    assert env.find_eni("10.0.0.5", vpc_id="vpc-b")[2]["NetworkInterfaceId"] == "eni-B"


# ---- R6: session policy fails closed ----------------------------------------------------------------
def test_packaged_policy_equals_repo_policy():
    repo = Path(__file__).resolve().parents[1] / "iam" / "nettrace-readonly-policy.json"
    assert json.loads(aws.session_policy()) == json.loads(repo.read_text())


def test_session_policy_unloadable_refuses(monkeypatch):
    monkeypatch.setattr(aws.resources, "files", lambda pkg: (_ for _ in ()).throw(ModuleNotFoundError(pkg)))
    monkeypatch.delenv("NETTRACE_ALLOW_NO_SESSION_POLICY", raising=False)
    with pytest.raises(CredentialError, match="refusing to AssumeRole"):
        aws.session_policy()
    monkeypatch.setenv("NETTRACE_ALLOW_NO_SESSION_POLICY", "1")
    with pytest.warns(UserWarning):
        assert aws.session_policy() is None


def test_session_policy_too_long_refuses(monkeypatch):
    monkeypatch.setattr(aws, "_SESSION_POLICY_MAX", 10)
    monkeypatch.delenv("NETTRACE_ALLOW_NO_SESSION_POLICY", raising=False)
    with pytest.raises(CredentialError, match="2048|10-character"):
        aws.session_policy()


def test_assume_role_not_called_without_policy(monkeypatch):
    from test_aws_assume import _env as assume_env

    monkeypatch.setattr(aws, "install_aws_guard", lambda s: s)
    monkeypatch.setattr(aws, "_SESSION_POLICY_MAX", 10)
    monkeypatch.delenv("NETTRACE_ALLOW_NO_SESSION_POLICY", raising=False)
    env = assume_env()
    with pytest.raises(CredentialError):
        env.session("111111111111")
    assert env.base.sts.calls == []


# ---- R7: terminal output ----------------------------------------------------------------------------
def _hostile():
    h = Hop(domain="cisco", node="[bold]n" + ESC, component="router", status=Status.BLOCK, summary="s" + ESC,
            ingress="[/x]" + ESC + "Gi0", egress="[bold" + ESC, policy="p" + ESC, nat="n" + ESC,
            details=["d" + ESC], index=1)
    return TraceResult(Flow("10.0.0.1", "10.0.0.2"), Outcome.BLOCKED, "[/oops]" + ESC + "reason", [h],
                       ["w[/x]" + ESC])


def _render(fmt):
    buf = io.StringIO()
    emit(Console(file=buf, width=200, force_terminal=False), _hostile(), fmt, verbose=True)
    return buf.getvalue()


@pytest.mark.parametrize("fmt", ["table", "text"])
def test_renderers_strip_escapes_and_survive_markup(fmt):
    out = _render(fmt)
    assert "\x1b" not in out and "\x07" not in out and "\x9b" not in out
    assert "[/x]" in out and "Gi0" in out and "reason" in out  # shown literally, trace not hidden


def test_text_renderer_keeps_one_record_per_hop():
    h = _hostile().hops[0]
    h.ingress = "a\tb\nc"
    result = TraceResult(Flow("10.0.0.1", "10.0.0.2"), Outcome.BLOCKED, "r", [h])
    lines = [ln for ln in _text_lines(result.to_dict()) if ln.startswith("HOP")]
    assert len(lines) == 1 and len(lines[0].split("\t")) == 10


def test_json_renderer_stays_raw_json():
    out = _render("json")
    assert "\x1b" not in out  # escaped by JSON
    assert json.loads(out)["Hops"][0]["ingress"].startswith("[/x]\x1b]0;PWNED")
