"""Never-guess gaps (PAN-OS config, Prisma, Cisco ECMP/PBR), AWS/PAN-OS/SCM robustness, SSH/TLS edges.
Everything is local: fakes only, files only under tmp_path."""

from types import SimpleNamespace

import pytest
import requests

from nettrace.demo import install
from nettrace.drivers import aws, cisco_iosxe, panos, prisma
from nettrace.drivers.cisco_iosxe import CefEntry, CefResult, CiscoClient
from nettrace.engine import Tracer
from nettrace.errors import DeviceError, InventoryError
from nettrace.inventory import load_inventory
from nettrace.models import Flow, Outcome, Status
from nettrace.steps import DeviceAt, PrismaAt

FLOW = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)


# ---- PAN-OS config_get ---------------------------------------------------------------------
def _client(request):
    c = panos.PanosClient.__new__(panos.PanosClient)
    c.device = SimpleNamespace(name="fw", vsys=None, serial=None)
    c.panorama = None
    c.request = request
    return c


def _ok(xml):
    import xml.etree.ElementTree as ET

    return lambda params, label: ET.fromstring(f"<response status='success'>{xml}</response>")


def _fail(params, label):
    raise DeviceError("API timeout")


def test_config_get_unavailable_is_distinct_from_not_found():
    assert _client(_ok("<result/>")).config_get("/x") is None  # configured nowhere
    got = _client(_fail).config_get("/x")
    assert isinstance(got, panos.Unavailable) and "timeout" in got.reason


def test_config_lookup_failure_is_an_error_not_a_miss():
    with pytest.raises(DeviceError, match="could not answer"):
        _client(_fail).rule_config("security", "r1")
    assert _client(_ok("<result/>")).rule_config("security", "r1") is None  # answered: not configured


def test_config_lookup_found_after_a_failed_query_still_works():
    import xml.etree.ElementTree as ET

    calls = []

    def req(params, label):
        calls.append(params["xpath"])
        if len(calls) == 1:
            raise DeviceError("blip")
        return ET.fromstring("<response status='success'><result><entry name='r1'><action>allow</action></entry>"
                             "</result></response>")

    assert _client(req).rule_config("security", "r1").findtext("action") == "allow"


# ---- Prisma uncertainty --------------------------------------------------------------------------
def _scm(rules, objects=None):
    objects = objects or {}

    def get_objects(kind, folder):
        if kind not in objects:
            raise DeviceError(f"404 {kind}")
        return objects[kind]

    return SimpleNamespace(evidence=[], security_rules=lambda folder: rules, objects=get_objects)


def _rule(name, action, **kw):
    return {"name": name, "action": action, "_position": "pre", **kw}


def _prisma_step(rules, objects=None, flow=None):
    inv = install()
    pool = inv.prisma.mobile_user_pools[0].split("/")[0].rsplit(".", 1)
    src = f"{pool[0]}.{int(pool[1]) + 1}"
    flow = flow or Flow(src=src, dst="203.0.113.9", protocol="tcp", dst_port=443)
    return prisma.step(_scm(rules, objects), inv, PrismaAt(entry="source", name="x"), flow)


def test_prisma_deny_below_uncertain_rule_is_unknown_not_block():
    res = _prisma_step([_rule("needs-appid", "allow", application=["ssl"]), _rule("deny-all", "deny")])
    assert res.outcome == Outcome.INCOMPLETE and res.hops[0].status == Status.UNKNOWN


def test_prisma_deny_without_uncertainty_still_blocks():
    res = _prisma_step([_rule("deny-all", "deny")])
    assert res.outcome == Outcome.BLOCKED and res.hops[0].status == Status.BLOCK


@pytest.mark.parametrize("extra", [{"category": ["gambling"]}, {"source_hip": ["managed"]}, {"destination": ["fqdn-obj"]}])
def test_prisma_unevaluable_criteria_are_uncertain(extra):
    objs = {"addresses": {"fqdn-obj": {"name": "fqdn-obj", "fqdn": "example.com"}}, "address-groups": {}}
    res = _prisma_step([_rule("r", "allow", **extra)], objs)
    assert res.hops[0].status == Status.UNKNOWN and res.outcome == Outcome.INCOMPLETE


def test_prisma_application_group_is_uncertain_not_a_miss():
    r = prisma.Resolver(_scm([], {"application-groups": {"web-apps": {}}, "application-filters": {}}), "f")
    assert r.application_match("ssl", ["web-apps"]) is None  # may be inside the group
    assert r.application_match("ssl", ["ssl"]) is True
    assert r.application_match("ssl", ["dns"]) is False
    assert r.application_match(None, ["dns"]) is None
    assert prisma.Resolver(_scm([]), "f").application_match("ssl", ["web-apps"]) is None  # lookup failed


# ---- Cisco ECMP / PBR ----------------------------------------------------------------------------
def _cisco(entries, pbr=None):
    dev = SimpleNamespace(name="r1", vrf=None)
    return SimpleNamespace(
        device=dev, evidence=[], interface=lambda n: {}, policy_route_map=lambda n: pbr,
        cef=lambda ip, vrf: CefResult(prefix="10.20.0.0/16", entries=entries),
        route=lambda ip, vrf: ("10.20.0.0/16", "bgp 65001"))


NH = [CefEntry("nexthop", "10.0.0.2", "Gi1"), CefEntry("nexthop", "10.0.1.2", "Gi2")]


def test_cisco_ecmp_is_warn_and_lists_alternatives():
    res = cisco_iosxe.step(_cisco(NH), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)
    h = res.hops[0]
    assert h.status == Status.WARN and any("10.0.1.2 Gi2" in d and "10.0.0.2 Gi1" in d for d in h.details)
    assert any("ECMP" in w for w in res.warnings)


def test_cisco_single_path_stays_pass():
    res = cisco_iosxe.step(_cisco(NH[:1]), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)
    assert res.hops[0].status == Status.PASS


def test_cisco_pbr_on_ingress_is_warn_and_never_a_clean_block():
    res = cisco_iosxe.step(_cisco(NH[:1], pbr="STEER"), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)
    assert res.hops[0].status == Status.WARN and any("STEER" in d for d in res.hops[0].details)
    none = cisco_iosxe.step(_cisco([], pbr="STEER"), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW)
    assert none.outcome == Outcome.INCOMPLETE and none.hops[0].status == Status.UNKNOWN  # PBR may rescue it
    assert cisco_iosxe.step(_cisco([]), DeviceAt(device="r1", arrival_interface="Gi0"), FLOW).outcome == Outcome.BLOCKED


def test_policy_route_map_parsed_from_raw_show():
    c = CiscoClient(install().devices["core-rtr1"])
    c.show = lambda cmd: "  Policy routing is enabled, using route-map STEER\n"
    assert c.policy_route_map("Gi1") == "STEER"
    c.show = lambda cmd: "  Policy routing is disabled\n"
    assert c.policy_route_map("Gi1") is None


# ---- deadline ------------------------------------------------------------------------------------
def test_deadline_expiry_is_incomplete_and_keeps_hops():
    t = Tracer(install(), timeout=120)
    t.deadline._end = 0  # already expired
    r = t.trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and "deadline" in r.reason
    assert r.hops[0].component == "source" and r.hops[-1].status == Status.UNKNOWN


def test_default_timeout_is_120_and_inventory_overrides(tmp_path):
    assert install().trace_timeout == 120 and Tracer(install()).deadline.seconds == 120
    f = tmp_path / "inv.yaml"
    f.write_text("trace_timeout: 45\ndevices: []\n")
    assert load_inventory(f).trace_timeout == 45
    assert Tracer(load_inventory(f), timeout=7).deadline.seconds == 7  # CLI wins
    f.write_text("trace_timeout: 0\ndevices: []\n")
    with pytest.raises(InventoryError, match="trace_timeout"):
        load_inventory(f)


def test_request_paths_stop_at_the_deadline(monkeypatch):
    from nettrace.errors import Deadline, DeadlineExceeded

    d = Deadline(1)
    d._end = 0
    c = CiscoClient(install().devices["core-rtr1"])
    c.deadline = d
    with pytest.raises(DeadlineExceeded):
        c.show("show version")
    env = object.__new__(aws.AwsEnv)
    env._cache, env.deadline = {}, d
    with pytest.raises(DeadlineExceeded):
        env.call("1", "us-east-1", "describe_vpcs")


# ---- AWS client config / ENI lookup --------------------------------------------------------------
def test_boto_config():
    cfg = aws.boto_config()
    assert (cfg.connect_timeout, cfg.read_timeout) == (5, 20)
    assert cfg.retries == {"mode": "standard", "max_attempts": 3}


def _env(enis):
    """enis: {(account, region): [eni, ...]}; the fake honours the vpc-id filter like EC2 does."""
    env = object.__new__(aws.AwsEnv)
    env.targets = lambda: list(enis)

    def call(acct, region, op, **p):
        flt = {f["Name"]: f["Values"] for f in p["Filters"]}
        out = [e for e in enis[(acct, region)] if "vpc-id" not in flt or e["VpcId"] in flt["vpc-id"]]
        return {"NetworkInterfaces": out}

    env.call = call
    return env


def _eni(i, vpc):
    return {"NetworkInterfaceId": i, "VpcId": vpc}


def test_find_eni_overlapping_ip_is_ambiguous_unless_vpc_given():
    env = _env({("1", "us-east-1"): [_eni("eni-a", "vpc-a")], ("2", "us-east-1"): [_eni("eni-b", "vpc-b")]})
    with pytest.raises(aws.AmbiguousEni, match="eni-a.*eni-b"):
        env.find_eni("10.0.0.5")
    assert env.find_eni("10.0.0.5", vpc_id="vpc-b")[2]["NetworkInterfaceId"] == "eni-b"
    assert env.find_eni("10.0.0.5", vpc_id="vpc-zzz") is None


def test_find_eni_same_eni_seen_from_two_accounts_is_one_hit():
    env = _env({("1", "us-east-1"): [_eni("eni-a", "vpc-a")], ("2", "us-east-1"): [_eni("eni-a", "vpc-a")]})
    assert env.find_eni("10.0.0.5")[0] == "1"


# ---- PAN-OS / SCM retry on timeout ---------------------------------------------------------------
class _Session:
    def __init__(self, outcomes):
        self.outcomes, self.posts = list(outcomes), 0

    def post(self, url, **kw):
        self.posts += 1
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return o


def _api(monkeypatch, outcomes):
    monkeypatch.setenv("TEST_KEY", "k")
    monkeypatch.setattr(panos.XmlApi, "session_override", None)
    api = panos.XmlApi("fw", ["h1"], None, "TEST_KEY", True)
    api.session = _Session(outcomes)
    return api


OK = SimpleNamespace(status_code=200, content=b"<response status='success'><result/></response>")
SHOW = {"type": "op", "cmd": "<show><system><info></info></system></show>"}


def test_panos_retries_a_timeout_once(monkeypatch):
    api = _api(monkeypatch, [requests.Timeout("slow"), OK])
    api.request(SHOW, "x")
    assert api.session.posts == 2
    api = _api(monkeypatch, [requests.Timeout("slow"), requests.Timeout("slow")])
    with pytest.raises(DeviceError, match="slow"):
        api.request(SHOW, "x")
    assert api.session.posts == 2  # exactly one retry


def test_panos_does_not_retry_other_errors(monkeypatch):
    api = _api(monkeypatch, [requests.ConnectionError("refused"), OK])
    with pytest.raises(DeviceError):
        api.request(SHOW, "x")
    assert api.session.posts == 1


def test_scm_get_retries_a_timeout_once(monkeypatch):
    monkeypatch.setattr(prisma.ScmClient, "transport_override", None)
    scm = prisma.ScmClient()
    scm._get_token = lambda: "t"
    seen = []

    def get(url, **kw):
        seen.append(url)
        if len(seen) == 1:
            raise requests.Timeout("slow")
        return SimpleNamespace(status_code=200, json=lambda: {"data": []})

    monkeypatch.setattr(prisma.requests, "get", get)
    assert scm.get_all("/config/security/v1/security-rules", {"folder": "f"}) == []
    assert len(seen) == 2
    seen.clear()

    def always_slow(url, **kw):
        seen.append(url)
        raise requests.Timeout("x")

    monkeypatch.setattr(prisma.requests, "get", always_slow)
    with pytest.raises(DeviceError):
        scm.get_all("/config/security/v1/other", {"folder": "f"})
    assert len(seen) == 2


# ---- SSH host keys -------------------------------------------------------------------------------
def _ssh_client(monkeypatch, exc):
    import netmiko

    dev = install().devices["core-rtr1"]  # install() sets the simulation seam: clear it afterwards
    monkeypatch.setattr(CiscoClient, "connection_override", None)
    monkeypatch.setenv(dev.username_env, "u")
    monkeypatch.setenv(dev.password_env, "p")

    def boom(**kw):
        raise exc

    monkeypatch.setattr(netmiko, "ConnectHandler", boom)
    return CiscoClient(dev)


def test_unknown_host_key_is_a_clear_device_error(monkeypatch):
    import paramiko

    c = _ssh_client(monkeypatch, paramiko.SSHException("Server '10.0.0.1' not found in known_hosts"))
    with pytest.raises(DeviceError) as e:
        c.show("show version")
    assert "not in known_hosts: ssh once to verify the fingerprint; do not set ssh_strict: false" in str(e.value)


def test_changed_host_key_says_possible_spoofing(monkeypatch):
    import paramiko

    exc = paramiko.BadHostKeyException.__new__(paramiko.BadHostKeyException)
    c = _ssh_client(monkeypatch, exc)
    with pytest.raises(DeviceError, match="CHANGED.*possible spoofing"):
        c.show("show version")


# ---- verify_tls at inventory load ----------------------------------------------------------------
def _inv(tmp_path, text):
    f = tmp_path / "inv.yaml"
    f.write_text(text)
    return load_inventory(f)


DEV = "devices:\n  - {name: fw1, platform: panos, host: 192.0.2.1%s}\n"


def test_insecure_tls_in_defaults_needs_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NETTRACE_ALLOW_INSECURE_TLS", raising=False)
    text = "defaults:\n  panos: {verify_tls: false}\n" + DEV % ""
    with pytest.raises(InventoryError, match="NETTRACE_ALLOW_INSECURE_TLS"):
        _inv(tmp_path, text)
    monkeypatch.setenv("NETTRACE_ALLOW_INSECURE_TLS", "1")
    assert _inv(tmp_path, text).devices["fw1"].verify_tls is False


def test_insecure_tls_on_panorama_needs_env(tmp_path, monkeypatch):
    monkeypatch.delenv("NETTRACE_ALLOW_INSECURE_TLS", raising=False)
    text = "panorama: {host: 192.0.2.9, verify_tls: false}\ndevices: []\n"
    with pytest.raises(InventoryError, match="panorama.verify_tls"):
        _inv(tmp_path, text)
    monkeypatch.setenv("NETTRACE_ALLOW_INSECURE_TLS", "1")
    assert _inv(tmp_path, text).panorama.verify_tls is False


def test_per_device_insecure_tls_stays_allowed(tmp_path, monkeypatch):
    monkeypatch.delenv("NETTRACE_ALLOW_INSECURE_TLS", raising=False)
    assert _inv(tmp_path, DEV % ", verify_tls: false").devices["fw1"].verify_tls is False


def test_verify_tls_string_must_be_an_existing_ca_bundle(tmp_path):
    with pytest.raises(InventoryError, match="CA bundle"):
        _inv(tmp_path, DEV % f", verify_tls: {tmp_path}/missing.pem")
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    assert _inv(tmp_path, DEV % f", verify_tls: {ca}").devices["fw1"].verify_tls == str(ca)
    with pytest.raises(InventoryError, match="verify_tls"):
        _inv(tmp_path, DEV % ", verify_tls: 3")
