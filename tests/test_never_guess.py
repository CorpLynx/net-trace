from types import SimpleNamespace

import pytest

from nettrace.drivers import cisco_iosxe, ntc, panos
from nettrace.drivers.aws import AwsWalker
from nettrace.drivers.cisco_iosxe import CefResult
from nettrace.engine import Tracer
from nettrace.errors import DeviceError
from nettrace.models import Flow, Hop, Outcome, Status
from nettrace.demo import install
from nettrace.steps import DeviceAt, StepResult

FLOW = Flow(src="10.1.10.25", dst="10.20.1.50", protocol="tcp", dst_port=443)


def _unhandled(monkeypatch, exc):
    inv = install()
    def boom(self, pos, flow):
        raise exc
    monkeypatch.setattr(Tracer, "_step", boom)
    return Tracer(inv).trace(FLOW)


@pytest.mark.parametrize("exc", [IndexError("list index out of range"), RecursionError("deep"), OSError("refused")])
def test_any_driver_exception_becomes_unknown_hop(monkeypatch, exc):
    r = _unhandled(monkeypatch, exc)
    assert r.outcome == Outcome.INCOMPLETE and type(exc).__name__ in r.reason
    assert r.hops[0].component == "source"  # hops collected so far are kept
    assert r.hops[-1].status == Status.UNKNOWN


@pytest.mark.parametrize("end", [Outcome.REACHABLE, Outcome.EXITED])
def test_reachable_or_exited_with_unknown_hop_is_incomplete(monkeypatch, end):
    inv = install()
    def step(self, pos, flow):
        h = Hop(domain="engine", node="x", component="router", status=Status.UNKNOWN, summary="?")
        return StepResult([h], flow, outcome=end, reason="delivered")
    monkeypatch.setattr(Tracer, "_step", step)
    r = Tracer(inv).trace(FLOW)
    assert r.outcome == Outcome.INCOMPLETE and "UNKNOWN" in r.reason


def test_ntc_parse_empty_vs_failure(monkeypatch):
    assert ntc.ntc_parse("show ip interface", "  \n") == []
    def bad(**kw):
        raise ValueError("template mismatch")
    monkeypatch.setattr(ntc, "parse_output", bad)
    with pytest.raises(DeviceError):
        ntc.ntc_parse("show ip interface", "something")


def test_cisco_interface_without_data_raises():
    client = cisco_iosxe.CiscoClient(install().devices["core-rtr1"])
    client.show = lambda cmd: "no template for this"
    with pytest.raises(DeviceError):
        client.interface("Gi1")


def test_cisco_unknown_ingress_is_unknown_not_pass():
    dev = SimpleNamespace(name="r1", vrf=None)
    client = SimpleNamespace(device=dev, evidence=[], cef=lambda ip, vrf: CefResult(prefix=None))
    res = cisco_iosxe.step(client, DeviceAt(device="r1"), FLOW)
    assert res.outcome == Outcome.INCOMPLETE and res.hops[0].status == Status.UNKNOWN


def _fib_client(xml):
    import xml.etree.ElementTree as ET

    c = panos.PanosClient.__new__(panos.PanosClient)
    c.device = SimpleNamespace(name="fw", routing_engine="", virtual_router="default")
    c.op = lambda path, fields=None: ET.fromstring(f"<response status='success'>{xml}</response>")
    return c


def test_fib_lookup_tri_state():
    assert _fib_client("<result/>").fib_lookup("vr", "10.0.0.1") is None  # confirmed no route
    assert _fib_client("<result><nh>discard</nh><interface>eth1</interface></result>").fib_lookup("vr", "10.0.0.1") is None
    ok = _fib_client("<result><nh>ip</nh><ip>10.9.9.9</ip><interface>eth1</interface></result>").fib_lookup("vr", "10.0.0.1")
    assert ok.next_hop == "10.9.9.9"
    for bad in ("", "<result><weird>1</weird></result>", "<result><nh>vpn</nh><interface>t1</interface></result>"):
        with pytest.raises(DeviceError):
            _fib_client(bad).fib_lookup("vr", "10.0.0.1")


def test_panos_unresolved_nat_is_error():
    c = SimpleNamespace(device=SimpleNamespace(name="fw"), rule_config=lambda kind, rule: None)
    with pytest.raises(DeviceError):
        panos._nat_translation(c, "snat1", "eth1")


def test_panos_missing_zone_is_unknown():
    dev = SimpleNamespace(name="fw", virtual_router="default", vsys=None, aws=None)
    c = SimpleNamespace(device=dev, evidence=[], notes=[], meta={},
                        interfaces=lambda: {"eth1": {"zone": "", "fwd": "", "ip": "", "vsys": ""}},
                        interface_for_ip=lambda ip: None,
                        fib_lookup=lambda router, ip: panos.FibResult(interface="eth1", next_hop=None))
    res = panos.step(c, DeviceAt(device="fw", arrival_interface="eth1"), FLOW)
    assert res.outcome == Outcome.INCOMPLETE and res.hops[0].status == Status.UNKNOWN


def test_aws_tgw_vpc_loop_ends_incomplete():
    inv = install()
    acct = inv.aws_accounts[0].account_id
    w = AwsWalker(SimpleNamespace(evidence=[]), inv)
    w._tgw_entries.add(("tgw-attach-1", FLOW.src, FLOW.dst))
    res = w._enter_vpc_from_tgw(acct, "us-east-1", "tgw-attach-1", FLOW, [], [], None)
    assert res.outcome == Outcome.INCOMPLETE and "loop" in res.reason
