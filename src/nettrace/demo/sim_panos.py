"""PAN-OS firewall + Panorama XML API simulator. Evaluates policy, NAT and FIB lookups from the lab
model and answers in the same XML shapes the driver parses (see docs/gaps-and-roadmap.md V3–V5, V12–V14)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from defusedxml import ElementTree as SafeET

from nettrace.demo.lab import APP_PORTS, PANORAMA, PANOS

PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}


class Resp:
    def __init__(self, body: str, status_code: int = 200):
        self.status_code, self.content = status_code, body.encode()


def ok(inner: str) -> Resp:
    return Resp(f'<response status="success"><result>{inner}</result></response>')


def err(msg: str) -> Resp:
    return Resp(f'<response status="error"><msg><line>{_x(msg)}</line></msg></response>')


def _x(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _in_any(ip: str | None, members: list[str]) -> bool:
    if not ip or "any" in members:
        return True
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(m, strict=False) for m in members)


def _service_ok(rule: dict[str, Any], proto: str | None, port: int | None, app: str | None) -> bool:
    services = rule.get("service", ["any"])
    if "any" in services:
        return True
    for svc in services:
        if svc == "application-default":
            apps = [app] if app else rule.get("application", ["any"])
            if "any" in apps:
                return True
            if any((proto, port) in APP_PORTS.get(a, []) for a in apps):
                return True
            continue
        p, _, n = svc.partition("/")
        if p == proto and (port is None or str(port) in n.split(",")):
            return True
    return False


# ==== firewall =========================================================================================
class Firewall:
    def __init__(self, name: str, serial: str | None = None):
        self.name, self.dev, self.serial = name, PANOS[name], serial or PANOS[name]["serials"][0]

    def interfaces(self) -> list[tuple[str, ipaddress.IPv4Interface, str]]:
        return [(n, ipaddress.ip_interface(ip), z) for n, ip, z in self.dev["interfaces"]]

    def fib(self, ip: str) -> tuple[str, str | None, str] | None:
        """(interface, next_hop or None, source ip)."""
        addr = ipaddress.ip_address(ip)
        best = None
        for name, iface, _z in self.interfaces():
            if addr in iface.network and (best is None or iface.network.prefixlen > best[0].prefixlen):
                best = (iface.network, name, None)
        for prefix, nh, name in self.dev["routes"]:
            net = ipaddress.ip_network(prefix)
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, name, nh)
        if best is None:
            return None
        src = next(str(i.ip) for n, i, _z in self.interfaces() if n == best[1])
        return best[1], best[2], src

    def _match(self, rules: list[dict[str, Any]], q: dict[str, str]) -> tuple[int, dict[str, Any]] | None:
        proto = PROTO.get(q.get("protocol", ""), q.get("protocol"))
        port = int(q["destination-port"]) if q.get("destination-port", "").isdigit() else None
        app = q.get("application")
        for i, r in enumerate(rules, start=1):
            if q.get("from") and "any" not in r["from"] and q["from"] not in r["from"]:
                continue
            if q.get("to") and "any" not in r["to"] and q["to"] not in r["to"]:
                continue
            if not _in_any(q.get("source"), r["source"]) or not _in_any(q.get("destination"), r["destination"]):
                continue
            apps = r.get("application", ["any"])
            if app and "any" not in apps and app not in apps:
                continue
            if not _service_ok(r, proto, port, app):
                continue
            return i, r
        return None

    def op(self, cmd: str) -> Resp:
        try:
            root = SafeET.fromstring(cmd)
        except Exception:
            return err("Malformed command")
        compact = re.sub(r"\s+", "", cmd)

        def fields_of(tag: str) -> dict[str, str]:
            node = root.find(f".//{tag}") if root.tag != tag else root
            return {c.tag: (c.text or "").strip() for c in node} if node is not None else {}

        key = ""
        for prefix, name in (("<show><interface>", "show/interface"), ("<show><system>", "show/system"),
                             ("<show><routing>", "show/routing"), ("<show><high-availability>", "show/high-availability"),
                             ("<test><routing><fib-lookup>", "fib-lookup"),
                             ("<test><advanced-routing><fib-lookup>", "fib-lookup"),
                             ("<test><security-policy-match>", "security-policy-match"),
                             ("<test><nat-policy-match>", "nat-policy-match")):
            if compact.startswith(prefix):
                key = name
                break
        fields = fields_of(key) if key in ("fib-lookup", "security-policy-match", "nat-policy-match") else {}

        if key.startswith("show/interface"):
            return ok("<ifnet>" + "".join(
                f"<entry><name>{n}</name><zone>{z}</zone><fwd>vr:default</fwd><vsys>1</vsys><ip>{i.with_prefixlen}</ip></entry>"
                for n, i, z in self.interfaces()) + "</ifnet>")
        if key.startswith("show/system"):
            ha = PANORAMA["hostnames"].get(self.serial, self.dev["hostname"])
            return ok(f"<system><hostname>{ha}</hostname><ip-address>{PANORAMA['mgmt'].get(self.serial, self.dev['mgmt'])}"
                      f"</ip-address><model>{self.dev['model']}</model><serial>{self.serial}</serial>"
                      f"<sw-version>{self.dev['version']}</sw-version><app-version>8911-9134</app-version>"
                      f"<uptime>212 days, 4:17:09</uptime><operational-mode>normal</operational-mode></system>")
        if key.startswith("show/routing"):
            rows = "".join(f"<entry><virtual-router>default</virtual-router><destination>{p}</destination>"
                           f"<nexthop>{nh}</nexthop><metric>10</metric><flags>A S</flags><interface>{n}</interface></entry>"
                           for p, nh, n in self.dev["routes"])
            rows += "".join(f"<entry><virtual-router>default</virtual-router><destination>{i.network}</destination>"
                            f"<nexthop>{i.ip}</nexthop><metric>0</metric><flags>A C</flags><interface>{n}</interface></entry>"
                            for n, i, _z in self.interfaces())
            return ok(rows)
        if key.startswith("show/high-availability"):
            state, peer = PANORAMA["ha"].get(self.serial, ("disabled", ""))
            if state == "disabled":
                return ok("<enabled>no</enabled>")
            return ok(f"<enabled>yes</enabled><group><local-info><state>{state}</state><serial-num>{self.serial}"
                      f"</serial-num></local-info><peer-info><serial-num>{peer}</serial-num><state>"
                      f"{'passive' if state == 'active' else 'active'}</state></peer-info></group>")
        if key == "fib-lookup":
            ip = fields.get("ip", "")
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return err("invalid ip")
            hit = self.fib(ip)
            if hit is None:
                return ok("")
            name, nh, src = hit
            if nh is None:
                return ok(f"<nh>0</nh><src>{src}</src><ip>{ip}</ip><metric>0</metric><interface>{name}</interface><dp>dp0</dp>")
            return ok(f"<nh>ip</nh><src>{src}</src><ip>{nh}</ip><metric>10</metric><interface>{name}</interface><dp>dp0</dp>")
        if key.endswith("security-policy-match"):
            hit = self._match(self.dev["security"], fields)
            if hit is None:
                return ok("<rules/>")
            i, r = hit
            return ok(f'<rules><entry name="{_x(r["name"])}"><index>{i}</index><from>{" ".join(r["from"])}</from>'
                      f'<source>{" ".join(r["source"])}</source><to>{" ".join(r["to"])}</to>'
                      f'<destination>{" ".join(r["destination"])}</destination>'
                      f'<application>{" ".join(r["application"])}</application><action>{r["action"]}</action>'
                      f"<terminal>yes</terminal></entry></rules>")
        if key.endswith("nat-policy-match"):
            hit = self._match([dict(r, application=["any"]) for r in self.dev["nat"]], fields)
            if hit is None:
                return ok("<rules/>")
            return ok(f'<rules><entry name="{_x(hit[1]["name"])}"><index>{hit[0]}</index></entry></rules>')
        return err("Unknown command (the simulated firewall supports show interface / system info / routing route / "
                   "high-availability state, and test routing fib-lookup / security-policy-match / nat-policy-match)")

    def config(self, xpath: str) -> Resp:
        m = re.search(r"(?:pre|post)-rulebase/(security|nat)/rules/entry\[@name='([^']+)'\]", xpath)
        # Rules are pushed from Panorama: visible under /config/panorama on the firewall, not in local config.
        if not m or "/config/panorama/" not in xpath:
            return ok("")
        base, name = m.group(1), m.group(2)
        rule = next((r for r in self.dev[base] if r["name"] == name), None)
        if rule is None:
            return ok("")
        if base == "security":
            return ok(f'<entry name="{_x(name)}"><action>{rule["action"]}</action></entry>')
        inner = ""
        if rule.get("snat_interface"):
            inner += (f"<source-translation><dynamic-ip-and-port><interface-address><interface>{rule['snat_interface']}"
                      "</interface></interface-address></dynamic-ip-and-port></source-translation>")
        if rule.get("dnat"):
            port = f"<translated-port>{rule['dnat']['port']}</translated-port>" if rule["dnat"].get("port") else ""
            inner += f"<destination-translation><translated-address>{rule['dnat']['address']}</translated-address>{port}</destination-translation>"
        return ok(f'<entry name="{_x(name)}">{inner}</entry>')


# ==== Panorama ===========================================================================================
def _firewall_for(serial: str) -> Firewall | None:
    for name, dev in PANOS.items():
        if serial in dev["serials"]:
            return Firewall(name, serial)
    return None


def _panorama_op(cmd: str) -> Resp:
    compact = re.sub(r"\s+", "", cmd)
    if compact.startswith("<show><devices>"):
        rows = []
        for _name, dev in PANOS.items():
            for serial in dev["serials"]:
                ha = ""
                if serial in PANORAMA["ha"]:
                    st, peer = PANORAMA["ha"][serial]
                    ha = f"<ha><state>{st}</state><peer><serial>{peer}</serial></peer></ha>"
                rows.append(f'<entry name="{serial}"><serial>{serial}</serial><connected>yes</connected>'
                            f"<hostname>{PANORAMA['hostnames'][serial]}</hostname><ip-address>{PANORAMA['mgmt'][serial]}"
                            f"</ip-address><model>{dev['model']}</model><sw-version>{dev['version']}</sw-version>{ha}"
                            "<vsys><entry name=\"vsys1\"><display-name>vsys1</display-name></entry></vsys></entry>")
        return ok("<devices>" + "".join(rows) + "</devices>")
    if compact.startswith("<show><devicegroups>"):
        groups = {}
        for dev in PANOS.values():
            groups.setdefault(dev["device_group"], []).extend(dev["serials"])
        return ok("<devicegroups>" + "".join(
            f'<entry name="{g}"><devices>' + "".join(f'<entry name="{s}"/>' for s in serials) + "</devices></entry>"
            for g, serials in groups.items()) + "</devicegroups>")
    if compact.startswith("<show><dg-hierarchy>"):
        def render(parent: str | None) -> str:
            return "".join(f'<dg name="{g}">{render(g)}</dg>' for g, p in PANORAMA["device_groups"].items() if p == parent)
        return ok(f"<dg-hierarchy>{render(None)}</dg-hierarchy>")
    if compact.startswith("<show><system>"):
        return ok(f"<system><hostname>{PANORAMA['hostname']}</hostname><model>M-600</model>"
                  f"<sw-version>{PANORAMA['version']}</sw-version></system>")
    return err("Unknown command on Panorama (policy tests must be sent with target=<firewall serial>)")


class SimSession:
    """Stands in for requests.Session inside XmlApi."""

    def __init__(self) -> None:
        self.verify: Any = True

    def post(self, url: str, data: dict[str, str] | None = None, headers: dict[str, str] | None = None,
             timeout: int | None = None, allow_redirects: bool = True) -> Resp:
        data = data or {}
        if not (headers or {}).get("X-PAN-KEY"):
            return Resp('<response status="error"><msg>Invalid credentials.</msg></response>', 403)
        host = urlparse(url).hostname or ""
        target = data.get("target")
        if host == PANORAMA["host"] and not target:
            fw = None
        elif target:
            fw = _firewall_for(target)
            if fw is None:
                return err(f"device {target} is not managed by this Panorama")
        else:
            fw = next((Firewall(n, s) for n, d in PANOS.items() for s in d["serials"]
                       if PANORAMA["mgmt"].get(s) == host), None)
            if fw is None:
                return Resp("", 504)
        if data.get("type") == "op":
            return fw.op(data.get("cmd", "")) if fw else _panorama_op(data.get("cmd", ""))
        if data.get("type") == "config":
            return fw.config(data.get("xpath", "")) if fw else ok("")
        return err("unsupported request type")


def session(api: Any) -> SimSession:
    return SimSession()
