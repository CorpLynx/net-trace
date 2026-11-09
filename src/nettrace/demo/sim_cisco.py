"""IOS-XE simulator: answers `show` commands from the lab model in real IOS-XE output formats,
so the driver's parsers and ntc-templates run unchanged."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from nettrace.demo.lab import CISCO

INVALID = "                ^\n% Invalid input detected at '^' marker.\n"


# Real IOS accepts any unambiguous prefix of every keyword (`show run` = `show running-config`). The
# simulator does the same so a guard that only matches full words is exercised realistically.
_KEYWORDS = [k.split() for k in (
    "show ip cef", "show ip route", "show ip interface brief", "show ip interface", "show ip arp",
    "show ip access-lists", "show access-lists", "show version", "show running-config", "show startup-config",
    "show derived-config", "show tech-support", "show archive", "show logging", "show snmp user",
    "show crypto pki certificates", "show aaa servers", "show interfaces description", "show interface description",
    "show vrf",
)]


def expand_abbreviations(cmd: str) -> str | None:
    """Canonical full-word command, or None when a keyword is ambiguous. Unknown words pass through."""
    toks, out, cands = cmd.split(), [], _KEYWORDS
    for i, t in enumerate(toks):
        live = [k for k in cands if len(k) > i and k[i].startswith(t)]
        if not live:
            out.extend(toks[i:])
            break
        exact = [k for k in live if k[i] == t]
        pool = exact or live
        words = {k[i] for k in pool}
        if len(words) != 1:
            return None
        out.append(words.pop())
        cands = pool
    return " ".join(out)


class SimConnection:
    def __init__(self, name: str):
        self.name = name
        self.dev = CISCO[name]

    def disconnect(self) -> None:
        pass

    def enable(self) -> None:
        pass

    # ---- dispatcher -------------------------------------------------------------------------
    def send_command(self, command: str, read_timeout: int = 60) -> str:
        cmd = expand_abbreviations(" ".join(command.split()))
        if cmd is None:
            return "% Ambiguous command:  " + repr(command) + "\n"
        handlers = [
            (r"show ip cef (?:vrf \S+ )?(\S+)", self._cef),
            (r"show ip route (?:vrf \S+ )?(\d+\.\d+\.\d+\.\d+)", self._route_one),
            (r"show ip route", lambda: self._route_table()),
            (r"show ip interface brief", lambda: self._brief()),
            (r"show ip interface (\S+)", self._interface),
            (r"show ip arp (?:vrf \S+ )?(\S+)", self._arp),
            (r"show ip arp", lambda: self._arp(None)),
            (r"show ip access-lists (\S+)", self._acl),
            (r"show (?:ip )?access-lists", lambda: "".join(self._acl(n) for n in self.dev["acls"])),
            (r"show version", lambda: self._version()),
            (r"show (?:running-config|startup-config|derived-config)", lambda: self._running()),
            (r"show (?:tech-support|archive|logging|snmp user|crypto pki certificates|aaa servers)",
             lambda: "! simulated sensitive output (never reachable through the nettrace guard)\n"),
            (r"show vrf", lambda: "  Name      Default RD  Protocols  Interfaces\n"),
            (r"show interfaces? description", lambda: self._descriptions()),
        ]
        for pattern, fn in handlers:
            m = re.fullmatch(pattern, cmd)
            if m:
                return fn(*m.groups())
        return INVALID

    # ---- model helpers -------------------------------------------------------------------------
    def _connected(self) -> list[tuple[ipaddress.IPv4Network, str, str]]:
        out = []
        for i in self.dev["interfaces"]:
            iface = ipaddress.ip_interface(i["ip"])
            out.append((iface.network, i["name"], str(iface.ip)))
        return out

    def _lookup(self, ip: str) -> tuple[str, str, str | None, str] | None:
        """(prefix, kind, next_hop, interface) by longest match: receive > connected > routes."""
        addr = ipaddress.ip_address(ip)
        for _net, name, own in self._connected():
            if own == ip:
                return f"{own}/32", "receive", None, name
        best = None
        for net, name, _own in self._connected():
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, "attached", None, name)
        for prefix, nh, name, _src in self.dev["routes"]:
            net = ipaddress.ip_network(prefix)
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, "nexthop", nh, name)
        if best is None:
            return None
        return str(best[0]), best[1], best[2], best[3]

    # ---- commands ---------------------------------------------------------------------------------
    def _cef(self, ip: str) -> str:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return INVALID
        hit = self._lookup(ip)
        if hit is None:
            return "0.0.0.0/0\n  no route\n"
        prefix, kind, nh, name = hit
        if kind == "receive":
            return f"{prefix}\n  receive for {name}\n"
        if kind == "attached":
            return f"{prefix}\n  attached to {name}\n"
        return f"{prefix}\n  nexthop {nh} {name}\n"

    def _source(self, prefix: str, kind: str) -> str:
        if kind in ("attached", "receive"):
            return "connected"
        for p, _nh, _name, src in self.dev["routes"]:
            if p == prefix:
                return src
        return "static"

    def _route_one(self, ip: str) -> str:
        hit = self._lookup(ip)
        if hit is None:
            return "% Network not in table\n"
        prefix, kind, nh, name = hit
        if kind == "receive":
            prefix = next(str(n) for n, nm, _o in self._connected() if nm == name)
        src = self._source(prefix, kind)
        dist = {"connected": 0, "static": 1}.get(src, 20)
        lines = [f"Routing entry for {prefix}", f'  Known via "{src}", distance {dist}, metric 0',
                 "  Routing Descriptor Blocks:"]
        lines.append(f"  * directly connected, via {name}" if kind != "nexthop" else f"  * {nh}, via {name}")
        return "\n".join(lines) + "\n"

    def _route_table(self) -> str:
        lines = ["Codes: L - local, C - connected, S - static, B - BGP", "", "Gateway of last resort is 10.0.0.2 to network 0.0.0.0", ""]
        for prefix, nh, name, src in self.dev["routes"]:
            code = "S*" if prefix == "0.0.0.0/0" else ("B " if src.startswith("bgp") else "S ")
            dist = "[1/0]" if code.startswith("S") else "[20/0]"
            lines.append(f"{code}    {prefix} {dist} via {nh}, {name}")
        for net, name, own in self._connected():
            lines.append(f"C        {net} is directly connected, {name}")
            if net.prefixlen < 32:
                lines.append(f"L        {own}/32 is directly connected, {name}")
        return "\n".join(lines) + "\n"

    def _brief(self) -> str:
        lines = ["Interface              IP-Address      OK? Method Status                Protocol"]
        for i in self.dev["interfaces"]:
            ip = i["ip"].split("/")[0]
            lines.append(f"{i['name']:<22} {ip:<15} YES manual up                    up      ")
        return "\n".join(lines) + "\n"

    def _find_intf(self, name: str) -> dict[str, Any] | None:
        aliases = {"gi": "GigabitEthernet", "tu": "Tunnel", "lo": "Loopback"}
        m = re.fullmatch(r"([A-Za-z]+?)(\d.*)", name)
        if m and m.group(1).lower() in aliases:
            name = aliases[m.group(1).lower()] + m.group(2)
        return next((i for i in self.dev["interfaces"] if i["name"].lower() == name.lower()), None)

    def _interface(self, name: str) -> str:
        i = self._find_intf(name)
        if i is None:
            return INVALID
        iface = ipaddress.ip_interface(i["ip"])
        out = [f"{i['name']} is up, line protocol is up", f"  Internet address is {iface.ip}/{iface.network.prefixlen}",
               "  Broadcast address is 255.255.255.255", "  MTU is 1500 bytes"]
        if i.get("vrf"):
            out.append(f'  VPN Routing/Forwarding "{i["vrf"]}"')
        out.append("  Outgoing Common access list is not set ")
        out.append(f"  Outgoing access list is {i['acl_out']}" if i.get("acl_out") else "  Outgoing access list is not set")
        out.append("  Inbound Common access list is not set ")
        out.append(f"  Inbound  access list is {i['acl_in']}" if i.get("acl_in") else "  Inbound  access list is not set")
        out.append("  Proxy ARP is enabled")
        return "\n".join(out) + "\n"

    def _arp(self, ip: str | None) -> str:
        header = "Protocol  Address          Age (min)  Hardware Addr   Type   Interface"
        rows = []
        for addr, mac in self.dev["arp"].items():
            if ip and addr != ip:
                continue
            hit = self._lookup(addr)
            intf = hit[3] if hit else "?"
            rows.append(f"Internet  {addr:<16} {'3':>10}   {mac}  ARPA   {intf}")
        return "\n".join([header] + rows) + "\n" if rows else header + "\n"

    def _acl(self, name: str) -> str:
        lines = self.dev["acls"].get(name)
        if lines is None:
            return ""
        return f"Extended IP access list {name}\n" + "".join(f"    {line}\n" for line in lines)

    def _version(self) -> str:
        d = self.dev
        return (f"Cisco IOS XE Software, Version {d['version']}\nCisco IOS Software [Dublin], Virtual XE Software, "
                f"Version {d['version']}, RELEASE SOFTWARE (fc2)\n\n{d['hostname']} uptime is 41 weeks, 2 days, 7 hours\n"
                f"cisco {d['model']} (1RU) processor with 3755424K/6147K bytes of memory.\n"
                "Configuration register is 0x2102\n\n(simulated device: nettrace demo lab)\n")

    def _descriptions(self) -> str:
        lines = ["Interface                      Status         Protocol Description"]
        for i in self.dev["interfaces"]:
            lines.append(f"{i['name']:<30} up             up       {i.get('desc', '')}")
        return "\n".join(lines) + "\n"

    def _running(self) -> str:
        d = self.dev
        out = ["Building configuration...", "", "!", f"hostname {d['hostname']}", "!"]
        for i in d["interfaces"]:
            iface = ipaddress.ip_interface(i["ip"])
            out += [f"interface {i['name']}", f" description {i.get('desc', '')}",
                    f" ip address {iface.ip} {iface.network.netmask}"]
            if i.get("acl_in"):
                out.append(f" ip access-group {i['acl_in']} in")
            if i.get("acl_out"):
                out.append(f" ip access-group {i['acl_out']} out")
            out.append("!")
        for name, lines in d["acls"].items():
            out.append(f"ip access-list extended {name}")
            out += [f" {line}" for line in lines]
            out.append("!")
        for prefix, nh, name, src in d["routes"]:
            if src == "static":
                net = ipaddress.ip_network(prefix)
                out.append(f"ip route {net.network_address} {net.netmask} {name} {nh}")
        out += ["!", "end"]
        return "\n".join(out) + "\n"


def connect(device: Any) -> SimConnection:
    from nettrace.errors import DeviceError

    if device.name not in CISCO:
        raise DeviceError(f"{device.name}: not part of the demo lab")
    return SimConnection(device.name)
