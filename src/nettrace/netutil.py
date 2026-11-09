"""Small, dependency-free networking helpers."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

PROTOCOL_NUMBERS = {
    "icmp": 1,
    "igmp": 2,
    "ip": 0,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ahp": 51,
    "ah": 51,
    "eigrp": 88,
    "ospf": 89,
    "pim": 103,
    "sctp": 132,
    "icmpv6": 58,
}

# Cisco IOS port keywords as printed by "show ip access-lists".
CISCO_PORT_NAMES = {
    "bgp": 179,
    "bootpc": 68,
    "bootps": 67,
    "chargen": 19,
    "cmd": 514,
    "daytime": 13,
    "discard": 9,
    "domain": 53,
    "echo": 7,
    "exec": 512,
    "finger": 79,
    "ftp": 21,
    "ftp-data": 20,
    "gopher": 70,
    "hostname": 101,
    "ident": 113,
    "irc": 194,
    "isakmp": 500,
    "klogin": 543,
    "kshell": 544,
    "ldap": 389,
    "login": 513,
    "lpd": 515,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "netbios-ss": 139,
    "nntp": 119,
    "non500-isakmp": 4500,
    "ntp": 123,
    "onep-plain": 15001,
    "onep-tls": 15002,
    "pim-auto-rp": 496,
    "pop2": 109,
    "pop3": 110,
    "rip": 520,
    "smtp": 25,
    "snmp": 161,
    "snmptrap": 162,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "talk": 517,
    "telnet": 23,
    "tftp": 69,
    "time": 37,
    "uucp": 540,
    "who": 513,
    "whois": 43,
    "www": 80,
    "xdmcp": 177,
    "https": 443,
    "ssh": 22,
}

DEFAULT_EPHEMERAL_PORT = 49152


def protocol_number(protocol: str | int) -> int:
    if isinstance(protocol, int):
        return protocol
    p = str(protocol).strip().lower()
    if p.isdigit():
        return int(p)
    if p not in PROTOCOL_NUMBERS:
        raise ValueError(f"unknown protocol {protocol!r}")
    return PROTOCOL_NUMBERS[p]


def protocol_name(protocol: str | int) -> str:
    num = protocol_number(protocol)
    for name, value in PROTOCOL_NUMBERS.items():
        if value == num and name not in ("ip", "ah"):
            return name
    return str(num)


def uses_ports(protocol: str | int) -> bool:
    return protocol_number(protocol) in (6, 17, 132)


def cisco_port(value: str) -> int | None:
    value = value.strip().lower()
    if value.isdigit():
        return int(value)
    return CISCO_PORT_NAMES.get(value)


def ip_in(ip: str, prefixes: Iterable[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    for prefix in prefixes:
        try:
            if addr in ipaddress.ip_network(prefix, strict=False):
                return True
        except ValueError:
            continue
    return False


def longest_match(ip: str, prefixes: Iterable[str]) -> str | None:
    """Return the longest prefix in `prefixes` containing `ip`."""
    addr = ipaddress.ip_address(ip)
    best: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    best_raw: str | None = None
    for raw in prefixes:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == addr.version and addr in net:
            if best is None or net.prefixlen > best.prefixlen:
                best, best_raw = net, raw
    return best_raw


def wildcard_match(ip: str, network: str, wildcard: str) -> bool:
    """Cisco wildcard-mask match (supports discontiguous masks)."""
    a = int(ipaddress.IPv4Address(ip))
    n = int(ipaddress.IPv4Address(network))
    w = int(ipaddress.IPv4Address(wildcard))
    return (a & ~w & 0xFFFFFFFF) == (n & ~w & 0xFFFFFFFF)


def port_in_spec(port: int | None, spec: str) -> bool | None:
    """Match against a PAN/SCM style port spec: "80,443,8000-8080". None = can't tell."""
    if port is None:
        return None
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            if lo.strip().isdigit() and hi.strip().isdigit() and int(lo) <= port <= int(hi):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def ip_in_range(ip: str, start: str, end: str) -> bool:
    a = ipaddress.ip_address(ip)
    return ipaddress.ip_address(start) <= a <= ipaddress.ip_address(end)
