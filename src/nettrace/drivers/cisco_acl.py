"""Evaluate a flow against IOS / IOS-XE "show ip access-lists <name>" output.

Parsing uses the ntc-templates TextFSM template; this module adds first-match
evaluation and reports anything it could not evaluate instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from nettrace.drivers.ntc import ntc_parse
from nettrace.models import Flow
from nettrace.netutil import cisco_port, protocol_number, wildcard_match

_ACE_LINE = re.compile(r"^\s+(\d+)\s+(?:permit|deny)\b.*?(?=\s*\(\d+ match(?:es)?\)|\s*$)", re.M)


@dataclass
class AclResult:
    name: str
    action: str  # permit | deny
    line: str  # matching sequence number or "implicit deny"
    exists: bool = True
    uncertain: list[str] = field(default_factory=list)  # entries above the match we could not evaluate

    @property
    def certain(self) -> bool:
        return not self.uncertain


def _addr_match(ip: str, any_: str, host: str, net: str, wc: str, group: str) -> bool | None:
    if any_:
        return True
    if host:
        return ip == host
    if net:
        return wildcard_match(ip, net, wc or "0.0.0.0")
    if group:
        return None  # object-group: contents not fetched
    return None


def _port_match(port: int | None, op: str, value: str, start: str, end: str) -> bool | None:
    if not op:
        return True
    if op in ("precedence", "tos"):
        return None
    if port is None:
        return None
    if op == "range":
        lo, hi = cisco_port(start), cisco_port(end)
        if lo is None or hi is None:
            return None
        return lo <= port <= hi
    values = [cisco_port(v) for v in value.split()]
    if not values or any(v is None for v in values):
        return None
    if op == "eq":
        return port in values
    if op == "neq":
        return port not in values
    if op == "lt":
        return port < values[0]
    if op == "gt":
        return port > values[0]
    return None


def _proto_match(flow_proto: int, ace_proto: str, service_group: str) -> bool | None:
    if service_group and not ace_proto:
        return None
    p = (ace_proto or "").lower()
    if p == "ip":
        return True
    if p == "object-group":
        return None
    try:
        return protocol_number(p) == flow_proto
    except ValueError:
        return None


def _entry_match(rec: dict[str, Any], flow: Flow) -> bool | None:
    proto = protocol_number(flow.protocol)
    if rec.get("STATE") == "inactive":
        return False
    if rec["ACL_TYPE"] == "Standard":
        return _addr_match(flow.src, rec["SRC_ANY"], rec["SRC_HOST"], rec["SRC_NETWORK"], rec["SRC_WILDCARD"], "")

    results = [
        _proto_match(proto, rec["PROTOCOL"], rec["SERVICE_OBJECT_GROUP_NAME"]),
        _addr_match(flow.src, rec["SRC_ANY"], rec["SRC_HOST"], rec["SRC_NETWORK"], rec["SRC_WILDCARD"],
                    rec["SRC_NETWORK_OBJECT_GROUP_NAME"]),
        _addr_match(flow.dst, rec["DST_ANY"], rec["DST_HOST"], rec["DST_NETWORK"], rec["DST_WILDCARD"],
                    rec["DST_NETWORK_OBJECT_GROUP_NAME"]),
    ]
    if proto in (6, 17):
        results.append(_port_match(flow.src_port, rec["SRC_PORT_MATCH"], rec["SRC_PORT"],
                                   rec["SRC_PORT_RANGE_START"], rec["SRC_PORT_RANGE_END"]))
        results.append(_port_match(flow.dst_port, rec["DST_PORT_MATCH"], rec["DST_PORT"],
                                   rec["DST_PORT_RANGE_START"], rec["DST_PORT_RANGE_END"]))
    flags = (rec.get("TCP_FLAG") or "").split()
    if "established" in flags or "+ack" in flags or "ack" in flags or "rst" in flags:
        # The first packet of a new TCP flow (SYN) never matches these.
        results.append(False)
    elif flags:
        results.append(None)
    icmp_type = rec.get("ICMP_TYPE")
    if icmp_type and proto == 1:
        results.append(icmp_type == "echo")  # nettrace models ICMP as echo-request

    if any(r is False for r in results):
        return False
    if any(r is None for r in results):
        return None
    return True


def evaluate_acl(name: str, output: str, flow: Flow) -> AclResult:
    records = [r for r in ntc_parse("show ip access-lists", output) if r.get("LINE_NUM")]
    raw_lines = {m.group(1): " ".join(m.group(0).split()) for m in _ACE_LINE.finditer(output)}
    if not raw_lines and not records:
        # IOS permits all traffic when an interface references an ACL that doesn't exist.
        return AclResult(name=name, action="permit", line="ACL not defined (IOS permits all)", exists=False)

    parsed_seqs = {r["LINE_NUM"] for r in records}
    unparsed = [seq for seq in raw_lines if seq not in parsed_seqs]
    uncertain: list[str] = []
    order = sorted(set(parsed_seqs) | set(unparsed), key=int)
    by_seq = {r["LINE_NUM"]: r for r in records}
    for seq in order:
        rec = by_seq.get(seq)
        if rec is None:
            uncertain.append(f"{seq} (could not parse: {raw_lines[seq]})")
            continue
        verdict = _entry_match(rec, flow)
        if verdict is None:
            uncertain.append(f"{seq} ({raw_lines.get(seq, rec['ACTION'])})")
        elif verdict:
            return AclResult(name=name, action=rec["ACTION"], line=raw_lines.get(seq, seq), uncertain=uncertain)
    return AclResult(name=name, action="deny", line="implicit deny", uncertain=uncertain)
