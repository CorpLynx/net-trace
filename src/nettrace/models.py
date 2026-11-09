"""Data model shared by the engine, drivers and output renderers."""

from __future__ import annotations

import dataclasses
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nettrace.netutil import protocol_name


class Status(str, Enum):
    PASS = "PASS"  # component forwards / permits the flow
    BLOCK = "BLOCK"  # component drops / denies the flow
    WARN = "WARN"  # forwards, but something looks wrong (e.g. return path)
    UNKNOWN = "UNKNOWN"  # could not determine
    INFO = "INFO"  # informational step (lookup, NAT, handoff)


class Outcome(str, Enum):
    REACHABLE = "REACHABLE"
    BLOCKED = "BLOCKED"
    EXITED = "EXITED"  # left the networks nettrace knows about (internet, unmanaged next hop)
    INCOMPLETE = "INCOMPLETE"  # could not finish the trace


@dataclass
class Flow:
    src: str
    dst: str
    protocol: str = "tcp"  # tcp | udp | icmp | <number>
    dst_port: int | None = None
    src_port: int | None = None
    application: str | None = None
    user: str | None = None

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.src)
        ipaddress.ip_address(self.dst)

    @property
    def src_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(self.src)

    @property
    def dst_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(self.dst)

    def with_changes(self, **kwargs: Any) -> Flow:
        return dataclasses.replace(self, **kwargs)

    def describe(self) -> str:
        proto = protocol_name(self.protocol)
        port = f":{self.dst_port}" if self.dst_port else ""
        return f"{self.src} -> {self.dst}{port} ({proto})"


MAX_TEXT = 256 * 1024  # hard cap on any stored device output (console output, Evidence)


def truncate(text: str, limit: int = MAX_TEXT) -> str:
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


@dataclass
class Evidence:
    """A read-only request that was sent and the relevant part of its answer."""

    source: str  # device / account that answered
    request: str  # command, API call or XML
    response: str = ""

    def __post_init__(self) -> None:
        self.response = truncate(self.response)


@dataclass
class Hop:
    domain: str  # cisco | panos | prisma | aws | engine
    node: str  # device name or AWS resource id
    component: str  # router, firewall, security-group, nacl, route-table, tgw-route-table, ...
    status: Status
    summary: str
    ingress: str | None = None
    egress: str | None = None
    policy: str | None = None
    nat: str | None = None
    details: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    index: int = 0
    # Where the hop is, for grouping on the map. Keys used: site (on-prem / Prisma), cloud, account,
    # account_name, region, vpc, vrf, zone_from, zone_to, serial, device_group. All optional.
    location: dict[str, str] = field(default_factory=dict)


@dataclass
class TraceResult:
    flow: Flow
    outcome: Outcome
    reason: str
    hops: list[Hop] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    final_flow: Flow | None = None
    cancelled: bool = False  # the user cancelled; outcome is INCOMPLETE and hops are those found before that

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if dataclasses.is_dataclass(value):
                return {k: convert(v) for k, v in dataclasses.asdict(value).items()}
            if isinstance(value, list):
                return [convert(v) for v in value]
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items()}
            return value

        data = {
            "Flow": convert(self.flow),
            "Outcome": self.outcome.value,
            "Reason": self.reason,
            "Hops": [convert(h) for h in self.hops],
            "Warnings": list(self.warnings),
        }
        if self.cancelled:
            data["Cancelled"] = True
        if self.final_flow and self.final_flow != self.flow:
            data["FinalFlow"] = convert(self.final_flow)
        return data
