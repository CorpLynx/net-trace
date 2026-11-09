"""Positions the engine moves between, and what each driver step returns."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

from nettrace.models import Flow, Hop, Outcome


@dataclass(frozen=True)
class DeviceAt:
    """Traffic is arriving at an inventory device (Cisco or PAN-OS)."""

    device: str
    arrival_ip: str | None = None  # the device address the previous hop sent to
    arrival_interface: str | None = None
    vrf: str | None = None
    gwlb_endpoint: str | None = None  # set when a PAN-OS VM sits behind an AWS GWLB
    resume: AwsAt | None = None  # where to continue in AWS after an inline (GWLB) firewall


@dataclass(frozen=True)
class AwsAt:
    """Traffic is at a point inside AWS."""

    kind: str  # source_eni | tgw_attachment | vgw | subnet | appliance_egress
    account: str | None = None  # account id
    region: str | None = None
    resource_id: str | None = None  # eni / tgw-attach / vgw / subnet id
    ip: str | None = None  # appliance egress interface IP
    note: str | None = None


@dataclass(frozen=True)
class PrismaAt:
    entry: str  # source | service_connection
    name: str | None = None


Position = Union[DeviceAt, AwsAt, PrismaAt]


@dataclass
class Egress:
    """A device forwarded the flow out of an interface; the engine decides where it goes next."""

    device: str
    interface: str | None
    next_hop: str | None  # None when the destination is directly connected
    vrf: str | None = None


@dataclass
class StepResult:
    hops: list[Hop]
    flow: Flow
    next: Position | None = None
    egress: Egress | None = None
    outcome: Outcome | None = None
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
