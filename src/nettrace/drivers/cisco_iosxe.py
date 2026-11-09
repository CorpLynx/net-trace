"""Cisco IOS-XE over SSH (Netmiko), "show" commands only."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any

from nettrace import audit
from nettrace.credentials import env_value
from nettrace.drivers.cisco_acl import AclResult, evaluate_acl
from nettrace.drivers.ntc import ntc_parse
from nettrace.errors import Deadline, DeviceError, ReadOnlyViolation
from nettrace.inventory import Device
from nettrace.models import Evidence, Flow, Hop, Outcome, Status, truncate
from nettrace.readonly import check_cisco_command, safe_token
from nettrace.steps import DeviceAt, Egress, StepResult


# ---- parsers for specific-lookup commands (no ntc template exists) ---------------
@dataclass
class CefEntry:
    kind: str  # nexthop | attached | receive | drop
    next_hop: str | None = None
    interface: str | None = None


@dataclass
class CefResult:
    prefix: str | None
    entries: list[CefEntry] = field(default_factory=list)


_PREFIX_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+/\d+)", re.M)
_NH_RE = re.compile(r"^\s+nexthop\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", re.M)
_ATTACHED_RE = re.compile(r"^\s+attached to\s+(\S+)", re.M)
_RECEIVE_RE = re.compile(r"^\s+receive(?:\s+for\s+(\S+))?", re.M)
_DROP_RE = re.compile(r"^\s+(drop|discard|no route|unresolved|null0)\b", re.M | re.I)


def parse_cef(output: str) -> CefResult:
    m = _PREFIX_RE.search(output)
    result = CefResult(prefix=m.group(1) if m else None)
    for nh, intf in _NH_RE.findall(output):
        result.entries.append(CefEntry("nexthop", nh, intf))
    for intf in _ATTACHED_RE.findall(output):
        result.entries.append(CefEntry("attached", None, intf))
    for intf in _RECEIVE_RE.findall(output):
        result.entries.append(CefEntry("receive", None, intf or None))
    if not result.entries and _DROP_RE.search(output):
        result.entries.append(CefEntry("drop"))
    for e in result.entries:
        if e.interface and e.interface.lower().startswith("null"):
            e.kind = "drop"
    return result


def parse_route_source(output: str) -> tuple[str | None, str | None]:
    """'show ip route <ip>' -> (prefix, 'bgp 65001' / 'connected' / ...)."""
    prefix = re.search(r"Routing entry for (\S+)", output)
    known = re.search(r'Known via "([^"]+)"', output)
    return (prefix.group(1) if prefix else None, known.group(1) if known else None)


# ---- client ----------------------------------------------------------------------
AUTH_COOLDOWN = 300  # seconds to refuse new logins to a device after an authentication failure
EVIDENCE_CHARS = 4000


class CiscoClient:
    # device name -> monotonic time of the last auth failure. Shared by all clients (trace and console)
    # so a wrong shared password cannot lock the account on every retry.
    _auth_failed: dict[str, float] = {}

    def __init__(self, device: Device):
        self.device = device
        self._conn: Any = None
        self._cache: dict[str, str] = {}
        self.evidence: list[Evidence] = []

    # Simulation seam (demo lab, tests): factory(device) -> object with send_command()/disconnect().
    connection_override: Any = None
    deadline: Deadline | None = None  # overall trace budget, set by the engine

    def _connect(self) -> Any:
        if self._conn is None and CiscoClient.connection_override is not None:
            self._conn = CiscoClient.connection_override(self.device)
        if self._conn is None:
            from netmiko import ConnectHandler  # imported lazily: slow import
            from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
            from paramiko.ssh_exception import SSHException

            wait = CiscoClient._auth_failed.get(self.device.name, 0) + AUTH_COOLDOWN - time.monotonic()
            if wait > 0:
                raise DeviceError(f"{self.device.name}: authentication failed earlier; not retrying for another "
                                  f"{int(wait)}s (5 minute cooldown to avoid locking the account)")
            params = {
                "device_type": "cisco_xe",
                "host": self.device.host,
                "username": env_value(self.device.username_env, what=f"{self.device.name} username"),
                "password": env_value(self.device.password_env, what=f"{self.device.name} password"),
                "port": self.device.port or 22,
                "conn_timeout": 15,
                "ssh_strict": self.device.ssh_strict,
                "system_host_keys": True,
            }
            secret = env_value(self.device.secret_env, required=False)
            if secret:
                params["secret"] = secret
            try:
                self._conn = ConnectHandler(**params)
                # Netmiko sends these itself during login, outside check_cisco_command; session settings only.
                for prep in ("terminal length 0", "terminal width 511"):
                    audit.log("ssh", self.device.name, prep, "ok")
                if secret:
                    self._conn.enable()  # privilege level only; never enters config mode
                    audit.log("ssh", self.device.name, "enable", "ok")
            except (NetmikoAuthenticationException, NetmikoTimeoutException) as exc:
                if isinstance(exc, NetmikoAuthenticationException):
                    CiscoClient._auth_failed[self.device.name] = time.monotonic()
                raise DeviceError(f"{self.device.name}: SSH failed: {exc}") from None
            except SSHException as exc:  # host key checks (ssh_strict) surface here, not as Netmiko errors
                raise DeviceError(self._ssh_error(exc)) from None
        return self._conn

    def _ssh_error(self, exc: Exception) -> str:
        from paramiko.ssh_exception import BadHostKeyException

        name = self.device.name
        if isinstance(exc, BadHostKeyException):
            return (f"{name}: host key for {self.device.host} CHANGED since it was saved in known_hosts: possible "
                    "spoofing (man-in-the-middle) or a replaced device. Do not connect until the new fingerprint "
                    "is verified out of band; do not set ssh_strict: false")
        if "known_hosts" in str(exc):
            return (f"{name}: host key for {self.device.host} not in known_hosts: ssh once to verify the "
                    "fingerprint; do not set ssh_strict: false")
        return f"{name}: SSH failed: {exc}"

    def show(self, command: str) -> str:
        try:
            check_cisco_command(command)
        except ReadOnlyViolation as exc:
            audit.refused(exc, "ssh", self.device.name, command)
            raise
        if command not in self._cache:
            if self.deadline:
                self.deadline.check()
            try:
                out = self._connect().send_command(command, read_timeout=60)
            except Exception:
                audit.log("ssh", self.device.name, command, "error")
                raise
            audit.log("ssh", self.device.name, command, "ok")
            if re.search(r"^% (?!Network not in table)|--More--", out, re.M):  # any IOS error line
                raise DeviceError(f"{self.device.name}: '{command}' rejected: {out.strip().splitlines()[0]}")
            self._cache[command] = out
            self.evidence.append(Evidence(self.device.name, command, truncate(out.strip(), EVIDENCE_CHARS)))
        return self._cache[command]

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            finally:
                self._conn = None

    # ---- typed helpers ---------------------------------------------------------
    @staticmethod
    def _vrf(vrf: str | None) -> str:
        return f"vrf {safe_token(vrf, 'vrf')} " if vrf and vrf not in ("default", "global") else ""

    def cef(self, ip: str, vrf: str | None) -> CefResult:
        ipaddress.ip_address(ip)
        result = parse_cef(self.show(f"show ip cef {self._vrf(vrf)}{ip}"))
        if result.prefix is None and not result.entries:  # a real "no route" reply still names a prefix or says so
            raise DeviceError(f"{self.device.name}: 'show ip cef {ip}' returned output nettrace could not parse")
        return result

    def route(self, ip: str, vrf: str | None) -> tuple[str | None, str | None]:
        ipaddress.ip_address(ip)
        return parse_route_source(self.show(f"show ip route {self._vrf(vrf)}{ip}"))

    def interfaces_brief(self) -> list[dict[str, Any]]:
        return ntc_parse("show ip interface brief", self.show("show ip interface brief"))

    def interface(self, name: str) -> dict[str, Any]:
        out = self.show(f"show ip interface {safe_token(name, 'interface')}")
        rows = ntc_parse("show ip interface", out)
        if not rows:
            raise DeviceError(f"{self.device.name}: no data for interface {name}")
        return rows[0]

    def policy_route_map(self, name: str) -> str | None:
        """Route-map applied as policy routing (PBR) on the interface, from the raw `show ip interface`
        ("Policy routing is enabled, using route-map X"); the ntc template drops that line."""
        out = self.show(f"show ip interface {safe_token(name, 'interface')}")
        m = re.search(r"^\s*Policy routing is enabled(?:, using route-map\s+(\S+))?", out, re.M | re.I)
        return (m.group(1) or "(unnamed)") if m else None

    def interface_for_ip(self, ip: str) -> str | None:
        for row in self.interfaces_brief():
            if row.get("IP_ADDRESS") == ip:
                return row.get("INTERFACE")
        return None

    def arp(self, ip: str, vrf: str | None) -> dict[str, Any] | None:
        ipaddress.ip_address(ip)
        rows = ntc_parse("show ip arp", self.show(f"show ip arp {self._vrf(vrf)}{ip}"))
        return rows[0] if rows else None

    def acl(self, name: str, flow: Flow) -> AclResult:
        out = self.show(f"show ip access-lists {safe_token(name, 'ACL name')}")
        return evaluate_acl(name, out, flow)


def _acl_name(value: str | None) -> str | None:
    if not value or value.strip().lower() in ("not set", ""):
        return None
    return value.strip()


# ---- hop evaluation ---------------------------------------------------------------
def step(client: CiscoClient, at: DeviceAt, flow: Flow) -> StepResult:
    dev = client.device
    start_evidence = len(client.evidence)
    details: list[str] = []
    warnings: list[str] = []
    vrf = at.vrf or dev.vrf

    def hop(status: Status, summary: str, **kw: Any) -> Hop:
        return Hop(domain="cisco", node=dev.name, component="router", status=status, summary=summary,
                   details=details, evidence=client.evidence[start_evidence:],
                   location={"vrf": vrf} if vrf else {}, **kw)

    # 1. ingress interface
    ingress = at.arrival_interface
    inferred = False
    if not ingress and at.arrival_ip:
        ingress = client.interface_for_ip(at.arrival_ip)
    if not ingress:
        src_cef = client.cef(flow.src, vrf)
        first = next((e for e in src_cef.entries if e.interface), None)
        ingress = first.interface if first else None
        if ingress:
            inferred = True
            details.append(f"ingress {ingress} inferred from route back to {flow.src}")
            warnings.append(f"{dev.name}: ingress {ingress} inferred from the route back to {flow.src}; "
                            "with asymmetric routing or ECMP the real ingress (and its ACL) may differ")

    if not ingress:
        # Without the ingress interface the inbound ACL can't be read: don't skip it silently.
        return StepResult([hop(Status.UNKNOWN, f"ingress interface for {flow.src} unknown; inbound ACL not evaluated")],
                          flow, outcome=Outcome.INCOMPLETE, reason=f"{dev.name}: ingress interface unknown")
    in_info = client.interface(ingress)
    if in_info.get("VRF") and not at.vrf:
        vrf = in_info["VRF"]

    # 2. inbound ACL
    acl_results: list[tuple[str, AclResult]] = []
    in_acl = _acl_name(in_info.get("INBOUND_ACL"))
    if in_acl:
        res = client.acl(in_acl, flow)
        acl_results.append(("in", res))
        if res.action == "deny":
            return StepResult([hop(Status.BLOCK if res.certain else Status.UNKNOWN,
                                   f"inbound ACL {in_acl} denies ({res.line})", ingress=ingress,
                                   policy=f"{in_acl} in: {res.line}")],
                              flow, outcome=Outcome.BLOCKED if res.certain else Outcome.INCOMPLETE,
                              reason=f"{dev.name}: ACL {in_acl} inbound on {ingress} denies the flow")

    # 3. policy routing: route-map clauses are not evaluated, so the routing-table result below is only a candidate
    pbr = client.policy_route_map(ingress)
    if pbr:
        details.append(f"policy routing (route-map {pbr}) is applied on {ingress}: it may override the routing "
                       "table; the route-map is not evaluated")
        warnings.append(f"{dev.name}: policy routing on {ingress} (route-map {pbr}) not evaluated")
    deny = (Status.UNKNOWN, Outcome.INCOMPLETE) if pbr else (Status.BLOCK, Outcome.BLOCKED)  # PBR may rescue it

    # 4. forwarding lookup
    cef = client.cef(flow.dst, vrf)
    prefix, source = client.route(flow.dst, vrf)
    route_txt = f"{cef.prefix or prefix or '?'}" + (f" [{source}]" if source else "")
    if vrf:
        route_txt = f"vrf {vrf}: {route_txt}"

    if not cef.entries:
        return StepResult([hop(deny[0], f"no route to {flow.dst} ({route_txt})", ingress=ingress)], flow,
                          outcome=deny[1], reason=f"{dev.name}: no route to {flow.dst}")
    first = cef.entries[0]
    if first.kind == "drop":
        return StepResult([hop(deny[0], f"route {route_txt} drops traffic (Null0/discard)", ingress=ingress)],
                          flow, outcome=deny[1], reason=f"{dev.name}: route to {flow.dst} is a discard route")
    if first.kind == "receive":
        return StepResult([hop(Status.WARN if pbr else Status.PASS, f"{flow.dst} is an address on this router",
                               ingress=ingress)], flow,
                          outcome=Outcome.REACHABLE, reason=f"destination is {dev.name} itself")
    ecmp = [e for e in cef.entries if e.kind == "nexthop"]
    if len(ecmp) > 1:
        alts = ", ".join(f"{e.next_hop} {e.interface}" for e in ecmp)
        details.append(f"ECMP: {len(ecmp)} equal-cost next hops ({alts}); the real path depends on the flow hash. "
                       f"Following the first ({ecmp[0].next_hop} {ecmp[0].interface}) only")
        warnings.append(f"{dev.name}: ECMP to {flow.dst} via {alts}; only the first path was traced")

    egress = first.interface
    out_info = client.interface(egress) if egress else {}
    out_acl = _acl_name(out_info.get("OUTGOING_ACL"))
    if out_acl:
        res = client.acl(out_acl, flow)
        acl_results.append(("out", res))
        if res.action == "deny":
            return StepResult([hop(Status.BLOCK if res.certain else Status.UNKNOWN,
                                   f"outbound ACL {out_acl} denies ({res.line})", ingress=ingress, egress=egress,
                                   policy=f"{out_acl} out: {res.line}")],
                              flow, outcome=Outcome.BLOCKED if res.certain else Outcome.INCOMPLETE,
                              reason=f"{dev.name}: ACL {out_acl} outbound on {egress} denies the flow")

    policy = "; ".join(f"{r.name} {d}: {r.line}" for d, r in acl_results) or "no interface ACLs"
    status = Status.WARN if pbr or len(ecmp) > 1 or inferred else Status.PASS
    for d, r in acl_results:
        if not r.exists:
            details.append(f"ACL {r.name} ({d}) is referenced but not defined; IOS permits all")
        if r.uncertain:
            status = Status.WARN
            details.append(f"ACL {r.name} ({d}): could not evaluate entries {', '.join(r.uncertain)}")

    if first.kind == "attached":
        arp = client.arp(flow.dst, vrf)
        if arp:
            details.append(f"ARP {flow.dst} -> {arp.get('MAC_ADDRESS')} on {arp.get('INTERFACE') or egress}")
        else:
            details.append(f"no ARP entry for {flow.dst} on {egress}")
            status = Status.WARN if status == Status.PASS else status
            warnings.append(f"{dev.name}: {flow.dst} is on a connected subnet but has no ARP entry")
        summary = f"{route_txt} connected via {egress}"
    else:
        summary = f"{route_txt} via {first.next_hop} {egress}"

    return StepResult(
        [hop(status, summary, ingress=ingress, egress=egress, policy=policy)],
        flow,
        egress=Egress(device=dev.name, interface=egress, next_hop=first.next_hop, vrf=vrf),
        warnings=warnings,
    )


def discover_addresses(client: CiscoClient) -> dict[str, str]:
    """{ip: interface} for every interface with an address."""
    out = {}
    for row in client.interfaces_brief():
        ip = row.get("IP_ADDRESS", "")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        out[ip] = row.get("INTERFACE", "")
    return out
