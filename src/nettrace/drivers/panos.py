"""PAN-OS firewalls (on-prem and VM-Series on EC2) via the XML API.

The firewall answers for itself: route lookup with `test routing fib-lookup`,
NAT with `test nat-policy-match` and policy with `test security-policy-match`.
Firewalls are reached directly or through Panorama (`target=<serial>`, PAN-OS
"Query a Firewall from Panorama"). Only <show>/<test> op commands and config
get/show requests are sent.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

import requests
from defusedxml import ElementTree as SafeET

from nettrace import audit
from nettrace.credentials import env_value
from nettrace.errors import Deadline, DeviceError, NetTraceError, ReadOnlyViolation
from nettrace.inventory import Device, PanoramaConfig
from nettrace.models import Evidence, Flow, Hop, Outcome, Status
from nettrace.netutil import protocol_number, uses_ports
from nettrace.readonly import check_panos_request
from nettrace.steps import DeviceAt, Egress, StepResult

log = logging.getLogger("nettrace")

ALLOW_ACTIONS = {"allow"}


_TAG = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")


def build_op(path: list[str], fields: dict[str, Any] | None = None) -> str:
    """Build an op command like <test><routing><fib-lookup><ip>..</ip></fib-lookup></routing></test>.

    Values are escaped by ElementTree, so device data can't inject XML.
    """
    for tag in (*path, *(fields or {})):
        if not _TAG.fullmatch(tag):
            raise DeviceError(f"invalid XML tag name {tag!r}")
    root = ET.Element(path[0])
    node = root
    for tag in path[1:]:
        node = ET.SubElement(node, tag)
    for key, value in (fields or {}).items():
        if value is None:
            continue
        ET.SubElement(node, key).text = str(value)
    return ET.tostring(root, encoding="unicode")


def _quote_xpath(value: str) -> str:
    if "'" in value:
        raise DeviceError(f"unsupported character in name {value!r}")
    return f"'{value}'"


@dataclass
class FibResult:
    interface: str | None
    next_hop: str | None  # None = directly connected
    source: str | None = None


@dataclass
class Unavailable:
    """A config query the device could not answer (error, timeout). Distinct from None = 'not configured'."""
    reason: str


@dataclass
class PolicyMatch:
    rule: str | None
    action: str | None


class XmlApi:
    """One PAN-OS XML API endpoint (a firewall or a Panorama). Every request passes the read-only check."""

    session_override: Any = None
    deadline: Deadline | None = None  # overall trace budget, set by the engine

    def __init__(self, label: str, hosts: list[str], port: int | None, key_env: str | None,
                 verify_tls: bool | str, timeout: int = 30, panorama: bool = False):
        self.label = label
        self.panorama = panorama
        self.urls = [f"https://{h}{':' + str(port) if port else ''}/api/" for h in hosts]
        self.key_env = key_env
        self.timeout = timeout
        # Simulation seam (demo lab, tests): factory(XmlApi) -> object with .post(url, data, headers, timeout, allow_redirects).
        self.session = XmlApi.session_override(self) if XmlApi.session_override else requests.Session()
        self.session.verify = verify_tls
        if verify_tls is False:
            log.warning("TLS certificate verification is DISABLED for %s: the API key is sent to %s without "
                        "checking the server identity. Set verify_tls to true or a CA bundle path.",
                        label, ", ".join(hosts))
        self._cache: dict[str, Any] = {}
        self.evidence: list[Evidence] = []

    def request(self, params: dict[str, str], label: str, source: str | None = None) -> Any:
        who = source or self.label
        what = params.get("cmd") or f"config {params.get('action')} {params.get('xpath')}"
        if "target" in params:
            what += f" [target={params['target']}]"
        try:
            check_panos_request(params, panorama=self.panorama)
        except ReadOnlyViolation as exc:
            audit.refused(exc, "panos", who, what)
            raise
        cache_key = repr(sorted(params.items()))
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            root = self._post(params, label, source)
        except Exception:
            audit.log("panos", who, what, "error")
            raise
        audit.log("panos", who, what, "ok")
        self._cache[cache_key] = root
        return root

    def _post(self, params: dict[str, str], label: str, source: str | None) -> Any:
        key = env_value(self.key_env, what=f"{self.label} API key")
        resp = None
        errors = []
        for url in self.urls:  # second URL = Panorama HA peer
            for _attempt in (1, 2):  # one retry on a timeout; safe because check_panos_request allows reads only
                if self.deadline:
                    self.deadline.check()
                try:
                    # No redirects: the X-PAN-KEY header would follow a 307/308 to another host.
                    resp = self.session.post(url, data=params, headers={"X-PAN-KEY": key}, timeout=self.timeout,
                                             allow_redirects=False)
                    break
                except requests.RequestException as exc:
                    errors.append(f"{url}: {exc}")
                    if not isinstance(exc, requests.Timeout):
                        break
            if resp is not None:
                break
        if resp is None:
            raise DeviceError(f"{self.label}: API request failed: {'; '.join(errors)}")
        if 300 <= resp.status_code < 400:
            raise DeviceError(f"{self.label}: refusing HTTP {resp.status_code} redirect (the API key is not sent elsewhere)")
        if resp.status_code in (401, 403):
            raise DeviceError(f"{self.label}: API key rejected (HTTP {resp.status_code})")
        try:
            root = SafeET.fromstring(resp.content)
        except Exception:
            raise DeviceError(f"{self.label}: non-XML response (HTTP {resp.status_code})") from None
        text = ET.tostring(root, encoding="unicode")
        self.evidence.append(Evidence(source or self.label, label, text[:4000]))
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())
            raise DeviceError(f"{source or self.label}: {label} failed: {msg[:300]}")
        return root


def direct_api(device: Device) -> XmlApi:
    return XmlApi(device.name, [device.host or ""], device.port, device.api_key_env, device.verify_tls)


class PanosClient:
    """A firewall, reached directly or through Panorama (`target=<serial>`).

    `notes` collects context (Panorama target, HA redirection, device group) that step() adds to the hop.
    """

    def __init__(self, device: Device, api: XmlApi | None = None, *, target: str | None = None,
                 panorama: PanoramaClient | None = None, notes: list[str] | None = None,
                 meta: dict[str, str] | None = None):
        self.device = device
        self.api = api or direct_api(device)
        self.target = target
        self.panorama = panorama
        self.notes = list(notes or [])
        self.meta = dict(meta or {})  # serial / device_group, shown on the map

    @property
    def evidence(self) -> list[Evidence]:
        return self.api.evidence

    def request(self, params: dict[str, str], label: str) -> Any:
        if self.device.vsys:
            params = {**params, "vsys": self.device.vsys}
        if self.target:
            params = {**params, "target": self.target}
            label = f"{label}  [via Panorama, target={self.target}]"
        return self.api.request(params, label, source=self.device.name)

    def op(self, path: list[str], fields: dict[str, Any] | None = None) -> Any:
        cmd = build_op(path, fields)
        return self.request({"type": "op", "cmd": cmd}, cmd)

    def config_get(self, xpath: str, action: str = "get") -> Any | None | Unavailable:
        """The config result; None = not configured there; Unavailable = the device could not answer
        (callers must not treat that as 'not found')."""
        try:
            root = self.request({"type": "config", "action": action, "xpath": xpath}, f"config {action} {xpath}")
        except DeviceError as exc:
            return Unavailable(str(exc))
        return _non_empty_result(root)

    # ---- typed helpers ---------------------------------------------------------
    def system_info(self) -> dict[str, str]:
        root = self.op(["show", "system", "info"])
        sysinfo = root.find("result/system")
        return {c.tag: (c.text or "") for c in sysinfo} if sysinfo is not None else {}

    def interfaces(self) -> dict[str, dict[str, str]]:
        """{interface: {zone, fwd, ip, vsys}} from `show interface all`."""
        cmd = "<show><interface>all</interface></show>"
        root = self.request({"type": "op", "cmd": cmd}, cmd)
        out: dict[str, dict[str, str]] = {}
        for entry in root.findall("result/ifnet/entry"):
            name = entry.findtext("name")
            if not name:
                continue
            out[name] = {
                "zone": entry.findtext("zone") or "",
                "fwd": entry.findtext("fwd") or "",
                "ip": entry.findtext("ip") or "",
                "vsys": entry.findtext("vsys") or "",
            }
        return out

    def interface_for_ip(self, ip: str) -> str | None:
        for name, info in self.interfaces().items():
            if info["ip"].split("/")[0] == ip:
                return name
        return None

    def fib_lookup(self, router: str, ip: str) -> FibResult | None:
        """None = confirmed no route (empty result or a discard route). Any other unexpected reply raises."""
        ipaddress.ip_address(ip)
        if self.device.routing_engine == "advanced":
            root = self.op(["test", "advanced-routing", "fib-lookup"], {"logical-router": router, "ip": ip})
        else:
            root = self.op(["test", "routing", "fib-lookup"], {"virtual-router": router, "ip": ip})
        result = root.find("result")
        if result is None:
            raise DeviceError(f"{self.device.name}: fib-lookup for {ip} returned no <result>; reply not understood")
        if len(result) == 0 and not (result.text or "").strip():
            return None  # empty result: the only shape treated as "no route"
        nh_type = (result.findtext("nh") or "").strip()
        if nh_type == "discard":
            return None
        interface = result.findtext("interface")
        if not interface or nh_type not in ("ip", "0", ""):
            raise DeviceError(f"{self.device.name}: fib-lookup for {ip} reply not understood "
                              f"(next-hop type {nh_type!r}, interface {interface!r})")
        nh_ip = (result.findtext("ip") or "").strip()
        next_hop = nh_ip if nh_type == "ip" and nh_ip and nh_ip not in ("0.0.0.0", ip) else None
        return FibResult(interface=interface, next_hop=next_hop, source=result.findtext("src"))

    def _match_fields(self, flow: Flow, from_zone: str | None, to_zone: str | None) -> dict[str, Any]:
        proto = protocol_number(flow.protocol)
        return {
            "from": from_zone,
            "to": to_zone,
            "source": flow.src,
            "destination": flow.dst,
            "protocol": proto,
            "destination-port": flow.dst_port if uses_ports(proto) and flow.dst_port else None,
            "application": flow.application,
            "source-user": flow.user,
        }

    def security_match(self, flow: Flow, from_zone: str | None, to_zone: str | None) -> PolicyMatch:
        root = self.op(["test", "security-policy-match"], self._match_fields(flow, from_zone, to_zone))
        rule, action = parse_policy_match(root)
        if rule and not action:
            cfg = self.rule_config("security", rule)
            action = cfg.findtext(".//action") if cfg is not None else None
        return PolicyMatch(rule, action)

    def nat_match(self, flow: Flow, from_zone: str | None, to_zone: str | None) -> str | None:
        fields = self._match_fields(flow, from_zone, to_zone)
        fields.pop("application", None)
        fields.pop("source-user", None)
        root = self.op(["test", "nat-policy-match"], fields)
        rule, _ = parse_policy_match(root)
        return rule

    def _lookup(self, local_xpaths: list[str], pushed_xpaths: list[str], dg_suffixes: list[str]) -> Any | None:
        """Find a config entry: firewall local config, then Panorama-pushed config on the firewall
        (running config), then the Panorama device-group hierarchy and shared."""
        failures: list[str] = []

        def found(hit: Any) -> bool:
            if isinstance(hit, Unavailable):
                failures.append(hit.reason)
                return False
            return hit is not None

        for xp in local_xpaths:
            hit = self.config_get(xp)
            if found(hit):
                return _entry(hit)
        for xp in pushed_xpaths:
            for action in ("show", "get"):
                hit = self.config_get(xp, action=action)
                if found(hit):
                    return _entry(hit)
        if self.panorama and self.device.serial:
            try:
                xpaths = self.panorama.dg_chain_xpaths(self.device.serial, dg_suffixes)
            except NetTraceError as exc:
                failures.append(f"Panorama device-group lookup: {exc}")
                xpaths = []
            for xp in xpaths:
                hit = self.panorama.config_get(xp)
                if found(hit):
                    return _entry(hit)
        if failures:  # never guess: an unanswered query is not "not configured"
            more = f" (+{len(failures) - 1} more)" if len(failures) > 1 else ""
            raise DeviceError(f"{self.device.name}: config lookup incomplete, device could not answer: "
                              f"{failures[0]}{more}")
        return None

    def rule_config(self, rulebase: str, name: str) -> Any | None:
        vsys = _quote_xpath(self.device.vsys or "vsys1")[1:-1]
        q = _quote_xpath(name)
        return self._lookup(
            [f"{LOCAL_VSYS.format(vsys=vsys)}/rulebase/{rulebase}/rules/entry[@name={q}]"],
            [f"/config/panorama/vsys/entry[@name='{vsys}']/{pos}-rulebase/{rulebase}/rules/entry[@name={q}]"
             for pos in ("pre", "post")],
            [f"{pos}-rulebase/{rulebase}/rules/entry[@name={q}]" for pos in ("pre", "post")],
        )

    def address_value(self, name: str) -> str | None:
        """Resolve an address object to its first IP, or return the literal if it already is one."""
        literal = name.split("/")[0]
        try:
            ipaddress.ip_address(literal)
            return literal
        except ValueError:
            pass
        vsys = _quote_xpath(self.device.vsys or "vsys1")[1:-1]
        q = _quote_xpath(name)
        result = self._lookup(
            [f"{LOCAL_VSYS.format(vsys=vsys)}/address/entry[@name={q}]", f"/config/shared/address/entry[@name={q}]"],
            [f"/config/panorama/vsys/entry[@name='{vsys}']/address/entry[@name={q}]",
             f"/config/panorama/shared/address/entry[@name={q}]"],
            [f"address/entry[@name={q}]"],
        )
        if result is None:
            return None
        value = result.findtext(".//ip-netmask") or result.findtext(".//ip-range")
        return value.split("/")[0].split("-")[0] if value else None


LOCAL_VSYS = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
PANORAMA_DG = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name={dg}]"


def _non_empty_result(root: Any) -> Any | None:
    result = root.find("result")
    if result is None or len(result) == 0:
        return None
    return result


def _entry(result: Any) -> Any:
    found = result.find("entry")
    return found if found is not None else result


# ==== Panorama ======================================================================
@dataclass
class ManagedDevice:
    serial: str
    hostname: str
    ip: str
    model: str
    sw_version: str
    connected: bool
    ha_state: str | None  # active | passive | active-primary | ... | None (no HA)
    ha_peer: str | None
    device_group: str | None = None


class PanoramaClient:
    """Panorama itself. Used for device inventory, HA state, device-group lookups and as the proxy
    for firewall queries. Policy tests are never run on Panorama, only on a targeted firewall."""

    def __init__(self, cfg: PanoramaConfig):
        self.cfg = cfg
        hosts = [cfg.host] + ([cfg.peer_host] if cfg.peer_host else [])
        self.api = XmlApi("panorama", hosts, cfg.port, cfg.api_key_env, cfg.verify_tls, panorama=True)
        self._devices: dict[str, ManagedDevice] | None = None
        self._parents: dict[str, str | None] | None = None

    @property
    def evidence(self) -> list[Evidence]:
        return self.api.evidence

    def op(self, cmd: str) -> Any:
        return self.api.request({"type": "op", "cmd": cmd}, cmd)

    def config_get(self, xpath: str) -> Any | None | Unavailable:
        try:
            root = self.api.request({"type": "config", "action": "get", "xpath": xpath}, f"config get {xpath}")
        except DeviceError as exc:
            return Unavailable(f"Panorama: {exc}")
        return _non_empty_result(root)

    def system_info(self) -> dict[str, str]:
        sysinfo = self.op("<show><system><info></info></system></show>").find("result/system")
        return {c.tag: (c.text or "") for c in sysinfo} if sysinfo is not None else {}

    def devices(self) -> dict[str, ManagedDevice]:
        if self._devices is None:
            root = self.op("<show><devices><all></all></devices></show>")
            out = {}
            for e in root.findall("result/devices/entry"):
                serial = e.findtext("serial") or e.get("name")
                if not serial:
                    continue
                out[serial] = ManagedDevice(
                    serial=serial,
                    hostname=e.findtext("hostname") or "",
                    ip=e.findtext("ip-address") or "",
                    model=e.findtext("model") or "",
                    sw_version=e.findtext("sw-version") or "",
                    connected=(e.findtext("connected") or "").lower() == "yes",
                    ha_state=(e.findtext("ha/state") or "").strip().lower() or None,
                    ha_peer=(e.findtext("ha/peer/serial") or "").strip() or None,
                )
            try:
                groups = self.op("<show><devicegroups></devicegroups></show>")
                for dg in groups.findall("result/devicegroups/entry"):
                    for member in dg.findall("devices/entry"):
                        if member.get("name") in out:
                            out[member.get("name")].device_group = dg.get("name")
            except DeviceError:
                pass  # device-group context is optional
            self._devices = out
        return self._devices

    def dg_parents(self) -> dict[str, str | None]:
        if self._parents is None:
            ans: dict[str, str | None] = {}
            try:
                data = self.op("<show><dg-hierarchy></dg-hierarchy></show>").find("result/dg-hierarchy")
            except DeviceError:
                data = None
            if data is not None:
                nodes: list[tuple[str | None, Any]] = [(None, x) for x in data.findall("dg")]
                for parent, elm in nodes:
                    ans[elm.get("name")] = parent
                    nodes.extend((elm.get("name"), x) for x in elm.findall("dg"))
            self._parents = ans
        return self._parents

    def dg_chain_xpaths(self, serial: str, suffixes: list[str]) -> list[str]:
        """Xpaths for the firewall's device group, its ancestors, then Panorama shared."""
        dev = self.devices().get(serial)
        chain: list[str] = []
        dg = dev.device_group if dev else None
        parents = self.dg_parents() if dg else {}
        while dg and dg not in chain:
            chain.append(dg)
            dg = parents.get(dg)
        out = [f"{PANORAMA_DG.format(dg=_quote_xpath(g))}/{s}" for g in chain for s in suffixes]
        out += [f"/config/shared/{s}" for s in suffixes]
        return out

    def resolve_target(self, device: Device) -> tuple[str, list[str]]:
        """Serial to query for `device`, following HA to the active member. Returns (serial, notes)."""
        assert device.serial
        devs = self.devices()
        me = devs.get(device.serial)
        if me is None:
            raise DeviceError(f"{device.name}: serial {device.serial} is not managed by Panorama {self.cfg.host}")
        notes = [f"via Panorama {self.cfg.host}, target {device.serial} ({me.hostname or '?'})"]
        if me.device_group:
            notes.append(f"device group {me.device_group}")
        target = me
        state = me.ha_state or ""
        if state and not state.startswith("active"):
            peer = devs.get(me.ha_peer or "")
            if not self.cfg.follow_ha_active:
                notes.append(f"HA: {device.serial} is {state} and follow_ha_active is off; "
                             "answers come from a member that is not forwarding traffic")
            elif peer and peer.connected and (peer.ha_state or "").startswith("active"):
                notes.append(f"HA: {device.serial} is {state}; querying active peer {peer.serial} ({peer.hostname})")
                target = peer
            else:
                notes.append(f"HA: {device.serial} is {state} and no connected active peer was found")
        elif state.startswith("active") and me.ha_peer:
            notes.append(f"HA: {state} (peer {me.ha_peer})")
        if not target.connected:
            raise DeviceError(f"{device.name}: firewall {target.serial} is not connected to Panorama")
        return target.serial, notes


def make_client(device: Device, panorama: PanoramaClient | None) -> PanosClient:
    if device.via == "panorama":
        if panorama is None:
            raise DeviceError(f"{device.name}: via panorama but no panorama section in the inventory")
        serial, notes = panorama.resolve_target(device)
        managed = panorama.devices().get(serial)
        meta = {"serial": serial}
        if managed and managed.device_group:
            meta["device_group"] = managed.device_group
        return PanosClient(device, panorama.api, target=serial, panorama=panorama, notes=notes, meta=meta)
    return PanosClient(device, panorama=panorama if device.serial else None)


def parse_policy_match(root: Any) -> tuple[str | None, str | None]:
    """Handle the three response shapes PAN-OS versions return for *-policy-match."""
    entry = root.find("result/rules/entry")
    if entry is not None:
        name = entry.get("name") or (entry.text or "").strip()
        name = re.sub(r";\s*index:\s*\d+\s*$", "", name).strip() or None
        action = entry.findtext("action")
        return name, action.strip() if action else None
    line = root.findtext("result/msg/line")
    if line:
        m = re.search(r'"([^"]+?)(?:;\s*index:\s*\d+)?"', line)
        a = re.search(r"\baction\s+([\w-]+);", line)
        return (m.group(1) if m else None), (a.group(1) if a else None)
    return None, None


@dataclass
class NatResult:
    rule: str
    new_src: str | None = None
    new_dst: str | None = None
    new_port: int | None = None

    def describe(self) -> str:
        parts = []
        if self.new_src:
            parts.append(f"SNAT -> {self.new_src}")
        if self.new_dst:
            parts.append(f"DNAT -> {self.new_dst}" + (f":{self.new_port}" if self.new_port else ""))
        elif self.new_port:
            parts.append(f"port -> {self.new_port}")
        return f"{self.rule}: " + (", ".join(parts) if parts else "no translation")


def _nat_translation(client: PanosClient, rule: str, egress_if: str | None) -> NatResult:
    res = NatResult(rule=rule)
    cfg = client.rule_config("nat", rule)
    if cfg is None:
        raise DeviceError(f"{client.device.name}: NAT rule {rule} matched but its configuration could not be read; "
                          "translation unresolved")
    st = cfg.find("source-translation")
    if st is not None:
        iface_ip = st.findtext(".//interface-address/ip")
        iface = st.findtext(".//interface-address/interface")
        member = st.findtext(".//translated-address/member") or st.findtext(".//translated-address")
        if iface_ip:
            res.new_src = client.address_value(iface_ip)
        elif iface or st.find(".//interface-address") is not None:
            ifs = client.interfaces()
            ip = ifs.get(iface or egress_if or "", {}).get("ip", "")
            res.new_src = ip.split("/")[0] or None
        elif member:
            res.new_src = client.address_value(member.strip())
        if not res.new_src:
            raise DeviceError(f"{client.device.name}: NAT rule {rule} matched but the source translation is unresolved")
    for tag in ("destination-translation", "dynamic-destination-translation"):
        dt = cfg.find(tag)
        if dt is not None:
            addr = dt.findtext("translated-address")
            port = dt.findtext("translated-port")
            if addr:
                res.new_dst = client.address_value(addr.strip())
            if port and port.strip().isdigit():
                res.new_port = int(port)
            if not res.new_dst:
                raise DeviceError(f"{client.device.name}: NAT rule {rule} matched but the destination translation "
                                  "is unresolved")
    return res


def _router_for(client: PanosClient, ingress: str | None) -> str:
    if ingress:
        fwd = client.interfaces().get(ingress, {}).get("fwd", "")
        m = re.match(r"(?:vr|lr):(.+)", fwd)
        if m:
            return m.group(1)
    return client.device.virtual_router


def step(client: PanosClient, at: DeviceAt, flow: Flow) -> StepResult:
    dev = client.device
    start = len(client.evidence)
    details: list[str] = list(client.notes)

    def hop(status: Status, summary: str, **kw: Any) -> Hop:
        return Hop(domain="panos", node=dev.name, component="firewall", status=status, summary=summary,
                   details=details, evidence=client.evidence[start:], location=dict(loc), **kw)

    loc: dict[str, str] = dict(client.meta)  # zones are added once known

    # ---- inline mode: VM-Series behind an AWS Gateway Load Balancer -------------
    if at.gwlb_endpoint:
        zone = (dev.aws.gwlb_zone_map.get(at.gwlb_endpoint) if dev.aws else None) or (dev.aws.gwlb_zone if dev.aws else None)
        if not zone:
            return StepResult([hop(Status.UNKNOWN, f"GWLB endpoint {at.gwlb_endpoint}: no zone configured "
                                   "(set aws.gwlb_zone or aws.gwlb_zone_map in the inventory)")], flow,
                              outcome=Outcome.INCOMPLETE, reason=f"{dev.name}: GWLB zone unknown")
        loc.update(zone_from=zone, zone_to=zone)
        match = client.security_match(flow, zone, zone)
        return _policy_result(hop, match, flow, zone, zone, at.gwlb_endpoint, at.gwlb_endpoint,
                              next_pos=at.resume, details=details, dev=dev)

    # ---- routed mode --------------------------------------------------------------
    ifs = client.interfaces()
    ingress = at.arrival_interface or (client.interface_for_ip(at.arrival_ip) if at.arrival_ip else None)
    router = _router_for(client, ingress)
    if not ingress:
        back = client.fib_lookup(router, flow.src)
        ingress = back.interface if back else None
        if ingress:
            details.append(f"ingress {ingress} inferred from route back to {flow.src}")
            router = _router_for(client, ingress)

    fib = client.fib_lookup(router, flow.dst)
    if fib is None:
        return StepResult([hop(Status.BLOCK, f"no route to {flow.dst} in {router}", ingress=ingress)], flow,
                          outcome=Outcome.BLOCKED, reason=f"{dev.name}: no route to {flow.dst}")
    from_zone = ifs.get(ingress or "", {}).get("zone") or None
    to_zone = ifs.get(fib.interface or "", {}).get("zone") or None
    if not from_zone or not to_zone:
        return StepResult([hop(Status.UNKNOWN, f"zone unknown (from={from_zone} to={to_zone}); policy not evaluated",
                               ingress=ingress, egress=fib.interface)], flow, outcome=Outcome.INCOMPLETE,
                          reason=f"{dev.name}: no zone for {'ingress' if not from_zone else 'egress'} interface")

    # NAT is evaluated with pre-NAT zones; DNAT changes the egress zone used by security policy.
    nat_rule = client.nat_match(flow, from_zone, to_zone)
    nat = _nat_translation(client, nat_rule, fib.interface) if nat_rule else None
    egress_fib = fib
    if nat and nat.new_dst and nat.new_dst != flow.dst:
        post = client.fib_lookup(router, nat.new_dst)
        if post is None:
            return StepResult([hop(Status.BLOCK, f"no route to post-NAT destination {nat.new_dst}", ingress=ingress,
                                   nat=nat.describe())], flow, outcome=Outcome.BLOCKED,
                              reason=f"{dev.name}: no route to {nat.new_dst}")
        egress_fib = post
        to_zone = ifs.get(post.interface or "", {}).get("zone") or to_zone

    loc.update({k: v for k, v in (("zone_from", from_zone), ("zone_to", to_zone), ("vrf", router)) if v})
    match = client.security_match(flow, from_zone, to_zone)
    new_flow = flow
    if nat:
        new_flow = flow.with_changes(src=nat.new_src or flow.src, dst=nat.new_dst or flow.dst,
                                     dst_port=nat.new_port or flow.dst_port)
    route_txt = f"{router}: {flow.dst} via " + (f"{egress_fib.next_hop} " if egress_fib.next_hop else "connected ") + \
        f"{egress_fib.interface}"
    return _policy_result(hop, match, new_flow, from_zone, to_zone, ingress, egress_fib.interface,
                          egress=Egress(device=dev.name, interface=egress_fib.interface, next_hop=egress_fib.next_hop,
                                        vrf=router),
                          route_txt=route_txt, nat=nat.describe() if nat else None, details=details, dev=dev)


def _policy_result(hop: Any, match: PolicyMatch, flow: Flow, from_zone: str | None, to_zone: str | None,
                   ingress: str | None, egress_if: str | None, *, dev: Device, details: list[str],
                   next_pos: Any = None, egress: Egress | None = None, route_txt: str = "",
                   nat: str | None = None) -> StepResult:
    zones = f"{from_zone or '?'} -> {to_zone or '?'}"
    if match.rule is None:
        if from_zone and from_zone == to_zone:
            details.append("no explicit rule matched; intrazone-default allows unless overridden")
            status, policy = Status.WARN, "intrazone-default (allow)"
        else:
            policy = "interzone-default (deny)"
            return StepResult([hop(Status.BLOCK, f"{zones}: no rule matched", ingress=ingress, egress=egress_if,
                                   policy=policy, nat=nat)], flow, outcome=Outcome.BLOCKED,
                              reason=f"{dev.name}: no security rule matches ({zones}); interzone default denies")
    else:
        action = (match.action or "unknown").lower()
        policy = f"{match.rule} ({action})"
        if action not in ALLOW_ACTIONS:
            status = Status.UNKNOWN if action == "unknown" else Status.BLOCK
            return StepResult([hop(status, f"{zones}: rule {match.rule} -> {action}", ingress=ingress,
                                   egress=egress_if, policy=policy, nat=nat)], flow,
                              outcome=Outcome.BLOCKED if status == Status.BLOCK else Outcome.INCOMPLETE,
                              reason=f"{dev.name}: rule {match.rule} action {action}")
        status = Status.PASS
        if not flow.application:
            details.append("no --application given; App-ID may still block a different application")
    summary = f"{zones}" + (f"; {route_txt}" if route_txt else "")
    return StepResult([hop(status, summary, ingress=ingress, egress=egress_if, policy=policy, nat=nat)], flow,
                      next=next_pos, egress=egress)


def discover_addresses(client: PanosClient) -> dict[str, str]:
    out = {}
    for name, info in client.interfaces().items():
        ip = info["ip"].split("/")[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        out[ip] = name
    return out
