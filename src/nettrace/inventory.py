"""YAML inventory: devices, on-prem networks, AWS accounts, Prisma Access and links."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nettrace.errors import InventoryError
from nettrace.netutil import longest_match

PLATFORMS = ("cisco_iosxe", "panos")
DEFAULT_TRACE_TIMEOUT = 120.0  # seconds, whole trace

DEFAULT_ENV = {
    "cisco_iosxe": {
        "username_env": "NETTRACE_CISCO_USERNAME",
        "password_env": "NETTRACE_CISCO_PASSWORD",
        "secret_env": "NETTRACE_CISCO_SECRET",
    },
    "panos": {"api_key_env": "NETTRACE_PANOS_API_KEY"},
}


def default_inventory_path() -> Path:
    env = os.environ.get("NETTRACE_INVENTORY")
    if env:
        return Path(env).expanduser()
    local = Path("inventory.yaml")
    if local.exists():
        return local
    return Path("~/.nettrace/inventory.yaml").expanduser()


def cache_dir() -> Path:
    return Path(os.environ.get("NETTRACE_CACHE_DIR", "~/.cache/nettrace")).expanduser()


@dataclass
class AwsDeviceInfo:
    account: str | None = None
    region: str | None = None
    instance_id: str | None = None
    gwlb_endpoints: list[str] = field(default_factory=list)
    gwlb_zone: str | None = None
    gwlb_zone_map: dict[str, str] = field(default_factory=dict)


@dataclass
class PanoramaConfig:
    host: str
    peer_host: str | None = None  # second Panorama of an HA pair, tried if the first is unreachable
    port: int | None = None
    api_key_env: str = "NETTRACE_PANORAMA_API_KEY"
    verify_tls: bool | str = True
    follow_ha_active: bool = True  # query the active member when the inventory names the passive one


@dataclass
class Device:
    name: str
    platform: str
    host: str | None
    port: int | None = None
    site: str | None = None  # map grouping label, e.g. "DC1"; default "On-prem"
    serial: str | None = None  # PAN-OS: serial number, used to query through Panorama
    via: str = "direct"  # PAN-OS: direct | panorama (resolved at load time)
    addresses: list[str] = field(default_factory=list)
    vrf: str | None = None
    virtual_router: str = "default"
    routing_engine: str = "legacy"  # PAN-OS: legacy | advanced
    vsys: str | None = None
    verify_tls: bool | str = True
    ssh_strict: bool = True  # Cisco: verify SSH host keys against ~/.ssh/known_hosts; false only for labs
    username_env: str | None = None
    password_env: str | None = None
    secret_env: str | None = None
    api_key_env: str | None = None
    aws: AwsDeviceInfo | None = None


@dataclass
class Network:
    prefix: str
    gateway: str
    vrf: str | None = None


@dataclass
class AwsAccount:
    name: str
    account_id: str
    regions: list[str]
    role_arn: str | None = None
    profile: str | None = None
    external_id_env: str | None = None


@dataclass
class LinkEnd:
    device: str | None = None
    interface: str | None = None
    next_hop: str | None = None
    aws_tgw_attachment: str | None = None
    aws_vgw: str | None = None
    aws_account: str | None = None
    aws_region: str | None = None
    prisma_service_connection: str | None = None
    external: str | None = None  # e.g. "Internet (ISP-A)": the trace ends here as EXITED

    @property
    def kind(self) -> str:
        if self.device:
            return "device"
        if self.aws_tgw_attachment or self.aws_vgw:
            return "aws"
        if self.prisma_service_connection:
            return "prisma"
        if self.external:
            return "external"
        return "unknown"

    def label(self) -> str:
        if self.external:
            return self.external
        if self.device:
            return f"{self.device}" + (f" {self.interface}" if self.interface else "")
        if self.aws_tgw_attachment:
            return self.aws_tgw_attachment
        if self.aws_vgw:
            return self.aws_vgw
        if self.prisma_service_connection:
            return f"Prisma Access SC {self.prisma_service_connection}"
        return "?"


@dataclass
class Link:
    name: str
    a: LinkEnd
    b: LinkEnd


@dataclass
class PrismaRemoteNetwork:
    name: str
    prefixes: list[str]


@dataclass
class PrismaServiceConnection:
    name: str
    routes: list[str]


@dataclass
class PrismaConfig:
    mobile_user_pools: list[str] = field(default_factory=list)
    mobile_users_folder: str = "Mobile Users"
    remote_networks: list[PrismaRemoteNetwork] = field(default_factory=list)
    remote_networks_folder: str = "Remote Networks"
    service_connections: list[PrismaServiceConnection] = field(default_factory=list)
    user_zone: str = "trust"
    internal_zone: str = "trust"
    internet_zone: str = "untrust"


@dataclass
class Inventory:
    path: Path
    devices: dict[str, Device]
    networks: list[Network]
    aws_accounts: list[AwsAccount]
    links: list[Link]
    prisma: PrismaConfig | None
    panorama: PanoramaConfig | None = None
    discovered: dict[str, dict[str, str]] = field(default_factory=dict)
    trace_timeout: float = DEFAULT_TRACE_TIMEOUT  # overall seconds per trace; --timeout overrides

    # ---- lookups -------------------------------------------------------------
    def device(self, name: str) -> Device:
        try:
            return self.devices[name]
        except KeyError:
            raise InventoryError(f"device {name!r} is not in the inventory ({self.path})") from None

    def device_by_address(self, ip: str) -> tuple[Device, str | None] | None:
        """Return (device, interface) that owns `ip` from static addresses or the discovery cache."""
        for dev in self.devices.values():
            if ip in dev.addresses:
                return dev, None
        hit = self.discovered.get(ip)
        if hit and hit.get("device") in self.devices:
            return self.devices[hit["device"]], hit.get("interface")
        return None

    def network_for(self, ip: str) -> Network | None:
        best = longest_match(ip, [n.prefix for n in self.networks])
        if best is None:
            return None
        return next(n for n in self.networks if n.prefix == best)

    def account(self, name_or_id: str) -> AwsAccount | None:
        for acct in self.aws_accounts:
            if name_or_id in (acct.name, acct.account_id):
                return acct
        return None

    def device_by_serial(self, serial: str) -> Device | None:
        return next((d for d in self.devices.values() if d.serial == serial), None)

    def device_for_aws(self, *, instance_id: str | None = None, ip: str | None = None,
                       gwlb_endpoint: str | None = None) -> Device | None:
        for dev in self.devices.values():
            if not dev.aws:
                continue
            if instance_id and dev.aws.instance_id == instance_id:
                return dev
            if gwlb_endpoint and gwlb_endpoint in dev.aws.gwlb_endpoints:
                return dev
            if ip and ip in dev.addresses:
                return dev
        return None

    def link_from_device(self, device: str, interface: str | None, next_hop: str | None) -> tuple[Link, LinkEnd] | None:
        for link in self.links:
            for here, there in ((link.a, link.b), (link.b, link.a)):
                if here.device != device:
                    continue
                if here.interface and interface and here.interface.lower() == interface.lower():
                    return link, there
                if here.next_hop and next_hop and here.next_hop == next_hop:
                    return link, there
        return None

    def link_from_aws(self, resource_id: str) -> tuple[Link, LinkEnd] | None:
        for link in self.links:
            for here, there in ((link.a, link.b), (link.b, link.a)):
                if resource_id in (here.aws_tgw_attachment, here.aws_vgw):
                    return link, there
        return None

    def link_from_prisma(self, service_connection: str) -> tuple[Link, LinkEnd] | None:
        for link in self.links:
            for here, there in ((link.a, link.b), (link.b, link.a)):
                if here.prisma_service_connection == service_connection:
                    return link, there
        return None

    def prisma_location(self, ip: str) -> tuple[str, str] | None:
        """('mobile_users', 'Mobile Users') or ('remote_network', <name>) if ip is a Prisma Access client."""
        if not self.prisma:
            return None
        if longest_match(ip, self.prisma.mobile_user_pools):
            return "mobile_users", "Mobile Users"
        for rn in self.prisma.remote_networks:
            if longest_match(ip, rn.prefixes):
                return "remote_network", rn.name
        return None

    # ---- discovery cache -----------------------------------------------------
    def cache_file(self) -> Path:
        return cache_dir() / "addresses.json"

    def save_discovered(self, mapping: dict[str, dict[str, str]]) -> Path:
        path = self.cache_file()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(mapping, indent=2, sort_keys=True))
        os.chmod(path, 0o600)  # an existing file keeps its old mode otherwise
        self.discovered = mapping
        return path


# ---- loading ---------------------------------------------------------------------
def _ip_list(values: Any, where: str) -> list[str]:
    out = []
    for v in values or []:
        try:
            out.append(str(ipaddress.ip_address(str(v).split("/")[0])))
        except ValueError:
            raise InventoryError(f"{where}: {v!r} is not an IP address") from None
    return out


def _prefix_list(values: Any, where: str) -> list[str]:
    out = []
    for v in values or []:
        try:
            out.append(str(ipaddress.ip_network(str(v), strict=False)))
        except ValueError:
            raise InventoryError(f"{where}: {v!r} is not a prefix") from None
    return out


def _link_end(raw: dict[str, Any], where: str) -> LinkEnd:
    if not isinstance(raw, dict):
        raise InventoryError(f"{where} must be a mapping")
    aws = raw.get("aws") or {}
    prisma = raw.get("prisma_access") or {}
    end = LinkEnd(
        device=raw.get("device"),
        interface=raw.get("interface"),
        next_hop=raw.get("next_hop"),
        aws_tgw_attachment=aws.get("tgw_attachment"),
        aws_vgw=aws.get("vgw"),
        aws_account=str(aws["account"]) if aws.get("account") else None,
        aws_region=aws.get("region"),
        prisma_service_connection=prisma.get("service_connection"),
        external=str(raw["external"]) if raw.get("external") else None,
    )
    if end.kind == "unknown":
        raise InventoryError(f"{where} needs one of: device, aws.tgw_attachment, aws.vgw, "
                             "prisma_access.service_connection, external")
    return end


def _verify_tls(value: Any, where: str, *, fleet: bool = False) -> bool | str:
    """true | false | path of an existing CA bundle (file or directory), as `requests` takes it.
    `fleet` = the value comes from `defaults:` or `panorama:`, where `false` would switch off certificate
    checks for many devices at once: that needs NETTRACE_ALLOW_INSECURE_TLS=1. A per-device false is allowed."""
    if isinstance(value, bool):
        if not value and fleet and os.environ.get("NETTRACE_ALLOW_INSECURE_TLS") != "1":
            raise InventoryError(f"{where}: verify_tls: false here would disable certificate checks for every "
                                 "device that inherits it. Set it on the one device that needs it, or export "
                                 "NETTRACE_ALLOW_INSECURE_TLS=1 to allow it.")
        return value
    if isinstance(value, str) and os.path.exists(value):
        return value
    raise InventoryError(f"{where}: verify_tls must be true, false, or the path of an existing CA bundle "
                         f"(got {value!r})")


def _check_external_id(a: dict[str, Any], base_account: Any, where: str) -> None:
    """A role in another account than the base identity needs an external id (confused deputy).
    The base account is only known when aws.base_account_id is set (no STS GetCallerIdentity is allowed);
    when it is unknown, warn instead of failing."""
    role = a.get("role_arn")
    if not role or a.get("external_id_env"):
        return
    role_account = str(role).split(":")[4] if str(role).count(":") >= 5 else ""
    if base_account is None:
        warnings.warn(f"{where}: role_arn without external_id_env; set one if the role is in another account "
                      "(or set aws.base_account_id to enforce this)", stacklevel=2)
    elif role_account != str(base_account):
        raise InventoryError(f"{where}: role_arn is in account {role_account}, not the base account "
                             f"{base_account}: external_id_env is required")


def load_inventory(path: Path | str | None = None) -> Inventory:
    path = Path(path).expanduser() if path else default_inventory_path()
    if not path.exists():
        raise InventoryError(
            f"inventory file not found: {path}. Pass --inventory, set NETTRACE_INVENTORY, "
            "or copy inventory.example.yaml to inventory.yaml"
        )
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise InventoryError(f"{path}: invalid YAML: {exc}") from None

    defaults = raw.get("defaults") or {}

    panorama = None
    p_raw = raw.get("panorama")
    if p_raw:
        if not isinstance(p_raw, dict) or not p_raw.get("host"):
            raise InventoryError("panorama: host is required")
        panorama = PanoramaConfig(
            host=str(p_raw["host"]),
            peer_host=str(p_raw["peer_host"]) if p_raw.get("peer_host") else None,
            port=p_raw.get("port"),
            api_key_env=p_raw.get("api_key_env", "NETTRACE_PANORAMA_API_KEY"),
            verify_tls=_verify_tls(p_raw.get("verify_tls", True), "panorama.verify_tls", fleet=True),
            follow_ha_active=bool(p_raw.get("follow_ha_active", True)),
        )

    devices: dict[str, Device] = {}
    for i, d in enumerate(raw.get("devices") or []):
        where = f"devices[{i}]"
        if not isinstance(d, dict) or not d.get("name"):
            raise InventoryError(f"{where}: name is required")
        platform = d.get("platform")
        if platform not in PLATFORMS:
            raise InventoryError(f"{where} ({d['name']}): platform must be one of {', '.join(PLATFORMS)}")
        merged = {**DEFAULT_ENV[platform], **(defaults.get(platform) or {}), **d}
        serial = str(merged["serial"]) if merged.get("serial") else None
        if serial and not re.fullmatch(r"[A-Za-z0-9]{1,32}", serial):
            raise InventoryError(f"{where}: serial {serial!r} is not a valid serial number")
        via = merged.get("via")
        if platform == "panos":
            if via is None:
                via = "panorama" if (serial and panorama) else "direct"
            if via not in ("direct", "panorama"):
                raise InventoryError(f"{where}: via must be direct or panorama")
            if via == "panorama" and not (serial and panorama):
                raise InventoryError(f"{where}: via: panorama needs a serial and a top-level panorama section")
            if via == "direct" and not merged.get("host"):
                raise InventoryError(f"{where}: host is required (or give serial + a panorama section)")
        else:
            if not merged.get("host"):
                raise InventoryError(f"{where}: host is required")
            via = "direct"
        aws_raw = merged.get("aws")
        aws_info = None
        if aws_raw:
            aws_info = AwsDeviceInfo(
                account=str(aws_raw["account"]) if aws_raw.get("account") else None,
                region=aws_raw.get("region"),
                instance_id=aws_raw.get("instance_id"),
                gwlb_endpoints=list(aws_raw.get("gwlb_endpoints") or []),
                gwlb_zone=aws_raw.get("gwlb_zone"),
                gwlb_zone_map=dict(aws_raw.get("gwlb_zone_map") or {}),
            )
        engine = merged.get("routing_engine", "legacy")
        if engine not in ("legacy", "advanced"):
            raise InventoryError(f"{where}: routing_engine must be legacy or advanced")
        dev = Device(
            name=merged["name"],
            platform=platform,
            host=str(merged["host"]) if merged.get("host") else None,
            port=merged.get("port"),
            site=str(merged["site"]) if merged.get("site") else None,
            serial=serial,
            via=via,
            addresses=_ip_list(merged.get("addresses"), f"{where}.addresses"),
            vrf=merged.get("vrf"),
            virtual_router=merged.get("virtual_router") or merged.get("logical_router") or "default",
            routing_engine=engine,
            vsys=merged.get("vsys"),
            verify_tls=_verify_tls(merged.get("verify_tls", True), f"{where}.verify_tls",
                                   fleet="verify_tls" not in d),
            ssh_strict=merged.get("ssh_strict", True) is not False,
            username_env=merged.get("username_env"),
            password_env=merged.get("password_env"),
            secret_env=merged.get("secret_env"),
            api_key_env=merged.get("api_key_env"),
            aws=aws_info,
        )
        if dev.name in devices:
            raise InventoryError(f"{where}: duplicate device name {dev.name!r}")
        devices[dev.name] = dev

    networks = []
    for i, n in enumerate(raw.get("networks") or []):
        where = f"networks[{i}]"
        if not isinstance(n, dict) or "prefix" not in n or "gateway" not in n:
            raise InventoryError(f"{where}: prefix and gateway are required")
        if n["gateway"] not in devices:
            raise InventoryError(f"{where}: gateway {n['gateway']!r} is not a device")
        networks.append(Network(prefix=_prefix_list([n["prefix"]], where)[0], gateway=n["gateway"], vrf=n.get("vrf")))

    accounts = []
    aws_raw = raw.get("aws") or {}
    default_regions = aws_raw.get("regions") or []
    for i, a in enumerate(aws_raw.get("accounts") or []):
        where = f"aws.accounts[{i}]"
        if not isinstance(a, dict) or not a.get("account_id"):
            raise InventoryError(f"{where}: account_id is required")
        regions = a.get("regions") or default_regions
        if not regions:
            raise InventoryError(f"{where}: regions is required (or set aws.regions)")
        _check_external_id(a, aws_raw.get("base_account_id"), where)
        accounts.append(AwsAccount(
            name=str(a.get("name") or a["account_id"]),
            account_id=str(a["account_id"]),
            regions=list(regions),
            role_arn=a.get("role_arn"),
            profile=a.get("profile"),
            external_id_env=a.get("external_id_env"),
        ))

    links = []
    for i, l in enumerate(raw.get("links") or []):
        where = f"links[{i}]"
        if not isinstance(l, dict) or "a" not in l or "b" not in l:
            raise InventoryError(f"{where}: a and b are required")
        link = Link(name=l.get("name") or f"link-{i}", a=_link_end(l["a"], f"{where}.a"), b=_link_end(l["b"], f"{where}.b"))
        for end in (link.a, link.b):
            if end.device and end.device not in devices:
                raise InventoryError(f"{where}: device {end.device!r} is not in devices")
        links.append(link)

    prisma = None
    p = raw.get("prisma_access")
    if p:
        mu = p.get("mobile_users") or {}
        rn = p.get("remote_networks") or {}
        zones = p.get("zones") or {}
        prisma = PrismaConfig(
            mobile_user_pools=_prefix_list(mu.get("ip_pools"), "prisma_access.mobile_users.ip_pools"),
            mobile_users_folder=mu.get("folder", "Mobile Users"),
            remote_networks=[
                PrismaRemoteNetwork(name=r["name"], prefixes=_prefix_list(r.get("prefixes"), f"prisma_access.remote_networks.{r['name']}"))
                for r in (rn.get("networks") or [])
            ],
            remote_networks_folder=rn.get("folder", "Remote Networks"),
            service_connections=[
                PrismaServiceConnection(name=s["name"], routes=_prefix_list(s.get("routes"), f"prisma_access.service_connections.{s['name']}"))
                for s in (p.get("service_connections") or [])
            ],
            user_zone=zones.get("users", "trust"),
            internal_zone=zones.get("internal", "trust"),
            internet_zone=zones.get("internet", "untrust"),
        )

    serials = [d.serial for d in devices.values() if d.serial]
    dupes = {s for s in serials if serials.count(s) > 1}
    if dupes:
        raise InventoryError(f"devices: duplicate serial(s) {', '.join(sorted(dupes))}")

    timeout = raw.get("trace_timeout", DEFAULT_TRACE_TIMEOUT)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 3600:
        raise InventoryError("trace_timeout must be a number of seconds between 1 and 3600")

    inv = Inventory(path=path, devices=devices, networks=networks, aws_accounts=accounts, links=links, prisma=prisma,
                    panorama=panorama, trace_timeout=float(timeout))
    cache = inv.cache_file()
    if cache.exists():
        try:
            inv.discovered = json.loads(cache.read_text())
        except (OSError, ValueError):
            inv.discovered = {}
    return inv
