"""Command line: `nettrace <service> <command> [options]`, modelled on the AWS CLI."""

from __future__ import annotations

import ipaddress
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import click
from rich.console import Console
from rich.markup import escape

from nettrace import __version__
from nettrace.errors import NetTraceError
from nettrace.inventory import Inventory, load_inventory
from nettrace.models import Flow
from nettrace.netutil import PROTOCOL_NUMBERS
from nettrace.output import EXIT_CODES, clean, emit


class Ctx:
    def __init__(self, inventory_path: str | None, output: str, query: str | None, no_color: bool, debug: bool,
                 demo: bool = False):
        self.inventory_path = inventory_path
        self.output = output
        self.query = query
        self.debug = debug
        self.demo = demo
        self.console = Console(no_color=no_color, highlight=False)
        self.err = Console(stderr=True, no_color=no_color, highlight=False)
        self._inv: Inventory | None = None

    @property
    def inv(self) -> Inventory:
        if self._inv is None:
            if self.demo:
                from nettrace.demo import install

                self._inv = install()
            else:
                self._inv = load_inventory(self.inventory_path)
        return self._inv

    def emit(self, data: Any, verbose: bool = False) -> None:
        emit(self.console, data, self.output, self.query, verbose=verbose)

    def status(self, message: str) -> Any:
        if self.output == "table" and self.err.is_terminal:
            return self.err.status(message)
        return _Null()


class _Null:
    def __enter__(self) -> _Null:
        return self

    def __exit__(self, *a: Any) -> None:
        return None

    def update(self, *_: Any, **__: Any) -> None:
        return None


pass_ctx = click.make_pass_decorator(Ctx)


def _ip(_: Any, __: Any, value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise click.BadParameter(f"{value!r} is not an IP address") from None


def _protocol(_: Any, __: Any, value: str) -> str:
    v = value.lower()
    if v.isdigit() or v in PROTOCOL_NUMBERS:
        return v
    raise click.BadParameter(f"unknown protocol {value!r}")


def flow_options(require_port: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        opts = [
            click.option("--source", "-s", required=True, callback=_ip, help="Source IP address."),
            click.option("--destination", "-d", required=True, callback=_ip, help="Destination IP address."),
            click.option("--port", "-p", type=click.IntRange(1, 65535), required=require_port,
                         help="Destination port (TCP/UDP)."),
            click.option("--protocol", default="tcp", show_default=True, callback=_protocol,
                         help="tcp, udp, icmp or an IP protocol number."),
            click.option("--source-port", type=click.IntRange(1, 65535),
                         help="Source port. Default: unspecified (49152 is used for NACL return-path checks)."),
            click.option("--application", help="PAN-OS App-ID to test (e.g. ssl, web-browsing)."),
            click.option("--user", help="Source user for PAN-OS / Prisma Access user-based rules."),
        ]
        for opt in reversed(opts):
            fn = opt(fn)
        return fn

    return deco


def make_flow(source: str, destination: str, port: int | None, protocol: str, source_port: int | None,
              application: str | None, user: str | None) -> Flow:
    if protocol in ("tcp", "udp", "6", "17") and port is None:
        raise click.UsageError("--port is required for tcp/udp")
    return Flow(src=source, dst=destination, protocol=protocol, dst_port=port, src_port=source_port,
                application=application, user=user)


# ===== root ==================================================================================
@click.group(context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 110})
@click.option("--inventory", "-i", "inventory_path", envvar="NETTRACE_INVENTORY", type=click.Path(dir_okay=False),
              help="Inventory YAML. Default: $NETTRACE_INVENTORY, ./inventory.yaml, ~/.nettrace/inventory.yaml")
@click.option("--output", "-o", type=click.Choice(["table", "json", "text"]),
              default=lambda: os.environ.get("NETTRACE_OUTPUT", "table"), show_default="table",
              help="Output format (like the AWS CLI --output).")
@click.option("--query", help="JMESPath query applied to the JSON form of the result (like the AWS CLI --query).")
@click.option("--no-color", is_flag=True, help="Disable colour.")
@click.option("--debug", is_flag=True, help="Show tracebacks on errors.")
@click.option("--demo", is_flag=True, envvar="NETTRACE_DEMO",
              help="Run against the built-in simulated Acme Corp lab instead of your inventory.")
@click.version_option(__version__, prog_name="nettrace")
@click.pass_context
def cli(click_ctx: click.Context, inventory_path: str | None, output: str, query: str | None, no_color: bool,
        debug: bool, demo: bool) -> None:
    """Read-only network path tracer for Cisco IOS-XE, PAN-OS/Panorama, Prisma Access and AWS.

    \b
    Examples:
      nettrace trace run -s 10.1.1.10 -d 10.20.5.4 -p 443
      nettrace trace run -s 10.1.1.10 -d 10.20.5.4 -p 443 --output json --query 'Hops[?status==`BLOCK`]'
      nettrace panos test-security-policy --device fw-dc1 -s 10.1.1.10 -d 10.20.5.4 -p 443
      nettrace panorama list-devices
      nettrace aws find-ip --ip 10.20.5.4
      nettrace trace run -s 10.1.1.10 -d 10.20.5.4 -p 443 --map trace.html --open
      nettrace viz render --input trace.json --out-file trace.html
    """
    click_ctx.obj = Ctx(inventory_path, output, query, no_color, debug, demo)


# ===== trace ==================================================================================
@cli.group()
def trace() -> None:
    """Trace a flow hop by hop."""


@trace.command("run")
@flow_options()
@click.option("--start-at", help="Inventory device to start from (skips source lookup).")
@click.option("--max-hops", type=click.IntRange(1, 100), default=30, show_default=True)
@click.option("--timeout", type=click.FloatRange(1, 3600), default=None,
              help="Overall time budget in seconds (default: inventory trace_timeout, else 120). "
                   "On expiry the trace ends INCOMPLETE with the hops so far. Ctrl-C does the same (exit 4).")
@click.option("--no-return-check", is_flag=True, help="Skip NACL return-path checks in AWS.")
@click.option("--verbose", "-v", is_flag=True, help="Show hop details and the raw requests/answers.")
@click.option("--map", "map_file", type=click.Path(dir_okay=False, writable=True),
              help="Also write a path map: .html (interactive) or .svg (static).")
@click.option("--open", "open_map", is_flag=True, help="Open the path map in a browser (writes a temp file if no --map).")
@click.option("--with-evidence", is_flag=True, help="Keep raw device output (hop evidence) in the map. Do not share it.")
@pass_ctx
def trace_run(ctx: Ctx, source: str, destination: str, port: int | None, protocol: str, source_port: int | None,
              application: str | None, user: str | None, start_at: str | None, max_hops: int,
              timeout: float | None, no_return_check: bool, verbose: bool, map_file: str | None, open_map: bool,
              with_evidence: bool) -> None:
    """Trace SOURCE -> DESTINATION across every device and cloud component on the path."""
    from nettrace.engine import Tracer

    flow = make_flow(source, destination, port, protocol, source_port, application, user)
    inv = ctx.inv  # load (and validate) before the spinner starts
    with ctx.status(f"tracing {flow.describe()}") as status:
        tracer = Tracer(inv, max_hops=max_hops, check_return=not no_return_check, timeout=timeout,
                        progress=lambda m: status.update(f"tracing {flow.describe()}: {m}"))
        result = tracer.trace(flow, start_at=start_at)
    if result.cancelled:  # Ctrl-C: the engine stopped at the next safe point and kept the hops found so far
        ctx.err.print("[yellow]cancelled (Ctrl-C):[/] showing the hops found so far; the result is INCOMPLETE")
    ctx.emit(result, verbose=verbose)
    if map_file or open_map:
        path = write_map([result.to_dict()], map_file, with_evidence=with_evidence)
        ctx.err.print(f"path map written to {path}")
        if open_map:
            open_in_browser(path)
    sys.exit(EXIT_CODES[result.outcome])


# ===== viz ======================================================================================
def strip_evidence(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copies of the traces without raw device output (hop evidence), safe to share."""
    return [{**t, "Hops": [{k: v for k, v in h.items() if k != "evidence"} for h in t.get("Hops") or []]}
            for t in traces]


def write_private(path: str, text: str) -> None:
    """Write a file readable by the owner only (0600), also when it already exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(text)


def write_map(traces: list[dict[str, Any]], out_file: str | None, *, with_evidence: bool = False) -> str:
    """Write an .html or .svg path map (mode 0600). With no file, write a temp .html.
    Hop evidence (raw device output) is left out unless with_evidence."""
    import tempfile
    from pathlib import Path

    from nettrace.viz import build_map, render_html, render_svg

    if not with_evidence:
        traces = strip_evidence(traces)
    if out_file is None:
        fd, out_file = tempfile.mkstemp(prefix="nettrace-map-", suffix=".html")  # mkstemp creates it 0600
        os.close(fd)
    path = Path(out_file)
    if path.suffix.lower() == ".svg":
        if len(traces) != 1:
            raise click.UsageError("an .svg map holds one trace; use .html for several")
        text = render_svg(build_map(traces[0]))
    elif path.suffix.lower() in (".html", ".htm"):
        text = render_html(traces)
    else:
        raise click.UsageError(f"{out_file}: map file must end in .html or .svg")
    write_private(str(path), text)
    return str(path.resolve())


def open_in_browser(path: str) -> None:
    from pathlib import Path

    from nettrace.web.server import launch_browser

    launch_browser(Path(path).resolve().as_uri())


def _load_traces(inputs: tuple[str, ...]) -> list[dict[str, Any]]:
    import json

    traces = []
    sources = inputs or ("-",)
    for src in sources:
        text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8").read()
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise NetTraceError(f"{src}: not JSON ({exc})") from None
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not (isinstance(item, dict) and "Hops" in item and "Outcome" in item):
                raise NetTraceError(f"{src}: not a nettrace trace (expected 'trace run --output json' "
                                    "output without --query)")
            traces.append(item)
    if not traces:
        raise NetTraceError("no traces to render")
    return traces


@cli.group()
def viz() -> None:
    """Render path maps from saved traces (`trace run --output json`)."""


@viz.command("render")
@click.option("--input", "inputs", multiple=True, type=click.Path(dir_okay=False, allow_dash=True),
              help="Trace JSON file (repeatable; '-' or omitted = stdin). A JSON list of traces also works.")
@click.option("--out-file", required=True, type=click.Path(dir_okay=False, writable=True),
              help=".html (interactive, several traces with a picker) or .svg (one trace, static).")
@click.option("--open", "open_map", is_flag=True, help="Open the result in a browser.")
@click.option("--with-evidence", is_flag=True, help="Keep raw device output (hop evidence) in the map. Do not share it.")
@pass_ctx
def viz_render(ctx: Ctx, inputs: tuple[str, ...], out_file: str, open_map: bool, with_evidence: bool) -> None:
    """Draw a NetBrain-style path map of one or more traces.

    \b
    nettrace trace run -s 10.1.1.10 -d 10.20.1.50 -p 443 --output json > t.json
    nettrace viz render --input t.json --out-file t.html --open
    nettrace trace run ... --output json | nettrace viz render --out-file t.svg
    """
    traces = _load_traces(inputs)
    path = write_map(traces, out_file, with_evidence=with_evidence)
    ctx.emit({"OutFile": path, "Traces": len(traces),
              "Outcomes": ", ".join(t.get("Outcome", "?") for t in traces)})
    if open_map:
        open_in_browser(path)


# ===== inventory ===================================================================================
@cli.group()
def inventory() -> None:
    """Inspect and validate the inventory."""


@inventory.command("list")
@pass_ctx
def inventory_list(ctx: Ctx) -> None:
    """List devices, networks, AWS accounts and links."""
    inv = ctx.inv
    rows: list[dict[str, Any]] = []
    if inv.panorama:
        p = inv.panorama
        rows.append({"Type": "panorama", "Name": p.host, "Detail": f"peer {p.peer_host or '-'}; "
                     f"follow HA active: {'yes' if p.follow_ha_active else 'no'}"})
    for d in inv.devices.values():
        where = f"via panorama serial {d.serial}" if d.via == "panorama" else (d.host or "")
        rows.append({"Type": "device", "Name": d.name, "Detail": f"{d.platform} {where}"
                     + (f" aws:{d.aws.account}/{d.aws.region}" if d.aws else "")})
    for n in inv.networks:
        rows.append({"Type": "network", "Name": n.prefix, "Detail": f"gateway {n.gateway}" + (f" vrf {n.vrf}" if n.vrf else "")})
    for a in inv.aws_accounts:
        rows.append({"Type": "aws-account", "Name": a.name, "Detail": f"{a.account_id} {','.join(a.regions)} "
                     + (a.role_arn or a.profile or "default credentials")})
    for l in inv.links:
        rows.append({"Type": "link", "Name": l.name, "Detail": f"{l.a.label()} <-> {l.b.label()}"})
    if inv.prisma:
        rows.append({"Type": "prisma-access", "Name": "prisma-access",
                     "Detail": f"MU pools {','.join(inv.prisma.mobile_user_pools) or '-'}; "
                               f"{len(inv.prisma.remote_networks)} remote networks; "
                               f"{len(inv.prisma.service_connections)} service connections"})
    ctx.emit(rows)


@inventory.command("validate")
@pass_ctx
def inventory_validate(ctx: Ctx) -> None:
    """Load the inventory and report problems."""
    inv = ctx.inv
    ctx.emit({"Inventory": str(inv.path), "Devices": len(inv.devices), "Networks": len(inv.networks),
              "AwsAccounts": len(inv.aws_accounts), "Links": len(inv.links), "Prisma": bool(inv.prisma),
              "DiscoveredAddresses": len(inv.discovered), "Status": "OK"})


@inventory.command("resolve")
@click.option("--ip", required=True, callback=_ip)
@click.option("--aws/--no-aws", "search_aws", default=False, help="Also search AWS ENIs.")
@pass_ctx
def inventory_resolve(ctx: Ctx, ip: str, search_aws: bool) -> None:
    """Show what nettrace knows about an IP."""
    inv = ctx.inv
    rows = []
    owned = inv.device_by_address(ip)
    if owned:
        rows.append({"Match": "device-address", "Value": owned[0].name + (f" {owned[1]}" if owned[1] else "")})
    net = inv.network_for(ip)
    if net:
        rows.append({"Match": "network", "Value": f"{net.prefix} gateway {net.gateway}"})
    loc = inv.prisma_location(ip)
    if loc:
        rows.append({"Match": "prisma-access", "Value": f"{loc[0]} {loc[1]}"})
    if search_aws and inv.aws_accounts:
        from nettrace.drivers.aws import AwsEnv

        with ctx.status(f"searching AWS for {ip}"):
            hit = AwsEnv(inv).find_eni(ip)
        if hit:
            acct, region, eni = hit
            rows.append({"Match": "aws-eni", "Value": f"{eni['NetworkInterfaceId']} {eni['VpcId']} {eni['SubnetId']} "
                                                      f"{acct}/{region}"})
    if not rows:
        rows.append({"Match": "none", "Value": "not found"})
    ctx.emit(rows)


@inventory.command("discover")
@click.option("--device", "devices", multiple=True, help="Only these devices (repeatable). Default: all.")
@pass_ctx
def inventory_discover(ctx: Ctx, devices: tuple[str, ...]) -> None:
    """Pull interface IPs from devices (read-only) so next hops resolve to devices."""
    from nettrace.engine import Clients
    from nettrace.drivers import cisco_iosxe, panos

    inv = ctx.inv
    targets = [inv.device(d) for d in devices] if devices else list(inv.devices.values())
    clients = Clients(inv)
    mapping = dict(inv.discovered)
    rows = []

    def one(dev: Any) -> tuple[Any, dict[str, str] | None, str | None]:
        try:
            c = clients.device(dev)
            mod = cisco_iosxe if dev.platform == "cisco_iosxe" else panos
            return dev, mod.discover_addresses(c), None
        except NetTraceError as exc:
            return dev, None, str(exc)

    with ctx.status(f"discovering interface addresses on {len(targets)} devices"):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(one, targets))
    clients.close()
    for dev, found, err in results:
        if err:
            rows.append({"Device": dev.name, "Addresses": 0, "Status": f"error: {err}"})
            continue
        mapping = {ip: v for ip, v in mapping.items() if v.get("device") != dev.name}
        for ip, intf in (found or {}).items():
            mapping[ip] = {"device": dev.name, "interface": intf}
        rows.append({"Device": dev.name, "Addresses": len(found or {}), "Status": "ok"})
    path = inv.save_discovered(mapping)
    ctx.emit(rows)
    ctx.err.print(f"saved {len(mapping)} addresses to {path}")


# ===== cisco ====================================================================================
@cli.group()
def cisco() -> None:
    """Cisco IOS-XE lookups (show commands only)."""


def _cisco_client(ctx: Ctx, device: str) -> Any:
    from nettrace.drivers.cisco_iosxe import CiscoClient

    dev = ctx.inv.device(device)
    if dev.platform != "cisco_iosxe":
        raise NetTraceError(f"{device} is not a cisco_iosxe device")
    return CiscoClient(dev)


@cisco.command("show-route")
@click.option("--device", required=True)
@click.option("--destination", "-d", required=True, callback=_ip)
@click.option("--vrf")
@pass_ctx
def cisco_show_route(ctx: Ctx, device: str, destination: str, vrf: str | None) -> None:
    """Route and CEF entry for a destination."""
    c = _cisco_client(ctx, device)
    try:
        cef = c.cef(destination, vrf or c.device.vrf)
        prefix, source = c.route(destination, vrf or c.device.vrf)
    finally:
        c.close()
    ctx.emit([{"Device": device, "Prefix": cef.prefix or prefix, "Source": source, "Type": e.kind,
               "NextHop": e.next_hop, "Interface": e.interface} for e in cef.entries]
             or [{"Device": device, "Prefix": None, "Type": "no route"}])


@cisco.command("check-acl")
@click.option("--device", required=True)
@click.option("--acl", required=True, help="ACL name or number.")
@flow_options()
@pass_ctx
def cisco_check_acl(ctx: Ctx, device: str, acl: str, **flow_kw: Any) -> None:
    """Evaluate a flow against an ACL on the device."""
    flow = make_flow(**flow_kw)
    c = _cisco_client(ctx, device)
    try:
        res = c.acl(acl, flow)
    finally:
        c.close()
    ctx.emit({"Device": device, "Acl": acl, "Action": res.action, "MatchedEntry": res.line, "AclExists": res.exists,
              "UncertainEntries": res.uncertain})


# ===== panos ====================================================================================
@cli.group()
def panos() -> None:
    """PAN-OS firewall lookups (XML API, show/test only)."""


def _panos_client(ctx: Ctx, device: str) -> Any:
    from nettrace.engine import Clients

    dev = ctx.inv.device(device)
    if dev.platform != "panos":
        raise NetTraceError(f"{device} is not a panos device")
    return Clients(ctx.inv).device(dev)


@panos.command("lookup-route")
@click.option("--device", required=True)
@click.option("--destination", "-d", required=True, callback=_ip)
@click.option("--virtual-router", help="Virtual router (legacy) or logical router (advanced). Default from inventory.")
@pass_ctx
def panos_lookup_route(ctx: Ctx, device: str, destination: str, virtual_router: str | None) -> None:
    """FIB lookup on the firewall (test routing fib-lookup)."""
    c = _panos_client(ctx, device)
    vr = virtual_router or c.device.virtual_router
    fib = c.fib_lookup(vr, destination)
    zone = c.interfaces().get(fib.interface, {}).get("zone") if fib else None
    ctx.emit({"Device": device, "Router": vr, "Destination": destination,
              "Interface": fib.interface if fib else None, "NextHop": (fib.next_hop or "connected") if fib else None,
              "Zone": zone, "Result": "route" if fib else "no route"})


def _zones(c: Any, flow: Flow, from_zone: str | None, to_zone: str | None) -> tuple[str | None, str | None]:
    if from_zone and to_zone:
        return from_zone, to_zone
    ifs = c.interfaces()
    vr = c.device.virtual_router
    if not from_zone:
        back = c.fib_lookup(vr, flow.src)
        from_zone = ifs.get(back.interface, {}).get("zone") if back else None
    if not to_zone:
        fwd = c.fib_lookup(vr, flow.dst)
        to_zone = ifs.get(fwd.interface, {}).get("zone") if fwd else None
    return from_zone, to_zone


@panos.command("test-security-policy")
@click.option("--device", required=True)
@click.option("--from-zone", help="Default: zone of the interface routing back to the source.")
@click.option("--to-zone", help="Default: zone of the interface routing to the destination.")
@flow_options()
@pass_ctx
def panos_test_security(ctx: Ctx, device: str, from_zone: str | None, to_zone: str | None, **flow_kw: Any) -> None:
    """Which security rule matches (test security-policy-match)."""
    flow = make_flow(**flow_kw)
    c = _panos_client(ctx, device)
    fz, tz = _zones(c, flow, from_zone, to_zone)
    m = c.security_match(flow, fz, tz)
    ctx.emit({"Device": device, "FromZone": fz, "ToZone": tz, "Rule": m.rule or "(no match)", "Action": m.action})


@panos.command("test-nat-policy")
@click.option("--device", required=True)
@click.option("--from-zone")
@click.option("--to-zone")
@flow_options()
@pass_ctx
def panos_test_nat(ctx: Ctx, device: str, from_zone: str | None, to_zone: str | None, **flow_kw: Any) -> None:
    """Which NAT rule matches and how it translates (test nat-policy-match)."""
    from nettrace.drivers.panos import _nat_translation

    flow = make_flow(**flow_kw)
    c = _panos_client(ctx, device)
    fz, tz = _zones(c, flow, from_zone, to_zone)
    rule = c.nat_match(flow, fz, tz)
    nat = _nat_translation(c, rule, None) if rule else None
    ctx.emit({"Device": device, "FromZone": fz, "ToZone": tz, "Rule": rule or "(no match)",
              "TranslatedSource": nat.new_src if nat else None, "TranslatedDestination": nat.new_dst if nat else None,
              "TranslatedPort": nat.new_port if nat else None})


# ===== panorama ================================================================================
@cli.group()
def panorama() -> None:
    """Panorama: managed firewalls, HA state, device groups (read-only)."""


def _panorama(ctx: Ctx) -> Any:
    from nettrace.drivers.panos import PanoramaClient

    if not ctx.inv.panorama:
        raise NetTraceError("no panorama section in the inventory")
    return PanoramaClient(ctx.inv.panorama)


@panorama.command("list-devices")
@click.option("--connected-only", is_flag=True, help="Hide firewalls not connected to Panorama.")
@pass_ctx
def panorama_list_devices(ctx: Ctx, connected_only: bool) -> None:
    """Managed firewalls with HA state, device group and whether they are in the inventory."""
    pano = _panorama(ctx)
    with ctx.status("reading managed devices from Panorama"):
        devices = pano.devices()
    rows = []
    for d in sorted(devices.values(), key=lambda x: x.hostname):
        if connected_only and not d.connected:
            continue
        inv_dev = ctx.inv.device_by_serial(d.serial)
        rows.append({"Serial": d.serial, "Hostname": d.hostname, "MgmtIp": d.ip, "Model": d.model,
                     "Version": d.sw_version, "Connected": d.connected, "HaState": d.ha_state, "HaPeer": d.ha_peer,
                     "DeviceGroup": d.device_group, "Inventory": inv_dev.name if inv_dev else None})
    ctx.emit(rows)


@panorama.command("generate-inventory")
@click.option("--all", "include_all", is_flag=True, help="Include firewalls already in the inventory.")
@click.option("--include-passive", is_flag=True,
              help="Also list HA passive members (normally the active member stands for the pair).")
@pass_ctx
def panorama_generate_inventory(ctx: Ctx, include_all: bool, include_passive: bool) -> None:
    """Print YAML `devices:` entries for Panorama-managed firewalls (paste into inventory.yaml)."""
    import json

    pano = _panorama(ctx)
    with ctx.status("reading managed devices from Panorama"):
        devices = pano.devices()
    lines = ["devices:"]
    for d in sorted(devices.values(), key=lambda x: x.hostname):
        if not d.connected:
            continue
        if not include_all and (ctx.inv.device_by_serial(d.serial)
                                or (d.ha_peer and ctx.inv.device_by_serial(d.ha_peer))):
            continue  # already in the inventory, directly or as its HA pair
        peer = devices.get(d.ha_peer or "")
        if not include_passive and (d.ha_state or "").startswith("passive") and peer and peer.connected:
            continue  # nettrace follows HA to the active member, so the pair needs one entry
        name = d.hostname or d.serial
        comment = ", ".join(x for x in (d.model, d.ip, f"dg {d.device_group}" if d.device_group else "",
                                        f"HA {d.ha_state} peer {d.ha_peer}" if d.ha_state else "") if x)
        lines += [f"  # {comment}", f"  - name: {json.dumps(name)}", "    platform: panos",
                  f"    serial: {json.dumps(d.serial)}"]
    click.echo("\n".join(lines) + "\n" if len(lines) > 1 else "# no firewalls to add\n", nl=False)


@panorama.command("show-device")
@click.option("--device", required=True, help="Inventory device name or serial number.")
@pass_ctx
def panorama_show_device(ctx: Ctx, device: str) -> None:
    """How nettrace will reach a firewall: serial, HA redirection, device-group chain."""
    pano = _panorama(ctx)
    dev = ctx.inv.devices.get(device) or ctx.inv.device_by_serial(device)
    if dev is None or not dev.serial:
        raise NetTraceError(f"{device}: not an inventory panos device with a serial")
    target, notes = pano.resolve_target(dev)
    managed = pano.devices().get(dev.serial)
    chain = []
    g = managed.device_group if managed else None
    parents = pano.dg_parents() if g else {}
    while g and g not in chain:
        chain.append(g)
        g = parents.get(g)
    ctx.emit({"Device": dev.name, "Serial": dev.serial, "Via": dev.via, "QueriedSerial": target,
              "DeviceGroupChain": chain + ["shared"], "Notes": notes})


# ===== prisma ==================================================================================
@cli.group()
def prisma() -> None:
    """Prisma Access (Strata Cloud Manager API, GET only)."""


@prisma.command("list-security-rules")
@click.option("--folder", default="Mobile Users", show_default=True)
@pass_ctx
def prisma_list_rules(ctx: Ctx, folder: str) -> None:
    """List security rules in evaluation order (pre, then post)."""
    from nettrace.drivers.prisma import ScmClient

    rules = ScmClient().security_rules(folder)
    ctx.emit([{"Position": r["_position"], "Name": r.get("name"), "From": r.get("from"), "To": r.get("to"),
               "Source": r.get("source"), "Destination": r.get("destination"), "Application": r.get("application"),
               "Service": r.get("service"), "Action": r.get("action"), "Disabled": r.get("disabled", False),
               "Folder": r.get("folder")} for r in rules])


@prisma.command("test-security-policy")
@click.option("--folder", default="Mobile Users", show_default=True)
@click.option("--from-zone", default="trust", show_default=True)
@click.option("--to-zone", default="trust", show_default=True)
@flow_options()
@pass_ctx
def prisma_test_security(ctx: Ctx, folder: str, from_zone: str, to_zone: str, **flow_kw: Any) -> None:
    """Evaluate the folder's rules against a flow (config-based)."""
    from nettrace.drivers.prisma import Resolver, ScmClient, evaluate_rules

    flow = make_flow(**flow_kw)
    scm = ScmClient()
    res = evaluate_rules(scm.security_rules(folder), Resolver(scm, folder), flow, from_zone, to_zone)
    ctx.emit({"Folder": folder, "Rule": res.rule or "(no definite match)", "Position": res.position,
              "Action": res.action, "UncertainRulesAbove": res.uncertain})


# ===== aws ====================================================================================
@cli.group("aws")
def aws_group() -> None:
    """AWS lookups across inventory accounts (Describe/Get/Search only)."""


def _aws_env(ctx: Ctx) -> Any:
    from nettrace.drivers.aws import AwsEnv

    return AwsEnv(ctx.inv)


@aws_group.command("find-ip")
@click.option("--ip", required=True, callback=_ip)
@pass_ctx
def aws_find_ip(ctx: Ctx, ip: str) -> None:
    """Find the ENI that owns an IP in any inventory account/region."""
    env = _aws_env(ctx)
    with ctx.status(f"searching {len(env.targets())} account/region pairs"):
        hit = env.find_eni(ip)
    if not hit:
        ctx.emit({"Ip": ip, "Found": False})
        return
    acct, region, eni = hit
    ctx.emit({"Ip": ip, "Account": acct, "Region": region, "NetworkInterfaceId": eni["NetworkInterfaceId"],
              "VpcId": eni.get("VpcId"), "SubnetId": eni.get("SubnetId"), "AvailabilityZone": eni.get("AvailabilityZone"),
              "InterfaceType": eni.get("InterfaceType"), "InstanceId": (eni.get("Attachment") or {}).get("InstanceId"),
              "Description": eni.get("Description"), "SecurityGroups": [g["GroupId"] for g in eni.get("Groups", [])],
              "SourceDestCheck": eni.get("SourceDestCheck")})


@aws_group.command("describe-route")
@click.option("--account", required=True, help="Inventory account name or id.")
@click.option("--region", required=True)
@click.option("--subnet-id", required=True)
@click.option("--destination", "-d", required=True, callback=_ip)
@pass_ctx
def aws_describe_route(ctx: Ctx, account: str, region: str, subnet_id: str, destination: str) -> None:
    """Longest-prefix match in a subnet's route table."""
    from nettrace.drivers.aws import lookup_route, route_target

    env = _aws_env(ctx)
    acct = env.account(account).account_id
    subnet = env.subnet(acct, region, subnet_id)
    rtb = env.route_table(acct, region, subnet_id, subnet["VpcId"])
    route = lookup_route(env, acct, region, rtb, destination)
    kind, target = route_target(route) if route else ("none", None)
    ctx.emit({"RouteTableId": rtb["RouteTableId"], "Destination": destination,
              "MatchedPrefix": route.get("_matched") if route else None, "TargetType": kind, "Target": target,
              "State": route.get("State") if route else None})


@aws_group.command("search-tgw-routes")
@click.option("--account", required=True, help="TGW owner account (name or id).")
@click.option("--region", required=True)
@click.option("--route-table-id", required=True)
@click.option("--destination", "-d", required=True, callback=_ip)
@pass_ctx
def aws_search_tgw(ctx: Ctx, account: str, region: str, route_table_id: str, destination: str) -> None:
    """Longest-prefix match in a Transit Gateway route table."""
    env = _aws_env(ctx)
    route = env.search_tgw_routes(env.account(account).account_id, region, route_table_id, destination)
    if not route:
        ctx.emit({"RouteTableId": route_table_id, "Destination": destination, "Result": "no route"})
        return
    ctx.emit([{"RouteTableId": route_table_id, "Prefix": route.get("DestinationCidrBlock") or route.get("PrefixListId"),
               "Type": route.get("Type"), "State": route.get("State"),
               "AttachmentId": a.get("TransitGatewayAttachmentId"), "ResourceType": a.get("ResourceType"),
               "ResourceId": a.get("ResourceId")} for a in route.get("TransitGatewayAttachments", [])]
             or [{"RouteTableId": route_table_id, "Prefix": route.get("DestinationCidrBlock"), "State": route.get("State")}])


# ===== serve / demo =================================================================================
def _serve(ctx: Ctx, port: int, open_browser: bool, verbose: bool) -> None:
    from nettrace.web.server import serve

    inv = ctx.inv

    def ready(url: str, app: Any) -> None:
        mode = "DEMO LAB (simulated devices)" if ctx.demo else f"LIVE inventory {inv.path} (read-only queries)"
        ctx.err.print(f"[bold]nettrace web UI[/] · {mode}")
        ctx.err.print(f"  open  [cyan]{url}[/]")
        ctx.err.print(f"  token [cyan]{app.token}[/]  (paste it if the page asks; --open launches the URL without it)")
        ctx.err.print("  bound to 127.0.0.1 only; the token is required for every API call. Ctrl-C to stop.")

    try:
        serve(inv, demo=ctx.demo, port=port, open_browser=open_browser, verbose=verbose, on_ready=ready)
    except OSError as exc:
        raise NetTraceError(f"can't listen on 127.0.0.1:{port}: {exc.strerror or exc}") from None


@cli.command("serve")
@click.option("--port", type=click.IntRange(1024, 65535), default=8765, show_default=True)
@click.option("--open", "open_browser", is_flag=True, help="Open the bare URL in a browser; paste the token there.")
@click.option("--no-open", is_flag=True, hidden=True, help="Default now; kept for old scripts.")
@click.option("--verbose", "-v", is_flag=True, help="Log HTTP requests.")
@pass_ctx
def serve_cmd(ctx: Ctx, port: int, open_browser: bool, no_open: bool, verbose: bool) -> None:
    """Local web UI: topology, multi-packet flow animation, path maps, read-only device console.

    With --demo (or `nettrace demo serve`) it runs against the simulated Acme Corp lab.
    """
    _serve(ctx, port, open_browser and not no_open, verbose)


@cli.group()
def demo() -> None:
    """Built-in simulated lab (Acme Corp) to try nettrace without touching real devices.

    \b
    nettrace demo serve                  # web UI on http://127.0.0.1:8765
    nettrace demo scenarios              # preset flows and their expected outcome
    nettrace --demo trace run -s 10.1.10.25 -d 10.20.1.50 -p 443
    nettrace --demo panorama list-devices
    """


@demo.command("serve")
@click.option("--port", type=click.IntRange(1024, 65535), default=8765, show_default=True)
@click.option("--open", "open_browser", is_flag=True, help="Open the bare URL in a browser; paste the token there.")
@click.option("--no-open", is_flag=True, hidden=True, help="Default now; kept for old scripts.")
@click.option("--verbose", "-v", is_flag=True, help="Log HTTP requests.")
@pass_ctx
def demo_serve(ctx: Ctx, port: int, open_browser: bool, no_open: bool, verbose: bool) -> None:
    """Web UI against the demo lab."""
    ctx.demo = True
    _serve(ctx, port, open_browser and not no_open, verbose)


@demo.command("scenarios")
@pass_ctx
def demo_scenarios(ctx: Ctx) -> None:
    """Preset scenarios, with the CLI command for each."""
    from nettrace.demo import PRESETS

    rows = []
    for p in PRESETS:
        f = p["flow"]
        cmd = f"nettrace --demo trace run -s {f['src']} -d {f['dst']} --protocol {f['protocol']} -p {f['port']}"
        cmd += "".join(f" --{k.replace('_', '-')} {f[k]}" for k in ("application", "user", "start_at") if f.get(k))
        rows.append({"Id": p["id"], "Scenario": p["title"], "Expect": p["expect"], "Command": cmd})
    ctx.emit(rows)


# ===== configure ===================================================================================
@cli.group()
def configure() -> None:
    """Check credentials and connectivity."""


@configure.command("check")
@click.option("--test-connections", is_flag=True, help="Also make one read-only call to each device/account.")
@pass_ctx
def configure_check(ctx: Ctx, test_connections: bool) -> None:
    """Show which credential environment variables are set (values are never printed)."""
    inv = ctx.inv
    rows = []
    seen: set[str] = set()

    def env_row(var: str | None, used_by: str, required: bool = True) -> None:
        if not var or var in seen:
            return
        seen.add(var)
        rows.append({"Check": f"env {var}", "UsedBy": used_by,
                     "Status": "set" if os.environ.get(var) else ("MISSING" if required else "not set (optional)")})

    for d in inv.devices.values():
        if d.platform == "cisco_iosxe":
            env_row(d.username_env, d.name)
            env_row(d.password_env, d.name)
            env_row(d.secret_env, d.name, required=False)
        elif d.via == "direct":
            env_row(d.api_key_env, d.name)
    if inv.panorama:
        env_row(inv.panorama.api_key_env, "panorama")
    if inv.prisma:
        for v in ("NETTRACE_SCM_CLIENT_ID", "NETTRACE_SCM_CLIENT_SECRET", "NETTRACE_SCM_TSG_ID"):
            env_row(v, "prisma-access")
    if inv.aws_accounts:
        base = "AWS_PROFILE" if os.environ.get("AWS_PROFILE") else (
            "AWS_ACCESS_KEY_ID" if os.environ.get("AWS_ACCESS_KEY_ID") else None)
        rows.append({"Check": "aws base credentials", "UsedBy": "sts:AssumeRole",
                     "Status": f"from {base}" if base else "default chain (SSO/instance role/config)"})
        for a in inv.aws_accounts:
            env_row(a.external_id_env, a.name)

    if test_connections:
        from nettrace.engine import Clients

        clients = Clients(inv)
        if inv.panorama:
            try:
                info = clients.panorama.system_info()  # type: ignore[union-attr]
                n = len(clients.panorama.devices())  # type: ignore[union-attr]
                status = f"ok (Panorama {info.get('sw-version', '?')}, {n} managed firewalls)"
            except Exception as exc:
                status = f"FAILED: {exc}"
            rows.append({"Check": "connect panorama", "UsedBy": inv.panorama.host, "Status": status})
        for d in inv.devices.values():
            try:
                c = clients.device(d)
                if d.platform == "cisco_iosxe":
                    c.show("show version")
                    status = "ok (show version)"
                else:
                    info = c.system_info()
                    status = f"ok ({info.get('model', '?')} PAN-OS {info.get('sw-version', '?')})"
            except Exception as exc:  # report every failure, keep going
                status = f"FAILED: {exc}"
            used_by = f"panorama target {d.serial}" if d.via == "panorama" else d.host
            rows.append({"Check": f"connect {d.name}", "UsedBy": used_by, "Status": status})
        clients.close()
        if inv.aws_accounts:
            from nettrace.drivers.aws import AwsEnv

            env = AwsEnv(inv)
            for a in inv.aws_accounts:
                try:
                    env.call(a.account_id, a.regions[0], "describe_vpcs", MaxResults=5)
                    status = "ok (ec2:DescribeVpcs)"
                except Exception as exc:
                    status = f"FAILED: {exc}"
                rows.append({"Check": f"aws {a.name}", "UsedBy": a.role_arn or a.profile or "base credentials",
                             "Status": status})
        if inv.prisma:
            from nettrace.drivers.prisma import ScmClient

            try:
                if ScmClient.transport_override is not None:  # simulated (demo lab): no OAuth endpoint
                    n = len(ScmClient().security_rules(inv.prisma.mobile_users_folder))
                    status = f"ok ({n} rules in {inv.prisma.mobile_users_folder})"
                else:
                    ScmClient()._get_token()
                    status = "ok (token issued)"
            except Exception as exc:
                status = f"FAILED: {exc}"
            rows.append({"Check": "strata cloud manager", "UsedBy": "prisma-access", "Status": status})
    ctx.emit(rows)


# ===== entry point ===============================================================================
_GLOBAL_WITH_VALUE = {"--output", "-o", "--query", "--inventory", "-i"}
_GLOBAL_FLAGS = {"--no-color", "--debug", "--demo"}


def hoist_global_options(argv: list[str]) -> list[str]:
    """Allow global options anywhere on the line, as the AWS CLI does
    (`nettrace trace run ... --output json`)."""
    globals_, rest = [], []
    i = 0
    while i < len(argv):
        arg = argv[i]
        name = arg.split("=", 1)[0]
        if arg == "--":
            rest.extend(argv[i:])
            break
        if name in _GLOBAL_WITH_VALUE:
            if "=" in arg:
                globals_.append(arg)
            elif i + 1 < len(argv):
                globals_.extend(argv[i:i + 2])
                i += 1
            else:
                rest.append(arg)
        elif arg in _GLOBAL_FLAGS:
            globals_.append(arg)
        else:
            rest.append(arg)
        i += 1
    return globals_ + rest


def main() -> None:
    import warnings

    # Inventory and driver warnings: one plain line each, not Python's file:line format.
    warnings.showwarning = lambda msg, *_a, **_k: Console(stderr=True).print(
        f"[yellow]warning:[/] {escape(clean(str(msg)))}")
    try:
        cli(args=hoist_global_options(sys.argv[1:]), prog_name="nettrace", standalone_mode=False)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except (click.exceptions.Abort, KeyboardInterrupt):
        sys.exit(130)
    except NetTraceError as exc:
        Console(stderr=True).print(f"[red]error:[/] {escape(clean(str(exc)))}")
        sys.exit(1)
    except Exception as exc:
        if "--debug" in sys.argv:
            raise
        Console(stderr=True).print(f"[red]unexpected error:[/] {type(exc).__name__}: {escape(clean(str(exc)))} (use --debug for a traceback)")
        sys.exit(1)
