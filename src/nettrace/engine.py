"""Hop-by-hop orchestration across Cisco, PAN-OS, Prisma Access and AWS."""

from __future__ import annotations

from typing import Any, Callable

from nettrace import audit
from nettrace.drivers import cisco_iosxe, panos, prisma
from nettrace.errors import CancelToken, Cancelled, Deadline, NetTraceError, ReadOnlyViolation
from nettrace.inventory import Device, Inventory, LinkEnd
from nettrace.models import Flow, Hop, Outcome, Status, TraceResult
from nettrace.steps import AwsAt, DeviceAt, Egress, Position, PrismaAt, StepResult

DEFAULT_MAX_HOPS = 30
ONPREM_SITE = "On-prem"
PRISMA_SITE = "Prisma Access"


def _failure(exc: Exception) -> str:
    """User-facing text for any driver failure. NetTraceError messages are already clean; anything else
    (netmiko, botocore, requests, IndexError on a resource that isn't visible...) gets its type name."""
    return str(exc) if isinstance(exc, NetTraceError) else f"{type(exc).__name__}: {str(exc)[:300]}"


def _audit_kind(pos: Position, inv: Inventory) -> str:
    if isinstance(pos, DeviceAt) and pos.device in inv.devices:
        return "ssh" if inv.devices[pos.device].platform == "cisco_iosxe" else "panos"
    return "scm" if isinstance(pos, PrismaAt) else "aws"


class Clients:
    """Lazily-created, per-run connections. Close with .close()."""

    def __init__(self, inv: Inventory, deadline: Deadline | None = None):
        self.inv = inv
        self.deadline = deadline
        self._devices: dict[str, Any] = {}
        self._scm: prisma.ScmClient | None = None
        self._aws: Any = None
        self._panorama: panos.PanoramaClient | None = None

    @property
    def panorama(self) -> panos.PanoramaClient | None:
        if self._panorama is None and self.inv.panorama:
            self._panorama = panos.PanoramaClient(self.inv.panorama)
            self._panorama.api.deadline = self.deadline
        return self._panorama

    def device(self, dev: Device) -> Any:
        if dev.name not in self._devices:
            if dev.platform == "cisco_iosxe":
                client = cisco_iosxe.CiscoClient(dev)
                client.deadline = self.deadline
            else:
                client = panos.make_client(dev, self.panorama)
                client.api.deadline = self.deadline
            self._devices[dev.name] = client
        return self._devices[dev.name]

    @property
    def scm(self) -> prisma.ScmClient:
        if self._scm is None:
            self._scm = prisma.ScmClient()
            self._scm.deadline = self.deadline
        return self._scm

    @property
    def aws(self) -> Any:
        if self._aws is None:
            from nettrace.drivers.aws import AwsEnv

            if not self.inv.aws_accounts:
                raise NetTraceError("no AWS accounts in the inventory (aws.accounts)")
            self._aws = AwsEnv(self.inv)
            self._aws.deadline = self.deadline
        return self._aws

    def close(self) -> None:
        for c in self._devices.values():
            if hasattr(c, "close"):
                c.close()


class Tracer:
    def __init__(self, inv: Inventory, *, max_hops: int = DEFAULT_MAX_HOPS, check_return: bool = True,
                 progress: Callable[[str], None] | None = None, timeout: float | None = None,
                 cancel: CancelToken | None = None):
        self.inv = inv
        self.timeout = timeout if timeout is not None else inv.trace_timeout
        self.cancel = cancel if cancel is not None else CancelToken()
        self.deadline = Deadline(self.timeout, self.cancel)  # starts now: one Tracer = one trace
        self.clients = Clients(inv, self.deadline)
        self.max_hops = max_hops
        self.check_return = check_return
        self.progress = progress or (lambda _msg: None)

    # ---- locations (for map grouping) ---------------------------------------------------------------
    def device_location(self, dev: Device) -> dict[str, str]:
        if dev.aws and dev.aws.account:
            acct = self.inv.account(dev.aws.account)
            loc = {"cloud": "aws", "account": acct.account_id if acct else dev.aws.account,
                   "account_name": acct.name if acct else dev.aws.account}
            if dev.aws.region:
                loc["region"] = dev.aws.region
            return loc
        return {"site": dev.site or ONPREM_SITE}

    # ---- source --------------------------------------------------------------------------------
    def locate_source(self, flow: Flow, start_at: str | None) -> tuple[Position, Hop]:
        def info(summary: str, location: dict[str, str]) -> Hop:
            return Hop(domain="engine", node=flow.src, component="source", status=Status.INFO, summary=summary,
                       location=location)

        if start_at:
            dev = self.inv.device(start_at)
            return DeviceAt(device=start_at), info(f"starting at {start_at} (--start-at)", self.device_location(dev))
        net = self.inv.network_for(flow.src)
        if net:
            gw = self.inv.device(net.gateway)
            return (DeviceAt(device=net.gateway, vrf=net.vrf),
                    info(f"{flow.src} is in {net.prefix}; gateway {net.gateway}", self.device_location(gw)))
        loc = self.inv.prisma_location(flow.src)
        if loc:
            return (PrismaAt(entry="source", name=loc[1]),
                    info(f"{flow.src} is a Prisma Access {loc[0].replace('_', ' ')} ({loc[1]})", {"site": PRISMA_SITE}))
        owned = self.inv.device_by_address(flow.src)
        if owned:
            return (DeviceAt(device=owned[0].name),
                    info(f"{flow.src} is an address on {owned[0].name}", self.device_location(owned[0])))
        if self.inv.aws_accounts:
            self.progress(f"searching {len(self.clients.aws.targets())} AWS account/region pairs for {flow.src}")
            hit = self.clients.aws.find_eni(flow.src)
            if hit:
                acct, region, eni = hit
                owner = (eni.get("Attachment") or {}).get("InstanceId") or eni.get("Description") or eni.get("InterfaceType")
                a = self.inv.account(acct)
                where = {"cloud": "aws", "account": acct, "account_name": a.name if a else acct, "region": region,
                         "vpc": eni["VpcId"]}
                return (AwsAt(kind="source_eni", account=acct, region=region, resource_id=eni["NetworkInterfaceId"]),
                        info(f"{flow.src} is {eni['NetworkInterfaceId']} ({owner}) in {eni['VpcId']}, {acct}/{region}",
                             where))
        raise NetTraceError(
            f"can't tell where {flow.src} lives. Add its prefix under 'networks' in the inventory, "
            "or pass --start-at <device>.")

    # ---- dispatch -------------------------------------------------------------------------------
    def _step(self, pos: Position, flow: Flow) -> StepResult:
        if isinstance(pos, DeviceAt):
            dev = self.inv.device(pos.device)
            self.progress(f"querying {dev.name} ({dev.platform})")
            client = self.clients.device(dev)
            if dev.platform == "cisco_iosxe":
                res = cisco_iosxe.step(client, pos, flow)
            else:
                res = panos.step(client, pos, flow)
            base = self.device_location(dev)
            for h in res.hops:
                h.location = {**base, **h.location}
            return res
        if isinstance(pos, AwsAt):
            from nettrace.drivers.aws import AwsWalker

            self.progress(f"walking AWS from {pos.kind} {pos.resource_id or pos.ip}")
            return AwsWalker(self.clients.aws, self.inv, check_return=self.check_return).walk(pos, flow)
        if isinstance(pos, PrismaAt):
            if not self.inv.prisma:
                raise NetTraceError("path enters Prisma Access but prisma_access is not configured in the inventory")
            self.progress("evaluating Prisma Access security rules (Strata Cloud Manager)")
            res = prisma.step(self.clients.scm, self.inv, pos, flow)
            for h in res.hops:
                h.location = {"site": PRISMA_SITE, **h.location}
            return res
        raise NetTraceError(f"unknown position {pos!r}")

    def _from_link_end(self, there: LinkEnd) -> Position:
        if there.device:
            return DeviceAt(device=there.device, arrival_interface=there.interface, arrival_ip=there.next_hop)
        if there.aws_tgw_attachment:
            return AwsAt(kind="tgw_attachment", resource_id=there.aws_tgw_attachment, account=there.aws_account,
                         region=there.aws_region)
        if there.aws_vgw:
            return AwsAt(kind="vgw", resource_id=there.aws_vgw, account=there.aws_account, region=there.aws_region)
        return PrismaAt(entry="service_connection", name=there.prisma_service_connection)

    def _egress_ip(self, dev: Device, interface: str | None) -> str | None:
        if not interface:
            return None
        client = self.clients.device(dev)
        if dev.platform == "panos":
            return (client.interfaces().get(interface, {}).get("ip") or "").split("/")[0] or None
        ips = client.interface(interface).get("IP_ADDRESS") or []
        return ips[0] if ips else None

    def _resolve_egress(self, eg: Egress, flow: Flow) -> tuple[Position | None, Outcome | None, str, Hop | None]:
        dev = self.inv.device(eg.device)
        link = self.inv.link_from_device(eg.device, eg.interface, eg.next_hop)
        if link:
            lk, there = link
            hop = Hop(domain="engine", node=lk.name, component="link", status=Status.INFO,
                      summary=f"{eg.device} {eg.interface} -> {there.label()}")
            if there.external:
                return None, Outcome.EXITED, f"leaves via {eg.device} {eg.interface} to {there.external}", hop
            return self._from_link_end(there), None, "", hop
        if dev.aws:
            ip = self._egress_ip(dev, eg.interface)
            acct = self.inv.account(dev.aws.account) if dev.aws.account else None
            if not ip:
                return None, Outcome.INCOMPLETE, f"{dev.name}: can't find the IP of egress interface {eg.interface}", None
            return AwsAt(kind="appliance_egress", ip=ip, account=acct.account_id if acct else None,
                         region=dev.aws.region), None, "", None
        if eg.next_hop is None:
            owner = self.inv.device_by_address(flow.dst)
            where = f" ({owner[0].name})" if owner else ""
            return None, Outcome.REACHABLE, f"{flow.dst}{where} is on a subnet connected to {eg.device} {eg.interface}", None
        hit = self.inv.device_by_address(eg.next_hop)
        if hit:
            nxt, intf = hit
            return DeviceAt(device=nxt.name, arrival_ip=eg.next_hop, arrival_interface=intf), None, "", None
        return None, Outcome.EXITED, (f"next hop {eg.next_hop} from {eg.device} is not in the inventory "
                                      "(run 'nettrace inventory discover' or add a link)"), None

    # ---- main loop ---------------------------------------------------------------------------------
    def trace(self, flow: Flow, start_at: str | None = None) -> TraceResult:
        original = flow
        hops: list[Hop] = []
        warnings: list[str] = []
        outcome, reason = Outcome.INCOMPLETE, "max hops reached"
        visited: set[str] = set()
        cancelled = False
        try:
            pos, first = self.locate_source(flow, start_at)
            hops.append(first)
            for _ in range(self.max_hops):
                key = f"{pos!r}|{flow.src}|{flow.dst}"
                if key in visited:
                    outcome, reason = Outcome.BLOCKED, f"forwarding loop: {pos} visited twice"
                    break
                visited.add(key)
                try:
                    self.deadline.check()
                    res = self._step(pos, flow)
                except (Cancelled, KeyboardInterrupt):  # Ctrl-C in the CLI is the same as a cancel
                    cancelled = True
                    break
                except Exception as exc:  # any driver failure becomes an UNKNOWN hop; hops so far are kept
                    if self.cancel.cancelled:  # a driver wrapped the Cancelled it hit: still a cancel, not a device fault
                        cancelled = True
                        break
                    if isinstance(exc, ReadOnlyViolation):  # normally logged at the choke point already
                        audit.refused(exc, _audit_kind(pos, self.inv), str(getattr(pos, "device", "") or "-"), str(exc))
                    where: dict[str, str] = {}
                    if isinstance(pos, DeviceAt) and pos.device in self.inv.devices:
                        where = self.device_location(self.inv.devices[pos.device])
                    elif isinstance(pos, PrismaAt):
                        where = {"site": PRISMA_SITE}
                    hops.append(Hop(domain="engine", node=getattr(pos, "device", None) or type(pos).__name__,
                                    component="error", status=Status.UNKNOWN, summary=_failure(exc), location=where))
                    outcome, reason = Outcome.INCOMPLETE, _failure(exc)
                    break
                hops.extend(res.hops)
                warnings.extend(res.warnings)
                flow = res.flow
                if res.outcome:
                    outcome, reason = res.outcome, res.reason
                    break
                if res.next is not None:
                    pos = res.next
                    continue
                if res.egress is None:
                    outcome, reason = Outcome.INCOMPLETE, "driver returned no next step"
                    break
                nxt, term, why, link_hop = self._resolve_egress(res.egress, flow)
                if link_hop:
                    hops.append(link_hop)
                if term:
                    outcome, reason = term, why
                    break
                pos = nxt  # type: ignore[assignment]
        except (Cancelled, KeyboardInterrupt):
            cancelled = True
        except Exception as exc:  # e.g. source lookup in AWS failed
            if self.cancel.cancelled:
                cancelled = True
            else:
                outcome, reason = Outcome.INCOMPLETE, _failure(exc)
        finally:
            self.clients.close()

        if cancelled:  # keep the hops found so far; never a verified result
            self.cancel.cancel()
            outcome, reason = Outcome.INCOMPLETE, "cancelled by user"
            warnings.append("trace cancelled; the hops listed are those found before it stopped")

        unknown = sum(h.status == Status.UNKNOWN for h in hops)
        # never guess: a skipped component is not a verified path, whether it ends at dst or leaves the network
        if outcome in (Outcome.REACHABLE, Outcome.EXITED) and unknown:
            outcome, reason = Outcome.INCOMPLETE, f"{reason}, but {unknown} hop(s) could not be evaluated (UNKNOWN)"
            warnings.append("some components could not be evaluated; see UNKNOWN hops")
        for i, h in enumerate(hops, start=1):
            h.index = i
        return TraceResult(flow=original, outcome=outcome, reason=reason, hops=hops,
                           warnings=list(dict.fromkeys(warnings)), final_flow=flow, cancelled=cancelled)
