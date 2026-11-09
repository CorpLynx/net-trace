"""AWS: ENIs, security groups, NACLs, VPC route tables, Transit Gateways, GWLB endpoints,
NAT gateways, VPC peering. Multi-account via sts:AssumeRole. Exact read-only allowlist (readonly.py).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nettrace import audit
from nettrace.errors import CredentialError, Deadline, NetTraceError, ReadOnlyViolation
from nettrace.inventory import AwsAccount, Inventory
from nettrace.models import Evidence, Flow, Hop, Outcome, Status
from nettrace.netutil import DEFAULT_EPHEMERAL_PORT, protocol_number
from nettrace.readonly import check_aws_operation, install_aws_guard
from nettrace.steps import AwsAt, DeviceAt, PrismaAt, StepResult

MAX_AWS_STEPS = 40
ASSUME_DURATION = 900  # seconds; the shortest STS allows. Expired sessions are re-assumed once.
_SESSION_POLICY_FILE = Path(__file__).resolve().parents[3] / "iam" / "nettrace-readonly-policy.json"
_SESSION_POLICY_MAX = 2048  # STS limit on the packed inline session policy (characters)


def session_name() -> str:
    """nettrace-<user>-<host> for CloudTrail attribution: [\\w+=,.@-], at most 64 characters."""
    try:
        user = os.environ.get("USER") or os.getlogin()
    except OSError:
        user = "user"
    name = re.sub(r"[^\w+=,.@-]", "-", f"nettrace-{user}-{socket.gethostname().split('.')[0]}")
    return name[:64]


def boto_config() -> Any:
    """Bounded waits for every boto3 client: a dead endpoint costs seconds, not the default 60 s x retries."""
    from botocore.config import Config

    return Config(connect_timeout=5, read_timeout=20, retries={"mode": "standard", "max_attempts": 3})


class AmbiguousEni(NetTraceError):
    """Several ENIs own the same IP (overlapping address space across accounts/VPCs)."""


def session_policy() -> str | None:
    """The read-only IAM policy as a compact inline session policy, or None (with a warning) if it
    cannot be used. shortcut: the file is not packaged in wheels (editable installs only); then the
    role's own permissions are the only limit. Upgrade: ship the policy as package data."""
    try:
        doc = json.dumps(json.loads(_SESSION_POLICY_FILE.read_text()), separators=(",", ":"))
    except (OSError, ValueError):
        warnings.warn(f"{_SESSION_POLICY_FILE} not readable: AssumeRole without a session policy", stacklevel=2)
        return None
    if len(doc) > _SESSION_POLICY_MAX:
        warnings.warn("session policy exceeds the 2048-character STS limit: AssumeRole without it", stacklevel=2)
        return None
    return doc


# ==== sessions ======================================================================
class AwsEnv:
    # Simulation seam (used by the demo lab and tests): a factory returning an object with
    # .call(account_id, region, op, params) -> dict. When set, boto3 is never used.
    backend_override: Any = None
    deadline: Deadline | None = None  # overall trace budget, set by the engine

    def __init__(self, inv: Inventory):
        self.inv = inv
        self._sessions: dict[str, Any] = {}
        self._clients: dict[tuple[str, str, str], Any] = {}
        self._cache: dict[str, Any] = {}
        self.evidence: list[Evidence] = []
        self._backend = AwsEnv.backend_override(self) if AwsEnv.backend_override else None
        if self._backend is None:
            import boto3  # lazy: slow import

            self._boto3 = boto3
            self.base = install_aws_guard(boto3.Session())

    # ---- credentials -------------------------------------------------------------
    def account(self, name_or_id: str | None) -> AwsAccount:
        if not name_or_id:
            raise NetTraceError("AWS account not specified")
        acct = self.inv.account(str(name_or_id))
        if not acct:
            raise NetTraceError(f"AWS account {name_or_id} is not in the inventory (aws.accounts)")
        return acct

    def session(self, account_id: str) -> Any:
        if account_id in self._sessions:
            return self._sessions[account_id]
        acct = self.account(account_id)
        if acct.role_arn:
            params = {"RoleArn": acct.role_arn, "RoleSessionName": session_name(), "DurationSeconds": ASSUME_DURATION}
            policy = session_policy()
            if policy:
                params["Policy"] = policy
            if acct.external_id_env:
                ext = os.environ.get(acct.external_id_env)
                if not ext:
                    raise CredentialError(f"environment variable {acct.external_id_env} (external id) is not set")
                params["ExternalId"] = ext
            try:
                creds = self.base.client("sts", config=boto_config()).assume_role(**params)["Credentials"]
            except Exception as exc:
                raise CredentialError(f"assume role {acct.role_arn} failed: {exc}") from None
            sess = self._boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                                       aws_secret_access_key=creds["SecretAccessKey"],
                                       aws_session_token=creds["SessionToken"])
        elif acct.profile:
            sess = self._boto3.Session(profile_name=acct.profile)
        else:
            sess = self.base
        install_aws_guard(sess)
        self._sessions[account_id] = sess
        return sess

    def client(self, account_id: str, region: str, service: str = "ec2") -> Any:
        key = (account_id, region, service)
        if key not in self._clients:
            self._clients[key] = self.session(account_id).client(service, region_name=region, config=boto_config())
        return self._clients[key]

    def call(self, account_id: str, region: str, op: str, service: str = "ec2", **params: Any) -> dict[str, Any]:
        key = json.dumps([account_id, region, service, op, params], sort_keys=True, default=str)
        if key in self._cache:
            return self._cache[key]
        if self.deadline:
            self.deadline.check()
        try:
            if self._backend is not None:
                api_name = "".join(part.title() for part in op.split("_"))
                check_aws_operation(service, api_name)  # same rule as the botocore hook
                result = self._backend.call(account_id, region, op, dict(params))
            else:
                result = self._boto_call(account_id, region, op, service, params)
        except ReadOnlyViolation as exc:
            audit.refused(exc, "aws", account_id, f"{service}.{op}")
            raise
        except Exception:
            audit.log("aws", account_id, f"{service}.{op} {json.dumps(params, default=str)}", "error")
            raise
        return self._record(key, account_id, region, service, op, params, result)

    def _boto_call(self, account_id: str, region: str, op: str, service: str, params: dict[str, Any],
                   _retry: bool = True) -> dict[str, Any]:
        try:
            return self._boto_call_once(account_id, region, op, service, params)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if not (_retry and code in ("ExpiredToken", "ExpiredTokenException")):
                raise
        # Session credentials expired: drop this account's session and clients, re-assume once.
        self._sessions.pop(account_id, None)
        self._clients = {k: v for k, v in self._clients.items() if k[0] != account_id}
        return self._boto_call(account_id, region, op, service, params, _retry=False)

    def _boto_call_once(self, account_id: str, region: str, op: str, service: str,
                        params: dict[str, Any]) -> dict[str, Any]:
        client = self.client(account_id, region, service)
        if client.can_paginate(op):
            result: dict[str, Any] = {}
            for page in client.get_paginator(op).paginate(**params):
                for k, v in page.items():
                    if isinstance(v, list):
                        result.setdefault(k, []).extend(v)
        else:
            result = getattr(client, op)(**params)
        result.pop("ResponseMetadata", None)
        return result

    def _record(self, key: str, account_id: str, region: str, service: str, op: str, params: dict[str, Any],
                result: dict[str, Any]) -> dict[str, Any]:
        self._cache[key] = result
        audit.log("aws", account_id, f"{service}.{op} {json.dumps(params, default=str)}", "ok")
        acct = self.inv.account(account_id)
        label = f"{acct.name if acct else account_id}/{region}"
        self.evidence.append(Evidence(label, f"{service}.{op} {json.dumps(params, default=str)}",
                                      json.dumps(result, default=str)[:1500]))
        return result

    def targets(self) -> list[tuple[str, str]]:
        return [(a.account_id, r) for a in self.inv.aws_accounts for r in a.regions]

    # ---- lookups -------------------------------------------------------------------
    def find_eni(self, ip: str, only: list[tuple[str, str]] | None = None,
                 vpc_id: str | None = None) -> tuple[str, str, dict[str, Any]] | None:
        """Find the ENI that owns a private (or public) IP across all inventory accounts/regions.

        `vpc_id` narrows the search when the caller knows the VPC: private ranges overlap across accounts
        and VPCs. If several different ENIs still own the IP this raises AmbiguousEni (listing them)
        instead of picking one."""
        targets = only or self.targets()
        vpc = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []

        def probe(t: tuple[str, str]) -> tuple[str, str, dict[str, Any]] | None:
            acct, region = t
            for flt in ("addresses.private-ip-address", "association.public-ip"):
                enis = self.call(acct, region, "describe_network_interfaces",
                                 Filters=[{"Name": flt, "Values": [ip]}, *vpc]).get("NetworkInterfaces", [])
                if enis:
                    return acct, region, enis[0]
            return None

        if len(targets) == 1:
            hits = [probe(targets[0])]
        else:
            with ThreadPoolExecutor(max_workers=min(16, len(targets) or 1)) as pool:
                hits = list(pool.map(probe, targets))
        found: dict[tuple[str, str], tuple[str, str, dict[str, Any]]] = {}
        for hit in hits:  # the same ENI seen from two accounts (shared subnets) counts once
            if hit:
                found.setdefault((hit[1], hit[2]["NetworkInterfaceId"]), hit)
        if len(found) > 1:
            where = "; ".join(f"{e['NetworkInterfaceId']} ({a}/{r}, {e.get('VpcId')})" for a, r, e in found.values())
            raise AmbiguousEni(f"{ip} is owned by {len(found)} ENIs (overlapping address space): {where}. "
                               "Narrow it with --start-at or the inventory; nettrace will not pick one")
        return next(iter(found.values()), None)

    def eni(self, acct: str, region: str, eni_id: str) -> dict[str, Any]:
        return self.call(acct, region, "describe_network_interfaces",
                         NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]

    def subnet(self, acct: str, region: str, subnet_id: str) -> dict[str, Any]:
        return self.call(acct, region, "describe_subnets", SubnetIds=[subnet_id])["Subnets"][0]

    def route_table(self, acct: str, region: str, subnet_id: str, vpc_id: str) -> dict[str, Any]:
        explicit = self.call(acct, region, "describe_route_tables",
                             Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get("RouteTables", [])
        if explicit:
            return explicit[0]
        main = self.call(acct, region, "describe_route_tables",
                         Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                  {"Name": "association.main", "Values": ["true"]}]).get("RouteTables", [])
        if not main:
            raise NetTraceError(f"no route table found for {subnet_id}")
        return main[0]

    def nacl(self, acct: str, region: str, subnet_id: str) -> dict[str, Any] | None:
        acls = self.call(acct, region, "describe_network_acls",
                         Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get("NetworkAcls", [])
        return acls[0] if acls else None

    def security_groups(self, acct: str, region: str, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        return self.call(acct, region, "describe_security_groups", GroupIds=sorted(ids)).get("SecurityGroups", [])

    def prefix_list(self, acct: str, region: str, pl_id: str) -> list[str]:
        try:
            entries = self.call(acct, region, "get_managed_prefix_list_entries", PrefixListId=pl_id).get("Entries", [])
        except Exception:
            return []
        return [e["Cidr"] for e in entries]

    def tgw_owner(self, acct: str, region: str, tgw_id: str) -> str:
        tgws = self.call(acct, region, "describe_transit_gateways", TransitGatewayIds=[tgw_id]).get("TransitGateways", [])
        if not tgws:
            raise NetTraceError(f"{tgw_id} not visible from account {acct}")
        return tgws[0]["OwnerId"]

    def search_tgw_routes(self, acct: str, region: str, rtb: str, ip: str) -> dict[str, Any] | None:
        host = f"{ip}/32" if ipaddress.ip_address(ip).version == 4 else f"{ip}/128"
        try:
            routes = self.call(acct, region, "search_transit_gateway_routes", TransitGatewayRouteTableId=rtb,
                               Filters=[{"Name": "route-search.longest-prefix-match", "Values": [host]}]).get("Routes", [])
        except Exception:
            # Older API behaviour: fetch supernet matches and pick the longest ourselves.
            routes = self.call(acct, region, "search_transit_gateway_routes", TransitGatewayRouteTableId=rtb,
                               Filters=[{"Name": "route-search.supernet-of-match", "Values": [host]}]).get("Routes", [])
        candidates = []
        for r in routes:
            cidr = r.get("DestinationCidrBlock")
            if cidr and ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                candidates.append((ipaddress.ip_network(cidr).prefixlen, r))
            elif r.get("PrefixListId") and not cidr:
                candidates.append((0, r))
        if not candidates:
            return None
        return max(candidates, key=lambda c: c[0])[1]


# ==== pure evaluators ======================================================================
def _proto_matches(rule_proto: str, flow_proto: int) -> bool:
    if rule_proto in ("-1", "all"):
        return True
    try:
        return protocol_number(rule_proto) == flow_proto
    except ValueError:
        return False


def _port_matches(flow_proto: int, port: int | None, lo: int | None, hi: int | None) -> bool:
    if flow_proto == 1:  # ICMP: FromPort = type, ToPort = code; nettrace models echo-request (8)
        return lo in (None, -1) or lo == 8
    if flow_proto not in (6, 17):
        return True
    if lo is None or lo == -1:
        return True
    if port is None:
        return lo == 0 and (hi or 0) >= 65535
    return lo <= port <= (hi if hi is not None else lo)


@dataclass
class Decision:
    allowed: bool
    detail: str


def evaluate_sg(env: AwsEnv, acct: str, region: str, groups: list[dict[str, Any]], *, egress: bool,
                peer_ip: str, peer_sgs: set[str], flow: Flow) -> Decision:
    proto = protocol_number(flow.protocol)
    port = flow.dst_port
    addr = ipaddress.ip_address(peer_ip)
    for sg in groups:
        perms = sg.get("IpPermissionsEgress" if egress else "IpPermissions", [])
        for perm in perms:
            if not _proto_matches(str(perm.get("IpProtocol")), proto):
                continue
            if not _port_matches(proto, port, perm.get("FromPort"), perm.get("ToPort")):
                continue
            ranges = [r["CidrIp"] for r in perm.get("IpRanges", [])] + [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
            for cidr in ranges:
                net = ipaddress.ip_network(cidr)
                if net.version == addr.version and addr in net:
                    return Decision(True, f"{sg['GroupId']} ({sg.get('GroupName')}) {'egress' if egress else 'ingress'} "
                                          f"{perm.get('IpProtocol')} {perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')} {cidr}")
            for pl in perm.get("PrefixListIds", []):
                for cidr in env.prefix_list(acct, region, pl["PrefixListId"]):
                    if addr in ipaddress.ip_network(cidr):
                        return Decision(True, f"{sg['GroupId']} prefix list {pl['PrefixListId']} ({cidr})")
            for pair in perm.get("UserIdGroupPairs", []):
                if pair.get("GroupId") in peer_sgs:
                    return Decision(True, f"{sg['GroupId']} references {pair['GroupId']}")
    ids = ", ".join(g["GroupId"] for g in groups)
    return Decision(False, f"no {'egress' if egress else 'ingress'} rule in {ids} allows "
                           f"{flow.protocol}/{port or 'any'} {'to' if egress else 'from'} {peer_ip}")


def evaluate_nacl(nacl: dict[str, Any], *, egress: bool, peer_ip: str, protocol: str, port: int | None) -> Decision:
    proto = protocol_number(protocol)
    addr = ipaddress.ip_address(peer_ip)
    entries = sorted((e for e in nacl.get("Entries", []) if e.get("Egress") == egress), key=lambda e: e["RuleNumber"])
    for e in entries:
        cidr = e.get("CidrBlock") or e.get("Ipv6CidrBlock")
        if not cidr:
            continue
        net = ipaddress.ip_network(cidr)
        if net.version != addr.version or addr not in net:
            continue
        if not _proto_matches(str(e.get("Protocol")), proto):
            continue
        pr = e.get("PortRange")
        if proto in (6, 17) and pr and not _port_matches(proto, port, pr.get("From"), pr.get("To")):
            continue
        if proto == 1 and e.get("IcmpTypeCode") and e["IcmpTypeCode"].get("Type") not in (-1, 8, None):
            continue
        rule = "*" if e["RuleNumber"] == 32767 else e["RuleNumber"]
        return Decision(e["RuleAction"] == "allow", f"{nacl['NetworkAclId']} {'out' if egress else 'in'} rule {rule} "
                                                    f"{e['RuleAction']} {cidr}")
    return Decision(False, f"{nacl['NetworkAclId']} {'out' if egress else 'in'}: implicit deny")


def lookup_route(env: AwsEnv, acct: str, region: str, rtb: dict[str, Any], ip: str) -> dict[str, Any] | None:
    addr = ipaddress.ip_address(ip)
    best: tuple[int, dict[str, Any]] | None = None
    for r in rtb.get("Routes", []):
        cidrs = []
        if r.get("DestinationCidrBlock"):
            cidrs = [r["DestinationCidrBlock"]]
        elif r.get("DestinationIpv6CidrBlock"):
            cidrs = [r["DestinationIpv6CidrBlock"]]
        elif r.get("DestinationPrefixListId"):
            cidrs = env.prefix_list(acct, region, r["DestinationPrefixListId"])
        for c in cidrs:
            net = ipaddress.ip_network(c)
            if net.version == addr.version and addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, dict(r, _matched=c))
    return best[1] if best else None


def route_target(route: dict[str, Any]) -> tuple[str, str]:
    for key in ("TransitGatewayId", "NatGatewayId", "VpcPeeringConnectionId", "NetworkInterfaceId", "InstanceId",
                "VpcEndpointId", "LocalGatewayId", "CarrierGatewayId", "CoreNetworkArn", "EgressOnlyInternetGatewayId"):
        if route.get(key):
            return key, route[key]
    gw = route.get("GatewayId", "")
    if gw == "local":
        return "local", "local"
    if gw.startswith("vpce-"):
        return "VpcEndpointId", gw
    if gw.startswith("igw-"):
        return "InternetGatewayId", gw
    if gw.startswith("vgw-"):
        return "VpnGatewayId", gw
    return "unknown", gw or "?"


# ==== walker ======================================================================================
class AwsWalker:
    """Walks a flow through AWS until it is delivered, blocked, leaves AWS, or reaches a firewall."""

    # Components that live at region level, outside any VPC (for map grouping).
    REGIONAL = {"tgw", "tgw-route-table", "exit"}

    def __init__(self, env: AwsEnv, inv: Inventory, check_return: bool = True):
        self.env, self.inv, self.check_return = env, inv, check_return
        self._mark = 0
        self._region: str | None = None  # where the walk currently is; used for hop locations
        self._vpc: str | None = None
        self._tgw_entries: set[tuple[str, str, str]] = set()  # (attachment, src, dst) VPC entries from a TGW

    def _at(self, region: str | None, vpc: str | None) -> None:
        self._region, self._vpc = region, vpc

    # ---- hop helpers --------------------------------------------------------------------------
    def _hop(self, acct: str, component: str, node: str, status: Status, summary: str, *,
             vpc: str | None = None, **kw: Any) -> Hop:
        a = self.inv.account(acct)
        kw.setdefault("details", [])
        kw["details"] = [f"account {a.name if a else acct} ({acct})"] + kw["details"]
        evidence = self.env.evidence[self._mark:]
        self._mark = len(self.env.evidence)
        location = {"cloud": "aws", "account": acct, "account_name": a.name if a else acct}
        if self._region:
            location["region"] = self._region
        vpc = vpc or (None if component in self.REGIONAL else self._vpc)
        if vpc:
            location["vpc"] = vpc
        return Hop(domain="aws", node=node, component=component, status=status, summary=summary,
                   evidence=list(evidence), location=location, **kw)

    def _cross(self, acct: str, region: str, flow: Flow, from_subnet: str | None, to_subnet: str | None,
               hops: list[Hop], warnings: list[str], *, leaving_vpc: bool = False) -> bool:
        """NACL checks when traffic moves between subnets. Returns False if blocked."""
        if from_subnet and to_subnet and from_subnet == to_subnet and not leaving_vpc:
            return True
        checks = []
        if from_subnet:
            checks.append((from_subnet, True, flow.dst))
        if to_subnet and to_subnet != from_subnet:
            checks.append((to_subnet, False, flow.src))
        if leaving_vpc and from_subnet and to_subnet == from_subnet:
            checks.append((from_subnet, False, flow.src))  # same-subnet TGW attachment case (AWS docs)
        for subnet_id, egress, peer in checks:
            nacl = self.env.nacl(acct, region, subnet_id)
            if not nacl:
                continue
            nacl_vpc = nacl.get("VpcId")
            d = evaluate_nacl(nacl, egress=egress, peer_ip=peer, protocol=flow.protocol, port=flow.dst_port)
            details = [f"subnet {subnet_id}"]
            status = Status.PASS if d.allowed else Status.BLOCK
            if d.allowed and self.check_return and protocol_number(flow.protocol) in (6, 17):
                rport = flow.src_port or DEFAULT_EPHEMERAL_PORT
                r = evaluate_nacl(nacl, egress=not egress, peer_ip=peer, protocol=flow.protocol, port=rport)
                if not r.allowed:
                    status = Status.WARN
                    msg = f"return traffic (port {rport}) blocked by {r.detail}"
                    details.append(msg)
                    warnings.append(f"{nacl['NetworkAclId']}: {msg}")
            direction = "outbound" if egress else "inbound"
            hops.append(self._hop(acct, "nacl", nacl["NetworkAclId"], status,
                                  f"{subnet_id} {direction} {'allowed' if d.allowed else 'DENIED'}",
                                  details=details, policy=d.detail.split(" ", 1)[1], vpc=nacl_vpc))
            if not d.allowed:
                return False
        return True

    def _sg_check(self, acct: str, region: str, eni: dict[str, Any], flow: Flow, *, egress: bool,
                  peer_eni: dict[str, Any] | None, hops: list[Hop]) -> bool:
        sg_ids = [g["GroupId"] for g in eni.get("Groups", [])]
        if not sg_ids:
            return True
        groups = self.env.security_groups(acct, region, sg_ids)
        peer_sgs = {g["GroupId"] for g in (peer_eni or {}).get("Groups", [])}
        peer_ip = flow.dst if egress else flow.src
        d = evaluate_sg(self.env, acct, region, groups, egress=egress, peer_ip=peer_ip, peer_sgs=peer_sgs, flow=flow)
        direction = "egress" if egress else "ingress"
        hops.append(self._hop(acct, "security-group", ",".join(sg_ids), Status.PASS if d.allowed else Status.BLOCK,
                              f"{direction} {'allowed' if d.allowed else 'DENIED'} "
                              f"{'to' if egress else 'from'} {peer_ip}",
                              ingress=None if egress else eni["NetworkInterfaceId"],
                              egress=eni["NetworkInterfaceId"] if egress else None, policy=d.detail,
                              vpc=eni.get("VpcId")))
        return d.allowed

    def _same_region(self, acct: str, region: str) -> list[tuple[str, str]]:
        return [(acct, region)] + [t for t in self.env.targets() if t[1] == region and t[0] != acct]

    def _peer_eni(self, ip: str, acct: str, region: str) -> dict[str, Any] | None:
        """ENI of the other end, used only for security-group-reference rules (same region only)."""
        if self.inv.network_for(ip) or self.inv.prisma_location(ip):
            return None  # the inventory places this IP on-prem / in Prisma Access
        hit = self.env.find_eni(ip, only=self._same_region(acct, region))
        return hit[2] if hit else None

    # ---- entry points -----------------------------------------------------------------------------
    def walk(self, at: AwsAt, flow: Flow) -> StepResult:
        hops: list[Hop] = []
        warnings: list[str] = []
        self._mark = len(self.env.evidence)
        result = self._walk(at, flow, hops, warnings)
        result.warnings = warnings + result.warnings
        return result

    def _walk(self, at: AwsAt, flow: Flow, hops: list[Hop], warnings: list[str]) -> StepResult:
        acct, region = at.account, at.region
        self._at(region, None)
        if at.kind == "source_eni":
            eni = self.env.eni(acct, region, at.resource_id)
            self._at(region, eni.get("VpcId"))
            peer = self._peer_eni(flow.dst, acct, region)
            if not self._sg_check(acct, region, eni, flow, egress=True, peer_eni=peer, hops=hops):
                return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"security group on {eni['NetworkInterfaceId']} blocks egress")
            return self._route_from_subnet(acct, region, eni["VpcId"], eni["SubnetId"], flow, hops, warnings)
        if at.kind == "appliance_egress":
            hit = self.env.find_eni(at.ip, only=[(acct, region)] if acct and region else None)
            if not hit:
                return StepResult(hops, flow, outcome=Outcome.INCOMPLETE,
                                  reason=f"firewall egress IP {at.ip} not found on any ENI")
            acct, region, eni = hit
            self._at(region, eni.get("VpcId"))
            if eni.get("SourceDestCheck", True):
                hops.append(self._hop(acct, "eni", eni["NetworkInterfaceId"], Status.BLOCK,
                                      "source/destination check is enabled on firewall ENI; AWS drops forwarded traffic"))
                return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="source/dest check enabled on firewall ENI")
            peer = self._peer_eni(flow.dst, acct, region)
            if not self._sg_check(acct, region, eni, flow, egress=True, peer_eni=peer, hops=hops):
                return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="security group on firewall egress ENI blocks")
            return self._route_from_subnet(acct, region, eni["VpcId"], eni["SubnetId"], flow, hops, warnings)
        if at.kind == "subnet":
            subnet = self.env.subnet(acct, region, at.resource_id)
            return self._route_from_subnet(acct, region, subnet["VpcId"], subnet["SubnetId"], flow, hops, warnings,
                                           note=at.note)
        if at.kind in ("tgw_attachment", "vgw"):
            account = self.env.account(acct)
            region = region or account.regions[0]
            self._at(region, None)
            if at.kind == "vgw":
                return self._from_vgw(account.account_id, region, at.resource_id, flow, hops, warnings)
            return self._tgw_from_attachment(account.account_id, region, at.resource_id, flow, hops, warnings, az_id=None)
        raise NetTraceError(f"unknown AWS position {at.kind}")

    # ---- VPC routing -------------------------------------------------------------------------------
    def _route_from_subnet(self, acct: str, region: str, vpc_id: str, subnet_id: str, flow: Flow, hops: list[Hop],
                           warnings: list[str], note: str | None = None, steps: int = 0) -> StepResult:
        if steps > MAX_AWS_STEPS:
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason="AWS routing loop suspected")
        self._at(region, vpc_id)
        subnet = self.env.subnet(acct, region, subnet_id)
        rtb = self.env.route_table(acct, region, subnet_id, vpc_id)
        route = lookup_route(self.env, acct, region, rtb, flow.dst)
        rtb_id = rtb["RouteTableId"]
        if route is None:
            hops.append(self._hop(acct, "route-table", rtb_id, Status.BLOCK, f"no route to {flow.dst}",
                                  details=[f"subnet {subnet_id} ({vpc_id})"]))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{rtb_id} has no route to {flow.dst}")
        kind, target = route_target(route)
        summary = f"{route['_matched']} -> {target}"
        details = [f"subnet {subnet_id} ({vpc_id}, {subnet.get('AvailabilityZone')})"] + ([note] if note else [])
        if route.get("State") == "blackhole":
            hops.append(self._hop(acct, "route-table", rtb_id, Status.BLOCK, summary + " (blackhole)", details=details))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{rtb_id} route {route['_matched']} is a blackhole")
        hops.append(self._hop(acct, "route-table", rtb_id, Status.INFO, summary, details=details))
        az_id = subnet.get("AvailabilityZoneId")

        if kind == "local":
            return self._deliver_local(acct, region, vpc_id, subnet_id, flow, hops, warnings)
        if kind == "TransitGatewayId":
            return self._to_tgw(acct, region, vpc_id, subnet_id, az_id, target, flow, hops, warnings)
        if kind == "InternetGatewayId":
            if not self._cross(acct, region, flow, subnet_id, None, hops, warnings):
                return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the internet gateway")
            hops.append(self._hop(acct, "internet-gateway", target, Status.INFO, f"leaves AWS to the internet via {target}"))
            return StepResult(hops, flow, outcome=Outcome.EXITED, reason=f"egresses to the internet via {target}")
        if kind == "NatGatewayId":
            return self._via_nat(acct, region, vpc_id, subnet_id, target, flow, hops, warnings, steps)
        if kind == "VpcEndpointId":
            return self._via_endpoint(acct, region, vpc_id, subnet_id, target, flow, hops, warnings, steps)
        if kind in ("NetworkInterfaceId", "InstanceId"):
            return self._to_appliance(acct, region, subnet_id, kind, target, flow, hops, warnings)
        if kind == "VpcPeeringConnectionId":
            return self._via_peering(acct, region, subnet_id, target, flow, hops, warnings)
        if kind == "VpnGatewayId":
            if not self._cross(acct, region, flow, subnet_id, None, hops, warnings):
                return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the VGW")
            return self._leave_via(target, acct, region, flow, hops, f"virtual private gateway {target}")
        hops.append(self._hop(acct, "route-table", rtb_id, Status.UNKNOWN, f"target type {kind} is not supported yet"))
        return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"unsupported route target {target}")

    def _deliver_local(self, acct: str, region: str, vpc_id: str, from_subnet: str | None, flow: Flow,
                       hops: list[Hop], warnings: list[str]) -> StepResult:
        # Same account first, then other accounts in the region (shared VPC subnets via RAM).
        hit = self.env.find_eni(flow.dst, only=self._same_region(acct, region), vpc_id=vpc_id)
        if not hit:
            hops.append(self._hop(acct, "vpc", vpc_id, Status.UNKNOWN, f"no ENI in {vpc_id} owns {flow.dst}"))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"{flow.dst} is in {vpc_id} but no ENI has it")
        dacct, dregion, eni = hit
        self._at(dregion, eni.get("VpcId"))
        if not self._cross(dacct, dregion, flow, from_subnet, eni["SubnetId"], hops, warnings):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks delivery to destination subnet")
        src_eni = self._peer_eni(flow.src, dacct, dregion)
        if not self._sg_check(dacct, dregion, eni, flow, egress=False, peer_eni=src_eni, hops=hops):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"security group on {eni['NetworkInterfaceId']} blocks ingress")
        desc = eni.get("Description") or eni.get("InterfaceType") or ""
        owner = eni.get("Attachment", {}).get("InstanceId") or desc
        hops.append(self._hop(dacct, "eni", eni["NetworkInterfaceId"], Status.PASS,
                              f"delivered to {flow.dst} ({owner})", ingress=eni["NetworkInterfaceId"]))
        return StepResult(hops, flow, outcome=Outcome.REACHABLE, reason=f"delivered to {eni['NetworkInterfaceId']} ({owner})")

    # ---- Transit Gateway ------------------------------------------------------------------------------
    def _to_tgw(self, acct: str, region: str, vpc_id: str, subnet_id: str, az_id: str | None, tgw_id: str,
                flow: Flow, hops: list[Hop], warnings: list[str]) -> StepResult:
        atts = self.env.call(acct, region, "describe_transit_gateway_vpc_attachments",
                             Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                      {"Name": "transit-gateway-id", "Values": [tgw_id]},
                                      {"Name": "state", "Values": ["available"]}]).get("TransitGatewayVpcAttachments", [])
        if not atts:
            hops.append(self._hop(acct, "tgw", tgw_id, Status.BLOCK, f"{vpc_id} has no available attachment to {tgw_id}"))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{vpc_id} is not attached to {tgw_id}")
        att = atts[0]
        tgw_subnet = self._subnet_in_az(acct, region, att.get("SubnetIds", []), az_id)
        if tgw_subnet is None:
            hops.append(self._hop(acct, "tgw", tgw_id, Status.BLOCK,
                                  f"attachment {att['TransitGatewayAttachmentId']} has no subnet in this AZ ({az_id})"))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="TGW attachment has no subnet in source AZ")
        if not self._cross(acct, region, flow, subnet_id, tgw_subnet, hops, warnings, leaving_vpc=True):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic toward the TGW attachment")
        owner = self.env.tgw_owner(acct, region, tgw_id)
        if not self.inv.account(owner):
            hops.append(self._hop(acct, "tgw", tgw_id, Status.UNKNOWN, f"TGW owner account {owner} is not in the inventory"))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"add TGW owner account {owner} to aws.accounts")
        return self._tgw_from_attachment(owner, region, att["TransitGatewayAttachmentId"], flow, hops, warnings, az_id)

    def _subnet_in_az(self, acct: str, region: str, subnet_ids: list[str], az_id: str | None) -> str | None:
        if not subnet_ids:
            return None
        if not az_id:
            return subnet_ids[0]
        for sid in subnet_ids:
            if self.env.subnet(acct, region, sid).get("AvailabilityZoneId") == az_id:
                return sid
        return None

    def _tgw_from_attachment(self, owner: str, region: str, attachment_id: str, flow: Flow, hops: list[Hop],
                             warnings: list[str], az_id: str | None, depth: int = 0) -> StepResult:
        if depth > 5:
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason="TGW peering loop suspected")
        self._at(region, None)
        att = self.env.call(owner, region, "describe_transit_gateway_attachments",
                            TransitGatewayAttachmentIds=[attachment_id])["TransitGatewayAttachments"][0]
        tgw_id = att["TransitGatewayId"]
        rtb = (att.get("Association") or {}).get("TransitGatewayRouteTableId")
        if not rtb:
            hops.append(self._hop(owner, "tgw", tgw_id, Status.BLOCK,
                                  f"attachment {attachment_id} is not associated with a TGW route table"))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{attachment_id} has no TGW route table association")
        route = self.env.search_tgw_routes(owner, region, rtb, flow.dst)
        details = [f"tgw {tgw_id}, ingress attachment {attachment_id} ({att.get('ResourceType')} {att.get('ResourceId')})"]
        if route is None:
            hops.append(self._hop(owner, "tgw-route-table", rtb, Status.BLOCK, f"no route to {flow.dst}", details=details))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"TGW route table {rtb} has no route to {flow.dst}")
        dest = route.get("DestinationCidrBlock") or route.get("PrefixListId")
        if route.get("State") == "blackhole":
            hops.append(self._hop(owner, "tgw-route-table", rtb, Status.BLOCK, f"{dest} is a blackhole", details=details))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"TGW route {dest} in {rtb} is a blackhole")
        targets = route.get("TransitGatewayAttachments", [])
        if not targets:
            hops.append(self._hop(owner, "tgw-route-table", rtb, Status.UNKNOWN, f"{dest} has no attachment", details=details))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason="TGW route has no attachment")
        nxt = targets[0]
        if len(targets) > 1:
            details.append("ECMP: " + ", ".join(t["TransitGatewayAttachmentId"] for t in targets) + "; following the first")
        hops.append(self._hop(owner, "tgw-route-table", rtb, Status.INFO,
                              f"{dest} -> {nxt['TransitGatewayAttachmentId']} ({nxt.get('ResourceType')} {nxt.get('ResourceId')}) "
                              f"[{route.get('Type')}]", details=details))
        rtype = nxt.get("ResourceType")
        nxt_id = nxt["TransitGatewayAttachmentId"]
        if rtype == "vpc":
            return self._enter_vpc_from_tgw(owner, region, nxt_id, flow, hops, warnings, az_id)
        if rtype == "peering":
            return self._via_tgw_peering(owner, region, tgw_id, nxt_id, flow, hops, warnings, az_id, depth)
        return self._leave_via(nxt_id, owner, region, flow, hops, f"TGW {rtype} attachment {nxt_id}")

    def _enter_vpc_from_tgw(self, owner: str, region: str, att_id: str, flow: Flow, hops: list[Hop],
                            warnings: list[str], az_id: str | None) -> StepResult:
        key = (att_id, flow.src, flow.dst)
        if key in self._tgw_entries:  # TGW -> VPC -> TGW -> same VPC attachment: would recurse forever
            hops.append(self._hop(owner, "tgw", att_id, Status.UNKNOWN,
                                  f"forwarding loop: traffic re-enters VPC attachment {att_id}"))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE,
                              reason=f"AWS forwarding loop between a TGW and the VPC behind {att_id}")
        self._tgw_entries.add(key)
        vatt = self.env.call(owner, region, "describe_transit_gateway_vpc_attachments",
                             TransitGatewayAttachmentIds=[att_id])["TransitGatewayVpcAttachments"][0]
        vpc_owner = vatt.get("VpcOwnerId", owner)
        if not self.inv.account(vpc_owner):
            hops.append(self._hop(owner, "tgw", att_id, Status.UNKNOWN, f"VPC owner account {vpc_owner} is not in the inventory"))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"add account {vpc_owner} to aws.accounts")
        subnet = self._subnet_in_az(vpc_owner, region, vatt.get("SubnetIds", []), az_id)
        if subnet is None:
            subnet = vatt["SubnetIds"][0]
            warnings.append(f"{att_id}: no attachment subnet in source AZ {az_id}; used {subnet}")
        if (vatt.get("Options") or {}).get("ApplianceModeSupport") == "enable":
            hops[-1].details.append("appliance mode enabled on destination attachment")
        return self._route_from_subnet(vpc_owner, region, vatt["VpcId"], subnet, flow, hops, warnings,
                                       note=f"arrived from TGW attachment {att_id}")

    def _via_tgw_peering(self, owner: str, region: str, tgw_id: str, att_id: str, flow: Flow, hops: list[Hop],
                         warnings: list[str], az_id: str | None, depth: int) -> StepResult:
        peer = self.env.call(owner, region, "describe_transit_gateway_peering_attachments",
                             TransitGatewayAttachmentIds=[att_id])["TransitGatewayPeeringAttachments"][0]
        sides = [peer.get("RequesterTgwInfo", {}), peer.get("AccepterTgwInfo", {})]
        other = next((s for s in sides if s.get("TransitGatewayId") != tgw_id), None)
        if not other or not self.inv.account(other.get("OwnerId", "")):
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE,
                              reason=f"peer TGW of {att_id} ({other}) is not in an inventory account")
        return self._tgw_from_attachment(other["OwnerId"], other["Region"], att_id, flow, hops, warnings, None, depth + 1)

    # ---- other targets ------------------------------------------------------------------------------
    def _via_nat(self, acct: str, region: str, vpc_id: str, subnet_id: str, nat_id: str, flow: Flow,
                 hops: list[Hop], warnings: list[str], steps: int) -> StepResult:
        nat = self.env.call(acct, region, "describe_nat_gateways", NatGatewayIds=[nat_id])["NatGateways"][0]
        if not self._cross(acct, region, flow, subnet_id, nat["SubnetId"], hops, warnings):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the NAT gateway")
        addr = (nat.get("NatGatewayAddresses") or [{}])[0]
        new_src = addr.get("PrivateIp") or flow.src
        status = Status.INFO if nat.get("State") == "available" else Status.BLOCK
        hops.append(self._hop(acct, "nat-gateway", nat_id, status,
                              f"SNAT {flow.src} -> {new_src}" + (f" (public {addr['PublicIp']})" if addr.get("PublicIp") else ""),
                              nat=f"SNAT -> {new_src}", details=[f"state {nat.get('State')}, {nat.get('ConnectivityType')}"]))
        if status == Status.BLOCK:
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{nat_id} is {nat.get('State')}")
        return self._route_from_subnet(acct, region, vpc_id, nat["SubnetId"], flow.with_changes(src=new_src), hops,
                                       warnings, note=f"after NAT gateway {nat_id}", steps=steps + 1)

    def _via_endpoint(self, acct: str, region: str, vpc_id: str, subnet_id: str, vpce: str, flow: Flow,
                      hops: list[Hop], warnings: list[str], steps: int) -> StepResult:
        ep = self.env.call(acct, region, "describe_vpc_endpoints", VpcEndpointIds=[vpce])["VpcEndpoints"][0]
        if ep.get("VpcEndpointType") != "GatewayLoadBalancer":
            hops.append(self._hop(acct, "vpc-endpoint", vpce, Status.INFO, f"to AWS service {ep.get('ServiceName')}"))
            return StepResult(hops, flow, outcome=Outcome.EXITED, reason=f"goes to {ep.get('ServiceName')} via {vpce}")
        ep_subnet = (ep.get("SubnetIds") or [None])[0]
        if not self._cross(acct, region, flow, subnet_id, ep_subnet, hops, warnings):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the GWLB endpoint")
        resume = AwsAt(kind="subnet", account=acct, region=region, resource_id=ep_subnet,
                       note=f"returned from GWLB endpoint {vpce}")
        device = self.inv.device_for_aws(gwlb_endpoint=vpce)
        if device is None:
            hops.append(self._hop(acct, "gwlb-endpoint", vpce, Status.UNKNOWN,
                                  f"inspected by firewalls behind {ep.get('ServiceName')}; no inventory device lists "
                                  f"{vpce} in aws.gwlb_endpoints, so policy was not checked"))
            warnings.append(f"firewall policy behind {vpce} was not checked")
            return self._route_from_subnet(acct, region, vpc_id, ep_subnet, flow, hops, warnings,
                                           note=resume.note, steps=steps + 1)
        hops.append(self._hop(acct, "gwlb-endpoint", vpce, Status.INFO, f"to GWLB -> {device.name}"))
        return StepResult(hops, flow, next=DeviceAt(device=device.name, gwlb_endpoint=vpce, resume=resume))

    def _to_appliance(self, acct: str, region: str, subnet_id: str, kind: str, target: str, flow: Flow,
                      hops: list[Hop], warnings: list[str]) -> StepResult:
        if kind == "InstanceId":
            enis = self.env.call(acct, region, "describe_network_interfaces",
                                 Filters=[{"Name": "attachment.instance-id", "Values": [target]},
                                          {"Name": "attachment.device-index", "Values": ["0"]}]).get("NetworkInterfaces", [])
            if not enis:
                return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"no ENI found for {target}")
            eni = enis[0]
        else:
            eni = self.env.eni(acct, region, target)
        instance_id = (eni.get("Attachment") or {}).get("InstanceId")
        ip = eni.get("PrivateIpAddress")
        if not self._cross(acct, region, flow, subnet_id, eni["SubnetId"], hops, warnings):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the appliance ENI")
        if eni.get("SourceDestCheck", True):
            hops.append(self._hop(acct, "eni", eni["NetworkInterfaceId"], Status.BLOCK,
                                  "route points at an ENI with source/destination check enabled; AWS drops the traffic"))
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="source/dest check enabled on appliance ENI")
        src_eni = self._peer_eni(flow.src, acct, region)
        if not self._sg_check(acct, region, eni, flow, egress=False, peer_eni=src_eni, hops=hops):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="security group on appliance ENI blocks ingress")
        device = self.inv.device_for_aws(instance_id=instance_id, ip=ip)
        if device is None:
            hops.append(self._hop(acct, "eni", eni["NetworkInterfaceId"], Status.UNKNOWN,
                                  f"appliance {instance_id or eni['NetworkInterfaceId']} ({ip}) is not in the inventory"))
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE,
                              reason=f"route goes to appliance {instance_id or target}; add it to the inventory with aws.instance_id")
        return StepResult(hops, flow, next=DeviceAt(device=device.name, arrival_ip=ip))

    def _via_peering(self, acct: str, region: str, subnet_id: str, pcx_id: str, flow: Flow, hops: list[Hop],
                     warnings: list[str]) -> StepResult:
        pcx = self.env.call(acct, region, "describe_vpc_peering_connections",
                            VpcPeeringConnectionIds=[pcx_id])["VpcPeeringConnections"][0]
        status = (pcx.get("Status") or {}).get("Code")
        here_vpc = self.env.subnet(acct, region, subnet_id)["VpcId"]
        sides = [pcx.get("RequesterVpcInfo", {}), pcx.get("AccepterVpcInfo", {})]
        other = next((s for s in sides if s.get("VpcId") != here_vpc), {})
        hops.append(self._hop(acct, "vpc-peering", pcx_id, Status.INFO if status == "active" else Status.BLOCK,
                              f"to {other.get('VpcId')} ({other.get('OwnerId')}, {other.get('Region')}) [{status}]"))
        if status != "active":
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{pcx_id} is {status}")
        if not self._cross(acct, region, flow, subnet_id, None, hops, warnings):
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason="NACL blocks traffic to the peering connection")
        if not self.inv.account(other.get("OwnerId", "")):
            return StepResult(hops, flow, outcome=Outcome.INCOMPLETE, reason=f"peer account {other.get('OwnerId')} not in inventory")
        return self._deliver_local(other["OwnerId"], other["Region"], other["VpcId"], None, flow, hops, warnings)

    def _from_vgw(self, acct: str, region: str, vgw_id: str, flow: Flow, hops: list[Hop],
                  warnings: list[str]) -> StepResult:
        vgw = self.env.call(acct, region, "describe_vpn_gateways", VpnGatewayIds=[vgw_id])["VpnGateways"][0]
        vpcs = [a["VpcId"] for a in vgw.get("VpcAttachments", []) if a.get("State") == "attached"]
        if not vpcs:
            return StepResult(hops, flow, outcome=Outcome.BLOCKED, reason=f"{vgw_id} is not attached to a VPC")
        self._at(region, vpcs[0])
        edge = self.env.call(acct, region, "describe_route_tables",
                             Filters=[{"Name": "association.gateway-id", "Values": [vgw_id]}]).get("RouteTables", [])
        if edge:
            route = lookup_route(self.env, acct, region, edge[0], flow.dst)
            if route and route_target(route)[0] != "local":
                kind, target = route_target(route)
                hops.append(self._hop(acct, "route-table", edge[0]["RouteTableId"], Status.INFO,
                                      f"ingress routing: {route['_matched']} -> {target}"))
                if kind in ("NetworkInterfaceId", "InstanceId"):
                    return self._to_appliance(acct, region, None, kind, target, flow, hops, warnings)  # type: ignore[arg-type]
                if kind == "VpcEndpointId":
                    return self._via_endpoint(acct, region, vpcs[0], None, target, flow, hops, warnings, 0)  # type: ignore[arg-type]
        hops.append(self._hop(acct, "vgw", vgw_id, Status.INFO, f"from on-prem into {vpcs[0]}"))
        return self._deliver_local(acct, region, vpcs[0], None, flow, hops, warnings)

    def _leave_via(self, resource_id: str, acct: str, region: str, flow: Flow, hops: list[Hop], label: str) -> StepResult:
        link = self.inv.link_from_aws(resource_id)
        if not link:
            hops.append(self._hop(acct, "exit", resource_id, Status.INFO, f"leaves AWS via {label}"))
            return StepResult(hops, flow, outcome=Outcome.EXITED,
                              reason=f"leaves AWS via {label}; add a link in the inventory to follow it")
        lk, there = link
        hops.append(self._hop(acct, "exit", resource_id, Status.INFO, f"leaves AWS via {label} -> {there.label()} (link {lk.name})"))
        if there.device:
            return StepResult(hops, flow, next=DeviceAt(device=there.device, arrival_interface=there.interface,
                                                        arrival_ip=there.next_hop))
        if there.prisma_service_connection:
            return StepResult(hops, flow, next=PrismaAt(entry="service_connection", name=there.prisma_service_connection))
        return StepResult(hops, flow, outcome=Outcome.EXITED, reason=f"leaves AWS via {label} to {there.label()}")
