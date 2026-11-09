"""AWS EC2 API simulator for the demo lab: answers the Describe/Get/Search calls nettrace makes.

Visibility mirrors AWS: VPC-scoped resources (subnets, route tables, NACLs, SGs, ENIs) are only
visible to their owner account; Transit Gateway resources are shared with every lab account (RAM).
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Any

from nettrace.demo.lab import AWS, REGION
from nettrace.errors import NetTraceError


class SimAwsError(NetTraceError):
    pass


def _filters(params: dict[str, Any]) -> dict[str, list[str]]:
    return {f["Name"]: [str(v) for v in f["Values"]] for f in params.get("Filters", [])}


def _get(d: dict[str, Any], path: str) -> list[str]:
    """Values at a dotted path (lists are flattened)."""
    cur: list[Any] = [d]
    for part in path.split("."):
        nxt: list[Any] = []
        for c in cur:
            v = c.get(part) if isinstance(c, dict) else None
            if isinstance(v, list):
                nxt.extend(v)
            elif v is not None:
                nxt.append(v)
        cur = nxt
    return [str(v).lower() if isinstance(v, bool) else str(v) for v in cur]


FILTER_PATHS = {
    "addresses.private-ip-address": "PrivateIpAddresses.PrivateIpAddress",
    "association.public-ip": "Association.PublicIp",
    "attachment.instance-id": "Attachment.InstanceId",
    "attachment.device-index": "Attachment.DeviceIndex",
    "association.subnet-id": "Associations.SubnetId",
    "association.main": "Associations.Main",
    "association.gateway-id": "Associations.GatewayId",
    "vpc-id": "VpcId",
    "transit-gateway-id": "TransitGatewayId",
    "state": "State",
}


def _apply(items: list[dict[str, Any]], params: dict[str, Any], id_key: str | None = None,
           id_param: str | None = None) -> list[dict[str, Any]]:
    out = items
    if id_param and params.get(id_param):
        wanted = set(params[id_param])
        out = [i for i in out if i.get(id_key) in wanted]
        missing = wanted - {i.get(id_key) for i in out}
        if missing:
            raise SimAwsError(f"InvalidID.NotFound: {', '.join(sorted(missing))}")
    for name, values in _filters(params).items():
        path = FILTER_PATHS.get(name)
        if path is None:
            raise SimAwsError(f"filter {name!r} is not simulated")
        out = [i for i in out if set(_get(i, path)) & set(values)]
    return copy.deepcopy(out)


class Backend:
    def __init__(self) -> None:
        self.m = AWS

    def _owned(self, kind: str, account: str) -> list[dict[str, Any]]:
        return [r for r in self.m[kind] if r.get("OwnerId") == account]

    def call(self, account: str, region: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        if region != REGION:
            return _EMPTY.get(op, {})
        m = self.m
        if op == "describe_network_interfaces":
            return {"NetworkInterfaces": _apply(self._owned("enis", account), params, "NetworkInterfaceId",
                                                "NetworkInterfaceIds")}
        if op == "describe_subnets":
            return {"Subnets": _apply(self._owned("subnets", account), params, "SubnetId", "SubnetIds")}
        if op == "describe_vpcs":
            return {"Vpcs": _apply(self._owned("vpcs", account), params, "VpcId", "VpcIds")}
        if op == "describe_route_tables":
            return {"RouteTables": _apply(self._owned("route_tables", account), params, "RouteTableId", "RouteTableIds")}
        if op == "describe_network_acls":
            return {"NetworkAcls": _apply(self._owned("nacls", account), params, "NetworkAclId", "NetworkAclIds")}
        if op == "describe_security_groups":
            return {"SecurityGroups": _apply(self._owned("security_groups", account), params, "GroupId", "GroupIds")}
        if op == "describe_transit_gateways":
            return {"TransitGateways": _apply(m["tgws"], params, "TransitGatewayId", "TransitGatewayIds")}
        if op == "describe_transit_gateway_attachments":
            return {"TransitGatewayAttachments": _apply(m["tgw_attachments"], params, "TransitGatewayAttachmentId",
                                                        "TransitGatewayAttachmentIds")}
        if op == "describe_transit_gateway_vpc_attachments":
            return {"TransitGatewayVpcAttachments": _apply(m["vpc_attachments"], params, "TransitGatewayAttachmentId",
                                                           "TransitGatewayAttachmentIds")}
        if op == "search_transit_gateway_routes":
            return {"Routes": self._search(params), "AdditionalRoutesAvailable": False}
        if op == "get_managed_prefix_list_entries":
            return {"Entries": []}
        if op in _EMPTY:
            ids = next((v for k, v in params.items() if k.endswith("Ids")), None)
            if ids:
                raise SimAwsError(f"InvalidID.NotFound: {', '.join(ids)}")
            return _EMPTY[op]
        raise SimAwsError(f"{op} is not simulated in the demo lab")

    def _search(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        routes = self.m["tgw_routes"].get(params["TransitGatewayRouteTableId"])
        if routes is None:
            raise SimAwsError(f"InvalidRouteTableID.NotFound: {params['TransitGatewayRouteTableId']}")
        f = _filters(params)
        target = (f.get("route-search.longest-prefix-match") or f.get("route-search.supernet-of-match") or [None])[0]
        if target is None:
            return copy.deepcopy(routes)
        addr = ipaddress.ip_network(target, strict=False).network_address
        hits = [r for r in routes if addr in ipaddress.ip_network(r["DestinationCidrBlock"])]
        if "route-search.longest-prefix-match" in f and hits:
            hits = [max(hits, key=lambda r: ipaddress.ip_network(r["DestinationCidrBlock"]).prefixlen)]
        return copy.deepcopy(hits)


_EMPTY = {
    "describe_network_interfaces": {"NetworkInterfaces": []}, "describe_subnets": {"Subnets": []},
    "describe_vpcs": {"Vpcs": []}, "describe_route_tables": {"RouteTables": []},
    "describe_network_acls": {"NetworkAcls": []}, "describe_security_groups": {"SecurityGroups": []},
    "describe_nat_gateways": {"NatGateways": []}, "describe_vpc_endpoints": {"VpcEndpoints": []},
    "describe_vpc_peering_connections": {"VpcPeeringConnections": []}, "describe_vpn_gateways": {"VpnGateways": []},
    "describe_transit_gateway_peering_attachments": {"TransitGatewayPeeringAttachments": []},
}


def backend(env: Any) -> Backend:
    return Backend()
