"""Read-only enforcement.

Every request nettrace sends goes through one of these checks. They are a second
line of defence: the credentials you give nettrace should also be read-only
(see README "Least-privilege credentials").
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from defusedxml import ElementTree as SafeET

from nettrace import audit
from nettrace.errors import ReadOnlyViolation

# --- Cisco ---------------------------------------------------------------------
# ALLOWLIST of full-word commands (IOS accepts abbreviations such as `show run`, so a deny list or a
# "starts with show" rule cannot work). Every word is matched exactly, case-sensitively, single-spaced;
# arguments are only an IPv4 address or a safe_token-style name. Pipes, ';', '?', newlines and anything
# else cannot match. Keep in step with what drivers/cisco_iosxe.py sends and the web console QUICK list.
_TOK = r"[A-Za-z0-9._:/\-]{1,128}"
_IPV4 = r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
_CISCO_ALLOWED = tuple(re.compile(p) for p in (
    rf"show ip route(?: vrf {_TOK})?(?: {_IPV4})?",
    rf"show ip cef(?: vrf {_TOK})? {_IPV4}",
    rf"show ip arp(?: vrf {_TOK})?(?: {_IPV4})?",
    r"show ip interface brief",
    rf"show ip interface {_TOK}",
    rf"show ip access-lists(?: {_TOK})?",
    r"show interfaces description",
    r"show version",
    r"show vrf",
))
_CISCO_MAX = 400


def check_cisco_command(command: str) -> str:
    ok = (isinstance(command, str) and len(command) <= _CISCO_MAX and command.isascii()
          and any(p.fullmatch(command) for p in _CISCO_ALLOWED))
    if ok:
        try:
            for ip in re.findall(_IPV4, command):
                ipaddress.ip_address(ip)
        except ValueError:
            ok = False
    if not ok:
        raise ReadOnlyViolation(f"refusing to send Cisco command that is not on the read-only allowlist: {command!r}")
    return command


def safe_token(value: str, what: str = "value") -> str:
    """Validate a token (ACL name, VRF, interface) before putting it in a command."""
    if not re.fullmatch(r"[A-Za-z0-9._:/\-]{1,128}", value or ""):
        raise ReadOnlyViolation(f"unsafe {what} {value!r}")
    return value


# --- PAN-OS --------------------------------------------------------------------
_PANOS_OP_ROOTS = ("show", "test")
# <test> is active (it can start tunnels or send credentials to AAA), so only these children are allowed.
_PANOS_TEST_CHILDREN = ("security-policy-match", "nat-policy-match", "routing", "advanced-routing")
_PANOS_TEST_ROUTING = ("fib-lookup",)


# Strict: path segments with an optional [@name='..'] / [@uuid='..'] predicate, under devices/shared/panorama.
# No '..', '|', '*', '//', 'or', functions or other predicates, so it can never reach /config/mgt-config.
_PANOS_XPATH = re.compile(
    r"/config/(?:devices|shared|panorama)"
    r"(?:/[A-Za-z0-9_][A-Za-z0-9_.:\-]*(?:\[@(?:name|uuid)='[A-Za-z0-9 _.:\-]{1,128}'\])?)+"
)


def check_panos_request(params: dict[str, str], panorama: bool = False) -> dict[str, str]:
    req_type = params.get("type")
    if req_type == "op":
        cmd = params.get("cmd", "").lstrip()
        try:
            root = SafeET.fromstring(cmd)  # raises on multi-root or malformed XML
        except Exception as exc:
            raise ReadOnlyViolation("PAN-OS op cmd is not a single well-formed XML element") from exc
        if root.tag not in _PANOS_OP_ROOTS:
            raise ReadOnlyViolation("PAN-OS op commands must be <show> or <test>")
        if root.tag == "test":
            child = next(iter(root), None)
            if len(root) != 1 or child.tag not in _PANOS_TEST_CHILDREN:
                raise ReadOnlyViolation("PAN-OS <test> may only contain " + ", ".join(_PANOS_TEST_CHILDREN))
            if child.tag.endswith("routing") and any(c.tag not in _PANOS_TEST_ROUTING for c in child):
                raise ReadOnlyViolation("PAN-OS <test><routing> may only contain fib-lookup")
        if panorama and root.tag == "test" and "target" not in params:
            raise ReadOnlyViolation("<test> on Panorama itself is not allowed; send it with target=<serial>")
        if "action" in params or "xpath" in params:
            raise ReadOnlyViolation("PAN-OS op requests take no action/xpath")
    elif req_type == "config":
        if params.get("action") not in ("get", "show"):
            raise ReadOnlyViolation("PAN-OS config requests must use action=get or action=show")
        if not _PANOS_XPATH.fullmatch(params.get("xpath", "")):
            raise ReadOnlyViolation("PAN-OS config xpath must be under /config/devices, /config/shared or /config/panorama")
    else:
        raise ReadOnlyViolation(f"PAN-OS API type {req_type!r} is not allowed")
    allowed = {"type", "cmd", "action", "xpath", "target", "vsys"}
    extra = set(params) - allowed
    if extra:
        raise ReadOnlyViolation(f"PAN-OS request parameter(s) not allowed: {', '.join(sorted(extra))}")
    # `target` makes Panorama proxy the request to a managed firewall; it must be a plain serial.
    if "target" in params and not re.fullmatch(r"[A-Za-z0-9]{1,32}", params["target"]):
        raise ReadOnlyViolation(f"invalid Panorama target {params['target']!r}")
    return params


# --- Strata Cloud Manager -----------------------------------------------------
def check_http_method(method: str) -> None:
    if method.upper() != "GET":
        raise ReadOnlyViolation(f"HTTP {method} is not allowed against Strata Cloud Manager")


# --- AWS -----------------------------------------------------------------------
# Exact (service, operation) allowlist: what drivers/aws.py and the demo simulator call. Keep in
# step with iam/nettrace-readonly-policy.json. Never add Reachability/Network Access Analyzer.
_AWS_ALLOWED = frozenset(
    [("sts", "AssumeRole")]
    + [("ec2", op) for op in (
        "DescribeNetworkInterfaces", "DescribeSubnets", "DescribeVpcs", "DescribeRouteTables",
        "DescribeNetworkAcls", "DescribeSecurityGroups", "GetManagedPrefixListEntries",
        "DescribeTransitGateways", "DescribeTransitGatewayAttachments",
        "DescribeTransitGatewayVpcAttachments", "DescribeTransitGatewayPeeringAttachments",
        "SearchTransitGatewayRoutes", "DescribeVpcEndpoints", "DescribeNatGateways",
        "DescribeVpcPeeringConnections", "DescribeVpnGateways",
    )]
)


def aws_operation_allowed(service: str, operation: str) -> bool:
    return (service, operation) in _AWS_ALLOWED


def check_aws_operation(service: str, operation: str) -> None:
    if not aws_operation_allowed(service, operation):
        raise ReadOnlyViolation(f"refusing AWS API call {service}:{operation} (not in the read-only allowlist)")


def _aws_before_call(model: Any = None, **_: Any) -> None:
    service = getattr(getattr(model, "service_model", None), "service_name", "")
    try:
        check_aws_operation(service, getattr(model, "name", ""))
    except ReadOnlyViolation as exc:
        audit.refused(exc, "aws", "aws", f"{service}:{getattr(model, 'name', '')}")
        raise


def install_aws_guard(session: Any) -> Any:
    """Register a botocore hook that blocks any non read-only API operation.

    Works for boto3.Session and botocore.session.Session objects.
    """
    events = session.events if hasattr(session, "events") else session._session.get_component("event_emitter")
    events.register("before-call.*.*", _aws_before_call, unique_id="nettrace-readonly-guard")
    return session
