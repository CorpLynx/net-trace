import pytest

from nettrace.drivers.panos import build_op
from nettrace.errors import ReadOnlyViolation
from nettrace.readonly import (
    aws_operation_allowed,
    check_aws_operation,
    check_cisco_command,
    check_http_method,
    check_panos_request,
    safe_token,
)


# ---- Cisco ----
@pytest.mark.parametrize("cmd", ["show ip route 10.0.0.1", "show ip access-lists ACL_IN",
                                 "show running-config interface Gi0/0/1"])
def test_cisco_show_allowed(cmd):
    assert check_cisco_command(cmd) == cmd


@pytest.mark.parametrize("cmd", [
    "configure terminal", "conf t", "reload", "write memory", "clear ip route *", "debug ip packet",
    "show ip route | include 10", "show version; reload", "show version\nreload", "show run && reload",
    "show $(reload)", "Show version", " show version", "show ", "show", "",
])
def test_cisco_rejected(cmd):
    with pytest.raises(ReadOnlyViolation):
        check_cisco_command(cmd)


def test_safe_token():
    assert safe_token("Gi0/0/1.100") == "Gi0/0/1.100"
    for bad in ["", "a b", "a;b", "a|b", "a\nb", "x" * 129]:
        with pytest.raises(ReadOnlyViolation):
            safe_token(bad)


# ---- PAN-OS ----
@pytest.mark.parametrize("params", [
    {"type": "op", "cmd": "<show><system><info/></system></show>"},
    {"type": "op", "cmd": "<test><routing><fib-lookup/></routing></test>", "target": "007051000012345"},
    {"type": "config", "action": "get", "xpath": "/config/shared/address", "vsys": "vsys1"},
    {"type": "config", "action": "show", "xpath": "/config/devices/entry"},
])
def test_panos_allowed(params):
    assert check_panos_request(params) is params


@pytest.mark.parametrize("params", [
    {"type": "op", "cmd": "<request><restart><system/></restart></request>"},
    {"type": "op", "cmd": "<set/>"},
    {"type": "op", "cmd": ""},
    {"type": "op"},
    {"type": "op", "cmd": "<show/>", "action": "get"},
    {"type": "op", "cmd": "<show/>", "xpath": "/x"},
    {"type": "commit", "cmd": "<commit/>"},
    {"type": "config", "action": "set", "xpath": "/x"},
    {"type": "config", "action": "edit", "xpath": "/x"},
    {"type": "config", "action": "delete", "xpath": "/x"},
    {"type": "config", "xpath": "/x"},
    {"type": "config", "action": "get", "xpath": "/config"},
    {"type": "config", "action": "get", "xpath": "/config/mgt-config/users"},
    {"type": "keygen"},
    {},
    {"type": "op", "cmd": "<show/>", "key": "secret"},
    {"type": "config", "action": "get", "element": "<x/>"},
    {"type": "op", "cmd": "<show/>", "target": "../etc"},
    {"type": "op", "cmd": "<show/>", "target": "a b"},
    {"type": "op", "cmd": "<show/>", "target": ""},
    {"type": "op", "cmd": "<show/>", "target": "x" * 33},
])
def test_panos_rejected(params):
    with pytest.raises(ReadOnlyViolation):
        check_panos_request(params)


def test_panos_multi_root_cmd_rejected():
    with pytest.raises(ReadOnlyViolation):
        check_panos_request({"type": "op", "cmd": "<show></show><request><restart/></request>"})


@pytest.mark.parametrize("tag", ["a<b", "a>b", "a b", "a</b><c>"])
def test_build_op_rejects_bad_tag(tag):
    with pytest.raises(Exception):
        build_op(["show", tag])


def test_build_op_escapes_values():
    out = build_op(["test", "routing"], {"ip": "1.1.1.1</ip><x/>"})
    assert out == "<test><routing><ip>1.1.1.1&lt;/ip&gt;&lt;x/&gt;</ip></routing></test>"


# ---- SCM ----
def test_http_get_only():
    check_http_method("get")
    check_http_method("GET")
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        with pytest.raises(ReadOnlyViolation):
            check_http_method(m)


# ---- AWS ----
_EC2_OPS = [
    "DescribeNetworkInterfaces", "DescribeSubnets", "DescribeVpcs", "DescribeRouteTables", "DescribeNetworkAcls",
    "DescribeSecurityGroups", "GetManagedPrefixListEntries", "DescribeTransitGateways",
    "DescribeTransitGatewayAttachments", "DescribeTransitGatewayVpcAttachments",
    "DescribeTransitGatewayPeeringAttachments", "SearchTransitGatewayRoutes", "DescribeVpcEndpoints",
    "DescribeNatGateways", "DescribeVpcPeeringConnections", "DescribeVpnGateways",
]


@pytest.mark.parametrize("op", _EC2_OPS)
def test_aws_allowed_ec2(op):
    assert aws_operation_allowed("ec2", op)


def test_aws_allowed_assume_role():
    assert aws_operation_allowed("sts", "AssumeRole")


@pytest.mark.parametrize("service,op", [
    ("ec2", "DescribeInstances"), ("ec2", "GetConsoleOutput"), ("ec2", "DescribeVolumes"),
    ("iam", "ListRoles"), ("iam", "GetUser"), ("s3", "ListBuckets"), ("sts", "GetCallerIdentity"),
    ("sts", "AssumeRoleWithSAML"), ("ec2", "AssumeRole"), ("sts", "DescribeVpcs"),
    ("ec2", "RunInstances"), ("ec2", "TerminateInstances"), ("ec2", "CreateSecurityGroup"),
    ("ec2", "AuthorizeSecurityGroupIngress"), ("ec2", "DeleteVpc"), ("ec2", "ModifyVpcAttribute"),
    ("ec2", "StartNetworkInsightsAnalysis"), ("ec2", "CreateNetworkInsightsPath"),
    ("ec2", "StartNetworkInsightsAccessScopeAnalysis"), ("ec2", ""), ("", "DescribeVpcs"),
    ("ec2", "describevpcs"),
])
def test_aws_rejected(service, op):
    assert not aws_operation_allowed(service, op)
    with pytest.raises(ReadOnlyViolation, match=f"{service}:{op}"):
        check_aws_operation(service, op)


def test_aws_backend_override_applies_guard():
    from nettrace.drivers.aws import AwsEnv

    class Boom:
        def call(self, *a):
            raise AssertionError("backend must not be reached")

    class Inv:
        def account(self, _):
            return None

    prev = AwsEnv.backend_override
    AwsEnv.backend_override = staticmethod(lambda env: Boom())
    try:
        env = AwsEnv(Inv())
        with pytest.raises(ReadOnlyViolation, match="ec2:DescribeInstances"):
            env.call("1", "us-east-1", "describe_instances")
        with pytest.raises(ReadOnlyViolation, match="iam:ListRoles"):
            env.call("1", "us-east-1", "list_roles", service="iam")
    finally:
        AwsEnv.backend_override = prev


def test_aws_botocore_hook():
    from types import SimpleNamespace as NS

    from nettrace.readonly import _aws_before_call

    _aws_before_call(model=NS(name="DescribeVpcs", service_model=NS(service_name="ec2")))
    with pytest.raises(ReadOnlyViolation):
        _aws_before_call(model=NS(name="DescribeVpcs", service_model=NS(service_name="iam")))


def test_iam_policy_matches_allowlist():
    import json
    from pathlib import Path

    from nettrace.readonly import _AWS_ALLOWED

    pol = json.loads((Path(__file__).parents[1] / "iam" / "nettrace-readonly-policy.json").read_text())
    actions = {a for st in pol["Statement"] for a in st["Action"]}
    assert actions == {f"{s}:{o}" for s, o in _AWS_ALLOWED if s == "ec2"}
