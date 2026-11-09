import re

import pytest

from nettrace.drivers import aws
from nettrace.errors import InventoryError
from nettrace.inventory import AwsAccount, load_inventory


class _Sts:
    def __init__(self):
        self.calls = []

    def assume_role(self, **kw):
        self.calls.append(kw)
        return {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T"}}


class _Base:
    def __init__(self):
        self.sts = _Sts()

    def client(self, name, **kw):
        assert name == "sts" and kw["config"].connect_timeout == 5
        return self.sts


class _Boto3:
    @staticmethod
    def Session(**kw):
        return object()


def _env(external=None):
    env = object.__new__(aws.AwsEnv)
    env._sessions, env._clients = {}, {}
    env._boto3, env.base = _Boto3, _Base()
    acct = AwsAccount("prod", "111111111111", ["us-east-1"], role_arn="arn:aws:iam::111111111111:role/r",
                      external_id_env=external)
    env.account = lambda _id: acct
    return env


def test_assume_role_params(monkeypatch):
    monkeypatch.setattr(aws, "install_aws_guard", lambda s: s)
    monkeypatch.setenv("EXT", "xid")
    env = _env("EXT")
    env.session("111111111111")
    kw = env.base.sts.calls[0]
    assert kw["DurationSeconds"] == 900 and kw["ExternalId"] == "xid"
    assert re.fullmatch(r"[\w+=,.@-]{2,64}", kw["RoleSessionName"]) and kw["RoleSessionName"].startswith("nettrace-")
    assert "ec2:DescribeVpcs" in kw["Policy"] and len(kw["Policy"]) <= 2048


def test_session_name_sanitised(monkeypatch):
    monkeypatch.setenv("USER", "a b/c" + "x" * 80)
    assert re.fullmatch(r"[\w+=,.@-]{1,64}", aws.session_name()) and len(aws.session_name()) == 64


class _Expired(Exception):
    response = {"Error": {"Code": "ExpiredToken"}}


def test_reassume_once_on_expired(monkeypatch):
    monkeypatch.setattr(aws, "install_aws_guard", lambda s: s)
    env = _env()
    env.session("111111111111")
    attempts = []

    def once(*a, **k):
        attempts.append(1)
        env.session("111111111111")  # what client() does on every call
        raise _Expired()

    monkeypatch.setattr(env, "_boto_call_once", once)
    with pytest.raises(_Expired):
        env._boto_call("111111111111", "us-east-1", "describe_vpcs", "ec2", {})
    assert len(attempts) == 2 and len(env.base.sts.calls) == 2  # one retry, one re-assume


def _inv(tmp_path, aws_yaml):
    f = tmp_path / "inv.yaml"
    f.write_text("devices: []\naws:\n" + aws_yaml)
    return load_inventory(f)


ROLE = "    - {account_id: '222222222222', regions: [us-east-1], role_arn: 'arn:aws:iam::222222222222:role/r'}\n"


def test_external_id_required_cross_account(tmp_path):
    with pytest.raises(InventoryError, match="external_id_env"):
        _inv(tmp_path, "  base_account_id: '111111111111'\n  accounts:\n" + ROLE)


def test_external_id_same_account_ok_and_unknown_base_warns(tmp_path):
    _inv(tmp_path, "  base_account_id: '222222222222'\n  accounts:\n" + ROLE)
    with pytest.warns(UserWarning, match="external_id_env"):
        _inv(tmp_path, "  accounts:\n" + ROLE)
