import pytest

from nettrace import netutil as n


def test_protocol_numbers():
    assert n.protocol_number("TCP") == 6
    assert n.protocol_number("17") == 17
    assert n.protocol_number(1) == 1
    assert n.protocol_name(6) == "tcp"
    assert n.protocol_name(99) == "99"
    with pytest.raises(ValueError):
        n.protocol_number("bogus")


def test_uses_ports():
    assert n.uses_ports("tcp") and n.uses_ports("udp")
    assert not n.uses_ports("icmp")


def test_cisco_port():
    assert n.cisco_port("www") == 80
    assert n.cisco_port(" 8080 ") == 8080
    assert n.cisco_port("nope") is None


def test_ip_in():
    assert n.ip_in("10.1.2.3", ["192.168.0.0/16", "10.0.0.0/8"])
    assert not n.ip_in("11.1.2.3", ["10.0.0.0/8"])
    assert n.ip_in("10.1.2.3", ["garbage", "10.0.0.0/8"])  # invalid prefixes are skipped
    assert not n.ip_in("10.1.2.3", [])


def test_longest_match():
    prefixes = ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "bad"]
    assert n.longest_match("10.1.2.3", prefixes) == "10.1.2.0/24"
    assert n.longest_match("10.9.9.9", prefixes) == "10.0.0.0/8"
    assert n.longest_match("8.8.8.8", prefixes) == "0.0.0.0/0"
    assert n.longest_match("8.8.8.8", ["10.0.0.0/8"]) is None
    assert n.longest_match("8.8.8.8", ["::/0"]) is None  # address family mismatch


def test_wildcard_match():
    assert n.wildcard_match("10.1.2.3", "10.1.2.0", "0.0.0.255")
    assert not n.wildcard_match("10.1.3.3", "10.1.2.0", "0.0.0.255")
    assert n.wildcard_match("1.2.3.4", "0.0.0.0", "255.255.255.255")
    assert n.wildcard_match("10.1.2.3", "10.1.2.3", "0.0.0.0")
    assert n.wildcard_match("10.0.5.1", "10.0.1.1", "0.0.254.0")  # discontiguous
    assert not n.wildcard_match("10.0.2.1", "10.0.1.1", "0.0.254.0")


def test_port_in_spec():
    assert n.port_in_spec(443, "80,443") is True
    assert n.port_in_spec(8050, "80, 8000-8080") is True
    assert n.port_in_spec(8081, "8000-8080") is False
    assert n.port_in_spec(80, "") is False
    assert n.port_in_spec(80, "any") is False
    assert n.port_in_spec(None, "80") is None
    assert n.port_in_spec(8000, "8000-8080") is True and n.port_in_spec(8080, "8000-8080") is True


def test_ip_in_range():
    assert n.ip_in_range("10.0.0.5", "10.0.0.1", "10.0.0.10")
    assert n.ip_in_range("10.0.0.1", "10.0.0.1", "10.0.0.10")
    assert not n.ip_in_range("10.0.0.11", "10.0.0.1", "10.0.0.10")
