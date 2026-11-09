from nettrace.drivers.cisco_acl import evaluate_acl
from nettrace.models import Flow

EXT = """Extended IP access list EDGE_IN
    10 deny tcp host 10.1.10.25 any eq telnet (5 matches)
    20 permit tcp 10.1.10.0 0.0.0.255 10.1.20.0 0.0.0.255 eq www 443
    30 permit udp any any range 5000 5010
    40 permit icmp any any echo
    50 deny ip any any
"""


def flow(src="10.1.10.25", dst="10.1.20.10", proto="tcp", port=443):
    return Flow(src=src, dst=dst, protocol=proto, dst_port=port)


def test_first_match_deny_wins_over_later_permit():
    r = evaluate_acl("EDGE_IN", EXT, flow(port=23))
    assert (r.action, r.certain) == ("deny", True)
    assert r.line.startswith("10 deny")


def test_permit_with_port_list():
    r = evaluate_acl("EDGE_IN", EXT, flow(port=443))
    assert r.action == "permit" and r.line.startswith("20 permit")
    assert evaluate_acl("EDGE_IN", EXT, flow(port=80)).action == "permit"


def test_port_range_and_protocol():
    assert evaluate_acl("EDGE_IN", EXT, flow(proto="udp", port=5005)).line.startswith("30")
    r = evaluate_acl("EDGE_IN", EXT, flow(proto="udp", port=6000))
    assert r.action == "deny" and r.line.startswith("50")


def test_icmp_echo():
    r = evaluate_acl("EDGE_IN", EXT, Flow(src="9.9.9.9", dst="8.8.8.8", protocol="icmp"))
    assert r.line.startswith("40")


def test_implicit_deny():
    out = "Extended IP access list X\n    10 permit tcp any any eq 22\n"
    r = evaluate_acl("X", out, flow(port=443))
    assert (r.action, r.line) == ("deny", "implicit deny")


def test_missing_acl_permits_all():
    r = evaluate_acl("NOPE", "", flow())
    assert r.action == "permit" and r.exists is False


def test_object_group_is_uncertain_not_guessed():
    out = ("Extended IP access list OG\n"
           "    10 permit tcp object-group SRCS any eq 443\n"
           "    20 permit tcp any any eq 443\n")
    r = evaluate_acl("OG", out, flow())
    assert r.action == "permit" and r.line.startswith("20")
    assert not r.certain and r.uncertain[0].startswith("10")


def test_standard_acl():
    out = "Standard IP access list S\n    10 permit 10.1.10.0, wildcard bits 0.0.0.255\n    20 deny any\n"
    assert evaluate_acl("S", out, flow()).action == "permit"
    assert evaluate_acl("S", out, flow(src="10.2.0.1")).action == "deny"
