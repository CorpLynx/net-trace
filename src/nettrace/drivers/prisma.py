"""Prisma Access via the Strata Cloud Manager (SCM) configuration API.

Prisma Access has no API equivalent of `test security-policy-match`, so nettrace
reads the security rules for the folder (GET only) and evaluates them in order.
Rule criteria nettrace can't evaluate (App-ID, users without --user, URL
categories, HIP, FQDN/dynamic objects) are reported as uncertain instead of
guessed. Prisma Access routing is taken from the inventory.
"""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from nettrace import audit
from nettrace.errors import CredentialError, Deadline, DeviceError
from nettrace.inventory import Inventory
from nettrace.models import Evidence, Flow, Hop, Outcome, Status
from nettrace.netutil import ip_in_range, longest_match, port_in_spec, protocol_number
from nettrace.readonly import check_http_method
from nettrace.steps import AwsAt, DeviceAt, PrismaAt, StepResult

DEFAULT_API_URL = "https://api.strata.paloaltonetworks.com"
DEFAULT_TOKEN_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"

PREDEFINED_SERVICES = {
    "service-http": {"tcp": {"port": "80,8080"}},
    "service-https": {"tcp": {"port": "443"}},
}


class ScmClient:
    def __init__(self, timeout: int = 30):
        self.api_url = os.environ.get("NETTRACE_SCM_API_URL", DEFAULT_API_URL).rstrip("/")
        self.token_url = os.environ.get("NETTRACE_SCM_TOKEN_URL", DEFAULT_TOKEN_URL)
        for url in (self.api_url, self.token_url):
            if not url.lower().startswith("https://"):
                raise DeviceError("NETTRACE_SCM_API_URL / NETTRACE_SCM_TOKEN_URL must use https://")
        self.timeout = timeout
        self._token: str | None = None
        self._token_expiry = 0.0
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self.evidence: list[Evidence] = []

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        client_id = os.environ.get("NETTRACE_SCM_CLIENT_ID")
        secret = os.environ.get("NETTRACE_SCM_CLIENT_SECRET")
        tsg = os.environ.get("NETTRACE_SCM_TSG_ID")
        missing = [n for n, v in (("NETTRACE_SCM_CLIENT_ID", client_id), ("NETTRACE_SCM_CLIENT_SECRET", secret),
                                  ("NETTRACE_SCM_TSG_ID", tsg)) if not v]
        if missing:
            raise CredentialError(f"Strata Cloud Manager credentials missing: {', '.join(missing)}")
        # OAuth2 client-credentials token request. This is authentication, not a config change.
        audit.log("scm", "strata-cloud-manager", f"POST {self.token_url} (OAuth2 token request)", "ok")
        try:
            resp = requests.post(self.token_url, data={"grant_type": "client_credentials", "scope": f"tsg_id:{tsg}"},
                                 auth=(client_id, secret), timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            raise DeviceError(f"SCM token request failed: {exc}") from None
        if resp.status_code != 200:  # includes 3xx: the client secret is never sent to a redirect target
            raise DeviceError(f"SCM token request failed: HTTP {resp.status_code}")
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 900))
        return self._token

    # Simulation seam (demo lab, tests): callable(endpoint, params) -> response JSON dict.
    transport_override: Any = None

    deadline: Deadline | None = None  # overall trace budget, set by the engine

    def _get_page(self, endpoint: str, q: dict[str, Any]) -> dict[str, Any]:
        check_http_method("GET")
        if self.deadline:
            self.deadline.check()
        try:
            data = self._fetch(endpoint, q)
        except Exception:
            audit.log("scm", "strata-cloud-manager", f"GET {endpoint} {q}", "error")
            raise
        audit.log("scm", "strata-cloud-manager", f"GET {endpoint} {q}", "ok")
        return data

    def _fetch(self, endpoint: str, q: dict[str, Any]) -> dict[str, Any]:
        if ScmClient.transport_override is not None:
            return ScmClient.transport_override(endpoint, q)
        for attempt in (1, 2):  # one retry on a timeout; safe because this is a read-only GET
            try:
                # No redirects: the Authorization header must not follow a 3xx to another host.
                resp = requests.get(f"{self.api_url}{endpoint}", params=q, timeout=self.timeout,
                                    allow_redirects=False, headers={"Authorization": f"Bearer {self._get_token()}"})
                break
            except requests.Timeout as exc:
                if attempt == 2:
                    raise DeviceError(f"SCM GET {endpoint} failed: {exc}") from None
                if self.deadline:
                    self.deadline.check()
            except requests.RequestException as exc:
                raise DeviceError(f"SCM GET {endpoint} failed: {exc}") from None
        if resp.status_code != 200:
            raise DeviceError(f"SCM GET {endpoint} failed: HTTP {resp.status_code} {resp.text[:200]}")
        try:
            return resp.json()
        except ValueError:
            raise DeviceError(f"SCM GET {endpoint}: response is not JSON") from None

    def get_all(self, endpoint: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        check_http_method("GET")
        key = endpoint + repr(sorted(params.items()))
        if key in self._cache:
            return self._cache[key]
        items: list[dict[str, Any]] = []
        limit, offset = 500, 0
        while True:
            q = {**params, "limit": limit, "offset": offset}
            data = self._get_page(endpoint, q).get("data", [])
            items.extend(data)
            if len(data) < limit:
                break
            offset += limit
        self.evidence.append(Evidence("strata-cloud-manager", f"GET {endpoint} {params}", f"{len(items)} items"))
        self._cache[key] = items
        return items

    def security_rules(self, folder: str) -> list[dict[str, Any]]:
        pre = self.get_all("/config/security/v1/security-rules", {"folder": folder, "position": "pre"})
        post = self.get_all("/config/security/v1/security-rules", {"folder": folder, "position": "post"})
        return [dict(r, _position="pre") for r in pre] + [dict(r, _position="post") for r in post]

    def objects(self, kind: str, folder: str) -> dict[str, dict[str, Any]]:
        return {o["name"]: o for o in self.get_all(f"/config/objects/v1/{kind}", {"folder": folder})}


# ---- rule evaluation ------------------------------------------------------------------
@dataclass
class RuleEval:
    rule: str | None
    action: str | None
    position: str | None = None
    uncertain: list[str] = field(default_factory=list)


class Resolver:
    def __init__(self, scm: ScmClient, folder: str):
        self.scm, self.folder = scm, folder

    def _addresses(self) -> dict[str, dict[str, Any]]:
        return self.scm.objects("addresses", self.folder)

    def _groups(self) -> dict[str, dict[str, Any]]:
        return self.scm.objects("address-groups", self.folder)

    def address_match(self, ip: str, members: list[str], depth: int = 0) -> bool | None:
        if not members or "any" in members:
            return True
        uncertain = False
        for m in members:
            r = self._one_address(ip, m, depth)
            if r is True:
                return True
            if r is None:
                uncertain = True
        return None if uncertain else False

    def _one_address(self, ip: str, name: str, depth: int) -> bool | None:
        if depth > 10:
            return None
        literal = _literal_match(ip, name)
        if literal is not None:
            return literal
        obj = self._addresses().get(name)
        if obj:
            if obj.get("ip_netmask"):
                return _literal_match(ip, obj["ip_netmask"])
            if obj.get("ip_range"):
                return _literal_match(ip, obj["ip_range"])
            return None  # fqdn / wildcard
        grp = self._groups().get(name)
        if grp:
            if grp.get("static"):
                return self.address_match(ip, grp["static"], depth + 1)
            return None  # dynamic group
        return None  # EDL, region or unknown object

    def application_match(self, app: str | None, apps: list[str]) -> bool | None:
        """A named app is certain; an app that is not listed may still be inside a listed application
        group or filter (not expanded here), and a failed lookup of those is uncertain too."""
        if not app:
            return None
        if app in apps:
            return True
        for kind in ("application-groups", "application-filters"):
            try:
                objs = self.scm.objects(kind, self.folder)
            except DeviceError:
                return None
            if any(a in objs for a in apps):
                return None
        return False

    def service_match(self, flow: Flow, services: list[str], rule_apps: list[str], depth: int = 0) -> bool | None:
        if not services or "any" in services:
            return True
        proto = protocol_number(flow.protocol)
        uncertain = False
        for name in services:
            if name == "application-default":
                # With --application we assume the flow uses that app's standard port(s).
                if rule_apps == ["any"] or (flow.application and flow.application in rule_apps):
                    return True
                uncertain = True
                continue
            obj = PREDEFINED_SERVICES.get(name) or (self.scm.objects("services", self.folder).get(name) or {}).get("protocol")
            if obj is None:
                grp = self.scm.objects("service-groups", self.folder).get(name)
                if grp and depth < 10:
                    r = self.service_match(flow, grp.get("members", []), rule_apps, depth + 1)
                    if r is True:
                        return True
                    uncertain = uncertain or r is None
                else:
                    uncertain = True
                continue
            key = {6: "tcp", 17: "udp"}.get(proto)
            if key and key in obj:
                r = port_in_spec(flow.dst_port, obj[key].get("port", ""))
                if r is True:
                    return True
                uncertain = uncertain or r is None
        return None if uncertain else False


def _literal_match(ip: str, value: str) -> bool | None:
    value = value.strip()
    try:
        if "-" in value:
            a, b = value.split("-", 1)
            return ip_in_range(ip, a.strip(), b.strip())
        return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _list(rule: dict[str, Any], key: str) -> list[str]:
    v = rule.get(key)
    if v is None:
        return ["any"]
    return list(v) if isinstance(v, list) else [v]


def _zone_match(zone: str, zones: list[str]) -> bool:
    return "any" in zones or zone in zones


def evaluate_rules(rules: list[dict[str, Any]], resolver: Resolver, flow: Flow, from_zone: str, to_zone: str) -> RuleEval:
    uncertain: list[str] = []
    for rule in rules:
        if rule.get("disabled"):
            continue
        name = rule.get("name", "?")
        if not _zone_match(from_zone, _list(rule, "from")) or not _zone_match(to_zone, _list(rule, "to")):
            continue
        checks: dict[str, bool | None] = {}
        src = resolver.address_match(flow.src, _list(rule, "source"))
        if rule.get("negate_source") and src is not None:
            src = not src
        checks["source"] = src
        dst = resolver.address_match(flow.dst, _list(rule, "destination"))
        if rule.get("negate_destination") and dst is not None:
            dst = not dst
        checks["destination"] = dst
        apps = _list(rule, "application")
        checks["service"] = resolver.service_match(flow, _list(rule, "service"), apps)
        if apps != ["any"]:
            checks["application"] = resolver.application_match(flow.application, apps)
        users = _list(rule, "source_user")
        if users != ["any"]:
            # An exact user match is certain; otherwise the user may still be in a listed group.
            exact = bool(flow.user) and any(flow.user.lower() == u.lower() for u in users)
            checks["user"] = True if exact else None
        if _list(rule, "category") != ["any"]:
            checks["url-category"] = None
        if rule.get("schedule"):  # a time-limited rule is not always in force; the clock is not evaluated
            checks["schedule"] = None
        for hip in ("source_hip", "destination_hip"):
            if _list(rule, hip) != ["any"]:
                checks[hip] = None

        if any(v is False for v in checks.values()):
            continue
        unknown = [k for k, v in checks.items() if v is None]
        if unknown:
            uncertain.append(f"{name} (depends on {', '.join(unknown)})")
            continue
        return RuleEval(rule=name, action=rule.get("action"), position=rule.get("_position"), uncertain=uncertain)
    return RuleEval(rule=None, action=None, uncertain=uncertain)


# ---- hop evaluation -----------------------------------------------------------------
def step(scm: ScmClient, inv: Inventory, at: PrismaAt, flow: Flow) -> StepResult:
    cfg = inv.prisma
    assert cfg is not None
    start = len(scm.evidence)
    details: list[str] = []
    src_loc = inv.prisma_location(flow.src)
    dst_loc = inv.prisma_location(flow.dst)

    def folder_for(loc: tuple[str, str] | None) -> str | None:
        if not loc:
            return None
        return cfg.mobile_users_folder if loc[0] == "mobile_users" else cfg.remote_networks_folder

    if at.entry == "source":
        from_zone = cfg.user_zone
        folder = folder_for(src_loc)
    else:
        from_zone = cfg.internal_zone
        folder = folder_for(dst_loc) or folder_for(src_loc)

    # Routing (from the inventory; Prisma Access routing state isn't exposed by the config API).
    sc_match = None
    best = None
    for sc in cfg.service_connections:
        hit = longest_match(flow.dst, sc.routes)
        if hit and (best is None or ipaddress.ip_network(hit).prefixlen > ipaddress.ip_network(best).prefixlen):
            best, sc_match = hit, sc
    if dst_loc:
        to_zone, route = cfg.user_zone, f"{flow.dst} is a Prisma Access {dst_loc[0].replace('_', ' ')} ({dst_loc[1]})"
    elif sc_match:
        to_zone, route = cfg.internal_zone, f"{best} via service connection {sc_match.name}"
    else:
        to_zone, route = cfg.internet_zone, f"{flow.dst} not internal; egress to internet"

    def hop(status: Status, summary: str, **kw: Any) -> Hop:
        return Hop(domain="prisma", node="prisma-access", component=f"security policy ({folder})", status=status,
                   summary=summary, details=details, evidence=scm.evidence[start:], **kw)

    if not folder:
        return StepResult([hop(Status.UNKNOWN, "can't tell which Prisma Access folder applies")], flow,
                          outcome=Outcome.INCOMPLETE, reason="Prisma Access folder unknown")

    rules = scm.security_rules(folder)
    result = evaluate_rules(rules, Resolver(scm, folder), flow, from_zone, to_zone)
    zones = f"{from_zone} -> {to_zone}"
    if result.uncertain:
        details.append("rules above the match that nettrace could not evaluate: " + "; ".join(result.uncertain))
    details.append(f"evaluated {len(rules)} rules from SCM folder '{folder}' (config, not a live policy test)")

    if result.rule is None:
        if result.uncertain:
            return StepResult([hop(Status.UNKNOWN, f"{zones}: no definite match", policy="undetermined")], flow,
                              outcome=Outcome.INCOMPLETE, reason="Prisma Access: match depends on criteria nettrace can't evaluate")
        if from_zone == to_zone:
            details.append("no rule matched; intrazone-default allows")
            policy, status = "intrazone-default (allow)", Status.WARN
        else:
            return StepResult([hop(Status.BLOCK, f"{zones}: no rule matched", policy="interzone-default (deny)")],
                              flow, outcome=Outcome.BLOCKED, reason="Prisma Access: no rule matches; interzone default denies")
    else:
        action = (result.action or "unknown").lower()
        policy = f"{result.rule} [{result.position}] ({action})"
        if action != "allow" and result.uncertain:
            # An earlier rule nettrace could not evaluate might allow the flow before this deny is reached.
            return StepResult([hop(Status.UNKNOWN, f"{zones}: rule {result.rule} -> {action}, but earlier rules "
                                   "could not be evaluated", policy=policy)], flow, outcome=Outcome.INCOMPLETE,
                              reason=f"Prisma Access: {result.rule} ({action}) is only reached if the rules above it "
                                     "do not match, and nettrace can't tell")
        if action != "allow":
            return StepResult([hop(Status.BLOCK, f"{zones}: rule {result.rule} -> {action}", policy=policy)], flow,
                              outcome=Outcome.BLOCKED, reason=f"Prisma Access rule {result.rule} action {action}")
        if result.uncertain:
            # An earlier rule nettrace could not evaluate might be a deny that catches the flow first.
            return StepResult([hop(Status.UNKNOWN, f"{zones}: rule {result.rule} -> allow, but earlier rules "
                                   "could not be evaluated", policy=policy)], flow, outcome=Outcome.INCOMPLETE,
                              reason=f"Prisma Access: {result.rule} (allow) is only reached if the rules above it "
                                     "do not match, and nettrace can't tell")
        status = Status.PASS

    h = hop(status, f"{zones}; {route}", policy=policy)
    if dst_loc:
        return StepResult([h], flow, outcome=Outcome.REACHABLE, reason=f"delivered to Prisma Access {dst_loc[1]}")
    if sc_match:
        link = inv.link_from_prisma(sc_match.name)
        if not link:
            return StepResult([h], flow, outcome=Outcome.EXITED,
                              reason=f"leaves Prisma Access via service connection {sc_match.name} (no link in inventory)")
        _, there = link
        if there.device:
            return StepResult([h], flow, next=DeviceAt(device=there.device, arrival_interface=there.interface))
        if there.aws_tgw_attachment:
            return StepResult([h], flow, next=AwsAt(kind="tgw_attachment", resource_id=there.aws_tgw_attachment,
                                                     account=there.aws_account, region=there.aws_region))
    return StepResult([h], flow, outcome=Outcome.EXITED, reason="egresses Prisma Access to the internet")
