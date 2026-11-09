"""Turn a trace (JSON dict) into a path map: nodes, edges with check badges, nested containers, layout.

Rules:
- Forwarding components (routers, firewalls, Prisma, route tables, TGW, gateways, ENIs) become nodes.
- Stateless/stateful checks between forwarding steps (security groups, NACLs) become badges on the
  edge they guard, like an interface ACL on a NetBrain map.
- `engine link` hops become the label of the next edge.
- Containers group nodes: on-prem site, Prisma Access, AWS account+region, VPC (nested in the account).
- The map always ends at a destination: the delivering node, or a synthetic endpoint showing
  where the flow stopped (not reached / outside known networks / unknown).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PASS, BLOCK, WARN, UNKNOWN, INFO = "PASS", "BLOCK", "WARN", "UNKNOWN", "INFO"
SEVERITY = {BLOCK: 4, UNKNOWN: 3, WARN: 2, PASS: 1, INFO: 0}

CHECK_COMPONENTS = {("aws", "security-group"): "SG", ("aws", "nacl"): "NACL"}
LINK_COMPONENTS = {("engine", "link")}

NODE_KINDS: dict[tuple[str, str], tuple[str, str]] = {
    ("engine", "source"): ("endpoint", "source"),
    ("engine", "error"): ("error", "could not evaluate"),
    ("cisco", "router"): ("router", "Cisco router"),
    ("panos", "firewall"): ("firewall", "PAN-OS firewall"),
    ("aws", "route-table"): ("vpc-router", "VPC route table"),
    ("aws", "tgw-route-table"): ("tgw", "Transit Gateway"),
    ("aws", "tgw"): ("tgw", "Transit Gateway"),
    ("aws", "eni"): ("eni", "ENI"),
    ("aws", "internet-gateway"): ("igw", "Internet gateway"),
    ("aws", "nat-gateway"): ("natgw", "NAT gateway"),
    ("aws", "gwlb-endpoint"): ("gwlbe", "GWLB endpoint"),
    ("aws", "vpc-endpoint"): ("vpce", "VPC endpoint"),
    ("aws", "vpc-peering"): ("peering", "VPC peering"),
    ("aws", "vgw"): ("vgw", "Virtual private gateway"),
    ("aws", "exit"): ("exit", "leaves AWS"),
    ("aws", "vpc"): ("error", "VPC"),
}

# ---- layout constants (px) --------------------------------------------------------------------
STEP = 230          # node-to-node distance
GROUP_GAP = 56      # extra distance when the container changes
MARGIN_X = 110
ICON = 56           # node tile size
PAD_X = (96, 80)    # container side padding by depth (outer, inner)
BAND = 28           # container label band height
NODE_BELOW = 64     # space for node labels under the tile
MIN_WIDTH = 900     # keeps the header line readable on short traces
BADGE_W = 60        # width reserved per SG/NACL badge on an edge (pill is 54)


@dataclass
class Container:
    key: str
    kind: str  # site | prisma | aws | vpc
    label: str
    depth: int
    x: float = 0
    y: float = 0
    w: float = 0
    h: float = 0


@dataclass
class Node:
    id: str
    kind: str
    title: str
    subtitle: str
    status: str
    hops: list[int]
    containers: list[str]  # outer -> inner container keys
    extra: str = ""
    role: str = ""  # source | destination | ""
    synthetic: bool = False
    x: float = 0
    y: float = 0


@dataclass
class Badge:
    hop: int
    label: str  # SG / NACL
    status: str
    text: str  # short description for tooltips


@dataclass
class Edge:
    id: str
    src: str
    dst: str
    status: str
    badges: list[Badge] = field(default_factory=list)
    label: str = ""
    link_hop: int | None = None
    dashed: bool = False
    note: str = ""


@dataclass
class PathMap:
    nodes: list[Node]
    edges: list[Edge]
    containers: list[Container]
    width: float
    height: float
    center_y: float
    trace: dict[str, Any]


# ---- helpers ----------------------------------------------------------------------------------
def _container_chain(loc: dict[str, str]) -> list[tuple[str, str, str]]:
    """[(key, kind, label)] outer -> inner for a hop location."""
    if not loc:
        return []
    if loc.get("cloud") == "aws" and loc.get("account"):
        acct, name, region = loc["account"], loc.get("account_name") or loc["account"], loc.get("region", "")
        outer_label = f"AWS · {name}" + (f" ({acct})" if name != acct else "") + (f" · {region}" if region else "")
        chain = [(f"aws:{acct}:{region}", "aws", outer_label)]
        if loc.get("vpc"):
            chain.append((f"vpc:{acct}:{loc['vpc']}", "vpc", f"VPC {loc['vpc']}"))
        return chain
    site = loc.get("site")
    if site:
        return [(f"site:{site}", "prisma" if site == "Prisma Access" else "site", site)]
    return []


def _worst(statuses: list[str]) -> str:
    return max(statuses, key=lambda s: SEVERITY.get(s, 0)) if statuses else INFO


def _extra_line(hop: dict[str, Any]) -> str:
    loc = hop.get("location") or {}
    parts = []
    if loc.get("zone_from") or loc.get("zone_to"):
        parts.append(f"{loc.get('zone_from', '?')} → {loc.get('zone_to', '?')}")
    elif loc.get("vrf") and hop.get("domain") == "cisco":
        parts.append(f"vrf {loc['vrf']}")
    if hop.get("nat"):
        parts.append("NAT")
    return " · ".join(parts)


def _inherit_vpc(hops: list[dict[str, Any]]) -> None:
    """A VM-Series in AWS has no VPC of its own in the trace; it sits between its ENIs' checks.
    Give it the VPC when the nearest hops on both sides agree."""
    for i, h in enumerate(hops):
        loc = h.get("location") or {}
        if loc.get("cloud") != "aws" or loc.get("vpc") or h.get("component") in ("tgw", "tgw-route-table", "exit"):
            continue
        before = next((hops[j]["location"] for j in range(i - 1, -1, -1) if (hops[j].get("location") or {}).get("vpc")), None)
        after = next((hops[j]["location"] for j in range(i + 1, len(hops)) if (hops[j].get("location") or {}).get("vpc")), None)
        if before and after and before.get("vpc") == after.get("vpc") and before.get("account") == loc.get("account"):
            h["location"] = {**loc, "vpc": before["vpc"]}


# ---- build -------------------------------------------------------------------------------------
def build_map(trace: dict[str, Any]) -> PathMap:
    hops = [dict(h) for h in trace.get("Hops", [])]
    _inherit_vpc(hops)
    flow = trace.get("FinalFlow") or trace.get("Flow") or {}
    outcome = trace.get("Outcome", "INCOMPLETE")
    reason = trace.get("Reason", "")

    containers: dict[str, Container] = {}
    nodes: list[Node] = []
    edges: list[Edge] = []
    pending: list[Badge] = []
    link_label, link_hop = "", None

    def chain_for(loc: dict[str, str]) -> list[str]:
        keys = []
        for depth, (key, kind, label) in enumerate(_container_chain(loc)):
            containers.setdefault(key, Container(key=key, kind=kind, label=label, depth=depth))
            keys.append(key)
        return keys

    def connect(node: Node, *, dashed: bool = False, note: str = "", status: str | None = None) -> None:
        nonlocal pending, link_label, link_hop
        if nodes:
            st = status or (_worst([b.status for b in pending]) if pending else (PASS if not dashed else UNKNOWN))
            edges.append(Edge(id=f"e{len(edges)}", src=nodes[-1].id, dst=node.id, status=st, badges=pending,
                              label=link_label, link_hop=link_hop, dashed=dashed, note=note))
        nodes.append(node)
        pending, link_label, link_hop = [], "", None

    for h in hops:
        key = (h.get("domain", ""), h.get("component", ""))
        idx = int(h.get("index", 0))
        if key in CHECK_COMPONENTS:
            pending.append(Badge(hop=idx, label=CHECK_COMPONENTS[key], status=h.get("status", INFO),
                                 text=h.get("summary", "")))
            continue
        if key in LINK_COMPONENTS:
            link_label, link_hop = h.get("node", ""), idx
            continue
        if h.get("domain") == "prisma":
            kind, sub = "prisma", "Prisma Access"
        else:
            kind, sub = NODE_KINDS.get(key, ("generic", h.get("component", "")))
        title = h.get("node", "")
        role = ""
        if key == ("engine", "source"):
            title, role = (trace.get("Flow") or {}).get("src", title), "source"
        connect(Node(id=f"n{len(nodes)}", kind=kind, title=title, subtitle=sub, status=h.get("status", INFO),
                     hops=[idx], containers=chain_for(h.get("location") or {}), extra=_extra_line(h), role=role))

    if not nodes:  # the source couldn't be located; still show both ends
        connect(Node(id="n0", kind="endpoint", title=(trace.get("Flow") or {}).get("src", "source"),
                     subtitle="location unknown", status=UNKNOWN, hops=[], containers=[], role="source",
                     synthetic=True))

    # ---- destination ---------------------------------------------------------------------------
    dst = flow.get("dst", "destination")
    last = nodes[-1] if nodes else None
    last_containers = last.containers if last else []
    if outcome == "REACHABLE":
        if last and last.kind == "eni" and not pending:
            last.role, last.kind = "destination", "endpoint"
            last.subtitle, last.extra, last.title = "destination", last.title, dst
        elif last and not pending and "itself" in reason:
            last.role = "destination"
        else:
            connect(Node(id=f"n{len(nodes)}", kind="endpoint", title=dst, subtitle="destination", status=PASS,
                         hops=[], containers=list(last_containers), role="destination", synthetic=True))
    elif outcome == "EXITED":
        label = "Internet" if "internet" in reason.lower() else "outside known network"
        connect(Node(id=f"n{len(nodes)}", kind="external", title=label, subtitle=f"toward {dst}", status=INFO,
                     hops=[], containers=[], role="destination", synthetic=True), note=reason, status=INFO)
    else:
        blocked_on_edge = bool(pending) and any(b.status == BLOCK for b in pending)
        sub = "not reached" if outcome == "BLOCKED" else "unknown"
        connect(Node(id=f"n{len(nodes)}", kind="endpoint", title=dst, subtitle=sub, status=INFO, hops=[],
                     containers=[] if not blocked_on_edge else list(last_containers), role="destination",
                     synthetic=True),
                dashed=not blocked_on_edge, note=reason,
                status=None if blocked_on_edge else (BLOCK if outcome == "BLOCKED" else UNKNOWN))

    width, height, cy = _layout(nodes, edges)
    used = {k for n in nodes for k in n.containers}
    return PathMap(nodes=nodes, edges=edges, containers=[c for c in _boxes(nodes, containers, cy) if c.key.split("#")[0] in used],
                   width=width, height=height, center_y=cy, trace=trace)


# ---- layout ------------------------------------------------------------------------------------
def _max_depth(nodes: list[Node]) -> int:
    return max((len(n.containers) for n in nodes), default=0)


def _common_prefix(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


def _layout(nodes: list[Node], edges: list[Edge]) -> tuple[float, float, float]:
    depth = _max_depth(nodes)
    cy = 40 + BAND * depth + ICON / 2 + 34  # room for container bands and link labels above the line
    badges_into = {e.dst: len(e.badges) for e in edges}
    x = MARGIN_X
    for i, n in enumerate(nodes):
        if i:
            # Edge must fit its badges plus clearance on both sides of the arrow.
            x += max(STEP, badges_into.get(n.id, 0) * BADGE_W + ICON + 90)
            prev = nodes[i - 1].containers
            if prev != n.containers:
                common = _common_prefix(prev, n.containers)
                x += GROUP_GAP * max(len(prev) - common, len(n.containers) - common, 1)
        n.x, n.y = x, cy
    width = max(x + MARGIN_X, MIN_WIDTH)
    height = cy + ICON / 2 + NODE_BELOW + 14 * depth + 60
    return width, height, cy


def _boxes(nodes: list[Node], containers: dict[str, Container], cy: float) -> list[Container]:
    """One rectangle per maximal run of consecutive nodes sharing a container (a container visited
    twice, e.g. AWS -> on-prem -> AWS, is drawn twice with the same label)."""
    depth_max = _max_depth(nodes)
    boxes: list[Container] = []
    for depth in range(depth_max):
        run_key, run_start = None, 0
        for i in range(len(nodes) + 1):
            key = nodes[i].containers[depth] if i < len(nodes) and len(nodes[i].containers) > depth else None
            if key != run_key:
                if run_key is not None:
                    c = containers[run_key]
                    first, last = nodes[run_start], nodes[i - 1]
                    pad = PAD_X[min(depth, len(PAD_X) - 1)]
                    top = cy - ICON / 2 - 22 - BAND * (depth_max - depth)
                    bottom = cy + ICON / 2 + NODE_BELOW + 14 * (depth_max - 1 - depth)
                    boxes.append(Container(key=f"{run_key}#{len(boxes)}", kind=c.kind, label=c.label, depth=depth,
                                           x=first.x - pad, y=top, w=(last.x - first.x) + 2 * pad, h=bottom - top))
                run_key, run_start = key, i
    return boxes
