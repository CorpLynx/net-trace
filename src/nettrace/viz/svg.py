"""Static SVG path map. Self-contained (no fonts, scripts or external images), so it can be
pasted into tickets, wikis or chat. Every element that maps to a hop carries data-hop for the
HTML viewer."""

from __future__ import annotations

from html import escape
from typing import Any

from nettrace.viz.model import BADGE_W, BLOCK, ICON, INFO, PASS, UNKNOWN, WARN, Edge, Node, PathMap

STATUS_COLOR = {PASS: "#1e9e5a", BLOCK: "#d93636", WARN: "#d9971c", UNKNOWN: "#8e5bd6", INFO: "#3b82c4"}
CONTAINER_STYLE = {
    "site": ("#f3f5f8", "#9aa7b8", "#4b5a6e"),
    "prisma": ("#fff5ec", "#f0a35e", "#a3561b"),
    "aws": ("#fff8ee", "#f29d38", "#9a5a10"),
    "vpc": ("#eef8ee", "#5aa95a", "#2f6e2f"),
}
OUTCOME_COLOR = {"REACHABLE": "#1e9e5a", "BLOCKED": "#d93636", "EXITED": "#3b82c4", "INCOMPLETE": "#d9971c"}
FONT = "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"


def _t(s: Any) -> str:
    return escape(str(s), quote=True)


# ---- icons (drawn in a 56x56 box centred on 0,0) -------------------------------------------------
def _icon(kind: str) -> str:
    w = "#ffffff"
    if kind == "router":  # Cisco-style router: disc with four arrows
        return (f'<circle r="21" fill="#2f6db5"/><g stroke="{w}" stroke-width="3" fill="none" stroke-linecap="round">'
                '<path d="M-12 0H-3M3 0H12M0 -12V-3M0 3V12"/></g>'
                f'<g fill="{w}"><path d="M-14 0l5-4v8z"/><path d="M14 0l-5-4v8z"/>'
                '<path d="M0 -14l-4 5h8z"/><path d="M0 14l-4-5h8z"/></g>')
    if kind == "firewall":  # brick wall
        bricks = "".join(f'<rect x="{x}" y="{y}" width="12" height="7" rx="1"/>'
                         for y, xs in ((-14, (-18, -5, 8)), (-5, (-12, 1, 14)), (4, (-18, -5, 8)))
                         for x in xs if x + 12 <= 20)
        return (f'<rect x="-22" y="-19" width="44" height="34" rx="5" fill="#c4442e"/>'
                f'<g fill="#f6c7a8">{bricks}</g><rect x="-22" y="13" width="44" height="5" rx="2" fill="#8f2d1d"/>')
    if kind == "prisma":  # cloud with shield
        return ('<path d="M-20 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 14 12a8 8 0 0 1-2 12z" fill="#f08a24"/>'
                '<path d="M0 -6l9 3v6c0 6-4 9-9 11c-5-2-9-5-9-11v-6z" fill="#fff"/>')
    if kind == "tgw":  # hub with spokes
        spokes = "".join(f'<line x1="0" y1="0" x2="{x}" y2="{y}"/>' for x, y in ((-16, -12), (16, -12), (-16, 12), (16, 12)))
        dots = "".join(f'<circle cx="{x}" cy="{y}" r="4.5"/>' for x, y in ((-16, -12), (16, -12), (-16, 12), (16, 12)))
        return (f'<rect x="-22" y="-20" width="44" height="40" rx="8" fill="#8c4fff"/>'
                f'<g stroke="{w}" stroke-width="2.5">{spokes}</g><g fill="{w}">{dots}</g><circle r="7" fill="{w}"/>')
    if kind == "vpc-router":  # route table
        rows = "".join(f'<rect x="-13" y="{y}" width="26" height="4" rx="1"/>' for y in (-10, -3, 4))
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#3f8f3f"/>'
                f'<g fill="{w}">{rows}</g><path d="M8 12h8l-3-3M16 12l-3 3" stroke="{w}" stroke-width="2" fill="none"/>')
    if kind == "lan":  # layer-2 switch: flat box with crossing arrows (Cisco style)
        return ('<rect x="-23" y="-12" width="46" height="24" rx="5" fill="#2f6db5"/>'
                f'<g stroke="{w}" stroke-width="2.2" fill="none" stroke-linecap="round">'
                '<path d="M-15 -4H13M9 -8l4 4-4 4"/><path d="M15 4H-13M-9 0l-4 4 4 4"/></g>')
    if kind == "users":  # group of people
        return ('<g fill="#4b5a6e"><circle cx="-9" cy="-9" r="6"/><path d="M-20 12a11 11 0 0 1 22 0z"/></g>'
                '<g fill="#2f6db5"><circle cx="8" cy="-6" r="7"/><path d="M-5 17a13 13 0 0 1 26 0z"/></g>')
    if kind == "account":  # AWS account: orange cloud
        return ('<path d="M-21 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 15 12a8 8 0 0 1-2 12z" fill="#f29d38"/>'
                f'<text y="7" text-anchor="middle" fill="{w}" style="font:700 10px sans-serif">AWS</text>')
    if kind in ("eni", "endpoint", "host"):  # server
        return ('<rect x="-15" y="-20" width="30" height="40" rx="4" fill="#4b5a6e"/>'
                '<g fill="#9fb0c4"><rect x="-10" y="-14" width="20" height="4" rx="1"/>'
                '<rect x="-10" y="-6" width="20" height="4" rx="1"/></g><circle cx="7" cy="12" r="2.5" fill="#5ee08a"/>')
    if kind == "igw":
        return (f'<circle r="20" fill="#2a8ac9"/><g fill="none" stroke="{w}" stroke-width="2">'
                '<ellipse rx="8" ry="18"/><line x1="-19" y1="0" x2="19" y2="0"/>'
                '<path d="M-16 -9H16M-16 9H16"/></g>')
    if kind == "external":
        return ('<path d="M-22 10a10 10 0 0 1 2-19a13 13 0 0 1 24-5a11 11 0 0 1 16 12a8 8 0 0 1-2 12z" '
                'fill="#e6edf5" stroke="#8aa0b8" stroke-width="2"/>')
    if kind == "natgw":
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#d67a1e"/>'
                f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 13px sans-serif">NAT</text>')
    if kind in ("gwlbe", "vpce"):
        return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#6a5acd"/>'
                f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 11px sans-serif">'
                f'{"GWLB" if kind == "gwlbe" else "VPCE"}</text>')
    if kind == "error":
        return (f'<circle r="20" fill="#8e5bd6"/><text y="7" text-anchor="middle" fill="{w}" '
                'style="font:700 20px sans-serif">?</text>')
    label = {"peering": "PCX", "vgw": "VGW", "exit": "→"}.get(kind, "•")
    return (f'<rect x="-21" y="-19" width="42" height="38" rx="7" fill="#5c6b80"/>'
            f'<text y="5" text-anchor="middle" fill="{w}" style="font:700 12px sans-serif">{_t(label)}</text>')


# ---- pieces ---------------------------------------------------------------------------------------
def _node(n: Node) -> str:
    color = STATUS_COLOR.get(n.status, "#888")
    ring = ""
    if n.status != INFO or n.role:
        unreached = n.synthetic and n.role == "destination" and n.subtitle != "destination"
        dash = ' stroke-dasharray="5 4"' if unreached else ""
        ring_color = "#9aa7b8" if unreached else color
        ring = (f'<rect x="{-ICON / 2 - 4}" y="{-ICON / 2 - 4}" width="{ICON + 8}" height="{ICON + 8}" rx="14" '
                f'fill="none" stroke="{ring_color}" stroke-width="{4 if n.status == BLOCK else 2.5}"{dash}/>')
    tile = f'<rect x="{-ICON / 2}" y="{-ICON / 2}" width="{ICON}" height="{ICON}" rx="11" fill="#fff" stroke="#d5dbe3"/>'
    hop = f' data-hop="{n.hops[0]}"' if n.hops else ""
    badge = ""
    if n.status in (BLOCK, WARN, UNKNOWN):
        glyph = {BLOCK: "✕", WARN: "!", UNKNOWN: "?"}[n.status]
        badge = (f'<circle cx="{ICON / 2}" cy="{-ICON / 2}" r="10" fill="{color}"/>'
                 f'<text x="{ICON / 2}" y="{-ICON / 2 + 4.5}" text-anchor="middle" fill="#fff" '
                 f'style="font:700 12px sans-serif">{glyph}</text>')
    role = ""
    if n.role:
        role = (f'<text y="{-ICON / 2 - 12}" text-anchor="middle" fill="#6b7a8f" '
                f'style="font:600 10px sans-serif;letter-spacing:.08em">{n.role.upper()}</text>')
    lines = [f'<text y="{ICON / 2 + 18}" text-anchor="middle" fill="#1d2633" style="font:600 13px sans-serif">{_t(_s(n.title, 26))}</text>',
             f'<text y="{ICON / 2 + 33}" text-anchor="middle" fill="#6b7a8f" style="font:11px sans-serif">{_t(_s(n.subtitle, 30))}</text>']
    if n.extra:
        lines.append(f'<text y="{ICON / 2 + 47}" text-anchor="middle" fill="#3b82c4" style="font:11px sans-serif">{_t(_s(n.extra, 30))}</text>')
    title = f"<title>{_t(n.title)} — {_t(n.subtitle)} ({_t(n.status)})</title>"
    return (f'<g class="node" id="{n.id}" transform="translate({n.x:.0f},{n.y:.0f})"{hop}>{title}{ring}{tile}'
            f'{_icon(n.kind)}{badge}{role}{"".join(lines)}</g>')


def _s(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _edge(e: Edge, a: Node, b: Node) -> str:
    color = STATUS_COLOR.get(e.status, "#888")
    x1, x2, y = a.x + ICON / 2 + 6, b.x - ICON / 2 - 10, a.y
    if e.status == BLOCK and e.badges:
        # Draw the path solid up to the blocking badge, faded after it.
        stop = next(i for i, bd in enumerate(e.badges) if bd.status == BLOCK)
        bx = _badge_x(e, a, b, stop)
        line = (f'<line x1="{x1:.0f}" y1="{y}" x2="{bx:.0f}" y2="{y}" stroke="{STATUS_COLOR[PASS]}" stroke-width="4"/>'
                f'<line x1="{bx:.0f}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="#c3cad4" stroke-width="3" '
                f'stroke-dasharray="6 5"/>')
    else:
        dash = ' stroke-dasharray="7 6"' if e.dashed else ""
        width = 3 if e.dashed or e.status == INFO else 4
        line = (f'<line x1="{x1:.0f}" y1="{y}" x2="{x2:.0f}" y2="{y}" stroke="{color}" stroke-width="{width}"{dash} '
                f'marker-end="url(#arrow-{_t(e.status)})"/>')
    parts = [line]
    if e.label:
        mid = (x1 + x2) / 2
        hop = f' data-hop="{e.link_hop}"' if e.link_hop else ""
        parts.append(f'<g class="link"{hop}><rect x="{mid - 60:.0f}" y="{y - 31}" width="120" height="18" rx="9" '
                     f'fill="#fff" stroke="#c9d1db"/><text x="{mid:.0f}" y="{y - 18}" text-anchor="middle" '
                     f'fill="#4b5a6e" style="font:11px sans-serif"><title>link {_t(e.label)}</title>⇄ {_t(_s(e.label, 16))}'
                     f'</text></g>')
    for i, bd in enumerate(e.badges):
        bx = _badge_x(e, a, b, i)
        c = STATUS_COLOR.get(bd.status, "#888")
        glyph = {PASS: "✓", BLOCK: "✕", WARN: "!", UNKNOWN: "?"}.get(bd.status, "")
        parts.append(f'<g class="badge" data-hop="{bd.hop}"><title>{_t(bd.label)}: {_t(bd.text)}</title>'
                     f'<rect x="{bx - 27:.0f}" y="{y - 11}" width="54" height="22" rx="11" fill="#fff" stroke="{c}" '
                     f'stroke-width="2"/><text x="{bx - 7:.0f}" y="{y + 4}" text-anchor="middle" fill="#1d2633" '
                     f'style="font:600 10px sans-serif">{bd.label}</text><text x="{bx + 16:.0f}" y="{y + 4.5}" '
                     f'text-anchor="middle" fill="{c}" style="font:700 12px sans-serif">{glyph}</text></g>')
    if e.note and (e.dashed or e.status in (BLOCK, UNKNOWN)) and not e.badges:
        mid = (x1 + x2) / 2
        chars = max(8, int((x2 - x1) / 6.6))
        parts.append(f'<text x="{mid:.0f}" y="{y + 22}" text-anchor="middle" fill="{color}" '
                     f'style="font:600 11px sans-serif"><title>{_t(e.note)}</title>{_t(_s(e.note, chars))}</text>')
    return f'<g class="edge" id="{e.id}">{"".join(parts)}</g>'


def _badge_x(e: Edge, a: Node, b: Node, i: int) -> float:
    n = len(e.badges)
    mid = (a.x + b.x) / 2
    return mid + (i - (n - 1) / 2) * BADGE_W


def _header(pm: PathMap) -> str:
    t = pm.trace
    flow = t.get("Flow") or {}
    port = f":{flow['dst_port']}" if flow.get("dst_port") else ""
    proto = flow.get("protocol", "")
    title = f"{flow.get('src', '?')} → {flow.get('dst', '?')}{port} ({proto})"
    final = t.get("FinalFlow")
    if final and final != flow:
        fport = f":{final['dst_port']}" if final.get("dst_port") else ""
        title += f"   after NAT: {final.get('src')} → {final.get('dst')}{fport}"
    outcome = t.get("Outcome", "")
    color = OUTCOME_COLOR.get(outcome, "#666")
    return (f'<g transform="translate(24,30)"><rect x="0" y="-18" width="{len(outcome) * 9 + 24}" height="26" rx="6" '
            f'fill="{color}"/><text x="12" y="0" fill="#fff" style="font:700 13px sans-serif">{_t(outcome)}</text>'
            f'<text x="{len(outcome) * 9 + 36}" y="0" fill="#1d2633" style="font:600 15px sans-serif">{_t(title)}</text>'
            f'<text x="0" y="24" fill="#4b5a6e" style="font:12px sans-serif">{_t(_s(t.get("Reason", ""), 160))}</text></g>')


def _markers() -> str:
    out = []
    for status, color in STATUS_COLOR.items():
        out.append(f'<marker id="arrow-{_t(status)}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" '
                   f'markerHeight="5" orient="auto"><path d="M0 0L10 5L0 10z" fill="{color}"/></marker>')
    return "".join(out)


def render_svg(pm: PathMap, *, header: bool = True) -> str:
    top = 62 if header else 0
    width, height = pm.width, pm.height + top
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height:.0f}" '
             f'width="{width:.0f}" height="{height:.0f}" style="{FONT};background:#fbfcfd">',
             f"<defs>{_markers()}</defs>"]
    if header:
        parts.append(_header(pm))
    parts.append(f'<g transform="translate(0,{top})">')
    for c in sorted(pm.containers, key=lambda c: c.depth):
        fill, stroke, text = CONTAINER_STYLE.get(c.kind, CONTAINER_STYLE["site"])
        parts.append(f'<g class="container"><rect x="{c.x:.0f}" y="{c.y:.0f}" width="{c.w:.0f}" height="{c.h:.0f}" '
                     f'rx="12" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
                     f'<text x="{c.x + 14:.0f}" y="{c.y + 19:.0f}" fill="{text}" style="font:600 12px sans-serif">'
                     f'{_t(_s(c.label, max(12, int(c.w / 7.2))))}</text></g>')
    by_id = {n.id: n for n in pm.nodes}
    for e in pm.edges:
        parts.append(_edge(e, by_id[e.src], by_id[e.dst]))
    for n in pm.nodes:
        parts.append(_node(n))
    parts.append("</g></svg>")
    return "".join(parts)
