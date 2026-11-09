"""Single-file interactive viewer: the SVG map plus a hop list and a details/evidence pane.

No network access is needed to open it (no CDN, fonts or external scripts), so it can be saved,
attached to a ticket or opened on an air-gapped jump host. Trace JSON is embedded in the page.
"""

from __future__ import annotations

import json
from typing import Any

from nettrace import __version__
from nettrace.viz.model import build_map
from nettrace.viz.svg import render_svg


def _payload(trace: dict[str, Any]) -> dict[str, Any]:
    pm = build_map(trace)
    flow = trace.get("Flow") or {}
    port = f":{flow['dst_port']}" if flow.get("dst_port") else ""
    return {
        "title": f"{flow.get('src')} → {flow.get('dst')}{port} {flow.get('protocol', '')}",
        "outcome": trace.get("Outcome"),
        "map": render_svg(pm, header=False),  # on screen; the side panel shows outcome and reason
        "svg": render_svg(pm),  # download: self-describing, includes the header
        "trace": trace,
        # packet-flow path: one entry per map node, in path order (positions are read from the SVG)
        "flow": [{"id": n.id, "status": n.status, "title": n.title, "hop": n.hops[0] if n.hops else None} for n in pm.nodes],
    }


def _json_for_script(data: Any) -> str:
    # Escape so device output can't close the <script> element.
    return (json.dumps(data, default=str)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render_html(traces: list[dict[str, Any]], *, title: str = "nettrace path map") -> str:
    payload = [_payload(t) for t in traces]
    has_evidence = any(h.get("evidence") for t in traces for h in t.get("Hops") or [])
    return (_PAGE.replace("__TITLE__", title.replace("<", "&lt;"))
            .replace("__VERSION__", __version__)
            .replace("__BANNER__", _BANNER if has_evidence else "")
            .replace("__DATA__", _json_for_script(payload)))


_BANNER = ('<span role="alert" style="background:#c62828;color:#fff;font-weight:700;padding:3px 8px;'
           'border-radius:4px">contains device output: do not share</span>')

_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>__TITLE__</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6f9;--panel:#fff;--line:#cfd8e3;--text:#1d2633;--muted:#566478;--accent:#1d5fbf;--soft:#f3f7fc;--sel:#e3eefb;--code:#f6f8fa;
--b-pass:#157a43;--b-block:#c62828;--b-warn:#f5b700;--b-unk:#6d3fc0;--b-info:#1f62a8;--fg-warn:#1a1300;
--pass:#157a43;--block:#c62828;--warn:#8a5a00;--unknown:#6d3fc0;--info:#1f62a8}
/* status colours: --b-* are fills (white text, dark text on warn), --pass/--block/... are text colours; all >= 4.5:1 on their surface.
   The map itself (#map) stays a light surface in dark mode. */
@media (prefers-color-scheme:dark){:root{--bg:#0e131b;--panel:#161d29;--line:#2c3a4e;--text:#e6ecf4;--muted:#a3b2c6;--accent:#8ec5ff;--soft:#1d2736;--sel:#1f3552;--code:#0f1720;
--pass:#4ade80;--block:#ff8f87;--warn:#fbbf24;--unknown:#c4a8ff;--info:#7cc0ff}}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}header :focus-visible{outline-color:#8ec5ff}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
kbd{font:11px ui-monospace,Menlo,monospace;border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 4px;background:var(--soft)}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{font:13px -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:var(--text);background:var(--bg);
display:grid;grid-template-rows:auto minmax(0,1fr);grid-template-columns:minmax(0,1fr) 420px}
@media (max-width:900px){html,body{height:auto;overflow:auto}body{display:flex;flex-direction:column;overflow-x:hidden}
#map{height:60vh;min-height:300px;flex:none;touch-action:pan-y}#side{display:block;border-top:1px solid var(--line)}#hops{max-height:50vh}header{flex-wrap:wrap}}
header{grid-column:1/3;display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:8px 14px;background:#1d2633;color:#fff}
header b{font-size:14px}header select{max-width:480px;padding:4px;border-radius:4px;border:0}
header .sp{flex:1}header button{background:#3a4c66;color:#fff;border:0;border-radius:4px;padding:5px 10px;cursor:pointer}
header button:hover{background:#45597a}
#map{position:relative;overflow:hidden;background:#fbfcfd;color:#1d2633;cursor:grab;border-right:1px solid var(--line)}
#map.drag{cursor:grabbing}#stage{position:absolute;left:0;top:0;transform-origin:0 0}
#map .hint{position:absolute;left:10px;bottom:8px;color:#3a4658;font-size:11px;background:#ffffffdd;padding:2px 6px;border-radius:4px;max-width:calc(100% - 20px)}
[data-hop]{cursor:pointer}.sel>rect:first-of-type,.badge.sel rect{filter:drop-shadow(0 0 4px #2f6db5)}
.node.sel rect{stroke:#2f6db5!important}
#side{display:grid;grid-template-rows:auto minmax(120px,40%) 1fr;min-height:0;min-width:0;background:var(--panel)}
#summary{padding:10px 14px;border-bottom:1px solid var(--line);border-left:8px solid var(--muted)}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-weight:700;font-size:11px;white-space:nowrap}
.pill.REACHABLE,.pill.PASS{background:var(--b-pass)}.pill.BLOCKED,.pill.BLOCK{background:var(--b-block)}.pill.EXITED,.pill.INFO{background:var(--b-info)}
.pill.INCOMPLETE,.pill.WARN{background:var(--b-warn);color:var(--fg-warn)}.pill.UNKNOWN{background:var(--b-unk)}
.V-REACHABLE{border-left-color:var(--b-pass)!important}.V-BLOCKED{border-left-color:var(--b-block)!important}.V-EXITED{border-left-color:var(--b-info)!important}.V-INCOMPLETE{border-left-color:var(--b-warn)!important}
#summary .vt{font-size:15px;padding:3px 10px}#summary .reason,#summary .vm{margin-top:6px;color:var(--text);line-height:1.4;overflow-wrap:anywhere}#summary .vm b{color:var(--muted);font-weight:600}
#summary ul{margin:6px 0 0;padding-left:16px;color:var(--warn)}
.lnk{background:none;border:0;padding:0;color:var(--accent);text-decoration:underline;font:inherit;font-weight:600;cursor:pointer}
#hops{overflow:auto;border-bottom:1px solid var(--line)}
#hops table{width:100%;border-collapse:collapse;table-layout:fixed}#hops td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
#hops td:nth-child(1){width:30px;color:var(--muted)}#hops td:nth-child(2){width:92px}
#hops .sum{color:var(--text);margin-top:2px}#hops .where{overflow-wrap:anywhere}
#hops tr{cursor:pointer}#hops tr:hover{background:var(--soft)}#hops tr.sel{background:var(--sel);box-shadow:inset 4px 0 0 var(--accent)}
.st{font-weight:700;font-size:11px}.st.PASS{color:var(--pass)}.st.BLOCK{color:var(--block)}.st.WARN{color:var(--warn)}
.st.UNKNOWN{color:var(--unknown)}.st.INFO{color:var(--info)}
#hops .where{font-weight:600}#hops .comp{color:var(--muted);font-size:11px}
#detail{overflow:auto;padding:10px 14px;min-height:0}#detail h3{margin:0 0 6px;font-size:14px}
#detail dl{display:grid;grid-template-columns:90px 1fr;gap:3px 8px;margin:0 0 10px}#detail dt{color:var(--muted)}
#detail dd{margin:0;word-break:break-word}#detail ul{padding-left:16px;margin:4px 0 10px}
details{border:1px solid var(--line);border-radius:6px;margin:6px 0}summary{padding:5px 8px;cursor:pointer;font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--accent)}
pre{margin:0;padding:8px;max-height:280px;overflow:auto;background:var(--code);font:11px/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all}
.empty{color:var(--muted)}
#pf{position:absolute;left:10px;top:10px;z-index:2;display:flex;flex-wrap:wrap;align-items:center;gap:5px;max-width:calc(100% - 20px);background:#fffffff2;border:1px solid var(--line);border-radius:6px;padding:4px 6px}
#pf button,#pf select{font:12px inherit;height:26px;border:1px solid #cfd8e3;border-radius:5px;background:#fff;color:#1d2633;cursor:pointer}#pf-scrub{width:110px;accent-color:#1d5fbf}
#pf button{min-width:30px}#pf button:disabled{opacity:.45;cursor:default}
#pf-info{font:11px ui-monospace,Menlo,monospace;color:#3a4658;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
@media print{header,#side{display:none}body{display:block}#map{overflow:visible}#stage{position:static;transform:none!important}}
</style></head>
<body>
<header><b role="heading" aria-level="1">nettrace</b><span>path map</span><select id="pick" aria-label="Choose trace"></select>__BANNER__<span class="sp"></span>
<button id="fit" title="Fit to window (F)">Fit</button><button id="one" title="Actual size (1)">100%</button>
<button id="dl" title="Download the map as SVG">SVG</button><button id="dj" title="Download the trace JSON">JSON</button>
<span style="color:#8a99ad;font-size:11px">v__VERSION__</span></header>
<main id="map" aria-label="Path map" tabindex="-1"><div id="pf" role="toolbar" aria-label="Packet flow controls"><button id="pf-back" title="Step back" aria-label="Step back">◀</button><button id="pf-play" title="Play / pause" aria-label="Play packet flow">▶</button><button id="pf-fwd" title="Step forward" aria-label="Step forward">▶|</button><button id="pf-replay" title="Replay from source" aria-label="Replay packet flow">↻ Replay</button><select id="pf-speed" title="Speed" aria-label="Animation speed"><option value="0.5">0.5x</option><option value="1" selected>1x</option><option value="2">2x</option></select><input type="range" id="pf-scrub" min="0" max="0" value="0" aria-label="Position in the packet flow"><span id="pf-info" role="status" aria-live="polite"></span></div><div id="stage"></div><div class="hint">drag to pan · scroll to zoom (Ctrl/⌘+scroll when the page scrolls) · click a device, check or link · <kbd>Space</kbd> play · <kbd>←</kbd><kbd>→</kbd> step · <kbd>R</kbd> replay · <kbd>F</kbd> fit</div></main>
<aside id="side" aria-label="Result, hops and details"><section id="summary" aria-label="Trace result" role="status" aria-live="polite"></section><div id="hops" role="region" aria-label="Hops" tabindex="0"></div><div id="detail" role="region" aria-label="Hop detail" tabindex="0"><p class="empty">Select a hop.</p></div></aside>
<script>
const DATA = __DATA__;
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
let cur = 0, scale = 1, tx = 0, ty = 0;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const STACKED = matchMedia("(max-width: 900px)");
const GLYPH = {PASS:"✓", BLOCK:"✕", WARN:"!", UNKNOWN:"?", INFO:"i"};
// status badge: glyph + word, so colour is never the only signal; `s` is escaped
const badge = s => `<span class="pill ${esc(s)}"><span aria-hidden="true">${esc(GLYPH[s] || "•")}</span> ${esc(s)}</span>`;
// Verdict: INCOMPLETE (or anything unrecognised) is "unverified", never green. Exit codes mirror `nettrace trace run`.
const VERDICT = {
  REACHABLE:  {icon:"✓", label:"Reachable", exit:0, meaning:"success: the destination was reached"},
  EXITED:     {icon:"↗", label:"Exited known network", exit:0, meaning:"success so far: traffic left the networks nettrace knows; the rest of the path is not verified"},
  BLOCKED:    {icon:"✕", label:"Blocked", exit:3, meaning:"blocked: a hop denied the flow"},
  INCOMPLETE: {icon:"?", label:"Unverified (incomplete)", exit:4, meaning:"not verified: the trace could not finish; do not treat this as reachable"},
};
function verdictHtml(t, title){
  const known = VERDICT[t.Outcome], v = known || VERDICT.INCOMPLETE, hops = t.Hops || [];
  const bad = hops.find(h => h.status === "BLOCK") || hops.find(h => h.status === "UNKNOWN"), h = bad || hops[hops.length - 1];
  const lead = bad ? (bad.status === "BLOCK" ? "Stopped at" : "Could not verify at") : (t.Outcome === "REACHABLE" ? "Reached via" : "Last hop");
  const where = h ? `<div class="vm"><b>${esc(lead)}</b> <button type="button" class="lnk" data-hop="${esc(h.index)}">#${esc(h.index)} ${esc(h.node)}</button> (${esc(h.domain)} ${esc(h.component)}, ${esc(h.status)})</div>` : "";
  return `<span class="pill vt ${known ? esc(t.Outcome) : "INCOMPLETE"}"><span aria-hidden="true">${esc(v.icon)}</span> ${esc(known ? v.label : "Unverified (" + t.Outcome + ")")}</span> <b>${esc(title)}</b>`
    + where + `<div class="reason"><span class="vm"><b>Reason</b></span> ${esc(t.Reason)}</div>`
    + `<div class="vm"><b>Exit code</b> ${esc(v.exit)}: ${esc(v.meaning)}</div>`;
}

function apply(){ $("#stage").style.transform = `translate(${tx}px,${ty}px) scale(${scale})`; }
function fit(){
  const svg = $("#stage svg"); if(!svg) return;
  const m = $("#map").getBoundingClientRect(), w = +svg.getAttribute("width"), h = +svg.getAttribute("height");
  scale = Math.min(m.width / w, m.height / h, 1.4) * 0.96;
  tx = (m.width - w * scale) / 2; ty = Math.max(8, (m.height - h * scale) / 2); apply();
}
function select(hop){
  document.querySelectorAll(".sel").forEach(e => e.classList.remove("sel"));
  document.querySelectorAll(`[data-hop="${hop}"]`).forEach(e => e.classList.add("sel"));
  const tr = document.querySelector(`#hops tr[data-hop="${hop}"]`); if(tr) tr.scrollIntoView({block:"nearest"});
  const h = DATA[cur].trace.Hops.find(x => x.index == hop); if(!h) return;
  const loc = Object.entries(h.location || {}).map(([k,v]) => `${k}=${v}`).join(", ");
  const rows = [["status", badge(h.status)], ["domain", `${esc(h.domain)} ${esc(h.component)}`],
    ["ingress", esc(h.ingress)], ["egress", esc(h.egress)], ["policy", esc(h.policy)], ["NAT", esc(h.nat)], ["location", esc(loc)]]
    .filter(r => r[1]).map(([k,v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
  const det = (h.details || []).map(d => `<li>${esc(d)}</li>`).join("");
  const ev = (h.evidence || []).map(e => `<details><summary>[${esc(e.source)}] ${esc(e.request)}</summary><pre>${esc(e.response)}</pre></details>`).join("");
  $("#detail").innerHTML = `<h3>#${esc(h.index)} ${esc(h.node)}</h3><p>${esc(h.summary)}</p><dl>${rows}</dl>`
    + (det ? `<b>Details</b><ul>${det}</ul>` : "")
    + `<b>Evidence</b> <span class="empty">(read-only requests sent and their answers)</span>` + (ev || `<p class="empty">none recorded</p>`);
}
function show(i){
  cur = i; const d = DATA[i], t = d.trace;
  $("#pick").value = i;
  $("#stage").innerHTML = d.map;
  const warn = (t.Warnings || []).map(w => `<li>${esc(w)}</li>`).join("");
  $("#summary").className = "V-" + (VERDICT[t.Outcome] ? t.Outcome : "INCOMPLETE");
  $("#summary").innerHTML = verdictHtml(t, d.title) + (warn ? `<ul aria-label="Warnings">${warn}</ul>` : "");
  $("#hops").innerHTML = '<table aria-label="Hops in path order">' + t.Hops.map(h => `<tr data-hop="${esc(h.index)}" tabindex="0"><td>${esc(h.index)}</td>`
    + `<td>${badge(h.status)}</td><td><div class="where">${esc(h.node)} `
    + `<span class="comp">${esc(h.domain)} ${esc(h.component)}</span></div><div class="sum">${esc(h.summary)}</div></td></tr>`).join("") + "</table>";
  $("#detail").innerHTML = '<p class="empty">Select a hop.</p>';
  $$("#hops tr").forEach(r => r.addEventListener("keydown", e => { if(e.key === "Enter" || e.key === " ") { e.preventDefault(); select(r.dataset.hop); } }));
  fit(); pfInit();
  const firstBad = t.Hops.find(h => h.status === "BLOCK") || t.Hops.find(h => h.status === "UNKNOWN");
  if(firstBad) select(firstBad.index);
}
// Deep link: page.html#trace=2&hop=10 (trace is 1-based, as in the picker order)
function fromHash(){
  const p = new URLSearchParams(location.hash.slice(1)), t = +p.get("trace") || 1;
  if(t >= 1 && t <= DATA.length && t - 1 !== cur) show(t - 1);
  if(p.get("hop")) select(p.get("hop"));
}
function download(name, text, type){
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], {type})); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
document.addEventListener("click", e => { const el = e.target.closest("[data-hop]"); if(el && !moved) { select(el.dataset.hop); const i = DATA[cur].flow.findIndex(n => n.hop != null && String(n.hop) === el.dataset.hop); if(i >= 0 && i <= pf.end) { pfStop(); pfGo(i, false); } } });
let drag = null, moved = false;
$("#map").addEventListener("mousedown", e => { drag = {x: e.clientX - tx, y: e.clientY - ty}; moved = false; $("#map").classList.add("drag"); });
window.addEventListener("mousemove", e => { if(!drag) return; const nx = e.clientX - drag.x, ny = e.clientY - drag.y;
  if(Math.abs(nx - tx) + Math.abs(ny - ty) > 2) moved = true; tx = nx; ty = ny; apply(); });
window.addEventListener("mouseup", () => { drag = null; $("#map").classList.remove("drag"); setTimeout(() => moved = false, 0); });
$("#map").addEventListener("wheel", e => { if(STACKED.matches && !(e.ctrlKey || e.metaKey)) return; e.preventDefault(); const r = $("#map").getBoundingClientRect();
  const mx = e.clientX - r.left, my = e.clientY - r.top, k = Math.exp(-e.deltaY * 0.0015), ns = Math.min(4, Math.max(0.15, scale * k));
  tx = mx - (mx - tx) * ns / scale; ty = my - (my - ty) * ns / scale; scale = ns; apply(); }, {passive: false});
$("#fit").onclick = fit; $("#one").onclick = () => { scale = 1; tx = 10; ty = 10; apply(); };
$("#dl").onclick = () => download("nettrace-map.svg", DATA[cur].svg, "image/svg+xml");
$("#dj").onclick = () => download("nettrace-trace.json", JSON.stringify(DATA[cur].trace, null, 2), "application/json");
window.addEventListener("resize", fit);
window.addEventListener("keydown", e => { if(e.ctrlKey || e.metaKey || e.altKey || e.target.closest("input,select,textarea")) return;
  const own = e.target.closest("button,a,summary,tr");
  if(e.key === " " && !own) { e.preventDefault(); pfPlay(); }
  if(e.key === "ArrowRight") pfStep(1); if(e.key === "ArrowLeft") pfStep(-1);
  if(e.key === "r" || e.key === "R") $("#pf-replay").click();
  if(e.key === "f" || e.key === "F") fit(); if(e.key === "1") $("#one").onclick();
  const hops = DATA[cur].trace.Hops, s = document.querySelector("#hops tr.sel"), i = s ? hops.findIndex(h => h.index == s.dataset.hop) : -1;
  if(e.key === "ArrowDown" || e.key === "j") { e.preventDefault(); select(hops[Math.min(hops.length - 1, i + 1)].index); }
  if(e.key === "ArrowUp" || e.key === "k") { e.preventDefault(); select(hops[Math.max(0, i - 1)].index); } });
DATA.forEach((d, i) => { const o = document.createElement("option"); o.value = i; o.textContent = `${d.outcome}  ${d.title}`; $("#pick").appendChild(o); });
$("#pick").onchange = e => show(+e.target.value);
if(DATA.length < 2) $("#pick").style.display = "none";
// ---- packet flow: staggered packets stream along each reached edge, hop by hop; stops at the BLOCK node ----
// Only numbers and fixed colours are written to the DOM; trace text goes through textContent / esc().
const RM = matchMedia("(prefers-reduced-motion: reduce)"), NS = "http://www.w3.org/2000/svg";
const PC = {PASS:"#1e9e5a", WARN:"#d9971c", UNKNOWN:"#d9971c", BLOCK:"#d93636", INFO:"#3b82c4"}, PF_N = 6, PF_V = 0.14, PF_REVEAL = 600;
const pf = {k:0, end:0, pts:[], edges:[], halos:[], pile:[], mark:null, playing:false, frozen:false, ft:0, born:{}, timer:null, rv:null};
const pfEl = (tag, a) => { const e = document.createElementNS(NS, tag); for (const k in a) e.setAttribute(k, a[k]); return e; };
const pfSpeed = () => +$("#pf-speed").value;
function pfInit(){
  pfStop(); clearTimeout(pf.rv); pf.born = {}; pf.ft = 0;
  const root = document.querySelector("#stage svg > g"), flow = DATA[cur].flow || [];
  pf.pts = flow.map(n => { const el = document.getElementById(n.id), m = el && /translate\(([-\d.]+),([-\d.]+)\)/.exec(el.getAttribute("transform") || "");
    return m ? {x:+m[1], y:+m[2], status:n.status, title:n.title, hop:n.hop} : null; }).filter(Boolean);
  const bi = pf.pts.findIndex(p => p.status === "BLOCK"); pf.end = Math.max(0, bi >= 0 ? bi : pf.pts.length - 1);
  pf.edges = []; pf.halos = []; pf.pile = []; pf.mark = null;
  if (!root || pf.pts.length < 2) { $("#pf").style.display = "none"; return; }
  $("#pf").style.display = "";
  const g = pfEl("g", {id:"pfl", "pointer-events":"none"}); root.append(g);
  for (let i = 0; i <= pf.end; i++) { const p = pf.pts[i], h = pfEl("rect", {x:p.x - 35, y:p.y - 35, width:70, height:70, rx:16, fill:"none", stroke:PC[p.status] || PC.INFO, "stroke-width":4, opacity:0}); g.append(h); pf.halos.push(h); }
  for (let i = 0; i < pf.end; i++) {
    const a = pf.pts[i], b = pf.pts[i + 1], len = Math.hypot(b.x - a.x, b.y - a.y) || 1, ux = (b.x - a.x) / len, uy = (b.y - a.y) / len, col = PC[a.status] || PC.INFO;
    const base = pfEl("line", {x1:a.x, y1:a.y, x2:b.x, y2:b.y, stroke:col, "stroke-width":RM.matches ? 5 : 4, "stroke-linecap":"round", opacity:0}); if (RM.matches) base.setAttribute("stroke-dasharray", "9 9");
    g.append(base); const ps = [];
    if (!RM.matches) for (let j = 0; j < PF_N; j++) { const q = pfEl("g", {opacity:0});
      q.append(pfEl("circle", {r:9, fill:col, opacity:.22}), pfEl("line", {x1:-ux * 28, y1:-uy * 28, x2:0, y2:0, stroke:col, "stroke-width":4, "stroke-linecap":"round", opacity:.4}), pfEl("circle", {r:4, fill:col})); g.append(q); ps.push(q); }
    pf.edges.push({a, b, len, ux, uy, base, ps});
  }
  if (DATA[cur].flow[pf.end] && pf.pts[pf.end].status === "BLOCK") {
    for (let m = 0; m < 5; m++) { const c = pfEl("circle", {r:4, fill:PC.BLOCK, opacity:0}); g.append(c); pf.pile.push(c); }
    const e = pf.pts[pf.end]; pf.mark = pfEl("g", {opacity:0, transform:`translate(${e.x},${e.y})`});
    pf.mark.append(pfEl("circle", {cx:29, cy:-29, r:11, fill:PC.BLOCK, stroke:"#fff", "stroke-width":2}), pfEl("path", {d:"M24 -34l10 10M34 -34l-10 10", stroke:"#fff", "stroke-width":2.5}));
    const t = pfEl("text", {y:-44, "text-anchor":"middle", fill:PC.BLOCK, style:"font:700 10px sans-serif;letter-spacing:.06em"}); t.textContent = "BLOCKED HERE"; pf.mark.append(t); g.append(pf.mark);
  }
  pfGo(RM.matches ? pf.end : 0, false);
  if (!RM.matches) setTimeout(() => { if (cur === pfCur) pfPlay(); }, 350);
  pfCur = cur;
}
let pfCur = -1;
function pfGo(k, animate){
  k = Math.max(0, Math.min(pf.end, k)); const from = pf.k; pf.k = k;
  for (const i of Object.keys(pf.born)) if (+i >= k) delete pf.born[i];
  if (animate && !RM.matches && k > from) { clearTimeout(pf.rv); for (let i = from; i < k; i++) pf.born[i] = pf.ft; }
  const p = pf.pts[k]; if (!p) return;
  $("#pf-info").textContent = `hop ${k + 1} / ${pf.end + 1}: ${p.title} (${p.status})`;
  const sc = $("#pf-scrub"); sc.max = pf.end; sc.value = k; sc.setAttribute("aria-valuetext", `step ${k + 1} of ${pf.end + 1}: ${p.title} (${p.status})`);
  if (p.hop != null) select(p.hop);
  pfDraw();
}
function pfDraw(){
  pf.halos.forEach((h, i) => h.setAttribute("opacity", i <= pf.k ? 1 : 0));
  pf.edges.forEach((e, i) => e.base.setAttribute("opacity", i < pf.k ? (RM.matches ? .9 : .3) : 0));
  const blocked = !!pf.mark && pf.k === pf.end; if (pf.mark) pf.mark.setAttribute("opacity", blocked ? 1 : 0);
}
function pfUpdate(){
  for (let i = 0; i < pf.edges.length; i++) {
    const e = pf.edges[i], on = i < pf.k, front = Math.min(1, (pf.ft - (pf.born[i] ?? -1e9)) / PF_REVEAL), blk = on && pf.mark && i === pf.end - 1 && pf.k === pf.end;
    e.ps.forEach((q, j) => {
      let u = (pf.ft * PF_V / e.len + j / PF_N) % 1, o = 1;
      if (blk) { o = 1 - u * u; u = 1 - (1 - u) * (1 - u); }   // slow down and fade into the block node
      if (!on || u > front) { q.setAttribute("opacity", 0); return; }
      q.setAttribute("transform", `translate(${e.a.x + (e.b.x - e.a.x) * u},${e.a.y + (e.b.y - e.a.y) * u})`); q.setAttribute("opacity", o);
    });
  }
  const last = pf.edges[pf.end - 1], show = pf.mark && pf.k === pf.end && (pf.ft - (pf.born[pf.end - 1] ?? -1e9)) / PF_REVEAL >= .9;
  pf.pile.forEach((c, m) => { if (!last) return; c.setAttribute("cx", last.b.x - last.ux * (12 + m * 5) + Math.sin(m * 2.3) * 7); c.setAttribute("cy", last.b.y - last.uy * (12 + m * 5) + Math.cos(m * 1.7) * 7);
    c.setAttribute("opacity", show ? .25 + .35 * Math.abs(Math.sin(pf.ft / 350 + m)) : 0); });
}
function pfTick(now){
  const dt = Math.min(64, now - (pfTick.last || now)); pfTick.last = now;
  if (!pf.frozen && !RM.matches) pf.ft += dt * pfSpeed();
  pfUpdate(); requestAnimationFrame(pfTick);
}
function pfStop(){ pf.playing = false; pf.frozen = false; clearTimeout(pf.timer); const b = $("#pf-play"); b.textContent = "▶"; b.setAttribute("aria-label", "Play packet flow"); }
function pfPlay(){
  if (RM.matches || pf.pts.length < 2) return;
  if (pf.playing) { pfStop(); pf.frozen = true; return; }   // pause freezes the stream too
  if (pf.k >= pf.end) pfGo(0, false);
  pf.playing = true; $("#pf-play").textContent = "⏸"; $("#pf-play").setAttribute("aria-label", "Pause packet flow");
  const next = () => {
    if (!pf.playing) return;
    if (pf.k >= pf.end) return pfStop();   // reached the last hop, or stopped at the BLOCK node
    pfGo(pf.k + 1, true); pf.timer = setTimeout(next, (PF_REVEAL + 380) / pfSpeed());
  };
  next();
}
// stepping keeps a paused (frozen) stream frozen; a frozen stream cannot grow a reveal, so it jumps without animating
const pfStep = d => { const fr = pf.frozen; pfStop(); pf.frozen = fr; pfGo(pf.k + d, !fr); };
$("#pf-scrub").addEventListener("input", e => { const fr = pf.frozen; pfStop(); pf.frozen = fr; pfGo(+e.target.value, false); });
$("#pf-play").onclick = pfPlay; $("#pf-fwd").onclick = () => pfStep(1); $("#pf-back").onclick = () => pfStep(-1);
$("#pf-replay").onclick = () => { pfStop(); pfGo(0, false); pfPlay(); };
const pfRm = () => { pfStop(); $("#pf-play").disabled = RM.matches; $("#pf-play").title = RM.matches ? "Auto-play is off (reduced motion): use the step buttons" : "Play / pause"; if (pf.pts.length) pfInit(); };
RM.addEventListener("change", pfRm); $("#pf-play").disabled = RM.matches; requestAnimationFrame(pfTick);
show(0); fromHash();
window.addEventListener("hashchange", fromHash);
</script></body></html>
"""
