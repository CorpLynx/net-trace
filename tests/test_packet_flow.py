import re
from importlib import resources

import pytest

from nettrace.demo import PRESETS, install
from nettrace.engine import Tracer
from nettrace.models import Flow
from nettrace.viz.html import render_html
from nettrace.viz.model import build_map
from nettrace.viz.svg import render_svg

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")
EVIL = "<img src=x onerror=alert(1)>"
EVIL_SCRIPT = "</script><script>alert(2)</script>"


@pytest.fixture(scope="module")
def blocked_trace():
    inv = install()
    preset = next(p for p in PRESETS if p["expect"] == "BLOCKED")
    f = dict(preset["flow"])
    start_at = f.pop("start_at", None)
    flow = Flow(src=f["src"], dst=f["dst"], protocol=f["protocol"], dst_port=f["port"],
                application=f.get("application"), user=f.get("user"))
    return Tracer(inv).trace(flow, start_at=start_at).to_dict()


@pytest.fixture(scope="module")
def offline_html(blocked_trace):
    return render_html([blocked_trace])


def _section(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i)]


def _strip_ns(text):
    return text.replace("http://www.w3.org/2000/svg", "")


HOOKS = ['aria-label="Step back"', 'aria-label="Step forward"', "Replay packet flow", "Animation speed",
         '<option value="0.5"', '<option value="2"', "prefers-reduced-motion"]


def test_web_ui_has_animation_hooks():
    for hook in ['id="replay"', 'id="flow"', "function buildFlow", "function reveal", 'aria-label="Step back"',
                 'aria-label="Step forward"', 'aria-label="Replay packet flow"', 'aria-label="Animation speed"',
                 '<option value="0.5"', '<option value="2"', "prefers-reduced-motion"]:
        assert hook in APP_HTML, hook


def test_offline_map_has_animation_hooks(offline_html):
    for hook in HOOKS + ['id="pf"', 'id="pf-replay"', 'id="pf-play"', "function pfInit", "const pfStep"]:
        assert hook in offline_html, hook


def test_no_external_urls(offline_html):
    for name, text in (("app.html", APP_HTML), ("viz html", offline_html)):
        assert not re.search(r"https?://", _strip_ns(text)), name
        assert "//cdn" not in text and "@import" not in text, name


def test_csp_unchanged(offline_html):
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', offline_html).group(1)
    assert csp == ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
                   "base-uri 'none'; form-action 'none'")


def test_reduced_motion_handled(offline_html):
    # no auto-play and no tweening under prefers-reduced-motion; step controls stay enabled
    assert 'matchMedia("(prefers-reduced-motion: reduce)")' in APP_HTML
    assert 'matchMedia("(prefers-reduced-motion: reduce)")' in offline_html
    assert "opts.autoplay !== false && !RM.matches" in APP_HTML
    assert "if (!RM.matches) setTimeout" in offline_html
    assert "if (!S.entry || RM.matches) return;" in APP_HTML
    assert "if (RM.matches || pf.pts.length < 2) return;" in offline_html
    assert 'seg.rm{stroke-dasharray' in APP_HTML  # static dashed path


def test_stream_has_several_packets_per_edge(offline_html):
    assert re.search(r"FLOW_N = [5-8],", APP_HTML)
    assert re.search(r"PF_N = [5-8],", offline_html)


def test_stream_stops_at_block_with_marker(offline_html):
    assert "BLOCKED HERE" in APP_HTML and "BLOCKED HERE" in offline_html
    assert "pf.edges.length" in offline_html and "i === pf.end - 1" in offline_html


def test_animation_code_never_uses_innerhtml_for_trace_data(offline_html):
    assert "innerHTML" not in _section(APP_HTML, "function svgEl", "function isBad")
    assert "innerHTML" not in _section(offline_html, "// ---- packet flow", "show(0); fromHash();")


def test_token_not_persisted():
    assert "localStorage" not in APP_HTML and "sessionStorage" not in APP_HTML


def test_malicious_hop_name_is_escaped_in_animation_path(blocked_trace):
    import copy
    t = copy.deepcopy(blocked_trace)
    for h in t["Hops"]:
        h["node"] = EVIL + EVIL_SCRIPT
    html = render_html([t])
    # raw markup never reaches the page, in the SVG nodes or in the animation payload
    assert EVIL not in html and EVIL_SCRIPT not in html
    assert html.count("</script>") == 1
    # the flow payload carries the name only as escaped JSON, and the animation reads it via textContent
    assert "\\u003cimg src=x onerror=alert(1)\\u003e" in html
    assert "$('#pf-info').textContent" in html or '$("#pf-info").textContent' in html
    pm_svg = render_svg(build_map(t))
    assert EVIL not in pm_svg and "&lt;img" in pm_svg


def test_static_svg_output_unchanged(blocked_trace):
    svg = render_svg(build_map(blocked_trace))
    for marker in ("pfl", "pf-", "requestAnimationFrame", "<script", "<animate"):
        assert marker not in svg


def test_step_buttons_keep_a_paused_stream_frozen(offline_html):
    # stepping must not call the plain stop/pfStop (which clears frozen) without restoring the paused state
    assert "const stepTo = " in APP_HTML and "S.frozen = fr" in APP_HTML
    assert "$(\"#next\").onclick = () => stepTo(" in APP_HTML and "{ stop(); goto(S.k + 1); }" not in APP_HTML
    assert "const pfStep = d => { const fr = pf.frozen; pfStop(); pf.frozen = fr;" in offline_html
