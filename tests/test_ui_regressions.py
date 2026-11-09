"""Regressions found by driving the UI in a real browser (see docs/gaps-and-roadmap.md)."""
from importlib import resources

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")


def test_deep_link_params_survive_token_stripping():
    # An old #token= is ignored and removed from the address bar, but #preset=/#trace=/#step=/#node= must still be read at start-up.
    assert "const HASH = new URLSearchParams(location.hash.slice(1))" in APP_HTML
    assert 'HASH.delete("token")' in APP_HTML
    start = APP_HTML.index("async function startup")
    body = APP_HTML[start:]
    assert "location.hash.slice" not in body          # start-up uses the saved HASH, not the already-cleared fragment
    assert 'h.get("preset")' in body and 'h.get("trace")' in body
    # no token is read from, or written to, the URL any more: the session is an HttpOnly cookie
    assert 'HASH.get("token")' not in APP_HTML and "TOKEN" not in APP_HTML.split("history.replaceState", 1)[1][:200]


def test_hop_list_scroll_never_scrolls_the_page():
    # scrollIntoView also scrolls the window on the stacked layout and hid the trace form.
    assert ".scrollIntoView(" not in APP_HTML
    assert "function revealRow" in APP_HTML and '$("#events")' in APP_HTML.split("function revealRow", 1)[1][:200]


def test_light_canvas_surface_overrides_soft_colour_for_dark_mode():
    # The canvas hint bar and its <kbd> chips sit on a light surface; --soft must be light there, or the
    # key letter is dark on dark in prefers-color-scheme: dark.
    rule = next(line for line in APP_HTML.splitlines() if line.startswith("#ws,#pmview{"))
    assert "--soft:#eef2f7" in rule


def test_path_map_scrolls_to_the_current_hop_when_narrower_than_its_minimum_width():
    assert "function centerPathMap" in APP_HTML
    assert "centerPathMap(st.hop ? st.hop.index : null)" in APP_HTML            # on every step
    assert 'v === "pm"' in APP_HTML.split("function setView", 1)[1][:700]       # and when the tab is opened
