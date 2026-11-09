"""Regressions found by driving the UI in a real browser (see docs/gaps-and-roadmap.md)."""
from importlib import resources

APP_HTML = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")


def test_deep_link_params_survive_token_stripping():
    # The token is removed from the address bar, but #preset=/#trace=/#step=/#node= must still be read at start-up.
    assert "const HASH = new URLSearchParams(location.hash.slice(1))" in APP_HTML
    assert 'HASH.delete("token")' in APP_HTML
    start = APP_HTML.index("async function startup")
    body = APP_HTML[start:]
    assert "location.hash.slice" not in body          # start-up uses the saved HASH, not the already-cleared fragment
    assert 'h.get("preset")' in body and 'h.get("trace")' in body
    # the token itself is never re-written into the URL
    assert 'HASH.get("token")' in APP_HTML and "TOKEN}" not in APP_HTML.split("history.replaceState", 1)[1][:200]


def test_hop_list_scroll_never_scrolls_the_page():
    # scrollIntoView also scrolls the window on the stacked layout and hid the trace form.
    assert ".scrollIntoView(" not in APP_HTML
    assert "function revealRow" in APP_HTML and '$("#events")' in APP_HTML.split("function revealRow", 1)[1][:200]
