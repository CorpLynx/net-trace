"""Path map (NetBrain-style) rendering of trace results.

Input is always the JSON form of a trace (`TraceResult.to_dict()`), so saved traces render the
same way as live ones.
"""

from nettrace.viz.html import render_html
from nettrace.viz.model import build_map
from nettrace.viz.svg import render_svg

__all__ = ["build_map", "render_html", "render_svg"]
