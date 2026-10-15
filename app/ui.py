"""Template helpers for the design system: inline Lucide SVG icons and colour utilities."""
import os
import re

from markupsafe import Markup

ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "icons")
_cache = {}
_SVG_OPEN = re.compile(r"<svg\b[^>]*>")


def _load(name):
    if name not in _cache:
        with open(os.path.join(ICON_DIR, f"{name}.svg"), encoding="utf-8") as f:
            svg = f.read()
        # drop the XML comment/licence header and normalise the opening tag
        svg = svg[svg.index("<svg"):]
        _cache[name] = svg
    return _cache[name]


def icon(name, cls="icon"):
    """Inline SVG icon (our own static files; no icon fonts, no third parties)."""
    if not re.fullmatch(r"[a-z0-9-]+", name) or not re.fullmatch(r"[A-Za-z0-9 :/_\-\[\].]*", cls):
        raise ValueError("bad icon name/class")
    svg = _SVG_OPEN.sub(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="{cls}" aria-hidden="true">',
        _load(name), count=1)
    return Markup(svg)


def hex_to_rgb(hex_color, default="37 99 235"):
    """'#2563eb' -> '37 99 235' for rgb(var(--accent) / alpha)."""
    m = re.fullmatch(r"#([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})", hex_color or "")
    return " ".join(str(int(x, 16)) for x in m.groups()) if m else default
