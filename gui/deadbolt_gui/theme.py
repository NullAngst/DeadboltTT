"""Themes and colors. Pure data and math here; Qt wiring is in apply().

System follows the desktop's palette and keeps its widget style (Breeze on
Plasma). The others replace the palette only. Status colors are fixed per
light or dark family and checked for contrast in tests.
"""

from __future__ import annotations

from dataclasses import dataclass

STATUS_LIGHT = {"green": "#2e7d32", "amber": "#b26a00", "red": "#c62828"}
STATUS_DARK = {"green": "#66bb6a", "amber": "#ffb74d", "red": "#ef5350"}

COPPER_LIGHT = "#a8683d"
COPPER_DARK = "#c48a5e"


@dataclass(frozen=True)
class Theme:
    key: str
    name: str
    dark: bool
    window: str
    base: str
    alt_base: str
    text: str
    button: str
    highlight: str
    highlight_text: str
    copper: str
    muted: str


THEMES: dict[str, Theme | None] = {
    "system": None,
    "light": Theme(
        "light",
        "Light",
        False,
        "#f4f4f5",
        "#ffffff",
        "#f0f0f2",
        "#1f2024",
        "#ececef",
        "#3a6ea5",
        "#ffffff",
        COPPER_LIGHT,
        "#5f6168",
    ),
    "dark": Theme(
        "dark",
        "Dark",
        True,
        "#202226",
        "#17181b",
        "#26282d",
        "#e8e8ea",
        "#2c2e33",
        "#5b8fd1",
        "#0d0e10",
        COPPER_DARK,
        "#a3a5ab",
    ),
    "verdigris": Theme(
        "verdigris",
        "Verdigris",
        True,
        "#18302d",
        "#11231f",
        "#1d3a35",
        "#e2efe9",
        "#22423c",
        "#43b3a0",
        "#08130f",
        "#c58b5f",
        "#9fbfb5",
    ),
    "kawaii-light": Theme(
        "kawaii-light",
        "Kawaii Light",
        False,
        "#fff4f9",
        "#ffffff",
        "#fdebf4",
        "#47283d",
        "#fbe1ee",
        "#c2457f",
        "#ffffff",
        "#b5714a",
        "#7a5670",
    ),
    "kawaii-dark": Theme(
        "kawaii-dark",
        "Kawaii Dark",
        True,
        "#2a1f2e",
        "#211826",
        "#33263a",
        "#f7e7f1",
        "#3a2b42",
        "#ff8cc6",
        "#2a0f1f",
        "#d79b72",
        "#c9a9bf",
    ),
}

ORDER = ["system", "light", "dark", "verdigris", "kawaii-light", "kawaii-dark"]
LABELS = {
    "system": "System",
    "light": "Light",
    "dark": "Dark",
    "verdigris": "Verdigris",
    "kawaii-light": "Kawaii Light",
    "kawaii-dark": "Kawaii Dark",
}


def _channel(c: int) -> float:
    v = c / 255
    return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def on_color(bg: str) -> str:
    """Black or white text, whichever reads better on bg."""
    return "#000000" if contrast(bg, "#000000") >= contrast(bg, "#ffffff") else "#ffffff"


def status_colors(dark: bool) -> dict[str, str]:
    return STATUS_DARK if dark else STATUS_LIGHT


def copper(dark: bool) -> str:
    return COPPER_DARK if dark else COPPER_LIGHT


def stylesheet(dark: bool, accent_copper: str) -> str:
    """Secondary copper touches only. Copper never carries meaning."""
    return f"""
QListWidget#sidebar {{ border: none; padding-top: 6px; outline: 0; }}
QListWidget#sidebar::item {{ padding: 8px 10px; border-left: 3px solid transparent; }}
QListWidget#sidebar::item:selected {{
    border-left: 3px solid {accent_copper};
    background: palette(highlight);
    color: palette(highlighted-text);
}}
QFrame#rule {{ color: {accent_copper}; background: {accent_copper}; max-height: 1px; border: none; }}
QFrame#tile {{ border: 1px solid {accent_copper}; border-radius: 6px; }}
QLabel#tileTitle {{ font-weight: 600; }}
QLabel#banner {{ border-radius: 6px; padding: 12px 14px; font-size: 15px; font-weight: 600; }}
QPushButton#bigScan {{ font-size: 16px; padding: 14px 28px; }}
"""


def apply(app, key: str) -> bool:
    """Apply a theme to a QApplication. Returns True if the result is dark."""
    from PyQt6.QtGui import QColor, QPalette

    t = THEMES.get(key)
    if t is None:
        # A default QPalette is the platform palette (Plasma color scheme).
        app.setPalette(QPalette())
        pal = app.palette()
        dark = pal.color(QPalette.ColorRole.Window).lightness() < 128
        app.setStyleSheet(stylesheet(dark, copper(dark)))
        return dark
    pal = QPalette()
    roles = {
        QPalette.ColorRole.Window: t.window,
        QPalette.ColorRole.WindowText: t.text,
        QPalette.ColorRole.Base: t.base,
        QPalette.ColorRole.AlternateBase: t.alt_base,
        QPalette.ColorRole.Text: t.text,
        QPalette.ColorRole.Button: t.button,
        QPalette.ColorRole.ButtonText: t.text,
        QPalette.ColorRole.Highlight: t.highlight,
        QPalette.ColorRole.HighlightedText: t.highlight_text,
        QPalette.ColorRole.ToolTipBase: t.base,
        QPalette.ColorRole.ToolTipText: t.text,
        QPalette.ColorRole.PlaceholderText: t.muted,
        QPalette.ColorRole.Link: t.highlight,
    }
    for role, color in roles.items():
        pal.setColor(role, QColor(color))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(t.muted))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(t.muted))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(t.muted))
    app.setPalette(pal)
    app.setStyleSheet(stylesheet(t.dark, t.copper))
    return t.dark
