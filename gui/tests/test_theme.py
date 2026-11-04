import pytest

from deadbolt_gui import theme

LIGHT_BG = ["#ffffff", "#f4f4f5"]
DARK_BG = ["#17181b", "#202226"]


def themed_backgrounds():
    out = []
    for key in theme.ORDER:
        t = theme.THEMES[key]
        if t is None:
            out += [(False, bg) for bg in LIGHT_BG] + [(True, bg) for bg in DARK_BG]
        else:
            out += [(t.dark, t.window), (t.dark, t.base)]
    return out


@pytest.mark.parametrize("level", ["green", "amber", "red"])
@pytest.mark.parametrize("dark", [False, True])
def test_banner_text_contrast(level, dark):
    bg = theme.status_colors(dark)[level]
    assert theme.contrast(bg, theme.on_color(bg)) >= 4.5


@pytest.mark.parametrize("dark,bg", themed_backgrounds())
@pytest.mark.parametrize("level", ["green", "amber", "red"])
def test_status_text_on_theme_background(dark, bg, level):
    # Tile values use the status color as bold text: WCAG large/bold text needs 3:1.
    assert theme.contrast(theme.status_colors(dark)[level], bg) >= 3.0


@pytest.mark.parametrize("key", [k for k in theme.ORDER if theme.THEMES[k]])
def test_theme_text_contrast(key):
    t = theme.THEMES[key]
    assert theme.contrast(t.text, t.window) >= 7.0
    assert theme.contrast(t.text, t.base) >= 7.0
    assert theme.contrast(t.highlight_text, t.highlight) >= 4.5


def test_required_themes_present():
    labels = set(theme.LABELS.values())
    assert {"Light", "Dark", "Verdigris", "Kawaii Light", "Kawaii Dark", "System"} <= labels


def test_spec_status_colors():
    assert theme.STATUS_LIGHT == {"green": "#2e7d32", "amber": "#b26a00", "red": "#c62828"}
    assert theme.STATUS_DARK == {"green": "#66bb6a", "amber": "#ffb74d", "red": "#ef5350"}
