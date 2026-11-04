"""Per-user GUI settings in ~/.config/deadbolt/gui.json. System settings live
in the daemon; this file only holds things that are about one person's GUI."""

from __future__ import annotations

import json
import os

DEFAULTS = {
    "theme": "system",
    "first_run_done": False,
    "thunar_asked": False,
    "tray_hint_shown": False,
}

AUTOSTART = """[Desktop Entry]
Type=Application
Name=Deadbolt
Comment=Anti-malware status in the system tray
Exec=deadbolt --tray
Icon=deadbolt
Terminal=false
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
"""


def _dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "deadbolt")


def path() -> str:
    return os.path.join(_dir(), "gui.json")


def load() -> dict:
    data = dict(DEFAULTS)
    try:
        with open(path(), encoding="utf-8") as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            data.update({k: v for k, v in stored.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return data


def save(data: dict) -> None:
    os.makedirs(_dir(), exist_ok=True)
    tmp = path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({k: data.get(k, v) for k, v in DEFAULTS.items()}, f, indent=2)
    os.replace(tmp, path())


def autostart_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "autostart", "deadbolt.desktop")


def autostart_enabled() -> bool:
    return os.path.exists(autostart_path())


def set_autostart(on: bool) -> None:
    p = autostart_path()
    if on:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(AUTOSTART)
    elif os.path.exists(p):
        os.remove(p)
