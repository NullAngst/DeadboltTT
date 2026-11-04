"""Plain, calm, specific wording. Every message says what happened, to which
file, and what was done. No "neutralized", no exclamation marks."""

from __future__ import annotations

import os
import time

ACTION_TEXT = {
    "quarantined": "Moved to quarantine.",
    "deleted": "Deleted.",
    "pending": "Waiting for your choice.",
    "reported": "Reported only, nothing was changed.",
}

SOURCE_TEXT = {
    "manual": "Manual scan",
    "realtime": "Real-time",
    "scheduled": "Scheduled scan",
    "ransomware": "Ransomware shield",
}

FORBIDDEN = ("neutraliz", "eliminat", "destroy", "danger", "!")


def detection(det: dict) -> str:
    name = os.path.basename(det.get("path", "")) or det.get("path", "a file")
    sig = det.get("signature", "unknown threat")
    action = det.get("action", "")
    what = ACTION_TEXT.get(action)
    if what is None:
        what = (action[:1].upper() + action[1:] + ".") if action else ""
    return f"Threat found in {name}: {sig}. {what}".strip()


def incident(inc: dict) -> str:
    return (
        f"{inc.get('app', 'An app')} was frozen by the ransomware shield after changing "
        f"{len(inc.get('files', []))} files the way ransomware does. It stays frozen until you choose."
    )


def age(seconds_ago: int) -> str:
    if seconds_ago < 90:
        return "just now"
    minutes = seconds_ago // 60
    if minutes < 90:
        return f"{minutes} minutes ago"
    hours = minutes // 60
    if hours < 36:
        return f"{hours} hours ago"
    return f"{hours // 24} days ago"


def when(ts: int | None) -> str:
    if not ts:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def size(n: int) -> str:
    units = ["bytes", "KB", "MB", "GB", "TB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.0f} {u}" if u == "bytes" else f"{v:.1f} {u}"
        v /= 1024
    return f"{n} bytes"


def banner(status: dict | None, daemon_up: bool) -> tuple[str, str, str]:
    """(level, text, fix) for the dashboard banner and the tray icon."""
    if not daemon_up or status is None:
        return ("red", "At risk: the Deadbolt service is not running.", "start-daemon")
    return (status.get("level", "red"), status.get("reason", ""), status.get("fix", ""))


FIX_LABELS = {
    "update-signatures": "Update now",
    "enable-realtime": "Turn on",
    "requirements": "Open System requirements",
    "start-daemon": "Start",
    "setup": "Finish setup",
    "resume": "Resume protection",
    "shield": "Open Protection",
}


def is_plain(text: str) -> bool:
    low = text.lower()
    return not any(w in low for w in FORBIDDEN)
