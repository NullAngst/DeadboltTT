"""Thunar custom action. Thunar has no system-wide drop-in folder, so the GUI
adds one entry to ~/.config/Thunar/uca.xml on first run, after asking. The
file is edited with an XML parser and only our own entry is touched."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET

UNIQUE_ID = "deadbolt-scan-1"

TEMPLATE = {
    "icon": "deadbolt",
    "name": "Scan with Deadbolt",
    "submenu": "",
    "unique-id": UNIQUE_ID,
    "command": "deadbolt --scan %F",
    "description": "Scan the selected files and folders for threats",
    "range": "*",
    "patterns": "*",
}
TYPES = ["directories", "audio-files", "image-files", "other-files", "text-files", "video-files"]


def default_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "Thunar", "uca.xml")


def _action() -> ET.Element:
    a = ET.Element("action")
    for k, v in TEMPLATE.items():
        ET.SubElement(a, k).text = v
    for t in TYPES:
        ET.SubElement(a, t)
    return a


def merge(xml_text: str | None) -> str:
    """Return uca.xml text with our action present exactly once."""
    if xml_text and xml_text.strip():
        root = ET.fromstring(xml_text)  # noqa: S314 - user's own file
        if root.tag != "actions":
            raise ValueError("uca.xml does not have an <actions> root")
    else:
        root = ET.Element("actions")
    for a in list(root.findall("action")):
        uid = a.findtext("unique-id") or ""
        if uid == UNIQUE_ID:
            root.remove(a)
    root.append(_action())
    ET.indent(root, space="\t")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def remove(xml_text: str) -> str:
    root = ET.fromstring(xml_text)  # noqa: S314 - user's own file
    for a in list(root.findall("action")):
        if (a.findtext("unique-id") or "") == UNIQUE_ID:
            root.remove(a)
    ET.indent(root, space="\t")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


def install(path: str | None = None) -> str:
    path = path or default_path()
    current = None
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            current = f.read()
    new = merge(current)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".deadbolt-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    os.replace(tmp, path)
    return path


def installed(path: str | None = None) -> bool:
    path = path or default_path()
    try:
        with open(path, encoding="utf-8") as f:
            return UNIQUE_ID in f.read()
    except OSError:
        return False
