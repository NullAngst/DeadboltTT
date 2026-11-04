import xml.etree.ElementTree as ET

from deadbolt_gui import thunar

EXISTING = """<?xml version="1.0" encoding="UTF-8"?>
<actions>
<action>
\t<icon>utilities-terminal</icon>
\t<name>Open Terminal Here</name>
\t<unique-id>1234-1</unique-id>
\t<command>exo-open --working-directory %f --launch TerminalEmulator</command>
\t<directories/>
</action>
</actions>
"""


def ids(text):
    return [a.findtext("unique-id") for a in ET.fromstring(text).findall("action")]


def test_merge_keeps_user_actions_and_adds_ours_once():
    once = thunar.merge(EXISTING)
    twice = thunar.merge(once)
    assert ids(twice) == ["1234-1", thunar.UNIQUE_ID]
    assert "exo-open" in twice


def test_merge_empty_file():
    assert ids(thunar.merge(None)) == [thunar.UNIQUE_ID]


def test_remove_only_ours():
    assert ids(thunar.remove(thunar.merge(EXISTING))) == ["1234-1"]


def test_install_roundtrip(tmp_path):
    p = tmp_path / "Thunar" / "uca.xml"
    thunar.install(str(p))
    assert thunar.installed(str(p))
    assert "deadbolt --scan %F" in p.read_text()
