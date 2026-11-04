"""Offscreen smoke test: the window builds and handles daemon signals with no daemon running."""

import os

import pytest

pytest.importorskip("PyQt6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_window_builds_without_daemon(app, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    from deadbolt_gui.window import PAGES, MainWindow

    w = MainWindow(app, start_hidden=True)
    assert w.minimumWidth() == 900
    assert w.width() == 1100
    assert w.height() == 720
    for i in range(len(PAGES)):
        w.sidebar.setCurrentRow(i)
    status = {
        "level": "green",
        "reason": "Your computer is protected.",
        "fix": "",
        "realtime": {"enabled": True, "running": True, "mode": "blocking"},
        "shield": {
            "enabled": True,
            "running": True,
            "protected": ["/home"],
            "unprotected": [],
            "canaries": 24,
            "frozen": 0,
        },
        "signatures": {"engine": "1.4.6", "updated": 0, "age_days": 0, "engine_outdated": False},
        "last_scan": None,
        "quarantine_count": 0,
        "network_blocks": 0,
        "paused_until": None,
        "setup_done": True,
        "overflow_count": 0,
    }
    w.on_signal("Status", "StatusChanged", status)
    assert w.pages["Dashboard"].tiles["realtime"].value.text() == "On"
    w.pages["Scan"].job = "j"
    w.pages["Scan"].on_signal(
        "Scan",
        "Progress",
        {
            "job": "j",
            "state": "running",
            "total": 10,
            "done": 5,
            "current": "/x",
            "found": 0,
            "fallback": False,
        },
    )
    assert w.pages["Scan"].bar.value() == 50
    for key in ["system", "light", "dark", "verdigris", "kawaii-light", "kawaii-dark"]:
        w.set_theme(key)
    w.quit()


def test_gui_refuses_root(monkeypatch):
    import deadbolt_gui.app as entry

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("sys.argv", ["deadbolt"])
    with pytest.raises(SystemExit) as e:
        entry.main()
    assert e.value.code == 2
