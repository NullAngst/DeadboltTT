from deadbolt_gui import config


def test_roundtrip_and_autostart(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    c = config.load()
    assert c["theme"] == "system"
    c["theme"] = "verdigris"
    c["unknown"] = 1
    config.save(c)
    back = config.load()
    assert back["theme"] == "verdigris"
    assert "unknown" not in back
    config.set_autostart(True)
    assert config.autostart_enabled()
    assert "deadbolt --tray" in (tmp_path / "autostart" / "deadbolt.desktop").read_text()
    config.set_autostart(False)
    assert not config.autostart_enabled()
