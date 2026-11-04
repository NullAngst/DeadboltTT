from deadbolt_gui import wording


def test_detection_wording():
    d = {"path": "/home/z/invoice.pdf", "signature": "Win.Trojan.Agent-123", "action": "quarantined"}
    assert wording.detection(d) == "Threat found in invoice.pdf: Win.Trojan.Agent-123. Moved to quarantine."


def test_all_messages_are_plain():
    for action in ["quarantined", "deleted", "pending", "reported", "failed: no such file"]:
        msg = wording.detection({"path": "/x/a", "signature": "S", "action": action})
        assert wording.is_plain(msg), msg
    assert wording.is_plain(wording.incident({"app": "x", "files": ["a"]}))
    for label in wording.FIX_LABELS.values():
        assert wording.is_plain(label)


def test_banner_when_daemon_down():
    level, text, fix = wording.banner(None, False)
    assert level == "red"
    assert fix == "start-daemon"
    assert "not running" in text


def test_banner_passthrough():
    st = {
        "level": "amber",
        "reason": "Attention needed: signatures are 5 days old.",
        "fix": "update-signatures",
    }
    assert wording.banner(st, True) == ("amber", st["reason"], "update-signatures")


def test_sizes_and_age():
    assert wording.size(10) == "10 bytes"
    assert wording.size(2048) == "2.0 KB"
    assert wording.age(30) == "just now"
    assert wording.age(3 * 86400) == "3 days ago"
