"""The frozen-app dialog and the first-run wizard."""

from __future__ import annotations

import json
import shutil

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from . import config, thunar, wording
from .widgets import heading, note


class FrozenDialog(QDialog):
    """Kill, Allow once, Always allow. Closing it leaves the app frozen."""

    decided = pyqtSignal(str)

    def __init__(self, ctx, incident: dict, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.inc = incident
        self.setWindowTitle("Deadbolt: an app was frozen")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.addWidget(heading("The ransomware shield froze an app"))
        lay.addWidget(note(wording.incident(incident)))
        grid = [
            ("App", incident.get("app", "")),
            ("Executable", incident.get("exe", "")),
            ("PID", str(incident.get("pid", ""))),
            ("User", incident.get("user", "")),
            ("Score", str(incident.get("score", ""))),
        ]
        if incident.get("binary_signature"):
            grid.append(("ClamAV knows it as", incident["binary_signature"]))
        for k, v in grid:
            row = QHBoxLayout()
            kl = QLabel(k + ":")
            kl.setMinimumWidth(130)
            vl = QLabel(v)
            vl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            vl.setWordWrap(True)
            row.addWidget(kl)
            row.addWidget(vl, 1)
            lay.addLayout(row)
        lay.addWidget(QLabel("Signals that fired"))
        sig = QListWidget()
        sig.addItems(incident.get("signals", []))
        sig.setMaximumHeight(110)
        lay.addWidget(sig)
        files = incident.get("files", [])
        lay.addWidget(QLabel(f"Files it touched ({len(files)})"))
        fl = QListWidget()
        fl.addItems(files[:500])
        fl.setMaximumHeight(160)
        lay.addWidget(fl)
        lay.addWidget(note("No answer means it stays frozen. That is deliberate."))
        self.status = QLabel("")
        lay.addWidget(self.status)
        row = QHBoxLayout()
        for label, choice in [
            ("Kill", "kill"),
            ("Allow once", "allow-once"),
            ("Always allow", "allow-always"),
        ]:
            b = QPushButton(label)
            b.clicked.connect(lambda _c=False, ch=choice: self.choose(ch))
            row.addWidget(b)
        later = QPushButton("Decide later")
        later.clicked.connect(self.hide)
        row.addStretch(1)
        row.addWidget(later)
        lay.addLayout(row)

    def choose(self, choice: str):
        self.status.setText("Waiting for authorization...")

        def ok(inc):
            self.decided.emit(self.inc["id"])
            notes = [s for s in inc.get("signals", []) if s.startswith("note:")]
            self.ctx.info(f"{inc.get('app')}: {inc.get('state')}. " + " ".join(n[5:].strip() for n in notes))
            self.accept()

        def err(msg):
            self.status.setText(msg)

        self.ctx.daemon.call("Shield", "Decide", self.inc["id"], choice, ok=ok, err=err)


class Step(QWidget):
    def __init__(self, title: str, text: str, step: str | None, run_label: str = "Run this step"):
        super().__init__()
        self.step = step
        lay = QVBoxLayout(self)
        lay.addWidget(heading(title))
        lay.addWidget(note(text))
        self.extra = QVBoxLayout()
        lay.addLayout(self.extra)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(200)
        lay.addWidget(self.log)
        lay.addStretch(1)
        self.run_label = run_label
        self.done = step is None


class SetupWizard(QDialog):
    """First run. The package turns nothing on by itself; you agree to each change."""

    finished_setup = pyqtSignal()

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Set up Deadbolt")
        self.setMinimumSize(640, 520)
        lay = QVBoxLayout(self)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)
        self.steps = [
            Step(
                "1. Kernel check",
                "Checks fanotify permission support, the kernel version and cgroup v2. "
                "Tells you whether real-time protection can block or only notify.",
                "kernel",
                "Check",
            ),
            Step(
                "2. Take over clamd",
                "Deadbolt runs its own clamd with its own config so a ClamAV package "
                "upgrade cannot rewrite it. To avoid two clamd processes each eating a gigabyte of RAM, the "
                "distro's clamav-daemon and clamav-clamonacc services get masked. Uninstalling Deadbolt "
                "unmasks them.",
                "clamd",
                "Take over",
            ),
            Step(
                "3. Signature update",
                "Asks freshclam for current signatures and waits for them.",
                "signatures",
                "Update",
            ),
            Step(
                "4. Ransomware shield",
                "Plants decoy files in Documents, Pictures, Desktop, Music, Videos and "
                "Downloads for every user, hidden from Dolphin, and starts the monitor. "
                "Reading them is fine. "
                "Writing, renaming or deleting them trips the shield.",
                "shield",
                "Plant and start",
            ),
            Step("5. Network blocking", "", "network", "Apply"),
            Step("6. Tray and file manager", "Choose what runs for you at login.", None),
        ]
        for s in self.steps:
            self.stack.addWidget(s)
        last = self.steps[-1]
        self.tray = QCheckBox("Show Deadbolt in the tray at login")
        self.tray.setChecked(True)
        self.thunar = QCheckBox('Add "Scan with Deadbolt" to Thunar\'s right-click menu')
        self.thunar.setVisible(bool(shutil.which("thunar")))
        self.weekly = QCheckBox("Weekly Quick scan, Sundays at 3 AM")
        self.weekly.setChecked(True)
        for w in (self.tray, self.thunar, self.weekly):
            last.extra.addWidget(w)
        row = QHBoxLayout()
        self.back = QPushButton("Back")
        self.back.clicked.connect(lambda: self.go(self.stack.currentIndex() - 1))
        self.run = QPushButton()
        self.run.clicked.connect(self.run_step)
        self.next = QPushButton("Next")
        self.next.clicked.connect(self.advance)
        row.addWidget(self.back)
        row.addStretch(1)
        row.addWidget(self.run)
        row.addWidget(self.next)
        lay.addLayout(row)
        self.net_preview()
        self.go(0)

    def net_preview(self):
        s = self.steps[4]

        def show(v):
            if not v.get("available"):
                s.log.setPlainText(
                    "OpenSnitch is not installed, so this step is skipped. You can install it "
                    "later and turn on blocking from the Network page."
                )
                s.done = True
                s.step = None
            elif v.get("uses_ui"):
                s.log.setPlainText(
                    "opensnitch-ui is installed, so its config is left alone. Deadbolt only "
                    "manages its own rule files."
                )
                s.done = True
                s.step = None
            else:
                s.log.setPlainText(
                    "Deadbolt will change /etc/opensnitchd/default-config.json so the daemon "
                    "allows by default and never waits on a UI:\n\n"
                    + "\n".join(diff_lines(v.get("current", ""), v.get("new", "")))
                )
            self.go(self.stack.currentIndex())

        self.ctx.daemon.call(
            "Settings", "SetupStep", "network-preview", ok=show, err=lambda m: s.log.setPlainText(m)
        )

    def go(self, i: int):
        i = max(0, min(i, len(self.steps) - 1))
        self.stack.setCurrentIndex(i)
        st = self.steps[i]
        self.back.setEnabled(i > 0)
        self.run.setVisible(st.step is not None)
        self.run.setText(st.run_label)
        self.next.setText("Finish" if i == len(self.steps) - 1 else "Next")
        self.next.setEnabled(st.done)

    def run_step(self):
        st = self.steps[self.stack.currentIndex()]
        self.run.setEnabled(False)
        st.log.appendPlainText("Working... this can take a few minutes for the signature step.")

        def ok(v):
            st.log.appendPlainText(json.dumps(v, indent=2))
            st.done = True
            self.run.setEnabled(True)
            self.go(self.stack.currentIndex())

        def err(m):
            st.log.appendPlainText("Failed: " + m)
            self.run.setEnabled(True)

        self.ctx.daemon.call("Settings", "SetupStep", st.step, ok=ok, err=err)

    def advance(self):
        i = self.stack.currentIndex()
        if i < len(self.steps) - 1:
            self.go(i + 1)
            return
        config.set_autostart(self.tray.isChecked())
        if self.thunar.isVisible() and self.thunar.isChecked():
            try:
                thunar.install()
            except (OSError, ValueError) as e:
                self.ctx.error(f"Could not add the Thunar action: {e}")
        cfg = self.ctx.cfg
        cfg["thunar_asked"] = True

        def finish(_v=None):
            self.ctx.daemon.call(
                "Settings", "SetupStep", "done", ok=lambda _x: self._done(), err=self.ctx.error
            )

        s = json.loads(json.dumps(self.ctx.settings or {}))
        if s:
            for x in s["schedules"]:
                if x["profile"] == "quick":
                    x["enabled"] = self.weekly.isChecked()
            self.ctx.daemon.call(
                "Settings",
                "Set",
                json.dumps(s),
                ok=lambda _v: self.ctx.daemon.call(
                    "Settings", "SetupStep", "schedules", ok=finish, err=self.ctx.error
                ),
                err=self.ctx.error,
            )
        else:
            finish()

    def _done(self):
        self.ctx.cfg["first_run_done"] = True
        config.save(self.ctx.cfg)
        self.finished_setup.emit()
        self.accept()


def diff_lines(old: str, new: str) -> list[str]:
    import difflib

    return list(difflib.unified_diff(old.splitlines(), new.splitlines(), "current", "after", lineterm=""))
