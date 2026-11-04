"""The eight pages of the main window."""

from __future__ import annotations

import json
import os
import shutil
import tempfile

from PyQt6.QtCore import QProcess, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from . import theme, thunar, wording
from .widgets import Banner, Tile, fill, heading, note, rule, selected_data, table

FP_URL = "https://www.clamav.net/reports/fp"


class Page(QWidget):
    """Base page: a scrollable column with a title."""

    def __init__(self, ctx, title: str):
        super().__init__()
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        self.lay = QVBoxLayout(inner)
        self.lay.setContentsMargins(18, 14, 18, 14)
        self.lay.addWidget(heading(title))
        self.lay.addWidget(rule())
        scroll.setWidget(inner)
        outer.addWidget(scroll)

    def call(self, iface, method, *args, ok=None, raw=False):
        self.ctx.daemon.call(iface, method, *args, ok=ok, err=self.ctx.error, raw=raw)

    def refresh(self):
        pass

    def shown(self):
        self.refresh()

    def hidden(self):
        pass


# ------------------------------------------------------------------ Dashboard


class Dashboard(Page):
    scan_requested = pyqtSignal(str)
    open_page = pyqtSignal(str)

    def __init__(self, ctx):
        super().__init__(ctx, "Dashboard")
        self.banner = Banner()
        self.banner.fix.connect(self.ctx.fix)
        self.lay.addWidget(self.banner)
        grid = QGridLayout()
        self.tiles = {}
        for i, (key, title, page) in enumerate(
            [
                ("realtime", "Real-time", "Protection"),
                ("shield", "Ransomware Shield", "Protection"),
                ("signatures", "Signatures", "Tools"),
                ("last", "Last scan", "Scan"),
                ("quarantine", "Quarantine", "Quarantine"),
                ("network", "Network blocks", "Network"),
            ]
        ):
            t = Tile(title)
            t.clicked.connect(lambda p=page: self.open_page.emit(p))
            self.tiles[key] = t
            grid.addWidget(t, i // 3, i % 3)
        self.lay.addLayout(grid)
        self.frozen_btn = QPushButton("Show frozen apps")
        self.frozen_btn.clicked.connect(self.ctx.show_frozen)
        self.frozen_btn.hide()
        self.lay.addWidget(self.frozen_btn)
        row = QHBoxLayout()
        row.addStretch(1)
        self.quick = QPushButton("Quick Scan")
        self.quick.setObjectName("bigScan")
        self.quick.clicked.connect(lambda: self.scan_requested.emit("quick"))
        row.addWidget(self.quick)
        row.addStretch(1)
        self.lay.addSpacing(16)
        self.lay.addLayout(row)
        self.lay.addStretch(1)

    def refresh(self):
        st = self.ctx.status
        level, text, fix = wording.banner(st, self.ctx.daemon.up)
        self.banner.dark = self.ctx.dark
        self.banner.set(level, text, fix, wording.FIX_LABELS.get(fix, "Fix"))
        if not st:
            for t in self.tiles.values():
                t.set("Unknown", "")
            return
        d = self.ctx.dark
        rt = st["realtime"]
        self.tiles["realtime"].set(
            "On" if rt["running"] else "Off", f"Mode: {rt['mode']}", "green" if rt["running"] else "red", d
        )
        sh = st["shield"]
        on = sh["enabled"] and sh["running"]
        lvl = "green" if on and not sh["unprotected"] else ("amber" if on else "red")
        detail = f"{sh['canaries']} canary files"
        if sh["unprotected"]:
            detail += f", {len(sh['unprotected'])} unprotected"
        if sh["frozen"]:
            lvl, detail = "red", f"{sh['frozen']} app(s) frozen, waiting for you"
        self.tiles["shield"].set("On" if on else "Off", detail, lvl, d)
        sg = st["signatures"]
        age = sg.get("age_days")
        self.tiles["signatures"].set(
            "Unknown" if age is None else ("Today" if age == 0 else f"{age} days old"),
            f"Engine {sg.get('engine') or '?'}" + (", update waiting" if sg.get("engine_outdated") else ""),
            None if age is None else ("green" if age < 3 else "amber"),
            d,
        )
        ls = st.get("last_scan")
        if ls:
            n = len(ls["detections"])
            self.tiles["last"].set(
                wording.when(ls["finished"]),
                f"{ls['profile'].title()}, {ls['files']} files, {n} threat{'s' if n != 1 else ''}",
                "amber" if n else None,
                d,
            )
        else:
            self.tiles["last"].set("Never", "Run a Quick Scan to start")
        self.tiles["quarantine"].set(
            f"{st['quarantine_count']} item{'s' if st['quarantine_count'] != 1 else ''}"
        )
        self.tiles["network"].set(
            f"{st['network_blocks']} app{'s' if st['network_blocks'] != 1 else ''} blocked"
        )
        self.frozen_btn.setVisible(sh["frozen"] > 0)


# ------------------------------------------------------------------ Scan


class DropZone(QLabel):
    dropped = pyqtSignal(list)

    def __init__(self):
        super().__init__("Drop files or folders here to scan them")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.setMinimumHeight(70)
        self.setFrameShape(QFrame.Shape.StyledPanel)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)


class ScanPage(Page):
    def __init__(self, ctx):
        super().__init__(ctx, "Scan")
        self.job: str | None = None
        self.paused = False
        row = QHBoxLayout()
        for prof, label in [("quick", "Quick"), ("home", "Home"), ("full", "Full"), ("custom", "Custom")]:
            b = QPushButton(label)
            b.clicked.connect(lambda _c=False, p=prof: self.start([], p))
            row.addWidget(b)
        f = QPushButton("Choose file...")
        f.clicked.connect(self.pick_file)
        d = QPushButton("Choose folder...")
        d.clicked.connect(self.pick_folder)
        row.addWidget(f)
        row.addWidget(d)
        self.lay.addLayout(row)
        self.lay.addWidget(
            note(
                "Quick covers Downloads, Desktop, temp folders, ~/.local/bin, autostart and "
                "browser extensions. Home is your whole home folder. Full is the whole system "
                "and asks for your password."
            )
        )
        self.drop = DropZone()
        self.drop.dropped.connect(lambda p: self.start(p, "custom"))
        self.lay.addWidget(self.drop)
        self.lay.addWidget(rule())
        self.state = QLabel("No scan running.")
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.current = QLabel("")
        self.current.setWordWrap(True)
        self.current.setEnabled(False)
        ctl = QHBoxLayout()
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(lambda: self.job and self.call("Scan", "Cancel", self.job))
        ctl.addWidget(self.pause_btn)
        ctl.addWidget(self.cancel_btn)
        ctl.addStretch(1)
        for w in (self.state, self.bar, self.current):
            self.lay.addWidget(w)
        self.lay.addLayout(ctl)
        self.lay.addWidget(rule())
        self.lay.addWidget(QLabel("Results"))
        self.results = table(["File", "Threat", "Action"])
        self.results.setMinimumHeight(200)
        self.lay.addWidget(self.results)
        act = QHBoxLayout()
        for label, what in [("Quarantine", "quarantine"), ("Delete", "delete"), ("Ignore", "report")]:
            b = QPushButton(label)
            b.clicked.connect(lambda _c=False, w=what: self.act(w))
            act.addWidget(b)
        act.addStretch(1)
        self.lay.addLayout(act)
        self.detections: list[dict] = []
        self._set_running(False)
        ctx.daemon.signal.connect(self.on_signal)

    def _set_running(self, on: bool):
        self.pause_btn.setEnabled(on)
        self.cancel_btn.setEnabled(on)

    def pick_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Choose a file to scan", os.path.expanduser("~"))
        if p:
            self.start([p], "custom")

    def pick_folder(self):
        p = QFileDialog.getExistingDirectory(self, "Choose a folder to scan", os.path.expanduser("~"))
        if p:
            self.start([p], "custom")

    def start(self, paths: list[str], profile: str):
        if profile == "custom" and not paths:
            custom = (self.ctx.settings or {}).get("scan", {}).get("custom_paths", [])
            if not custom:
                QMessageBox.information(
                    self, "Custom scan", "Add paths for the Custom preset in Settings first."
                )
                return
        self.detections = []
        fill(self.results, [])
        self.state.setText("Starting...")
        self.bar.setRange(0, 0)

        def ok(job):
            self.job = job
            self._set_running(True)
            self.ctx.go("Scan")

        abs_paths = [os.path.abspath(p) for p in paths]
        self.ctx.daemon.call(
            "Scan", "Start", json.dumps(abs_paths), profile, "manual", ok=ok, err=self._failed, raw=True
        )

    def _failed(self, msg):
        self.state.setText("Scan did not start.")
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.ctx.error(msg)

    def toggle_pause(self):
        if not self.job:
            return
        self.call("Scan", "Resume" if self.paused else "Pause", self.job)

    def on_signal(self, iface, member, p):
        if iface != "Scan" or not isinstance(p, dict):
            return
        if member == "Progress" and p.get("job") == self.job:
            st = p["state"]
            self.paused = st == "paused"
            self.pause_btn.setText("Resume" if self.paused else "Pause")
            if p.get("fallback"):
                self.bar.setRange(0, 0)
                self.state.setText(
                    f"clamd is down, scanning with clamscan. This is slow. {p['found']} found."
                )
            elif st == "counting":
                self.bar.setRange(0, 0)
                self.state.setText(f"Counting files... {p['total']}")
            elif p["total"]:
                self.bar.setRange(0, 100)
                self.bar.setValue(int(100 * p["done"] / max(p["total"], 1)))
                self.state.setText(
                    f"{'Paused' if self.paused else 'Scanning'}: {p['done']} of {p['total']} files, "
                    f"{p['found']} found"
                )
            self.current.setText(p.get("current", ""))
        elif member == "Detection" and self.job and p.get("source") == "manual":
            self.detections = [d for d in self.detections if d["path"] != p["path"]] + [p]
            self._show()
        elif member == "Finished" and p.get("job") == self.job:
            self._set_running(False)
            self.bar.setRange(0, 100)
            self.bar.setValue(100)
            self.current.setText("")
            n = len(p["detections"])
            word = "cancelled" if p["state"] == "cancelled" else "finished"
            self.state.setText(f"Scan {word}: {p['files']} files, {n} threat{'s' if n != 1 else ''}.")
            self.detections = p["detections"]
            self._show()

    def _show(self):
        fill(
            self.results, [[d["path"], d["signature"], d["action"]] for d in self.detections], self.detections
        )

    def act(self, what: str):
        for d in selected_data(self.results):
            if not d or d.get("action") != "pending" or not self.job:
                continue

            def ok(det, path=d["path"]):
                self.detections = [det if x["path"] == path else x for x in self.detections]
                self._show()

            self.call("Scan", "Act", self.job, d["path"], what, ok=ok)


# ------------------------------------------------------------------ Protection


class PathList(QWidget):
    def __init__(self, title: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel(title))
        self.list = QListWidget()
        self.list.setMaximumHeight(120)
        lay.addWidget(self.list)
        row = QHBoxLayout()
        add = QPushButton("Add folder...")
        add.clicked.connect(self.add)
        rm = QPushButton("Remove")
        rm.clicked.connect(lambda: [self.list.takeItem(self.list.row(i)) for i in self.list.selectedItems()])
        row.addWidget(add)
        row.addWidget(rm)
        row.addStretch(1)
        lay.addLayout(row)

    def add(self):
        p = QFileDialog.getExistingDirectory(self, "Choose a folder", "/")
        if p and p not in self.values():
            self.list.addItem(p)

    def set(self, vals):
        self.list.clear()
        self.list.addItems(vals)

    def values(self):
        return [self.list.item(i).text() for i in range(self.list.count())]


class ProtectionPage(Page):
    def __init__(self, ctx):
        super().__init__(ctx, "Protection")
        g = QGroupBox("Real-time protection")
        gl = QVBoxLayout(g)
        self.rt = QCheckBox("Scan files as they are opened")
        self.mode = QLabel("")
        self.include = PathList("Protected folders (/ itself is not allowed, ClamAV refuses it)")
        self.exclude = PathList("Exclusions. Each one is a blind spot. Put big game libraries here.")
        self.root = QCheckBox("Skip files opened by root (faster apt runs, less coverage)")
        for w in (self.rt, self.mode, self.include, self.exclude, self.root):
            gl.addWidget(w)
        self.lay.addWidget(g)
        s = QGroupBox("Ransomware shield")
        sl = QVBoxLayout(s)
        self.shield = QCheckBox("Freeze apps that mass-encrypt files")
        self.sens = QComboBox()
        self.sens.addItems(["low", "normal", "high"])
        row = QHBoxLayout()
        row.addWidget(QLabel("Sensitivity"))
        row.addWidget(self.sens)
        row.addStretch(1)
        self.marks = QLabel("")
        self.marks.setWordWrap(True)
        self.canary_label = QLabel("")
        replant = QPushButton("Plant canary files again")
        replant.clicked.connect(lambda: self.call("Shield", "ReplantCanaries", ok=lambda n: self.refresh()))
        sl.addWidget(self.shield)
        sl.addLayout(row)
        sl.addWidget(self.marks)
        sl.addWidget(self.canary_label)
        sl.addWidget(replant)
        sl.addWidget(
            note(
                "The shield catches the pattern after it starts: the first handful of files get hit "
                "before the score crosses the line. Freezing stops the rest. Backups and snapshots "
                "are still the real fix."
            )
        )
        sl.addWidget(QLabel("Allowlist (root-owned binaries only, interpreters are never allowed)"))
        self.allow = table(["Executable", "Package", "SHA-256"])
        self.allow.setMaximumHeight(180)
        sl.addWidget(self.allow)
        arow = QHBoxLayout()
        add = QPushButton("Add executable...")
        add.clicked.connect(self.allow_add)
        rm = QPushButton("Remove")
        rm.clicked.connect(self.allow_remove)
        arow.addWidget(add)
        arow.addWidget(rm)
        arow.addStretch(1)
        sl.addLayout(arow)
        self.lay.addWidget(s)
        save = QPushButton("Save")
        save.clicked.connect(self.save)
        self.lay.addWidget(save, alignment=Qt.AlignmentFlag.AlignRight)
        self.lay.addStretch(1)

    def refresh(self):
        s = self.ctx.settings
        st = self.ctx.status
        if s:
            self.rt.setChecked(s["realtime"]["enabled"])
            self.include.set(s["realtime"]["include_paths"])
            self.exclude.set(s["realtime"]["exclude_paths"])
            self.root.setChecked(s["realtime"]["exclude_root"])
            self.shield.setChecked(s["shield"]["enabled"])
            self.sens.setCurrentText(s["shield"]["sensitivity"])
        if st:
            mode = st["realtime"]["mode"]
            self.mode.setText(
                "Mode: blocking. Infected files cannot be opened."
                if mode == "blocking"
                else "Mode: notify-only. This kernel cannot block opens, so threats are reported "
                "after the fact."
            )
            sh = st["shield"]
            txt = "Watching: " + (", ".join(sh["protected"]) or "nothing yet")
            if sh["unprotected"]:
                txt += "\nUnprotected (these refuse a fanotify mark): " + "; ".join(sh["unprotected"])
            if st.get("overflow_count"):
                txt += f"\nEvent queue overflowed {st['overflow_count']} time(s). Some file events were lost."
            self.marks.setText(txt)
        self.call("Shield", "Canaries", ok=self._canaries)
        self.call("Shield", "Allowlist", ok=self._allow)

    def _canaries(self, v):
        v = v or []
        bad = [c for c in v if not c["unchanged"]]
        self.canary_label.setText(
            f"{len(v)} canary files planted"
            + (f", {len(bad)} changed or missing" if bad else ", all unchanged")
        )

    def _allow(self, v):
        v = v or []
        fill(self.allow, [[e["path"], e.get("package", ""), e["sha256"][:16] + "..."] for e in v], v)

    def allow_add(self):
        p, _ = QFileDialog.getOpenFileName(self, "Choose an executable", "/usr/bin")
        if p:
            self.call("Shield", "AllowlistAdd", p, ok=lambda _v: self.refresh())

    def allow_remove(self):
        for e in selected_data(self.allow):
            self.call("Shield", "AllowlistRemove", e["path"], ok=lambda _v: self.refresh())

    def save(self):
        s = json.loads(json.dumps(self.ctx.settings))
        s["realtime"]["enabled"] = self.rt.isChecked()
        s["realtime"]["include_paths"] = self.include.values()
        s["realtime"]["exclude_paths"] = self.exclude.values()
        s["realtime"]["exclude_root"] = self.root.isChecked()
        s["shield"]["enabled"] = self.shield.isChecked()
        s["shield"]["sensitivity"] = self.sens.currentText()
        self.ctx.save_settings(s)


# ------------------------------------------------------------------ Quarantine


class QuarantinePage(Page):
    def __init__(self, ctx):
        super().__init__(ctx, "Quarantine")
        self.lay.addWidget(
            note(
                "Quarantined files are stored scrambled in a root-only folder that is mounted "
                "noexec. Listing them asks for your password once."
            )
        )
        self.table = table(["Name", "Threat", "Original path", "Date", "Source"])
        self.table.setMinimumHeight(320)
        self.lay.addWidget(self.table)
        self.exec_box = QCheckBox("Restore execute permission")
        self.lay.addWidget(self.exec_box)
        row = QHBoxLayout()
        for label, fn in [
            ("Restore", self.restore),
            ("Restore to...", self.restore_to),
            ("Restore and exclude", self.restore_exclude),
            ("Delete", self.delete),
            ("Report false positive", self.report),
            ("Refresh", self.refresh),
        ]:
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        self.lay.addLayout(row)
        self.lay.addWidget(
            note(
                "Delete is a plain unlink. It does not shred: overwriting means nothing on an SSD "
                "or a copy-on-write filesystem."
            )
        )
        self.lay.addStretch(1)
        self.items: list[dict] = []

    def shown(self):
        self.refresh()

    def refresh(self):
        self.call("Quarantine", "List", ok=self._show)

    def _show(self, items):
        self.items = items or []
        rows = [
            [
                os.path.basename(i["original_path"]),
                i["signature"],
                i["original_path"],
                wording.when(i["date"]),
                wording.SOURCE_TEXT.get(i["source"], i["source"]),
            ]
            for i in self.items
        ]
        fill(self.table, rows, self.items)

    def _each(self, fn):
        sel = selected_data(self.table)
        if not sel:
            QMessageBox.information(self, "Quarantine", "Select an item first.")
        for i in sel:
            fn(i)

    def restore(self):
        self._each(
            lambda i: self.call(
                "Quarantine",
                "Restore",
                i["id"],
                "",
                self.exec_box.isChecked(),
                False,
                ok=lambda p: (self.ctx.info(f"Restored to {p}"), self.refresh()),
                raw=True,
            )
        )

    def restore_to(self):
        def one(i):
            p, _ = QFileDialog.getSaveFileName(self, "Restore to", i["original_path"])
            if p:
                self.call(
                    "Quarantine",
                    "Restore",
                    i["id"],
                    p,
                    self.exec_box.isChecked(),
                    False,
                    ok=lambda r: (self.ctx.info(f"Restored to {r}"), self.refresh()),
                    raw=True,
                )

        self._each(one)

    def restore_exclude(self):
        self._each(
            lambda i: self.call(
                "Quarantine",
                "Restore",
                i["id"],
                "",
                self.exec_box.isChecked(),
                True,
                ok=lambda p: (self.ctx.info(f"Restored to {p} and excluded from scans"), self.refresh()),
                raw=True,
            )
        )

    def delete(self):
        sel = selected_data(self.table)
        if not sel:
            return
        if (
            QMessageBox.question(self, "Delete", f"Delete {len(sel)} quarantined file(s) for good?")
            != QMessageBox.StandardButton.Yes
        ):
            return
        for i in sel:
            self.call("Quarantine", "Delete", i["id"], ok=lambda _v: self.refresh())

    def report(self):
        QDesktopServices.openUrl(QUrl(FP_URL))
        self.ctx.info(
            "ClamAV's false-positive page is open in your browser. Deadbolt uploads nothing itself."
        )


# ------------------------------------------------------------------ Network


class NetworkPage(Page):
    def __init__(self, ctx):
        super().__init__(ctx, "Network")
        self.unavailable = note(
            "Per-app network blocking needs OpenSnitch. Install it with your package "
            "manager (I use apt: sudo apt install opensnitch), then come back."
        )
        self.lay.addWidget(self.unavailable)
        self.body = QWidget()
        bl = QVBoxLayout(self.body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(
            note(
                "Blocking applies to new connections. A process in an unprivileged user namespace can "
                "get around path matching, so this keeps honest apps offline. It is not a sandbox."
            )
        )
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter apps")
        self.filter.textChanged.connect(self._show_apps)
        bl.addWidget(self.filter)
        self.apps_t = table(["App", "Blocked", "Allow local network", "Target"])
        self.apps_t.setMinimumHeight(280)
        self.apps_t.cellDoubleClicked.connect(self._toggle_cell)
        bl.addWidget(self.apps_t)
        row = QHBoxLayout()
        for label, fn in [
            ("Block / unblock", lambda: self._toggle(False)),
            ("Allow local network", lambda: self._toggle(True)),
            ("Add executable...", self.add_exe),
            ("Drop existing connections", self.drop),
        ]:
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        bl.addLayout(row)
        bl.addWidget(rule())
        bl.addWidget(QLabel("Active connections"))
        self.conns = table(["Process", "PID", "Protocol", "Local", "Remote"])
        self.conns.setMaximumHeight(220)
        bl.addWidget(self.conns)
        bl.addWidget(QLabel("Recently blocked"))
        self.recent = QListWidget()
        self.recent.setMaximumHeight(160)
        bl.addWidget(self.recent)
        self.lay.addWidget(self.body)
        self.lay.addStretch(1)
        self.apps: list[dict] = []
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._poll)

    def shown(self):
        self.refresh()
        self.timer.start()

    def hidden(self):
        # Nothing polled when the page is closed.
        self.timer.stop()

    def refresh(self):
        def avail(ok):
            self.unavailable.setVisible(not ok)
            self.body.setVisible(bool(ok))
            if ok:
                self.call("Network", "Apps", ok=self._apps)
                self._poll()

        self.call("Network", "Available", ok=avail)

    def _poll(self):
        if not self.body.isVisible():
            return
        self.call(
            "Network",
            "Connections",
            ok=lambda v: fill(
                self.conns, [[c["process"], c["pid"], c["proto"], c["local"], c["peer"]] for c in (v or [])]
            ),
        )
        self.call(
            "Network", "RecentlyBlocked", ok=lambda v: (self.recent.clear(), self.recent.addItems(v or []))
        )

    def _apps(self, v):
        self.apps = v or []
        self._show_apps()

    def _show_apps(self):
        f = self.filter.text().lower()
        shown = [a for a in self.apps if f in a["name"].lower() or f in a["target"].lower()]
        fill(
            self.apps_t,
            [
                [
                    a["name"],
                    "Blocked" if a["blocked"] else "Allowed",
                    "Yes" if a["allow_lan"] else "",
                    a["target"],
                ]
                for a in shown
            ],
            shown,
        )

    def _toggle_cell(self, row, col):
        self.apps_t.selectRow(row)
        self._toggle(col == 2)

    def _toggle(self, lan: bool):
        for a in selected_data(self.apps_t):
            blocked, allow = (True, not a["allow_lan"]) if lan else (not a["blocked"], a["allow_lan"])
            self.call(
                "Network",
                "SetBlocked",
                a["name"],
                a["kind"],
                a["target"],
                blocked,
                allow,
                ok=lambda _v: self.refresh(),
            )

    def add_exe(self):
        p, _ = QFileDialog.getOpenFileName(self, "Choose a program", "/usr/bin")
        if not p:
            return
        kind = "wine" if p.lower().endswith(".exe") else "native"
        target = os.path.basename(p) if kind == "wine" else os.path.realpath(p)
        self.call(
            "Network",
            "SetBlocked",
            os.path.basename(p),
            kind,
            target,
            True,
            False,
            ok=lambda _v: self.refresh(),
        )

    def drop(self):
        for a in selected_data(self.apps_t):
            if a["kind"] == "native":
                self.call(
                    "Network",
                    "DropConnections",
                    a["target"],
                    ok=lambda n: self.ctx.info(f"Dropped {n} connection(s)."),
                )


# ------------------------------------------------------------------ Tools


class Card(QGroupBox):
    def __init__(self, title: str, text: str):
        super().__init__(title)
        self.l = QVBoxLayout(self)
        self.text = note(text)
        self.out = note("")
        self.l.addWidget(self.text)
        self.buttons = QHBoxLayout()
        self.l.addLayout(self.buttons)
        self.l.addWidget(self.out)
        self.buttons.addStretch(1)

    def button(self, label: str, fn) -> QPushButton:
        b = QPushButton(label)
        b.clicked.connect(fn)
        self.buttons.insertWidget(self.buttons.count() - 1, b)
        return b


class ToolsPage(Page):
    def __init__(self, ctx):
        super().__init__(ctx, "Tools")
        self.cards: dict[str, Card] = {}
        self.need: dict[str, list[str]] = {}
        self.running: dict[str, str] = {}

        c = self._card("sig", "Signature updates", "freshclam keeps ClamAV's signatures current.", [])
        c.button(
            "Update now",
            lambda: self.call("Settings", "UpdateSignatures", raw=True, ok=lambda r: c.out.setText(str(r))),
        )
        c = self._card(
            "feeds",
            "Extra signature feeds",
            "fangfrisch adds free third-party feeds such as "
            "URLhaus and Sanesecurity, on its own timer. Opt-in.",
            ["fangfrisch"],
        )
        c = self._card("usb", "USB auto-scan", "Offer a scan when a removable drive mounts.", ["udisks2"])
        self.usb = QComboBox()
        self.usb.addItems(["ask", "always", "never"])
        self.usb.activated.connect(self._usb)
        c.buttons.insertWidget(0, self.usb)
        c = self._card(
            "eicar",
            "Test protection",
            "Writes the standard harmless EICAR test file to a temp "
            "folder and checks that real-time protection blocks it.",
            [],
        )
        c.button("Run test", self.test_eicar)
        c = self._card(
            "shieldtest",
            "Test ransomware shield",
            "Encrypts 200 dummy files in a temp folder with "
            "openssl and checks the shield freezes it. Never touches real files.",
            ["openssl"],
        )
        c.button("Run test", self.test_shield)
        c = self._card(
            "rootkit",
            "Rootkit check",
            "Runs rkhunter or chkrootkit and shows warnings in plain "
            "language. Many warnings are harmless on a normal desktop.",
            ["rkhunter", "chkrootkit"],
        )
        c.button("rkhunter", lambda: self.run_tool("rootkit", "rkhunter"))
        c.button("chkrootkit", lambda: self.run_tool("rootkit", "chkrootkit"))
        c = self._card(
            "lynis",
            "Hardening audit",
            "lynis audit system: the hardening index and the top suggestions.",
            ["lynis"],
        )
        c.button("Run audit", lambda: self.run_tool("lynis", "lynis"))
        c = self._card(
            "integrity",
            "Package integrity",
            "Lists system files that no longer match their package (debsums -s or rpm -Va).",
            ["debsums", "rpm"],
        )
        c.button(
            "Check",
            lambda: self.run_tool("integrity", "debsums" if shutil.which("debsums") else "rpm-verify"),
        )
        c = self._card(
            "recovery",
            "Ransomware recovery helper",
            "For a shield incident: the latest snapshot "
            "from before it, the files it touched, and the restore command to run. Deadbolt does "
            "not restore on its own.",
            [],
        )
        self.incidents = QComboBox()
        c.buttons.insertWidget(0, self.incidents)
        c.button("Show", self.recovery)
        c = self._card(
            "startup",
            "Startup items review",
            "What runs at login or on a schedule. Scan any target on demand.",
            [],
        )
        self.startup = table(["Kind", "Name", "Runs", "File"])
        self.startup.setMaximumHeight(220)
        c.l.insertWidget(1, self.startup)
        c.button("List", self.list_startup)
        c.button("Scan selected", self.scan_startup)
        self.lay.addStretch(1)
        ctx.daemon.signal.connect(self.on_signal)

    def _card(self, key, title, text, needs):
        c = Card(title, text)
        self.cards[key] = c
        self.need[key] = needs
        self.lay.addWidget(c)
        return c

    def refresh(self):
        reqs = (self.ctx.reqs or {}).get("rows", [])
        have = {r["tool"]: r for r in reqs}
        for key, needs in self.need.items():
            if not needs:
                continue
            ok = any(have.get(n, {}).get("installed") for n in needs)
            c = self.cards[key]
            for i in range(c.buttons.count()):
                w = c.buttons.itemAt(i).widget()
                if w:
                    w.setEnabled(ok)
            if not ok:
                hints = [have[n]["install_hint"] for n in needs if n in have and have[n]["install_hint"]]
                c.out.setText("Not installed. " + (hints[0] if hints else ""))
            elif c.out.text().startswith("Not installed"):
                c.out.setText("")
        st = self.ctx.status
        if st:
            sg = st["signatures"]
            self.cards["sig"].out.setText(
                f"Signatures {sg.get('age_days', '?')} days old, engine {sg.get('engine') or '?'}"
                + (". Warning: older than 3 days." if (sg.get("age_days") or 0) >= 3 else ".")
            )
        if self.ctx.settings:
            self.usb.setCurrentText(self.ctx.settings["usb"]["autoscan"])
        self.call("Shield", "Incidents", ok=self._incidents)

    def _incidents(self, v):
        self.incidents.clear()
        for i in v or []:
            self.incidents.addItem(f"{wording.when(i['time'])} {i['app']} ({i['state']})", i["id"])

    def _usb(self):
        s = json.loads(json.dumps(self.ctx.settings))
        s["usb"]["autoscan"] = self.usb.currentText()
        self.ctx.save_settings(s)

    def run_tool(self, card, tool):
        self.cards[card].out.setText(f"Running {tool}. This can take several minutes...")
        self.call("Settings", "RunTool", tool, raw=True, ok=lambda job: self.running.__setitem__(job, card))

    def on_signal(self, iface, member, p):
        if member != "ToolFinished" or not isinstance(p, dict):
            return
        card = self.running.pop(p.get("id", ""), None)
        if not card:
            return
        r = p["result"]
        text = r["summary"]
        if r.get("findings"):
            text += "\n" + "\n".join("  " + f for f in r["findings"][:20])
        self.cards[card].out.setText(text)

    def test_eicar(self):
        """Write EICAR as this user, then try to read it back. Real-time should refuse."""
        out = self.cards["eicar"].out
        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-" + "FILE!$H+H*"
        d = tempfile.mkdtemp(prefix="deadbolt-eicar-", dir="/var/tmp")
        p = os.path.join(d, "eicar.com")
        try:
            with open(p, "w", encoding="ascii") as f:
                f.write(eicar)
        except PermissionError:
            out.setText("Pass: real-time protection refused to let the test file be written.")
            return

        def check():
            try:
                with open(p, encoding="ascii") as f:
                    f.read()
                blocked = False
            except PermissionError:
                blocked = True
            except FileNotFoundError:
                blocked = True
            try:
                os.remove(p)
                os.rmdir(d)
            except OSError:
                pass
            out.setText(
                "Pass: the open was blocked and the file was reported."
                if blocked
                else "The open was not blocked. If real-time is notify-only on this kernel that is expected; "
                "otherwise check the Protection page."
            )

        QTimer.singleShot(800, check)

    def test_shield(self):
        out = self.cards["shieldtest"].out
        script = "/usr/share/deadbolt/tools/deadbolt-shield-test"
        if not os.path.exists(script):
            out.setText(f"{script} is missing. Reinstall the package.")
            return
        out.setText("Running. The shield should freeze it within a few seconds and ask you what to do.")
        self.proc = QProcess(self)
        self.proc.finished.connect(lambda _c, _s: clean_simulator_leftovers())
        self.proc.finished.connect(
            lambda code, _s: out.setText(
                "Simulator ended. If you chose Kill, the test passed."
                if code != 0
                else "The simulator finished all 200 files without being frozen. "
                "Check the shield on the Protection page."
            )
        )
        self.proc.start(script, [])

    def recovery(self):
        iid = self.incidents.currentData()
        if not iid:
            return

        def show(v):
            text = v["note"]
            snap = v.get("snapshot")
            if snap:
                text += f"\nCommand: {snap['restore_hint']}"
            text += "\nFiles touched:\n" + "\n".join("  " + f for f in v["files"][:40])
            if len(v["files"]) > 40:
                text += f"\n  ...and {len(v['files']) - 40} more, listed in the incident file."
            self.cards["recovery"].out.setText(text)

        self.call("Shield", "Recovery", iid, ok=show)

    def list_startup(self):
        self.call(
            "Settings",
            "StartupItems",
            ok=lambda v: fill(
                self.startup, [[i["kind"], i["name"], i["target"], i["file"]] for i in (v or [])], v or []
            ),
        )

    def scan_startup(self):
        targets = [i["target"] for i in selected_data(self.startup) if i and i["target"].startswith("/")]
        if targets:
            self.ctx.scan(targets)


# ------------------------------------------------------------------ History


class HistoryPage(Page):
    KINDS = ["", "scan", "detection", "action", "block", "shield", "protection", "update", "setup"]

    def __init__(self, ctx):
        super().__init__(ctx, "History")
        row = QHBoxLayout()
        self.kind = QComboBox()
        self.kind.addItems(["All"] + [k.title() for k in self.KINDS[1:]])
        self.text = QLineEdit()
        self.text.setPlaceholderText("Search")
        go = QPushButton("Filter")
        go.clicked.connect(self.refresh)
        self.text.returnPressed.connect(self.refresh)
        export = QPushButton("Export CSV...")
        export.clicked.connect(self.export)
        row.addWidget(self.kind)
        row.addWidget(self.text, 1)
        row.addWidget(go)
        row.addWidget(export)
        self.lay.addLayout(row)
        self.table = table(["Time", "Kind", "What happened"])
        self.table.setMinimumHeight(420)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._detail)
        self.lay.addWidget(self.table)
        self.detail = note("")
        self.lay.addWidget(self.detail)
        self.lay.addWidget(
            note("History keeps 180 days by default. Older rows are rolled up into monthly counts.")
        )

    def _filter(self):
        return json.dumps(
            {"kind": self.KINDS[self.kind.currentIndex()], "text": self.text.text(), "limit": 2000}
        )

    def refresh(self):
        self.call(
            "Settings",
            "History",
            self._filter(),
            ok=lambda v: fill(
                self.table, [[wording.when(e["time"]), e["kind"], e["summary"]] for e in (v or [])], v or []
            ),
        )

    def _detail(self):
        sel = selected_data(self.table)
        self.detail.setText(sel[0]["detail"][:2000] if sel and sel[0] else "")

    def export(self):
        p, _ = QFileDialog.getSaveFileName(
            self, "Export history", os.path.expanduser("~/deadbolt-history.csv"), "CSV (*.csv)"
        )
        if not p:
            return

        def write(csv):
            with open(p, "w", encoding="utf-8") as f:
                f.write(csv)
            self.ctx.info(f"Saved {p}")

        f = json.loads(self._filter())
        f["limit"] = 10000
        self.call("Settings", "HistoryCsv", json.dumps(f), ok=write, raw=True)


# ------------------------------------------------------------------ Settings


class SettingsPage(Page):
    ACTIONS = {
        "realtime": ["quarantine", "delete", "report-only"],
        "manual": ["ask", "quarantine", "delete", "report-only"],
        "scheduled": ["quarantine", "delete", "report-only"],
        "ransomware": ["quarantine", "delete"],
    }

    def __init__(self, ctx):
        super().__init__(ctx, "Settings")
        a = QGroupBox("What to do with threats")
        af = QFormLayout(a)
        self.act = {}
        for k, choices in self.ACTIONS.items():
            cb = QComboBox()
            cb.addItems(choices)
            self.act[k] = cb
            af.addRow(
                {
                    "realtime": "Real-time",
                    "manual": "Manual scan",
                    "scheduled": "Scheduled scan",
                    "ransomware": "Ransomware kill (the executable)",
                }[k],
                cb,
            )
        self.lay.addWidget(a)

        sc = QGroupBox("Schedules")
        sf = QFormLayout(sc)
        self.sched = {}
        for prof in ["quick", "home", "full", "custom"]:
            row = QHBoxLayout()
            en = QCheckBox("On")
            cal = QLineEdit()
            cal.setPlaceholderText("systemd OnCalendar, e.g. Sun *-*-* 03:00:00")
            bat = QCheckBox("Skip on battery")
            row.addWidget(en)
            row.addWidget(cal, 1)
            row.addWidget(bat)
            w = QWidget()
            w.setLayout(row)
            sf.addRow(prof.title(), w)
            self.sched[prof] = (en, cal, bat)
        self.custom = PathList("Paths for the Custom preset")
        sf.addRow(self.custom)
        self.lay.addWidget(sc)

        g = QGroupBox("App")
        gf = QFormLayout(g)
        self.theme = QComboBox()
        for k in theme.ORDER:
            self.theme.addItem(theme.LABELS[k], k)
        self.theme.activated.connect(lambda: self.ctx.set_theme(self.theme.currentData()))
        self.autostart = QCheckBox("Start in the tray at login")
        self.autostart.toggled.connect(self.ctx.set_autostart)
        self.thunar = QPushButton('Add "Scan with Deadbolt" to Thunar')
        self.thunar.clicked.connect(self.add_thunar)
        gf.addRow("Theme", self.theme)
        gf.addRow(self.autostart)
        gf.addRow(self.thunar)
        self.lay.addWidget(g)

        q = QGroupBox("Quarantine, history, network")
        qf = QFormLayout(q)
        self.purge = QComboBox()
        for d in [0, 7, 14, 30, 90]:
            self.purge.addItem("Off" if d == 0 else f"{d} days", d)
        self.retention = QSpinBox()
        self.retention.setRange(7, 3650)
        self.retention.setSuffix(" days")
        self.deny_tmp = QCheckBox("Reject network access for programs run from /tmp, /var/tmp, /dev/shm")
        qf.addRow("Auto-delete quarantine after", self.purge)
        qf.addRow("Keep history for", self.retention)
        qf.addRow(self.deny_tmp)
        self.lay.addWidget(q)

        adv = QGroupBox("Advanced scanning (maps straight to clamd options)")
        vf = QFormLayout(adv)
        self.pua = QCheckBox("DetectPUA: report potentially unwanted apps")
        self.archive = QCheckBox("ScanArchive")
        self.encrypted = QCheckBox("AlertEncrypted: flag encrypted archives")
        self.onefs = QCheckBox("Stay on one filesystem")
        self.maxfile = QSpinBox()
        self.maxfile.setRange(1, 4000)
        self.maxfile.setSuffix(" MB")
        self.maxscan = QSpinBox()
        self.maxscan.setRange(1, 4000)
        self.maxscan.setSuffix(" MB")
        self.recursion = QSpinBox()
        self.recursion.setRange(1, 64)
        self.threads = QSpinBox()
        self.threads.setRange(1, 64)
        self.rtmax = QSpinBox()
        self.rtmax.setRange(1, 4000)
        self.rtmax.setSuffix(" MB")
        for w in (self.pua, self.archive, self.encrypted, self.onefs):
            vf.addRow(w)
        vf.addRow("MaxFileSize", self.maxfile)
        vf.addRow("MaxScanSize", self.maxscan)
        vf.addRow("MaxRecursion", self.recursion)
        vf.addRow("MaxThreads", self.threads)
        vf.addRow("Real-time size limit", self.rtmax)
        self.lay.addWidget(adv)
        save = QPushButton("Save")
        save.clicked.connect(self.save)
        self.lay.addWidget(save, alignment=Qt.AlignmentFlag.AlignRight)

        self.lay.addWidget(rule())
        self.lay.addWidget(heading("System requirements"))
        self.lay.addWidget(
            note(
                "Deadbolt never bundles its backends. They come from your distro, so their "
                "security fixes arrive with normal updates. Deadbolt shows the install command; "
                "it does not run it."
            )
        )
        self.reqs = table(["Tool", "Needed", "State", "Version", "Used for", "Install"])
        self.reqs.setMinimumHeight(360)
        self.lay.addWidget(self.reqs)
        self.kernel = note("")
        self.lay.addWidget(self.kernel)
        row = QHBoxLayout()
        self.cmd = QLineEdit()
        self.cmd.setReadOnly(True)
        copy = QPushButton("Copy")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.cmd.text()))
        recheck = QPushButton("Re-check")
        recheck.clicked.connect(lambda: self.call("Status", "Requirements", True, ok=self._reqs))
        row.addWidget(self.cmd, 1)
        row.addWidget(copy)
        row.addWidget(recheck)
        self.lay.addLayout(row)
        self.lay.addStretch(1)

    def refresh(self):
        s = self.ctx.settings
        if s:
            for k, cb in self.act.items():
                cb.setCurrentText(s["actions"][k])
            by = {x["profile"]: x for x in s["schedules"]}
            for prof, (en, cal, bat) in self.sched.items():
                x = by.get(prof)
                en.setChecked(bool(x and x["enabled"]))
                cal.setText(x["on_calendar"] if x else "")
                bat.setChecked(x["skip_on_battery"] if x else True)
            self.custom.set(s["scan"]["custom_paths"])
            self.purge.setCurrentIndex(max(0, self.purge.findData(s["quarantine"]["auto_delete_days"])))
            self.retention.setValue(s["history"]["retention_days"])
            self.deny_tmp.setChecked(s["network"]["deny_tmp"])
            sc = s["scan"]
            self.pua.setChecked(sc["detect_pua"])
            self.archive.setChecked(sc["scan_archive"])
            self.encrypted.setChecked(sc["alert_encrypted"])
            self.onefs.setChecked(sc["one_filesystem"])
            self.maxfile.setValue(sc["max_file_mb"])
            self.maxscan.setValue(sc["max_scan_mb"])
            self.recursion.setValue(sc["max_recursion"])
            self.threads.setValue(sc["max_threads"])
            self.rtmax.setValue(s["realtime"]["max_file_mb"])
        self.theme.setCurrentIndex(max(0, self.theme.findData(self.ctx.cfg["theme"])))
        self.autostart.blockSignals(True)
        self.autostart.setChecked(self.ctx.autostart())
        self.autostart.blockSignals(False)
        self.thunar.setEnabled(bool(shutil.which("thunar")) and not thunar.installed())
        if self.ctx.reqs:
            self._reqs(self.ctx.reqs)

    def _reqs(self, r):
        self.ctx.reqs = r
        rows = []
        for x in r["rows"]:
            state = "Missing" if not x["installed"] else ("Stopped" if x["running"] is False else "Installed")
            rows.append(
                [
                    x["tool"],
                    "Required" if x["required"] else "Optional",
                    state,
                    x["version"],
                    x["feature"],
                    x["install_hint"],
                ]
            )
        fill(self.reqs, rows)
        self.kernel.setText(
            "Kernel: "
            + "; ".join(f"{k['name']}: {'ok' if k['ok'] else 'no'} ({k['detail']})" for k in r["kernel"])
        )
        self.cmd.setText(r["install_command"] or "Nothing missing.")

    def add_thunar(self):
        if (
            QMessageBox.question(
                self,
                "Thunar",
                'Add a "Scan with Deadbolt" custom action to '
                "~/.config/Thunar/uca.xml? Only Deadbolt's own entry is added.",
            )
            == QMessageBox.StandardButton.Yes
        ):
            try:
                self.ctx.info(f"Added to {thunar.install()}. Restart Thunar to see it.")
            except (OSError, ValueError) as e:
                self.ctx.error(f"Could not edit uca.xml: {e}")
            self.refresh()

    def save(self):
        s = json.loads(json.dumps(self.ctx.settings))
        for k, cb in self.act.items():
            s["actions"][k] = cb.currentText()
        scheds = []
        for prof, (en, cal, bat) in self.sched.items():
            if cal.text().strip():
                scheds.append(
                    {
                        "profile": prof,
                        "on_calendar": cal.text().strip(),
                        "enabled": en.isChecked(),
                        "skip_on_battery": bat.isChecked(),
                    }
                )
        s["schedules"] = scheds
        s["scan"]["custom_paths"] = self.custom.values()
        s["quarantine"]["auto_delete_days"] = self.purge.currentData()
        s["history"]["retention_days"] = self.retention.value()
        s["network"]["deny_tmp"] = self.deny_tmp.isChecked()
        sc = s["scan"]
        sc["detect_pua"] = self.pua.isChecked()
        sc["scan_archive"] = self.archive.isChecked()
        sc["alert_encrypted"] = self.encrypted.isChecked()
        sc["one_filesystem"] = self.onefs.isChecked()
        sc["max_file_mb"] = self.maxfile.value()
        sc["max_scan_mb"] = self.maxscan.value()
        sc["max_recursion"] = self.recursion.value()
        sc["max_threads"] = self.threads.value()
        s["realtime"]["max_file_mb"] = self.rtmax.value()
        self.ctx.save_settings(s)


def clean_simulator_leftovers() -> None:
    """A killed simulator cannot run its own cleanup. Remove its dummy folders."""
    for base in {os.path.expanduser("~"), os.environ.get("DEADBOLT_TEST_DIR", ""), "/srv"}:
        if not base or not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            p = os.path.join(base, name)
            if name.startswith(".deadbolt-shield-test.") and os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p, ignore_errors=True)
