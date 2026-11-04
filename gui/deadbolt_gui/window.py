"""Main window, the tray icon, and the shared context every page uses."""

from __future__ import annotations

import json

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from . import config, theme, wording
from .bus import Daemon
from .dialogs import FrozenDialog, SetupWizard
from .notify import Notifier
from .pages import (
    Dashboard,
    HistoryPage,
    NetworkPage,
    ProtectionPage,
    QuarantinePage,
    ScanPage,
    SettingsPage,
    ToolsPage,
)
from .widgets import Banner, app_icon, shield_icon

PAGES = [
    ("Dashboard", "security-high"),
    ("Scan", "edit-find"),
    ("Protection", "security-medium"),
    ("Quarantine", "archive-extract"),
    ("Network", "network-wired"),
    ("Tools", "tools"),
    ("History", "view-history"),
    ("Settings", "configure"),
]


class MainWindow(QMainWindow):
    def __init__(self, app: QApplication, start_hidden: bool):
        super().__init__()
        self.app = app
        self.cfg = config.load()
        self.dark = theme.apply(app, self.cfg["theme"])
        self.daemon = Daemon(self)
        self.notifier = Notifier(self)
        self.status: dict | None = None
        self.settings: dict | None = None
        self.reqs: dict | None = None
        self.frozen_dialogs: dict[str, FrozenDialog] = {}
        self.quitting = False

        self.setWindowTitle("Deadbolt")
        self.setWindowIcon(app_icon(self.dark))
        self.resize(1100, 720)
        self.setMinimumSize(900, 600)

        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        self.down_banner = Banner()
        self.down_banner.fix.connect(self.fix)
        outer.addWidget(self.down_banner)
        body = QHBoxLayout()
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(190)
        from PyQt6.QtGui import QIcon

        for name, icon in PAGES:
            self.sidebar.addItem(QListWidgetItem(QIcon.fromTheme(icon), name))
        self.stack = QStackedWidget()
        self.pages = {
            "Dashboard": Dashboard(self),
            "Scan": ScanPage(self),
            "Protection": ProtectionPage(self),
            "Quarantine": QuarantinePage(self),
            "Network": NetworkPage(self),
            "Tools": ToolsPage(self),
            "History": HistoryPage(self),
            "Settings": SettingsPage(self),
        }
        for name, _ in PAGES:
            self.stack.addWidget(self.pages[name])
        self.pages["Dashboard"].scan_requested.connect(lambda p: self.pages["Scan"].start([], p))
        self.pages["Dashboard"].open_page.connect(self.go)
        self.sidebar.currentRowChanged.connect(self._page_changed)
        body.addWidget(self.sidebar)
        body.addWidget(self.stack, 1)
        outer.addLayout(body)
        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self._current = 0

        self.tray = QSystemTrayIcon(shield_icon("amber", dark=self.dark), self)
        self.tray.setToolTip("Deadbolt")
        self.tray.activated.connect(self._tray_click)
        self.tray.setContextMenu(self._tray_menu())
        self.tray.show()

        self.daemon.signal.connect(self.on_signal)
        self.daemon.up_changed.connect(lambda _u: self.reload())
        self.reload()
        # Low-rate safety net in case a signal is missed. Signals do the real work.
        self.timer = QTimer(self)
        self.timer.setInterval(60_000)
        self.timer.timeout.connect(self.reload)
        self.timer.start()
        if not start_hidden:
            self.show()
        self.sidebar.setCurrentRow(0)

    # ---------------- context API used by pages

    def error(self, msg: str):
        self.statusBar().showMessage(msg, 12_000)
        if self.isVisible() and "Not authorized" not in msg:
            QMessageBox.warning(self, "Deadbolt", msg)

    def info(self, msg: str):
        self.statusBar().showMessage(msg, 10_000)

    def go(self, name: str):
        idx = [n for n, _ in PAGES].index(name)
        self.sidebar.setCurrentRow(idx)
        self.show_window()

    def scan(self, paths: list[str]):
        self.pages["Scan"].start(paths, "custom")

    def autostart(self) -> bool:
        return config.autostart_enabled()

    def set_autostart(self, on: bool):
        config.set_autostart(on)

    def set_theme(self, key: str):
        self.cfg["theme"] = key
        config.save(self.cfg)
        self.dark = theme.apply(self.app, key)
        self.setWindowIcon(app_icon(self.dark))
        self.reload()
        self._current_page().refresh()

    def save_settings(self, s: dict):
        def ok(log):
            self.info("Saved." + (" " + "; ".join(log) if log else ""))
            self.reload()

        self.daemon.call("Settings", "Set", json.dumps(s), ok=ok, err=self.error)

    def fix(self, code: str):
        if code == "start-daemon":
            # polkit asks for the password; systemd does the start.
            from PyQt6.QtCore import QProcess

            QProcess.startDetached("pkexec", ["systemctl", "start", "deadboltd.service"])
        elif code == "update-signatures":
            self.daemon.call(
                "Settings", "UpdateSignatures", raw=True, ok=lambda r: self.info(str(r)), err=self.error
            )
        elif code == "enable-realtime" and self.settings:
            s = json.loads(json.dumps(self.settings))
            s["realtime"]["enabled"] = True
            self.save_settings(s)
            self.daemon.call("Settings", "Resume", err=self.error)
        elif code == "resume":
            self.daemon.call("Settings", "Resume", err=self.error)
        elif code == "requirements":
            self.go("Settings")
        elif code == "setup":
            self.run_wizard()
        elif code == "shield":
            if self.status and self.status["shield"]["frozen"]:
                self.show_frozen()
            else:
                self.go("Protection")

    def run_wizard(self):
        w = SetupWizard(self, self)
        w.finished_setup.connect(self.reload)
        w.show()

    def show_frozen(self):
        def show(v):
            for inc in v or []:
                self._frozen_dialog(inc)

        self.daemon.call("Shield", "Frozen", ok=show, err=self.error)

    # ---------------- data

    def reload(self):
        up = self.daemon.up
        self.down_banner.dark = self.dark
        if not up:
            self.down_banner.set(
                "red",
                "The Deadbolt service is not running. Nothing is protected right now.",
                "start-daemon",
                "Start",
            )
            self.down_banner.show()
            self.status = None
            self.update_tray()
            self.pages["Dashboard"].refresh()
            return
        self.down_banner.hide()

        def got_status(st):
            first = self.status is None
            self.status = st
            self.update_tray()
            # Only the dashboard refreshes on status; other pages refresh when shown,
            # so a page behind a password prompt never asks on its own.
            self.pages["Dashboard"].refresh()
            if first and not st.get("setup_done"):
                self.run_wizard()
            if st["shield"]["frozen"]:
                self.show_frozen()

        self.daemon.call("Status", "GetStatus", ok=got_status, err=self.error)
        self.daemon.call("Settings", "Get", ok=self._got_settings, err=lambda _m: None)
        self.daemon.call("Status", "Requirements", False, ok=self._got_reqs, err=lambda _m: None)

    def _got_settings(self, s):
        self.settings = s
        if self._current in (2, 7):
            self._current_page().refresh()

    def _got_reqs(self, r):
        self.reqs = r
        if self._current in (5, 7):
            self._current_page().refresh()

    def _current_page(self):
        return self.pages[PAGES[self._current][0]]

    def _page_changed(self, idx: int):
        if idx < 0:
            return
        self._current_page().hidden()
        self._current = idx
        self.stack.setCurrentIndex(idx)
        self._current_page().shown()

    # ---------------- signals

    def on_signal(self, iface: str, member: str, p):
        if member == "StatusChanged" and isinstance(p, dict):
            self.status = p
            self.update_tray()
            self.pages["Dashboard"].refresh()
        elif member == "Detection" and isinstance(p, dict):
            if p.get("source") in ("realtime", "scheduled"):
                self._notify_detection(p)
        elif member == "Incident" and isinstance(p, dict):
            self.notifier.send(
                "An app was frozen",
                wording.incident(p),
                urgency="critical",
                actions=[("open", "Open")],
                on_action=lambda _a, inc=p: self._frozen_dialog(inc),
            )
            self._frozen_dialog(p)
        elif member == "Decided" and isinstance(p, dict):
            d = self.frozen_dialogs.pop(p.get("id", ""), None)
            if d:
                d.close()
        elif member == "ProtectionChanged" and isinstance(p, dict):
            if p.get("note"):
                text = p["note"]
            elif p.get("on") is False:
                what = {"realtime": "Real-time protection", "shield": "The ransomware shield"}.get(
                    p.get("what", ""), "Protection"
                )
                text = f"{what} was turned off by {p.get('by', 'someone')}."
            else:
                text = f"Protection is back on ({p.get('by', '')})."
            self.notifier.send("Deadbolt", text, urgency="normal" if p.get("on", True) else "critical")
            self.reload()
        elif member == "UsbMounted" and isinstance(p, dict):
            mp = p.get("mount", "")
            self.notifier.send(
                "Removable drive",
                f"{mp} was mounted. Scan it?",
                actions=[("scan", "Scan"), ("ignore", "Ignore")],
                on_action=lambda a, m=mp: a == "scan" and self.scan([m]),
            )

    def _notify_detection(self, det: dict):
        actions = [("open", "Open")]
        if det.get("action") == "reported":
            actions.insert(0, ("quarantine", "Quarantine"))
            actions.insert(1, ("ignore", "Ignore"))

        def on(a, d=det):
            if a == "open":
                self.go("Quarantine" if d.get("action") == "quarantined" else "History")
            elif a == "quarantine":
                self.daemon.call("Scan", "Act", "", d["path"], "quarantine", err=self.error)

        self.notifier.send(
            "Threat found", wording.detection(det), urgency="critical", actions=actions, on_action=on
        )

    def _frozen_dialog(self, inc: dict):
        d = self.frozen_dialogs.get(inc["id"])
        if d is None:
            d = FrozenDialog(self, inc, self)
            d.decided.connect(lambda i: self.frozen_dialogs.pop(i, None))
            self.frozen_dialogs[inc["id"]] = d
        d.show()
        d.raise_()
        d.activateWindow()

    # ---------------- tray

    def _tray_menu(self) -> QMenu:
        m = QMenu()
        m.addAction("Open Deadbolt", self.show_window)
        m.addAction("Quick scan", lambda: self.pages["Scan"].start([], "quick"))
        pause = m.addMenu("Pause protection")
        for label, mins in [("15 minutes", 15), ("1 hour", 60), ("Until restart", 0)]:
            a = QAction(label, pause)
            a.triggered.connect(
                lambda _c=False, n=mins: self.daemon.call("Settings", "Pause", n, err=self.error)
            )
            pause.addAction(a)
        m.addAction("Resume protection", lambda: self.daemon.call("Settings", "Resume", err=self.error))
        m.addAction("Update signatures", lambda: self.fix("update-signatures"))
        m.addSeparator()
        m.addAction("Quit (protection keeps running)", self.quit)
        return m

    def update_tray(self):
        level, text, _ = wording.banner(self.status, self.daemon.up)
        self.tray.setIcon(shield_icon(level, dark=self.dark))
        self.tray.setToolTip(f"Deadbolt: {text}")

    def _tray_click(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self.show_window()

    def show_window(self):
        self.show()
        self.setWindowState(self.windowState() & ~self.windowState().WindowMinimized)
        self.raise_()
        self.activateWindow()

    def closeEvent(self, e):
        if self.quitting or not QSystemTrayIcon.isSystemTrayAvailable():
            e.accept()
            return
        e.ignore()
        self.hide()
        if not self.cfg.get("tray_hint_shown"):
            self.notifier.send(
                "Deadbolt is still running",
                "The window is closed, protection keeps running. Open it again from the tray.",
            )
            self.cfg["tray_hint_shown"] = True
            config.save(self.cfg)

    def quit(self):
        self.quitting = True
        self.tray.hide()
        self.app.quit()
