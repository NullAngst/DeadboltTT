"""Talking to deadboltd over the D-Bus system bus with QtDBus.

Every call is asynchronous so a polkit password prompt never freezes the
window. Replies are JSON strings; this module hands back Python objects.
The GUI never does privileged work itself.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot
from PyQt6.QtDBus import (
    QDBusConnection,
    QDBusInterface,
    QDBusMessage,
    QDBusPendingCall,
    QDBusPendingCallWatcher,
    QDBusServiceWatcher,
)

SERVICE = "io.github.nullangst.Deadbolt1"
PATH = "/io/github/nullangst/Deadbolt1"
PREFIX = "io.github.nullangst.Deadbolt1"
# Long enough for someone to type a password at a polkit prompt.
TIMEOUT_MS = 10 * 60 * 1000

SIGNALS = [
    ("Status", "StatusChanged"),
    ("Status", "ProtectionChanged"),
    ("Status", "UsbMounted"),
    ("Scan", "Progress"),
    ("Scan", "Detection"),
    ("Scan", "Finished"),
    ("Shield", "Incident"),
    ("Shield", "Decided"),
    ("Settings", "ToolFinished"),
]

Ok = Callable[[object], None]
Err = Callable[[str], None]


class Daemon(QObject):
    """One object per GUI. Emits `signal(iface, member, payload)` for every daemon signal."""

    signal = pyqtSignal(str, str, object)
    up_changed = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.bus = QDBusConnection.systemBus()
        self._ifaces: dict[str, QDBusInterface] = {}
        self._watchers: set[QDBusPendingCallWatcher] = set()
        self.up = self._is_up()
        self._svc = QDBusServiceWatcher(
            SERVICE,
            self.bus,
            QDBusServiceWatcher.WatchModeFlag.WatchForRegistration
            | QDBusServiceWatcher.WatchModeFlag.WatchForUnregistration,
            self,
        )
        self._svc.serviceRegistered.connect(lambda _n: self._set_up(True))
        self._svc.serviceUnregistered.connect(lambda _n: self._set_up(False))
        for iface, member in SIGNALS:
            self.bus.connect(SERVICE, PATH, f"{PREFIX}.{iface}", member, self._on_signal)

    def _is_up(self) -> bool:
        reply = self.bus.interface().isServiceRegistered(SERVICE)
        return bool(reply.value()) if reply.isValid() else False

    def _set_up(self, up: bool):
        if up != self.up:
            self.up = up
            self.up_changed.emit(up)

    @pyqtSlot(QDBusMessage)
    def _on_signal(self, msg: QDBusMessage):
        iface = msg.interface().rsplit(".", 1)[-1]
        args = msg.arguments()
        payload: object = None
        if args:
            try:
                payload = json.loads(args[0])
            except (TypeError, ValueError):
                payload = args[0]
        self.signal.emit(iface, msg.member(), payload)

    def _iface(self, name: str) -> QDBusInterface:
        if name not in self._ifaces:
            i = QDBusInterface(SERVICE, PATH, f"{PREFIX}.{name}", self.bus, self)
            i.setTimeout(TIMEOUT_MS)
            self._ifaces[name] = i
        return self._ifaces[name]

    def call(
        self, iface: str, method: str, *args, ok: Ok | None = None, err: Err | None = None, raw: bool = False
    ):
        """Async call. ok(result) with parsed JSON unless raw; err(message) on failure."""
        pending: QDBusPendingCall = self._iface(iface).asyncCall(method, *args)
        w = QDBusPendingCallWatcher(pending, self)
        self._watchers.add(w)

        def done(watcher: QDBusPendingCallWatcher):
            self._watchers.discard(watcher)
            reply = watcher.reply()
            watcher.deleteLater()
            if reply.type() == QDBusMessage.MessageType.ErrorMessage:
                if err:
                    err(friendly_error(reply.errorName(), reply.errorMessage()))
                return
            vals = reply.arguments()
            value = vals[0] if vals else None
            if not raw and isinstance(value, str):
                with contextlib.suppress(ValueError):
                    value = json.loads(value)
            if ok:
                ok(value)

        w.finished.connect(done)


def friendly_error(name: str, message: str) -> str:
    if name.endswith("AccessDenied") or name.endswith("AuthFailed"):
        return "Not authorized. The password prompt was cancelled or the password was wrong."
    if name.endswith("ServiceUnknown") or name.endswith("NameHasNoOwner"):
        return "The Deadbolt service is not running."
    if name.endswith("NoReply"):
        return "The Deadbolt service did not answer in time."
    return message or name
