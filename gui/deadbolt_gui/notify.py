"""Desktop notifications through org.freedesktop.Notifications directly, so
they can carry action buttons (Quarantine, Ignore, Open)."""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QMetaType, QObject, pyqtSlot
from PyQt6.QtDBus import QDBusArgument, QDBusConnection, QDBusInterface, QDBusMessage

SERVICE = "org.freedesktop.Notifications"
PATH = "/org/freedesktop/Notifications"
IFACE = "org.freedesktop.Notifications"

URGENCY = {"low": 0, "normal": 1, "critical": 2}


class Notifier(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bus = QDBusConnection.sessionBus()
        self.iface = QDBusInterface(SERVICE, PATH, IFACE, self.bus, self)
        self._handlers: dict[int, Callable[[str], None]] = {}
        self.bus.connect(SERVICE, PATH, IFACE, "ActionInvoked", self._on_action)
        self.bus.connect(SERVICE, PATH, IFACE, "NotificationClosed", self._on_closed)

    def send(
        self,
        title: str,
        body: str,
        *,
        urgency: str = "normal",
        actions: list[tuple[str, str]] | None = None,
        on_action: Callable[[str], None] | None = None,
        icon: str = "deadbolt",
    ) -> None:
        flat: list[str] = []
        for key, label in actions or []:
            flat += [key, label]
        acts = QDBusArgument()
        acts.add(flat, QMetaType.Type.QStringList.value)
        hints = {
            "urgency": QDBusArgument(URGENCY.get(urgency, 1), QMetaType.Type.UChar.value),
            "desktop-entry": "io.github.nullangst.Deadbolt",
        }
        replaces = QDBusArgument(0, QMetaType.Type.UInt.value)
        timeout = 0 if urgency == "critical" else -1
        msg = self.iface.call("Notify", "Deadbolt", replaces, icon, title, body, acts, hints, timeout)
        if msg.type() == QDBusMessage.MessageType.ReplyMessage and msg.arguments() and on_action:
            self._handlers[int(msg.arguments()[0])] = on_action

    @pyqtSlot(QDBusMessage)
    def _on_action(self, msg: QDBusMessage):
        args = msg.arguments()
        if len(args) >= 2:
            h = self._handlers.pop(int(args[0]), None)
            if h:
                h(str(args[1]))

    @pyqtSlot(QDBusMessage)
    def _on_closed(self, msg: QDBusMessage):
        args = msg.arguments()
        if args:
            self._handlers.pop(int(args[0]), None)
