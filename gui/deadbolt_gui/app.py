"""Entry point: `deadbolt`, `deadbolt --tray`, `deadbolt --scan <paths>`.

--scan hands the paths to the running GUI (or starts it) so the scan shows
in the normal window. File manager menus call it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from PyQt6.QtCore import QByteArray
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication

from . import __version__


def server_name() -> str:
    return f"deadbolt-gui-{os.getuid()}"


def hand_off(paths: list[str], show: bool) -> bool:
    """Send paths to an already running GUI. True if one answered."""
    s = QLocalSocket()
    s.connectToServer(server_name())
    if not s.waitForConnected(500):
        return False
    s.write(QByteArray(json.dumps({"scan": paths, "show": show}).encode()))
    s.flush()
    s.waitForBytesWritten(1000)
    s.disconnectFromServer()
    return True


def main() -> None:
    p = argparse.ArgumentParser(prog="deadbolt", description="Deadbolt: Track and Terminate")
    p.add_argument("--tray", action="store_true", help="start hidden in the system tray")
    p.add_argument("--scan", nargs="+", metavar="PATH", help="scan these files or folders")
    p.add_argument("--version", action="version", version=f"deadbolt {__version__}")
    args, qt_args = p.parse_known_args()

    if os.geteuid() == 0:
        print(
            "deadbolt: the GUI is an unprivileged client and refuses to run as root. Run it as yourself; "
            "anything privileged goes through the daemon and polkit.",
            file=sys.stderr,
        )
        sys.exit(2)

    app = QApplication([sys.argv[0], *qt_args])
    app.setApplicationName("Deadbolt")
    app.setDesktopFileName("io.github.nullangst.Deadbolt")
    app.setQuitOnLastWindowClosed(False)

    paths = [os.path.abspath(x) for x in (args.scan or [])]
    if hand_off(paths, not args.tray):
        return

    from .window import MainWindow

    win = MainWindow(app, start_hidden=args.tray)
    QLocalServer.removeServer(server_name())
    server = QLocalServer(app)
    server.listen(server_name())

    def incoming():
        conn = server.nextPendingConnection()
        if conn is None:
            return

        def read():
            try:
                msg = json.loads(bytes(conn.readAll()).decode() or "{}")
            except ValueError:
                return
            if msg.get("scan"):
                win.scan(msg["scan"])
            if msg.get("show"):
                win.show_window()

        conn.readyRead.connect(read)
        conn.disconnected.connect(conn.deleteLater)

    server.newConnection.connect(incoming)
    if paths:
        win.scan(paths)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
