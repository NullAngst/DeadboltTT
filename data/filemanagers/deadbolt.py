"""Nautilus extension: right-click "Scan with Deadbolt". Installed system-wide
to /usr/share/nautilus-python/extensions/. Needs python3-nautilus."""

import shutil
import subprocess

from gi.repository import GObject, Nautilus


class DeadboltScanExtension(GObject.GObject, Nautilus.MenuProvider):
    def _scan(self, _item, files):
        paths = [f.get_location().get_path() for f in files if f.get_location().get_path()]
        exe = shutil.which("deadbolt")
        if paths and exe:
            subprocess.Popen([exe, "--scan", *paths])  # noqa: S603 - argument vector, no shell

    def get_file_items(self, *args):
        files = args[-1]
        if not files:
            return []
        item = Nautilus.MenuItem(
            name="DeadboltScanExtension::Scan",
            label="Scan with Deadbolt",
            tip="Scan the selected files and folders for threats",
            icon="deadbolt",
        )
        item.connect("activate", self._scan, files)
        return [item]
