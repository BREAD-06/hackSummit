"""Removable-media collector — the poster's "USB activity" signal.

Detection is by **drive-letter polling**, not by device notifications:
``GetDriveTypeW`` on each letter A-Z, looking for ``DRIVE_REMOVABLE``. That needs
no administrator rights, no ``pywin32``, and no window message loop, which is what
makes the agent a plain user-space process.

Because this collector is the only component that knows which volumes are
removable, it also answers :meth:`is_removable_path` for the file collector — that
is how a copy to a USB stick becomes a ``write_to_removable`` signal on the server.

On non-Windows hosts it falls back to ``psutil.disk_partitions()`` so the agent and
its tests still run anywhere.
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import string
import sys

from agent.collectors.base import CollectorContext, PollingCollector
from vigil.schema import DEVICE_CONNECT, DEVICE_DISCONNECT, LOG_DEVICE

log = logging.getLogger("vigil.agent.usb")

IS_WINDOWS = sys.platform == "win32"

# GetDriveTypeW return values (winbase.h)
DRIVE_UNKNOWN, DRIVE_NO_ROOT_DIR = 0, 1
DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_REMOTE, DRIVE_CDROM, DRIVE_RAMDISK = 2, 3, 4, 5, 6

DRIVE_TYPE_NAMES = {
    DRIVE_UNKNOWN: "unknown", DRIVE_NO_ROOT_DIR: "absent", DRIVE_REMOVABLE: "removable",
    DRIVE_FIXED: "fixed", DRIVE_REMOTE: "network", DRIVE_CDROM: "cdrom",
    DRIVE_RAMDISK: "ramdisk",
}

# Drive types treated as removable media for detection purposes. Optical discs are
# included because burning to one is data egress just as much as a USB copy is.
REMOVABLE_TYPES = (DRIVE_REMOVABLE, DRIVE_CDROM)


def windows_drive_type(root: str) -> int:
    """``GetDriveTypeW`` for a drive root such as ``"E:\\\\"``."""
    return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))


def scan_windows() -> dict[str, dict]:
    """Map ``"E:\\\\" -> volume info`` for every removable volume currently present."""
    found = {}
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        try:
            dtype = windows_drive_type(root)
        except OSError:
            continue
        if dtype in REMOVABLE_TYPES and os.path.exists(root):
            found[root] = {"drive": root, "drive_type": DRIVE_TYPE_NAMES.get(dtype, "removable")}
    return found


def scan_posix() -> dict[str, dict]:
    """Fallback for non-Windows hosts: removable mounts from ``psutil``."""
    import psutil

    found = {}
    for part in psutil.disk_partitions(all=False):
        opts = part.opts.lower()
        mount = part.mountpoint
        removable = (
            "removable" in opts
            or mount.startswith(("/media/", "/run/media/", "/Volumes/"))
            or (mount.startswith("/mnt/") and mount.count("/") == 2)
        )
        if removable:
            found[mount] = {"drive": mount, "drive_type": "removable",
                            "fstype": part.fstype}
    return found


def scan_removable() -> dict[str, dict]:
    return scan_windows() if IS_WINDOWS else scan_posix()


def volume_capacity(root: str) -> dict:
    """Total/free bytes for a volume, best-effort — never raises."""
    try:
        total, _used, free = shutil.disk_usage(root)
    except OSError:
        # An empty card reader or a disc-less drive answers the type probe but has
        # no filesystem to measure. The connect event still matters.
        return {}
    return {"total_bytes": int(total), "free_bytes": int(free)}


class UsbCollector(PollingCollector):
    """Emits a ``device`` Connect/Disconnect event per removable volume."""

    name = "usb"

    def __init__(self, ctx: CollectorContext, interval_s: float = 2.0,
                 scan=scan_removable):
        super().__init__(ctx, interval_s)
        self._scan = scan
        self._present: dict[str, dict] = {}
        try:
            self._present = dict(self._scan())
        except Exception as exc:      # a broken probe must not stop the agent
            self._note_error(exc)
        if self._present:
            log.info("usb: removable media already present at startup: %s",
                     ", ".join(sorted(self._present)))

    # ── shared knowledge for the file collector ──
    @property
    def removable_roots(self) -> tuple[str, ...]:
        return tuple(sorted(self._present))

    def is_removable_path(self, path: str) -> bool:
        """True when ``path`` lives on a volume this collector considers removable.

        Uses the live snapshot, so a file written to E:\\ is flagged while the
        stick is plugged in and not misattributed after it is pulled.
        """
        if not path:
            return False
        norm = os.path.abspath(path).lower()
        return any(norm.startswith(root.lower()) for root in self._present)

    # ── polling ──
    def snapshot(self) -> dict[str, dict]:
        return self._scan()

    def diff(self, previous: dict[str, dict], current: dict[str, dict]) -> None:
        self._present = dict(current)

        for root in sorted(set(current) - set(previous)):
            info = {**current[root], **volume_capacity(root)}
            log.warning("removable media connected: %s", root)
            self.emit(self.ctx.event(
                LOG_DEVICE, DEVICE_CONNECT, path=root,
                detail={**info, "removable": True},
            ))

        for root in sorted(set(previous) - set(current)):
            log.info("removable media disconnected: %s", root)
            self.emit(self.ctx.event(
                LOG_DEVICE, DEVICE_DISCONNECT, path=root,
                detail={**previous[root], "removable": True},
            ))

    @property
    def available(self) -> bool:
        try:
            self._scan()
            return True
        except Exception:
            return False

    def stats(self) -> dict:
        return {**super().stats(), "removable_present": list(self.removable_roots)}
