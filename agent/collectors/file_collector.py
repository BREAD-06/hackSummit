"""File-activity collector — the poster's "file access" signal.

Built on ``watchdog``, which uses the OS's native change notifications
(``ReadDirectoryChangesW`` on Windows) rather than polling, so watching a large
tree costs almost nothing.

**Metadata only.** The collector records the path, the action, the extension and
the size. It never opens a file or reads a byte of content. That is a deliberate
design boundary, not an omission — insider-threat detection here is about *volume
and pattern of movement*, and reading user documents would make the agent itself a
data-exfiltration risk.

Two pieces of realism that matter for signal quality:

* **Debouncing.** Copying one file in, or a single "save" in Word, produces a
  ``created`` notification followed by dozens of ``modified`` ones for the same
  path. Without collapsing them, ``file_count`` would measure notification chatter
  instead of user behaviour, and the model would learn nonsense. Writes to one path
  inside ``debounce_s`` become a single event, keeping the *first* action — so one
  copied file is one ``create``, not a ``create`` plus a run of ``modify``.
* **Late sizing.** During a copy the file grows, so the size at first notification
  is meaningless — often zero, because Windows announces the empty file before any
  data lands. The debounce flush re-reads the size at the end, which is what makes
  a 2 GB copy report 2 GB.

``delete`` and ``move`` are not debounced: they are immediately meaningful, and
they discard any write still pending for that path.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from watchdog.events import (
    EVENT_TYPE_CREATED,
    EVENT_TYPE_DELETED,
    EVENT_TYPE_MODIFIED,
    EVENT_TYPE_MOVED,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from agent.collectors.base import Collector, CollectorContext
from vigil.schema import LOG_FILE

log = logging.getLogger("vigil.agent.file")

# watchdog event type -> the action name in vigil.schema.FILE_ACTIONS
ACTION_MAP = {
    EVENT_TYPE_CREATED: "create",
    EVENT_TYPE_MODIFIED: "modify",
    EVENT_TYPE_DELETED: "delete",
    EVENT_TYPE_MOVED: "move",
}

# Actions that describe *writing* to a path, and so get debounced together. Copying
# one file in emits ADDED then a run of MODIFIEDs; collapsing them into a single
# event keyed by path is what makes `file_count` count files instead of
# notifications, and lets the size be read once the write has finished.
WRITE_ACTIONS = ("create", "modify")


def file_size(path: str) -> int:
    """Size in bytes, or 0 if the file is gone or unreadable. Never raises."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


class _Handler(FileSystemEventHandler):
    """Translates watchdog notifications into buffered agent events."""

    def __init__(self, collector: "FileCollector"):
        self._collector = collector

    def on_any_event(self, event) -> None:
        if event.is_directory:
            return
        # Anything not in ACTION_MAP (opened / closed / closed_no_write) is dropped:
        # those add no information the create/modify pair does not already carry.
        action = ACTION_MAP.get(event.event_type)
        if action is None:
            return
        try:
            self._collector.handle(action, event)
        except Exception as exc:
            self._collector._note_error(exc)


class FileCollector(Collector):
    """Watches directories for file create/modify/delete/move."""

    name = "file"

    def __init__(self, ctx: CollectorContext, watch_dirs: list[str],
                 exclude_patterns: list[str] | None = None,
                 debounce_s: float = 1.0):
        super().__init__(ctx)
        self.watch_dirs = [os.path.abspath(d) for d in watch_dirs]
        self.excludes = [p.lower() for p in (exclude_patterns or [])]
        self.debounce_s = max(0.0, float(debounce_s))
        self.skipped = 0

        self._observer = None
        self._handler = _Handler(self)
        self._watches: dict[str, object] = {}
        self._lock = threading.RLock()
        # path -> (action, first_seen, hits)
        self._pending: dict[str, tuple[str, float, int]] = {}
        self._stop = threading.Event()
        self._flusher: threading.Thread | None = None

    # ── filtering ──
    def excluded(self, path: str) -> bool:
        low = path.lower()
        return any(pattern in low for pattern in self.excludes)

    # ── lifecycle ──
    def start(self) -> None:
        if self._observer is not None:
            return
        self._observer = Observer()
        for directory in self.watch_dirs:
            self.watch(directory)
        self._observer.start()

        if self.debounce_s > 0:
            self._stop.clear()
            self._flusher = threading.Thread(target=self._flush_loop, name="file-debounce",
                                             daemon=True)
            self._flusher.start()
        log.info("file collector watching %d director%s",
                 len(self._watches), "y" if len(self._watches) == 1 else "ies")

    def watch(self, directory: str) -> bool:
        """Add a directory to the watch set. Safe to call while running."""
        directory = os.path.abspath(directory)
        with self._lock:
            if directory in self._watches or self._observer is None:
                return False
            if not os.path.isdir(directory):
                log.warning("file collector: not a directory, skipping: %s", directory)
                return False
            try:
                self._watches[directory] = self._observer.schedule(
                    self._handler, directory, recursive=True
                )
            except OSError as exc:
                # Permission denied on a system folder, or a stick pulled mid-schedule.
                self._note_error(exc)
                return False
        log.info("file collector: watching %s", directory)
        return True

    def unwatch(self, directory: str) -> bool:
        """Stop watching a directory (used when removable media is removed)."""
        directory = os.path.abspath(directory)
        with self._lock:
            handle = self._watches.pop(directory, None)
            if handle is None or self._observer is None:
                return False
            try:
                self._observer.unschedule(handle)
            except (KeyError, RuntimeError):
                pass       # already gone — unmounting can race the observer
        log.info("file collector: stopped watching %s", directory)
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._flusher is not None:
            self._flusher.join(timeout=2.0)
            self._flusher = None
        observer, self._observer = self._observer, None
        if observer is not None:
            observer.stop()
            observer.join(timeout=5.0)
        self._watches.clear()
        self.flush_pending(force=True)

    # ── event handling ──
    def handle(self, action: str, event) -> None:
        path = event.dest_path if action == "move" and getattr(event, "dest_path", "") \
            else event.src_path
        if not path or self.excluded(path):
            self.skipped += 1
            return

        if action in WRITE_ACTIONS and self.debounce_s > 0:
            with self._lock:
                pending = self._pending.get(path)
                if pending is None:
                    self._pending[path] = (action, time.monotonic(), 1)
                else:
                    # The *first* action wins: a create followed by writes is still a
                    # create, and reporting it as a modify would lose that fact.
                    first_action, first_seen, hits = pending
                    self._pending[path] = (first_action, first_seen, hits + 1)
            return

        # Delete and move are immediately meaningful (especially a move onto
        # removable media) and end the path's life, so they bypass debouncing and
        # discard any write still pending for it — emitting a create for a file that
        # has since been renamed or deleted would only mislead an analyst.
        with self._lock:
            self._pending.pop(path, None)
            if action == "move":
                self._pending.pop(event.src_path, None)

        detail = {"ext": os.path.splitext(path)[1].lower().lstrip(".")}
        if action == "move":
            detail["src"] = event.src_path
        if self.ctx.is_removable(path):
            detail["removable"] = True
        self.emit(self.ctx.event(LOG_FILE, action, path=path,
                                 size_bytes=file_size(path), detail=detail))

    # ── debounce flushing ──
    def _flush_loop(self) -> None:
        while not self._stop.wait(min(self.debounce_s, 1.0)):
            try:
                self.flush_pending()
            except Exception as exc:
                self._note_error(exc)

    def flush_pending(self, force: bool = False) -> int:
        """Emit one event per path whose write burst has gone quiet."""
        now = time.monotonic()
        with self._lock:
            ready = [
                (path, action, hits)
                for path, (action, first_seen, hits) in self._pending.items()
                if force or (now - first_seen) >= self.debounce_s
            ]
            for path, _action, _hits in ready:
                self._pending.pop(path, None)

        for path, action, hits in ready:
            detail = {"ext": os.path.splitext(path)[1].lower().lstrip(".")}
            if hits > 1:
                # Kept so an analyst can tell one big write from a chatty editor.
                detail["writes_coalesced"] = hits
            if self.ctx.is_removable(path):
                detail["removable"] = True
            # Size is read now, not when the first notification arrived, so a copy
            # in progress reports its finished size.
            self.emit(self.ctx.event(LOG_FILE, action, path=path,
                                     size_bytes=file_size(path), detail=detail))
        return len(ready)

    # ── introspection ──
    @property
    def watching(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._watches))

    def stats(self) -> dict:
        return {**super().stats(), "watching": list(self.watching),
                "skipped_excluded": self.skipped, "pending": len(self._pending)}
