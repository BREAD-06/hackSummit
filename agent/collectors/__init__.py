"""Endpoint collectors — the sources of the three signals this system watches.

Each collector observes one kind of activity and emits :class:`vigil.schema.Event`
objects into the agent's buffer. All three collect **metadata only**: paths, sizes,
drive letters, session names. No file contents, no process command lines, no
network payloads.
"""

from agent.collectors.base import Collector, CollectorContext, PollingCollector
from agent.collectors.file_collector import FileCollector
from agent.collectors.logon_collector import LogonCollector
from agent.collectors.usb_collector import UsbCollector

__all__ = [
    "Collector", "CollectorContext", "PollingCollector",
    "FileCollector", "LogonCollector", "UsbCollector",
]
