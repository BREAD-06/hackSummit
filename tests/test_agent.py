"""Endpoint-agent tests — buffer, collectors, transport, and the flush loop.

The collectors are driven through injected ``scan`` functions rather than real
hardware, so "a USB stick was plugged in" is expressible on a CI box with no USB
stick. The file collector is the exception: it runs a real ``watchdog`` observer
over a temp directory, because debouncing and late sizing are exactly the parts
that a fake would fail to prove.

The transport is exercised against the real FastAPI app over ``TestClient`` — a
subclass of ``httpx.Client``, so it drops straight into ``Transport``. Enrollment,
the ML-KEM handshake, sealed delivery, and recovery from a lost server session are
all end-to-end.
"""

from __future__ import annotations

import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from agent.buffer import EventBuffer
from agent.collectors.base import CollectorContext
from agent.collectors.file_collector import FileCollector
from agent.collectors.logon_collector import LogonCollector
from agent.collectors.usb_collector import (
    DRIVE_REMOVABLE,
    REMOVABLE_TYPES,
    UsbCollector,
    volume_capacity,
)
from agent.config import DEFAULT_EXCLUDES, AgentConfig
from agent.keygen import generate as agent_generate
from agent.keygen import keys_exist, load_keys
from agent.main import EndpointAgent
from agent.transport import FingerprintMismatch, Transport, TransportError
from server.config import ServerConfig
from server.db.sqlite_store import SQLiteStorage
from server.keygen import generate as server_generate
from server.main import create_app
from server.ml.train import train
from vigil.schema import DEVICE_CONNECT, DEVICE_DISCONNECT, LOG_DEVICE, LOG_FILE, LOG_LOGON

HOST = "WKS-AGENT-TEST"

# The production defaults exclude AppData, where pytest's tmp_path lives on Windows.
TEST_EXCLUDES = ["\\__pycache__\\", "/__pycache__/", ".partial", ".crdownload"]


# ── helpers ───────────────────────────────────────────────────────────────────
class Sink:
    """Stands in for the buffer when a test only wants to see what was emitted."""

    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)

    def actions(self):
        return [e.action for e in self.events]

    def of_type(self, log_type):
        return [e for e in self.events if e.log_type == log_type]


def make_ctx(sink=None, is_removable=None) -> CollectorContext:
    return CollectorContext(
        agent_id="AGENT-TEST", host=HOST, user="tester",
        emit=sink or Sink(),
        is_removable=is_removable or (lambda _p: False),
    )


def wait_for(predicate, timeout=6.0, interval=0.05) -> bool:
    """Poll until ``predicate`` is true. Filesystem notifications are asynchronous."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def make_event(ctx, action="create", path="C:/tmp/a.txt", size=10):
    return ctx.event(LOG_FILE, action, path=path, size_bytes=size)


# ── buffer ────────────────────────────────────────────────────────────────────
def test_buffer_drains_oldest_first():
    ctx = make_ctx()
    buf = EventBuffer(100)
    for i in range(5):
        buf.add(make_event(ctx, path=f"f{i}"))
    drained = buf.drain(3)
    assert [e.path for e in drained] == ["f0", "f1", "f2"]
    assert len(buf) == 2


def test_buffer_drops_the_oldest_events_when_full():
    ctx = make_ctx()
    buf = EventBuffer(3)
    for i in range(6):
        buf.add(make_event(ctx, path=f"f{i}"))
    assert len(buf) == 3
    assert buf.dropped == 3
    # The three most recent survive: a gap in old history beats an unbounded agent.
    assert [e.path for e in buf.drain(10)] == ["f3", "f4", "f5"]
    assert buf.stats()["accepted"] == 6


def test_requeue_restores_order_at_the_front():
    ctx = make_ctx()
    buf = EventBuffer(100)
    failed = [make_event(ctx, path=f"old{i}") for i in range(3)]
    buf.add(make_event(ctx, path="new"))
    buf.requeue(failed)
    assert [e.path for e in buf.drain(10)] == ["old0", "old1", "old2", "new"]


def test_requeue_of_nothing_is_a_no_op():
    buf = EventBuffer(10)
    buf.requeue([])
    assert len(buf) == 0


# ── USB collector ─────────────────────────────────────────────────────────────
def test_usb_collector_reports_connect_and_disconnect():
    sink = Sink()
    state = {"drives": {}}
    usb = UsbCollector(make_ctx(sink), interval_s=0.2, scan=lambda: dict(state["drives"]))
    assert usb.removable_roots == ()

    state["drives"] = {"E:\\": {"drive": "E:\\", "drive_type": "removable"}}
    usb.diff({}, usb.snapshot())
    assert sink.actions() == [DEVICE_CONNECT]
    assert sink.events[0].log_type == LOG_DEVICE
    assert sink.events[0].detail["removable"] is True
    assert usb.removable_roots == ("E:\\",)

    previous = usb.snapshot()
    state["drives"] = {}
    usb.diff(previous, usb.snapshot())
    assert sink.actions() == [DEVICE_CONNECT, DEVICE_DISCONNECT]
    assert usb.removable_roots == ()


def test_usb_collector_ignores_media_present_at_startup():
    """A stick already plugged in is pre-existing state, not a connect event."""
    sink = Sink()
    usb = UsbCollector(make_ctx(sink), interval_s=0.2,
                       scan=lambda: {"F:\\": {"drive": "F:\\", "drive_type": "removable"}})
    assert usb.removable_roots == ("F:\\",)
    assert sink.events == []


def test_is_removable_path_tracks_the_live_snapshot(tmp_path):
    """The answer must follow the stick: flagged while mounted, not after removal."""
    root = str(tmp_path) + os.sep
    state = {"drives": {root: {"drive": root, "drive_type": "removable"}}}
    usb = UsbCollector(make_ctx(), interval_s=0.2, scan=lambda: dict(state["drives"]))

    inside = str(tmp_path / "secret.xlsx")
    assert usb.is_removable_path(inside) is True
    assert usb.is_removable_path("") is False

    state["drives"] = {}
    usb.diff(usb._present, usb.snapshot())
    assert usb.is_removable_path(inside) is False


def test_optical_drives_count_as_removable():
    """Burning to a disc is egress too, so DRIVE_CDROM is in the removable set."""
    from agent.collectors.usb_collector import DRIVE_CDROM, DRIVE_FIXED

    assert DRIVE_REMOVABLE in REMOVABLE_TYPES
    assert DRIVE_CDROM in REMOVABLE_TYPES
    assert DRIVE_FIXED not in REMOVABLE_TYPES


def test_volume_capacity_never_raises_on_a_missing_volume():
    assert volume_capacity("Q:\\does-not-exist") == {}
    assert set(volume_capacity(os.getcwd())) == {"total_bytes", "free_bytes"}


def test_a_broken_probe_does_not_stop_the_collector():
    def exploding_scan():
        raise OSError("device not ready")

    usb = UsbCollector(make_ctx(), interval_s=0.2, scan=exploding_scan)
    assert usb.removable_roots == ()
    assert usb.available is False
    assert usb.stats()["errors"] == 1


# ── logon collector ───────────────────────────────────────────────────────────
def _session(user, terminal="console", started=1_700_000_000.0):
    return {(user, terminal, round(started)): {
        "user": user, "terminal": terminal, "remote_host": "",
        "started_at": "2023-11-14T22:13:20+00:00", "pid": None,
    }}


def test_logon_collector_reports_sign_in_and_sign_out():
    sink = Sink()
    state = {"sessions": {}}
    logon = LogonCollector(make_ctx(sink), interval_s=0.2,
                           scan=lambda: dict(state["sessions"]))
    assert logon.active_users == ()

    state["sessions"] = _session("alice")
    logon.diff({}, logon.snapshot())
    assert sink.actions() == ["Logon"]
    assert sink.events[0].log_type == LOG_LOGON
    assert sink.events[0].user == "alice"
    assert logon.active_users == ("alice",)

    previous = dict(state["sessions"])
    state["sessions"] = {}
    logon.diff(previous, logon.snapshot())
    assert sink.actions() == ["Logon", "Logoff"]


def test_a_re_logon_on_the_same_terminal_is_two_sessions():
    """The start time is part of the session key, so sign-out/sign-in is not a no-op."""
    sink = Sink()
    first = _session("bob", started=1_700_000_000.0)
    second = _session("bob", started=1_700_009_999.0)
    logon = LogonCollector(make_ctx(sink), interval_s=0.2, scan=lambda: first)
    logon.diff(first, second)
    assert sorted(sink.actions()) == ["Logoff", "Logon"]


def test_logon_collector_ignores_the_session_that_started_the_agent():
    sink = Sink()
    logon = LogonCollector(make_ctx(sink), interval_s=0.2, scan=lambda: _session("carol"))
    assert logon.active_users == ("carol",)
    assert sink.events == []


# ── file collector ────────────────────────────────────────────────────────────
@pytest.fixture
def watched(tmp_path):
    """A started FileCollector over a temp directory, with its emitted events.

    Note the narrowed exclude list: pytest's ``tmp_path`` lives under
    ``AppData\\Local\\Temp`` on Windows, which the production defaults filter out
    (rightly — it is pure churn). ``DEFAULT_EXCLUDES`` is pinned separately below.
    """
    sink = Sink()
    collector = FileCollector(make_ctx(sink), watch_dirs=[str(tmp_path)],
                             exclude_patterns=TEST_EXCLUDES, debounce_s=0.3)
    collector.start()
    try:
        yield collector, sink, tmp_path
    finally:
        collector.stop()


def test_the_default_excludes_filter_appdata_churn_and_editor_temp_files():
    collector = FileCollector(make_ctx(), watch_dirs=[], exclude_patterns=DEFAULT_EXCLUDES)
    assert collector.excluded(r"C:\Users\alice\AppData\Local\Temp\x.dat") is True
    assert collector.excluded(r"C:\proj\repo\.git\index") is True
    assert collector.excluded(r"C:\Users\alice\Documents\~$budget.xlsx") is True
    assert collector.excluded(r"C:\Users\alice\Documents\budget.xlsx") is False


def test_a_copied_file_is_one_event_carrying_its_finished_size(watched):
    """Windows announces the empty file first, so an eager size read reports 0."""
    collector, sink, tmp_path = watched
    target = tmp_path / "report.xlsx"
    target.write_bytes(b"x" * 4096)

    assert wait_for(lambda: any(e.size_bytes == 4096 for e in sink.events)), \
        f"never saw the finished size, got {[(e.action, e.size_bytes) for e in sink.events]}"
    collector.flush_pending(force=True)

    events = [e for e in sink.of_type(LOG_FILE) if e.path.endswith("report.xlsx")]
    assert len(events) == 1, f"one copied file became {len(events)} events"
    assert events[0].action == "create"          # the first action wins over later writes
    assert events[0].size_bytes == 4096
    assert events[0].detail["ext"] == "xlsx"


def test_a_deleted_file_does_not_also_report_a_stale_create(watched):
    """A create still sitting in the debounce window is dropped when the file goes."""
    collector, sink, tmp_path = watched
    target = tmp_path / "transient.tmp2"
    target.write_bytes(b"y" * 128)
    target.unlink()

    assert wait_for(lambda: any(e.action == "delete" for e in sink.events)), \
        f"no delete event, got {sink.actions()}"
    collector.flush_pending(force=True)
    actions = [e.action for e in sink.events if e.path.endswith("transient.tmp2")]
    assert "create" not in actions


def test_repeated_writes_collapse_to_one_event_with_the_final_size(watched):
    """One save in an editor is dozens of notifications; the model must see one event."""
    collector, sink, tmp_path = watched
    target = tmp_path / "growing.bin"
    target.write_bytes(b"a")
    assert wait_for(lambda: sink.events)
    sink.events.clear()

    with open(target, "ab") as fh:
        for _ in range(30):
            fh.write(b"b" * 1024)
            fh.flush()
    time.sleep(0.5)
    collector.flush_pending(force=True)

    modifies = [e for e in sink.events if e.path.endswith("growing.bin")
                and e.action == "modify"]
    assert modifies, f"no modify event observed, got {sink.actions()}"
    assert len(modifies) <= 2, f"debouncing failed: {len(modifies)} modify events"
    # Late sizing: the size is read at flush, so a copy in progress reports its
    # finished size rather than the byte count at the first notification.
    assert modifies[-1].size_bytes == os.path.getsize(target)


def test_excluded_paths_are_never_emitted(watched):
    collector, sink, tmp_path = watched
    noisy = tmp_path / "__pycache__"
    noisy.mkdir()
    (noisy / "mod.cpython-313.pyc").write_bytes(b"junk")
    (tmp_path / "real.docx").write_bytes(b"z")

    assert wait_for(lambda: any(e.path.endswith("real.docx") for e in sink.events))
    collector.flush_pending(force=True)
    assert not [e for e in sink.events if "__pycache__" in e.path]
    assert collector.skipped >= 1


def test_a_move_is_reported_immediately_with_its_source(watched):
    collector, sink, tmp_path = watched
    src = tmp_path / "draft.docx"
    src.write_bytes(b"q" * 32)
    assert wait_for(lambda: sink.events)
    sink.events.clear()

    dest = tmp_path / "final.docx"
    src.rename(dest)
    assert wait_for(lambda: any(e.action == "move" for e in sink.events)), \
        f"no move event, got {sink.actions()}"
    move = next(e for e in sink.events if e.action == "move")
    assert move.path.endswith("final.docx")
    assert move.detail["src"].endswith("draft.docx")


def test_writes_to_removable_media_are_flagged(tmp_path):
    """This flag is what becomes the server's write_to_removable exfiltration signal."""
    sink = Sink()
    stick = tmp_path / "stick"
    stick.mkdir()
    collector = FileCollector(
        make_ctx(sink, is_removable=lambda p: "stick" in p.lower()),
        watch_dirs=[str(tmp_path)], debounce_s=0.2,
    )
    collector.start()
    try:
        (stick / "customers.csv").write_bytes(b"," * 2048)
        assert wait_for(lambda: any("customers.csv" in e.path for e in sink.events))
        collector.flush_pending(force=True)
        flagged = [e for e in sink.events if "customers.csv" in e.path]
        assert flagged and all(e.detail.get("removable") for e in flagged)
    finally:
        collector.stop()


def test_directories_can_be_watched_and_unwatched_while_running(watched):
    collector, _sink, tmp_path = watched
    extra = tmp_path.parent / "hot-plugged"
    extra.mkdir()

    assert collector.watch(str(extra)) is True
    assert str(extra) in collector.watching
    assert collector.watch(str(extra)) is False        # idempotent
    assert collector.unwatch(str(extra)) is True
    assert str(extra) not in collector.watching
    assert collector.unwatch(str(extra)) is False


def test_watching_a_nonexistent_directory_is_refused_not_fatal(watched):
    collector, _sink, tmp_path = watched
    assert collector.watch(str(tmp_path / "nope")) is False
    assert collector.stats()["name"] == "file"


# ── transport & the wired agent ───────────────────────────────────────────────
@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A provisioned detection server, reachable through a TestClient."""
    root = tmp_path_factory.mktemp("vigil-agent-server")
    cfg = ServerConfig(
        db_path=str(root / "vigil.db"),
        model_path=str(root / "model.pkl"),
        keys_dir=str(root / "keys"),
        require_enroll_token=False,        # token handling is covered in test_api.py
        rl_epsilon=0.0,
    )
    server_generate(cfg)
    train(source="synthetic", out=cfg.model_path, users=10, days=10,
          n_estimators=60, check=False)
    storage = SQLiteStorage(cfg.db_path)
    storage.init_schema()
    with TestClient(create_app(cfg, storage=storage)) as client:
        yield {"cfg": cfg, "client": client, "storage": storage}


@pytest.fixture
def agent_cfg(tmp_path, server):
    cfg = AgentConfig(
        agent_id=f"AGENT-{tmp_path.name.upper()}"[:40],
        server_url=str(server["client"].base_url),
        keys_dir=str(tmp_path / "keys"),
        watch_dirs=[str(tmp_path)],
        directive_log=str(tmp_path / "directives.log"),
        flush_interval_s=0.2,
        collect_files=False, collect_usb=False, collect_logon=False,
    )
    agent_generate(cfg)
    assert keys_exist(cfg)
    return cfg


def make_transport(cfg, server) -> Transport:
    pk, sk = load_keys(cfg)
    return Transport(cfg, pk, sk, client=server["client"])


def test_transport_enrolls_and_establishes_a_post_quantum_session(agent_cfg, server):
    transport = make_transport(agent_cfg, server)
    assert transport.connected is False

    body = transport.connect()
    assert body["status"] == "established"
    assert transport.enrolled is True
    assert transport.connected is True
    assert len(transport.server_ek) == 800                 # ML-KEM-512 encapsulation key
    assert len(transport.stats()["server_kem_fingerprint"]) == 16


def test_a_pinned_fingerprint_mismatch_is_fatal(agent_cfg, server):
    """The machine-in-the-middle case: no silent fallback to the key we were handed."""
    agent_cfg.server_kem_fingerprint = "0" * 16
    transport = make_transport(agent_cfg, server)
    with pytest.raises(FingerprintMismatch):
        transport.enroll()
    assert transport.enrolled is False


def test_the_correct_pinned_fingerprint_is_accepted(agent_cfg, server):
    probe = make_transport(agent_cfg, server)
    actual = probe.enroll()["server_kem_fingerprint"]

    agent_cfg.server_kem_fingerprint = actual.upper()       # case must not matter
    transport = make_transport(agent_cfg, server)
    transport.connect()
    assert transport.connected is True


def test_a_sealed_batch_reaches_the_pipeline(agent_cfg, server):
    transport = make_transport(agent_cfg, server)
    transport.connect()
    ctx = make_ctx()
    events = [ctx.event(LOG_FILE, "create", path=f"C:/work/{i}.docx", size_bytes=1024)
              for i in range(4)]

    body = transport.send(events)
    assert body["status"] == "accepted"
    assert body["events_received"] == 4
    assert transport.batches_sent == 1
    assert transport.events_sent == 4


def test_sequence_numbers_advance_across_batches(agent_cfg, server):
    transport = make_transport(agent_cfg, server)
    transport.connect()
    ctx = make_ctx()
    seqs = [transport.send([ctx.event(LOG_FILE, "modify", path="C:/w/a.txt")])["seq"]
            for _ in range(3)]
    assert seqs == sorted(set(seqs)) and len(seqs) == 3


def test_a_lost_server_session_is_recovered_transparently(agent_cfg, server):
    """Session keys are never persisted, so a server restart must not lose telemetry."""
    transport = make_transport(agent_cfg, server)
    transport.connect()
    ctx = make_ctx()
    transport.send([ctx.event(LOG_FILE, "create", path="C:/w/before.txt")])

    # Exactly what a server restart looks like from the agent's side.
    server["client"].app.state.sessions.drop(agent_cfg.agent_id)

    body = transport.send([ctx.event(LOG_FILE, "create", path="C:/w/after.txt")])
    assert body["status"] == "accepted"
    assert body["seq"] == 1                # a fresh session has its own sequence space


def test_an_unreachable_server_raises_transport_error(agent_cfg):
    agent_cfg.server_url = "http://127.0.0.1:1"            # nothing listens here
    agent_cfg.request_timeout_s = 1.0
    pk, sk = load_keys(agent_cfg)
    transport = Transport(agent_cfg, pk, sk)
    try:
        with pytest.raises(TransportError):
            transport.connect()
    finally:
        transport.close()


def test_a_failed_flush_requeues_instead_of_losing_events(agent_cfg, server):
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    ctx = make_ctx(agent.buffer.add)
    for i in range(3):
        ctx.send(LOG_FILE, "create", path=f"C:/w/{i}.txt")

    def refuse(_events):
        raise TransportError("simulated outage")

    agent.transport.send = refuse
    with pytest.raises(TransportError):
        agent.flush_once()
    assert len(agent.buffer) == 3, "events were dropped by a failed send"

    del agent.transport.send                               # restore the real method
    body = agent.flush_once()
    assert body["events_received"] == 3
    assert len(agent.buffer) == 0


def test_flush_with_an_empty_buffer_does_nothing(agent_cfg, server):
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    assert agent.flush_once() is None
    assert agent.flushes == 0


def test_a_containment_directive_is_audited_and_never_destructive(agent_cfg, server):
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    directive = {"directive_id": "D-1", "severity": "CRITICAL", "mode": "simulated",
                 "steps": ["notify_user", "flag_session"],
                 "message": "Security has been notified."}
    agent._handle_directives([directive])

    assert agent.directives_received == 1
    lines = open(agent_cfg.directive_log, encoding="utf-8").read().strip().splitlines()
    record = json.loads(lines[-1])
    assert record["agent_id"] == agent_cfg.agent_id
    assert record["directive"]["mode"] == "simulated"       # nothing was enforced
    assert record["directive"]["directive_id"] == "D-1"


def test_directives_can_be_turned_off_entirely(agent_cfg, server):
    agent_cfg.apply_directives = False
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    agent._handle_directives([{"directive_id": "D-2", "mode": "simulated"}])
    assert agent.directives_received == 1
    assert not os.path.exists(agent_cfg.directive_log)


def test_removable_volumes_are_watched_while_mounted(tmp_path, agent_cfg, server):
    """Without this sync, writes to E:\\ would never be observed at all."""
    stick = tmp_path / "removable"
    stick.mkdir()
    agent_cfg.collect_files = True
    agent_cfg.collect_usb = True
    present = {"drives": {}}

    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    agent.usb._scan = lambda: dict(present["drives"])
    agent.usb._present = {}          # ignore any real media on the machine running this
    agent.files.start()
    try:
        present["drives"] = {str(stick): {"drive": str(stick), "drive_type": "removable"}}
        agent.usb.diff({}, agent.usb.snapshot())
        agent._sync_removable_watches()
        assert str(stick) in agent.files.watching

        previous = dict(present["drives"])
        present["drives"] = {}
        agent.usb.diff(previous, agent.usb.snapshot())
        agent._sync_removable_watches()
        assert str(stick) not in agent.files.watching
        # The configured directory is never unwatched by the removable sync.
        assert str(tmp_path) in agent.files.watching
    finally:
        agent.files.stop()


def test_the_agent_reports_its_own_health(agent_cfg, server):
    agent_cfg.collect_usb = True
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    stats = agent.stats()
    assert stats["agent_id"] == agent_cfg.agent_id
    assert stats["buffer"]["capacity"] == agent_cfg.buffer_size
    assert stats["transport"]["enrolled"] is False
    assert [c["name"] for c in stats["collectors"]] == ["usb"]


def test_disabled_collectors_are_not_constructed(agent_cfg, server):
    agent = EndpointAgent(agent_cfg, transport=make_transport(agent_cfg, server))
    assert (agent.files, agent.usb, agent.logon) == (None, None, None)
    assert agent.collectors == []
