"""Synthetic endpoint-event generators.

Used in two places so behaviour stays consistent:

- :func:`normal_events` — a large, realistic corpus of benign activity that the
  Isolation Forest is trained on (:mod:`server.ml.train`), so the model has a
  sensible notion of "normal" without any dataset download.
- :func:`exfiltration_events` / :func:`staging_events` — the poster's threat
  scenarios, injected end-to-end by :mod:`tools.replay` to demonstrate detection.

Everything is produced as :class:`vigil.schema.Event` objects, so it flows through
the exact same feature path as live data. Generation is seeded for reproducibility.

The "normal" generator deliberately includes *messy* benign behaviour — bursty
file saves, large legitimate downloads, occasional late-night work, weekend
catch-up, USB backups — because a model trained only on tidy 9-to-5 activity
flags ordinary real-world usage as an insider threat.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from vigil import schema
from vigil.schema import Event

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

SENSITIVE_DIRS = [
    r"C:\Finance\confidential",
    r"C:\HR\records",
    r"C:\Projects\classified",
    r"C:\Legal\contracts",
]
NORMAL_DIRS = [
    r"C:\Users\{u}\Documents",
    r"C:\Users\{u}\Downloads",
    r"C:\Users\{u}\Desktop",
    r"C:\Work\reports",
    r"C:\Work\shared",
    r"C:\Temp",
]
NORMAL_EXTS = [".docx", ".xlsx", ".pdf", ".pptx", ".txt", ".png", ".csv", ".log", ".json"]
BIG_EXTS = [".zip", ".iso", ".mp4", ".pst", ".bak", ".vmdk"]


def _at(day: datetime, hour: int, minute: int = 0, second: int = 0) -> datetime:
    """Build a UTC timestamp at a given hour/minute on ``day``."""
    return day.replace(hour=hour, minute=minute, second=second,
                       microsecond=0, tzinfo=timezone.utc)


def _file_event(rng, agent_id, host, user, ts, folder=None, size=None, action=None) -> Event:
    folder = folder if folder is not None else rng.choice(NORMAL_DIRS).format(u=user)
    ext = rng.choice(NORMAL_EXTS)
    return Event(
        agent_id=agent_id, host=host, user=user,
        log_type=schema.LOG_FILE,
        action=action or rng.choices(["modify", "create", "delete", "move"],
                                     weights=[60, 30, 7, 3])[0],
        path=f"{folder}\\item_{rng.randint(1, 9999)}{ext}",
        size_bytes=size if size is not None else rng.randint(1 * KB, 4 * MB),
        ts=ts,
    )


def _work_hour_files(rng, agent_id, host, user, day, hour, intensity=1.0) -> list[Event]:
    """One hour of benign file activity — usually light, sometimes a real burst."""
    # Editors/sync clients emit several events per logical save, so counts are bursty.
    n = rng.choices(
        [0, rng.randint(1, 6), rng.randint(7, 20), rng.randint(21, 60), rng.randint(61, 120)],
        weights=[18, 40, 26, 13, 3],
    )[0]
    n = int(n * intensity)
    evs = []
    for _ in range(n):
        ts = _at(day, hour, rng.randint(0, 59), rng.randint(0, 59))
        if rng.random() < 0.04:          # a legitimately large file: install, video, dataset
            evs.append(Event(
                agent_id=agent_id, host=host, user=user, log_type=schema.LOG_FILE,
                action="create",
                path=rf"C:\Users\{user}\Downloads\bundle_{rng.randint(1, 999)}"
                     f"{rng.choice(BIG_EXTS)}",
                size_bytes=rng.randint(80 * MB, 700 * MB), ts=ts))
        else:
            evs.append(_file_event(rng, agent_id, host, user, ts))
    return evs


def normal_events(
    num_users: int = 40,
    days: int = 30,
    agent_id: str = "TRAIN",
    seed: int = 42,
    start: datetime | None = None,
) -> list[Event]:
    """A realistic corpus of benign endpoint behaviour across many users and days."""
    rng = random.Random(seed)
    base_day = (start or datetime(2026, 1, 5)).replace(tzinfo=None)
    events: list[Event] = []

    for u in range(num_users):
        user = f"NORM{u + 1:03d}"
        host = f"PC-{rng.randint(1000, 9999)}"
        # Per-user personality: some people are heavy file users, some are light.
        intensity = rng.choice([0.5, 0.8, 1.0, 1.0, 1.4, 2.0])
        night_owl = rng.random() < 0.20      # occasionally works late, legitimately
        weekend_worker = rng.random() < 0.15

        for d in range(days):
            day = base_day + timedelta(days=d)
            weekend = day.weekday() >= 5
            if weekend and not (weekend_worker and rng.random() < 0.4):
                continue

            if weekend:
                # Light catch-up session at an odd hour — benign, but not 9-to-5.
                h0 = rng.randint(10, 16)
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_ON,
                                    ts=_at(day, h0, rng.randint(0, 59))))
                for h in range(h0, min(h0 + rng.randint(1, 3), 23)):
                    events += _work_hour_files(rng, agent_id, host, user, day, h,
                                               intensity * 0.5)
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                                    ts=_at(day, min(h0 + 3, 23), rng.randint(0, 59))))
                continue

            # ── ordinary weekday ──
            logon_h = rng.randint(7, 9)
            logoff_h = rng.randint(17, 19)
            events.append(Event(agent_id=agent_id, host=host, user=user,
                                log_type=schema.LOG_LOGON, action=schema.LOGON_ON,
                                ts=_at(day, logon_h, rng.randint(0, 59))))
            # lock/unlock during the day produces extra logon/logoff pairs
            for _ in range(rng.choices([0, 1, 2, 3], weights=[45, 30, 18, 7])[0]):
                h = rng.randint(logon_h + 1, max(logoff_h - 1, logon_h + 1))
                m = rng.randint(0, 30)
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                                    ts=_at(day, h, m)))
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_ON,
                                    ts=_at(day, h, min(m + rng.randint(5, 29), 59))))

            for h in range(logon_h, logoff_h + 1):
                events += _work_hour_files(rng, agent_id, host, user, day, h, intensity)

            # benign USB use, sometimes with a genuine backup copy onto the drive
            if rng.random() < 0.35:
                h = rng.randint(max(logon_h, 9), min(logoff_h, 17))
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_DEVICE, action=schema.DEVICE_CONNECT,
                                    ts=_at(day, h, rng.randint(0, 20))))
                if rng.random() < 0.5:
                    for _ in range(rng.randint(3, 25)):
                        events.append(_file_event(
                            rng, agent_id, host, user,
                            _at(day, h, rng.randint(21, 55), rng.randint(0, 59)),
                            folder=r"E:\backup", size=rng.randint(2 * MB, 60 * MB),
                            action="create"))
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_DEVICE, action=schema.DEVICE_DISCONNECT,
                                    ts=_at(day, min(h + rng.randint(0, 2), 23),
                                           rng.randint(0, 59))))

            events.append(Event(agent_id=agent_id, host=host, user=user,
                                log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                                ts=_at(day, logoff_h, rng.randint(0, 59))))

            # legitimate late-night work: after-hours alone must not mean "threat"
            if night_owl and rng.random() < 0.30:
                h = rng.choice([20, 21, 22, 23])
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_ON,
                                    ts=_at(day, h, rng.randint(0, 30))))
                events += _work_hour_files(rng, agent_id, host, user, day, h, intensity * 0.6)
                events.append(Event(agent_id=agent_id, host=host, user=user,
                                    log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                                    ts=_at(day, min(h + 1, 23), rng.randint(0, 59))))

    events.sort(key=lambda e: e.ts)
    return events


def exfiltration_events(
    user: str = "jdoe",
    host: str = "WKS-4471",
    agent_id: str = "AGENT-DEMO",
    seed: int = 7,
    when: datetime | None = None,
) -> list[Event]:
    """The poster's case study: after-hours USB insert + a 2.3 GB staging burst.

    All of it lands inside a single behaviour window, which is what makes it stand
    out: after-hours + removable device + massive byte volume + sensitive paths.
    """
    rng = random.Random(seed)
    day = (when or datetime(2026, 2, 3, 22, 15, 0)).replace(tzinfo=timezone.utc)
    ev: list[Event] = [
        Event(agent_id=agent_id, host=host, user=user,
              log_type=schema.LOG_LOGON, action=schema.LOGON_ON, ts=day),
        Event(agent_id=agent_id, host=host, user=user,
              log_type=schema.LOG_DEVICE, action=schema.DEVICE_CONNECT,
              ts=day + timedelta(minutes=2)),
    ]

    # the 2.3 GB archive
    t = day + timedelta(minutes=2, seconds=20)
    ev.append(Event(agent_id=agent_id, host=host, user=user,
                    log_type=schema.LOG_FILE, action="create",
                    path=r"C:\Finance\confidential\Q4_export.zip",
                    size_bytes=int(2.3 * GB), ts=t,
                    detail={"sensitive": True, "ext": ".zip"}))

    # plus a burst of sensitive documents being staged
    for _ in range(rng.randint(25, 45)):
        t += timedelta(seconds=rng.randint(3, 20))
        if t >= day + timedelta(minutes=44):     # keep it inside the same hour window
            break
        folder = rng.choice(SENSITIVE_DIRS)
        ev.append(Event(agent_id=agent_id, host=host, user=user,
                        log_type=schema.LOG_FILE, action="modify",
                        path=f"{folder}\\dump_{rng.randint(1, 500)}.xlsx",
                        size_bytes=rng.randint(2 * MB, 40 * MB), ts=t,
                        detail={"sensitive": True, "ext": ".xlsx"}))

    t = day + timedelta(minutes=45)
    ev.append(Event(agent_id=agent_id, host=host, user=user,
                    log_type=schema.LOG_DEVICE, action=schema.DEVICE_DISCONNECT, ts=t))
    ev.append(Event(agent_id=agent_id, host=host, user=user,
                    log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                    ts=t + timedelta(minutes=5)))
    return ev


def staging_events(
    user: str = "asmith",
    host: str = "WKS-2210",
    agent_id: str = "AGENT-DEMO",
    seed: int = 11,
    when: datetime | None = None,
) -> list[Event]:
    """A second scenario: after-hours mass copy of mail archives to a removable drive."""
    rng = random.Random(seed)
    day = (when or datetime(2026, 2, 4, 23, 5, 0)).replace(tzinfo=timezone.utc)
    ev: list[Event] = [
        Event(agent_id=agent_id, host=host, user=user,
              log_type=schema.LOG_LOGON, action=schema.LOGON_ON, ts=day),
        Event(agent_id=agent_id, host=host, user=user,
              log_type=schema.LOG_DEVICE, action=schema.DEVICE_CONNECT,
              ts=day + timedelta(minutes=1)),
    ]
    t = day + timedelta(minutes=1)
    for _ in range(rng.randint(40, 60)):
        t += timedelta(seconds=rng.randint(5, 25))
        if t >= day + timedelta(minutes=50):
            break
        ev.append(Event(agent_id=agent_id, host=host, user=user,
                        log_type=schema.LOG_FILE, action="create",
                        path=rf"E:\backup\archive_{rng.randint(1, 999)}.pst",
                        size_bytes=rng.randint(40 * MB, 180 * MB), ts=t,
                        detail={"removable": True, "ext": ".pst"}))
    ev.append(Event(agent_id=agent_id, host=host, user=user,
                    log_type=schema.LOG_DEVICE, action=schema.DEVICE_DISCONNECT,
                    ts=day + timedelta(minutes=52)))
    ev.append(Event(agent_id=agent_id, host=host, user=user,
                    log_type=schema.LOG_LOGON, action=schema.LOGON_OFF,
                    ts=day + timedelta(minutes=55)))
    return ev


# Backwards-compatible alias (the older name used during scaffolding).
email_leak_events = staging_events

SCENARIOS = {
    "exfiltration": exfiltration_events,
    "staging": staging_events,
}
