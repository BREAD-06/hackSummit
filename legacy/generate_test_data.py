# generate_test_data.py
# Generates 3 synthetic test scenario datasets in r4.2-1 format
# so the trained model can be demonstrated on different threat profiles.
#
# Scenarios:
#   1. data/test_scenarios/exfiltration/ — 5 users doing data exfiltration
#   2. data/test_scenarios/email_leak/   — 5 users leaking via mass email
#   3. data/test_scenarios/normal/       — 10 users with normal behavior (baseline)

import os
import uuid
import random
from datetime import datetime, timedelta

random.seed(42)


# ── Helpers ────────────────────────────────────────────────────────────────────

def gen_id() -> str:
    a = uuid.uuid4().hex[:4].upper()
    b = uuid.uuid4().hex[:2].upper()
    c = uuid.uuid4().hex[:8].upper()
    d = uuid.uuid4().hex[:8].upper()
    return "{" + f"{a}{b}-{c[:8]}-{d[:8]}" + "}"


def fmt_dt(dt: datetime) -> str:
    return dt.strftime("%m/%d/%Y %H:%M:%S")


def rand_time(base: datetime, h_start: int, h_end: int) -> datetime:
    h = random.randint(h_start, min(h_end, 23))
    m = random.randint(0, 59)
    s = random.randint(0, 59)
    return base.replace(hour=h, minute=m, second=s)


def write_csv(path: str, rows: list):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(",".join(str(c) for c in row) + "\n")


SUSPICIOUS_URLS = [
    "http://wikileaks.org/secrets/classified-data",
    "http://pastebin.com/raw/secret-dump",
    "http://dropbox.com/sh/confidential-export",
    "http://mega.nz/file/classified-documents",
    "http://anonfiles.com/upload/internal-data",
]

NORMAL_URLS = [
    "http://google.com/search",
    "http://stackoverflow.com/questions",
    "http://github.com/repositories",
    "http://slack.com/messages/general",
    "http://outlook.office365.com/mail",
    "http://confluence.internal/wiki",
    "http://jira.internal/issues",
]


# ── Scenario 1: Data Exfiltration ──────────────────────────────────────────────
def gen_exfiltration(out_dir: str, num_users: int = 5, days: int = 7):
    """After-hours USB + mass file access + suspicious HTTP visits."""
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2010, 9, 1)

    for i in range(num_users):
        user = f"EXFIL{i + 1:03d}"
        pc   = f"PC-{random.randint(1000, 9999):04d}"
        rows = []

        for d in range(days):
            day = base + timedelta(days=d)
            if day.weekday() >= 5:   # also do weekends — adds suspicion
                pass

            # --- Late-night session ---
            logon_t = rand_time(day, 21, 23)
            rows.append(["logon", gen_id(), fmt_dt(logon_t), user, pc, "Logon", ""])

            t = logon_t + timedelta(minutes=random.randint(3, 10))

            # USB connect
            rows.append(["device", gen_id(), fmt_dt(t), user, pc, "Connect", ""])
            t += timedelta(minutes=random.randint(1, 5))

            # Large burst of file accesses (data staging)
            for _ in range(random.randint(20, 45)):
                t += timedelta(seconds=random.randint(5, 30))
                fname = f"C:\\Projects\\confidential_{random.randint(1, 200)}.xlsx"
                rows.append(["file", gen_id(), fmt_dt(t), user, pc, fname, ""])

            # Suspicious URLs
            for _ in range(random.randint(4, 10)):
                t += timedelta(seconds=random.randint(20, 90))
                url = random.choice(SUSPICIOUS_URLS)
                rows.append(["http", gen_id(), fmt_dt(t), user, pc, url, "classified leak secret"])

            # USB disconnect
            t += timedelta(minutes=random.randint(15, 40))
            rows.append(["device", gen_id(), fmt_dt(t), user, pc, "Disconnect", ""])

            # Logoff
            logoff_t = t + timedelta(minutes=random.randint(5, 20))
            rows.append(["logon", gen_id(), fmt_dt(logoff_t), user, pc, "Logoff", ""])

        write_csv(os.path.join(out_dir, f"exfil-{user}.csv"), rows)

    print(f"[generate] ✅ Exfiltration scenario: {num_users} users → {out_dir}")


# ── Scenario 2: Email Leak ──────────────────────────────────────────────────────
def gen_email_leak(out_dir: str, num_users: int = 5, days: int = 7):
    """Mass emails with large attachments during off-hours."""
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2010, 9, 8)

    for i in range(num_users):
        user = f"EMAIL{i + 1:03d}"
        pc   = f"PC-{random.randint(1000, 9999):04d}"
        rows = []

        for d in range(days):
            day = base + timedelta(days=d)

            # --- Late night session ---
            logon_t = rand_time(day, 22, 23)
            rows.append(["logon", gen_id(), fmt_dt(logon_t), user, pc, "Logon", ""])

            t = logon_t + timedelta(minutes=5)

            # Mass high-volume email with large attachments
            for _ in range(random.randint(25, 50)):
                t += timedelta(seconds=random.randint(15, 60))
                size        = random.randint(3_000_000, 20_000_000)   # 3–20 MB per email
                attachments = random.randint(3, 12)
                rows.append(["email", gen_id(), fmt_dt(t), user, pc, str(size), str(attachments)])

            # A few suspicious URL visits
            for _ in range(random.randint(2, 6)):
                t += timedelta(seconds=random.randint(30, 120))
                url = random.choice(SUSPICIOUS_URLS)
                rows.append(["http", gen_id(), fmt_dt(t), user, pc, url, ""])

            # Logoff
            logoff_t = t + timedelta(minutes=random.randint(10, 30))
            rows.append(["logon", gen_id(), fmt_dt(logoff_t), user, pc, "Logoff", ""])

        write_csv(os.path.join(out_dir, f"emailleak-{user}.csv"), rows)

    print(f"[generate] ✅ Email leak scenario: {num_users} users → {out_dir}")


# ── Scenario 3: Normal Behavior ────────────────────────────────────────────────
def gen_normal(out_dir: str, num_users: int = 10, days: int = 10):
    """Typical 9-to-5 employees — model should NOT flag these as threats."""
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2010, 9, 15)

    for i in range(num_users):
        user = f"NORM{i + 1:03d}"
        pc   = f"PC-{random.randint(1000, 9999):04d}"
        rows = []

        for d in range(days):
            day = base + timedelta(days=d)
            if day.weekday() >= 5:   # skip weekends
                continue

            # --- Normal business hours (8 am – 6 pm) ---
            logon_t = rand_time(day, 8, 9)
            rows.append(["logon", gen_id(), fmt_dt(logon_t), user, pc, "Logon", ""])

            t = logon_t + timedelta(minutes=10)

            # Moderate file access throughout the day
            for _ in range(random.randint(5, 15)):
                t += timedelta(minutes=random.randint(10, 30))
                fname = f"C:\\Documents\\report_{random.randint(1, 30)}.docx"
                rows.append(["file", gen_id(), fmt_dt(t), user, pc, fname, ""])

            # Normal web browsing
            for _ in range(random.randint(8, 20)):
                t += timedelta(minutes=random.randint(3, 15))
                url = random.choice(NORMAL_URLS)
                rows.append(["http", gen_id(), fmt_dt(t), user, pc, url, "work task meeting"])

            # Occasional USB (once every 2--3 days)
            if random.random() < 0.35:
                t += timedelta(minutes=random.randint(20, 60))
                rows.append(["device", gen_id(), fmt_dt(t), user, pc, "Connect", ""])
                t += timedelta(minutes=random.randint(5, 15))
                rows.append(["device", gen_id(), fmt_dt(t), user, pc, "Disconnect", ""])

            # Low-volume email (small attachments)
            for _ in range(random.randint(3, 10)):
                t += timedelta(minutes=random.randint(15, 45))
                size        = random.randint(10_000, 400_000)
                attachments = random.randint(0, 2)
                rows.append(["email", gen_id(), fmt_dt(t), user, pc, str(size), str(attachments)])

            # Logoff (5–6 pm)
            logoff_t = rand_time(day, 17, 18)
            if logoff_t < t:
                logoff_t = t + timedelta(minutes=10)
            rows.append(["logon", gen_id(), fmt_dt(logoff_t), user, pc, "Logoff", ""])

        write_csv(os.path.join(out_dir, f"normal-{user}.csv"), rows)

    print(f"[generate] ✅ Normal behavior scenario: {num_users} users → {out_dir}")


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n=== Generating Synthetic Test Scenarios ===\n")

    gen_exfiltration("data/test_scenarios/exfiltration")
    gen_email_leak("data/test_scenarios/email_leak")
    gen_normal("data/test_scenarios/normal")

    print("\n=== All Scenarios Ready ===")
    print("  data/test_scenarios/exfiltration/ — 5 insiders (data exfiltration via USB + files)")
    print("  data/test_scenarios/email_leak/   — 5 insiders (mass email leak)")
    print("  data/test_scenarios/normal/       — 10 normal employees (baseline)")
    print("\nRun with: python test_model.py  (or select in the dashboard)")
