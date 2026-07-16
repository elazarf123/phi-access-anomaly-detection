"""
generate_logs.py
Generates a synthetic EHR access log (data/access_logs.csv) with four
planted attack/misuse patterns hidden in normal traffic:

  1. Off-hours PHI access by a non-clinical user
  2. Record-scraping burst (one user viewing far more charts than baseline)
  3. Access by a terminated employee account
  4. Failed-login brute-force burst followed by a success

Seeded RNG for reproducibility. All identities and data are fictitious.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)

OUT = Path(__file__).resolve().parent.parent / "data"
OUT.mkdir(exist_ok=True)

USERS = {
    # user_id: (role, department, terminated)
    "jchen":   ("Nurse", "Cardiology", False),
    "mlopez":  ("Physician", "Pulmonology", False),
    "kpatel":  ("Nurse", "Family Medicine", False),
    "rsmith":  ("Registration Clerk", "Front Desk", False),
    "tbrown":  ("Billing Specialist", "Revenue Cycle", False),
    "dwilson": ("Physician", "Orthopedics", False),
    "agarcia": ("Nurse", "Endocrinology", False),
    "hformer": ("Nurse", "Cardiology", True),     # terminated 2025-06-01
}
TERMINATION_DATES = {"hformer": datetime(2025, 6, 1)}

ACTIONS = ["VIEW_CHART", "VIEW_LABS", "UPDATE_VITALS", "VIEW_MEDS", "PRINT_SUMMARY"]
PATIENTS = [f"PT-{6000+i}" for i in range(120)]
WORKSTATIONS = [f"WS-{i:03d}" for i in range(1, 25)]

rows = []
base = datetime(2025, 6, 2, 0, 0)


def add(ts, user, action, patient, status="SUCCESS", ws=None):
    rows.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user,
        "role": USERS[user][0],
        "department": USERS[user][1],
        "action": action,
        "patient_id": patient,
        "workstation": ws or random.choice(WORKSTATIONS),
        "status": status,
    })


# --- Normal traffic: 10 business days, clinical staff working 07:00-19:00 ---
for day in range(10):
    day_start = base + timedelta(days=day)
    if day_start.weekday() >= 5:          # skip weekends
        continue
    for user, (role, dept, term) in USERS.items():
        if term:
            continue
        for _ in range(random.randint(15, 30)):
            ts = day_start + timedelta(hours=random.uniform(7, 19))
            add(ts, user, random.choice(ACTIONS), random.choice(PATIENTS))

# --- Planted pattern 1: off-hours access by billing specialist (03:00) ------
night = base + timedelta(days=3, hours=3)
for i in range(6):
    add(night + timedelta(minutes=4 * i), "tbrown", "VIEW_CHART",
        random.choice(PATIENTS), ws="WS-099")

# --- Planted pattern 2: record-scraping burst by registration clerk ---------
burst_start = base + timedelta(days=5, hours=14)
for i in range(85):
    add(burst_start + timedelta(seconds=40 * i), "rsmith", "VIEW_CHART",
        PATIENTS[i % len(PATIENTS)])

# --- Planted pattern 3: terminated account still accessing ------------------
for i in range(4):
    ts = base + timedelta(days=6, hours=10, minutes=13 * i)
    add(ts, "hformer", "VIEW_LABS", random.choice(PATIENTS), ws="WS-101")

# --- Planted pattern 4: failed-login brute force then success ---------------
attack = base + timedelta(days=7, hours=22, minutes=15)
for i in range(9):
    add(attack + timedelta(seconds=30 * i), "dwilson", "LOGIN",
        "", status="FAILED", ws="WS-777")
add(attack + timedelta(minutes=5), "dwilson", "LOGIN", "", status="SUCCESS", ws="WS-777")
add(attack + timedelta(minutes=7), "dwilson", "VIEW_CHART",
    random.choice(PATIENTS), ws="WS-777")

rows.sort(key=lambda r: r["timestamp"])

with open(OUT / "access_logs.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {len(rows)} log events -> {OUT / 'access_logs.csv'}")
