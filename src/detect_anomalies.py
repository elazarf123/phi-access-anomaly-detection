"""
detect_anomalies.py
Runs four detection rules over the EHR access log and produces:

  output/alerts.csv          — one row per triggered alert, severity-ranked
  output/incident_report.md  — analyst-style summary of findings

Detection rules (each maps to a HIPAA/NIST CSF control — see
docs/detection_playbook.md):

  R1  OFF_HOURS_PHI       PHI access between 22:00-06:00 by non-clinical roles
  R2  VOLUME_ANOMALY      User's daily chart views > mean + 3*std of all users
  R3  TERMINATED_ACCESS   Any activity from a terminated account
  R4  BRUTE_FORCE         >= 5 failed logins within 10 min, esp. then success

Run:  python src/detect_anomalies.py   (after src/generate_logs.py)
"""

from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parent.parent
LOG = BASE / "data" / "access_logs.csv"
OUT = BASE / "output"
OUT.mkdir(exist_ok=True)

TERMINATED = {"hformer": "2025-06-01"}
CLINICAL_ROLES = {"Nurse", "Physician"}
PHI_ACTIONS = {"VIEW_CHART", "VIEW_LABS", "VIEW_MEDS", "PRINT_SUMMARY"}

df = pd.read_csv(LOG, parse_dates=["timestamp"])
alerts = []


def alert(rule, severity, user, ts, detail):
    alerts.append({"rule": rule, "severity": severity, "user_id": user,
                   "first_seen": ts, "detail": detail})


# R1 — Off-hours PHI access by non-clinical staff --------------------------
mask = (
    df["action"].isin(PHI_ACTIONS)
    & ~df["role"].isin(CLINICAL_ROLES)
    & (df["timestamp"].dt.hour.isin([22, 23, 0, 1, 2, 3, 4, 5]))
)
for user, grp in df[mask].groupby("user_id"):
    alert("R1_OFF_HOURS_PHI", "HIGH", user, grp["timestamp"].min(),
          f"{len(grp)} PHI events between 22:00-06:00 by {grp['role'].iloc[0]} "
          f"({grp['department'].iloc[0]}), workstation(s): {', '.join(grp['workstation'].unique())}")

# R2 — Volume anomaly (statistical baseline) --------------------------------
views = df[df["action"] == "VIEW_CHART"].copy()
views["date"] = views["timestamp"].dt.date
daily = views.groupby(["user_id", "date"]).size().rename("views").reset_index()
threshold = daily["views"].mean() + 3 * daily["views"].std()
for _, row in daily[daily["views"] > threshold].iterrows():
    grp = views[(views["user_id"] == row["user_id"]) & (views["date"] == row["date"])]
    alert("R2_VOLUME_ANOMALY", "HIGH", row["user_id"], grp["timestamp"].min(),
          f"{row['views']} chart views on {row['date']} "
          f"(baseline mean {daily['views'].mean():.1f}, threshold {threshold:.1f}) — "
          f"{grp['patient_id'].nunique()} distinct patients")

# R3 — Terminated account activity ------------------------------------------
for user, term_date in TERMINATED.items():
    grp = df[(df["user_id"] == user) & (df["timestamp"] >= term_date)]
    if not grp.empty:
        alert("R3_TERMINATED_ACCESS", "CRITICAL", user, grp["timestamp"].min(),
              f"{len(grp)} events after termination date {term_date}; "
              f"actions: {', '.join(grp['action'].unique())}")

# R4 — Brute force: >=5 failed logins in 10 min ------------------------------
fails = df[(df["action"] == "LOGIN") & (df["status"] == "FAILED")].sort_values("timestamp")
for user, grp in fails.groupby("user_id"):
    ts = grp["timestamp"]
    window_counts = ts.apply(lambda t: ((ts >= t) & (ts < t + pd.Timedelta("10min"))).sum())
    if window_counts.max() >= 5:
        later_success = df[(df["user_id"] == user) & (df["action"] == "LOGIN")
                           & (df["status"] == "SUCCESS")
                           & (df["timestamp"] > ts.min())]
        followed = " FOLLOWED BY SUCCESSFUL LOGIN — possible account compromise" \
            if not later_success.empty else ""
        alert("R4_BRUTE_FORCE", "CRITICAL", user, ts.min(),
              f"{window_counts.max()} failed logins within 10 min on "
              f"{grp['workstation'].iloc[0]}{followed}")

# ---------------------------------------------------------------- outputs
alerts_df = pd.DataFrame(alerts).sort_values(
    "severity", key=lambda s: s.map({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}))
alerts_df.to_csv(OUT / "alerts.csv", index=False)

severity_counts = alerts_df["severity"].value_counts().to_dict()
lines = [
    "# Incident Report — EHR Access Log Review",
    "",
    f"**Log window analyzed:** {df['timestamp'].min()} to {df['timestamp'].max()}  ",
    f"**Total events:** {len(df):,}  |  **Alerts raised:** {len(alerts_df)} "
    f"({severity_counts})",
    "",
    "All findings below are from synthetic data generated for this project.",
    "",
]
for _, a in alerts_df.iterrows():
    lines += [
        f"## [{a['severity']}] {a['rule']} — user `{a['user_id']}`",
        f"- **First seen:** {a['first_seen']}",
        f"- **Finding:** {a['detail']}",
        f"- **Recommended action:** "
        + {
            "R1_OFF_HOURS_PHI": "Confirm business justification with manager; if none, treat as potential snooping (HIPAA minimum-necessary violation) and preserve logs.",
            "R2_VOLUME_ANOMALY": "Interview user and manager; compare accessed patients against assigned caseload; escalate to privacy officer if non-caseload access is confirmed.",
            "R3_TERMINATED_ACCESS": "Disable account immediately, invalidate sessions, audit all post-termination access, and review the deprovisioning workflow gap that left it active.",
            "R4_BRUTE_FORCE": "Force password reset + MFA re-enrollment, review workstation WS-777 for compromise, and check for lateral movement from the account.",
        }[a["rule"]],
        "",
    ]
(OUT / "incident_report.md").write_text("\n".join(lines))

print(f"{len(alerts_df)} alerts -> {OUT / 'alerts.csv'}")
print(f"Report -> {OUT / 'incident_report.md'}")
print(alerts_df[["rule", "severity", "user_id"]].to_string(index=False))
