# Incident Report — EHR Access Log Review

**Log window analyzed:** 2025-06-02 07:00:10 to 2025-06-11 18:58:20  
**Total events:** 1,346  |  **Alerts raised:** 4 ({'CRITICAL': 2, 'HIGH': 2})

All findings below are from synthetic data generated for this project.

## [CRITICAL] R4_BRUTE_FORCE — user `dwilson`
- **First seen:** 2025-06-09 22:15:00
- **Finding:** 9 failed logins within 10 min on WS-777 FOLLOWED BY SUCCESSFUL LOGIN — possible account compromise
- **Recommended action:** Force password reset + MFA re-enrollment, review workstation WS-777 for compromise, and check for lateral movement from the account.

## [CRITICAL] R3_TERMINATED_ACCESS — user `hformer`
- **First seen:** 2025-06-08 10:00:00
- **Finding:** 4 events after termination date 2025-06-01; actions: VIEW_LABS
- **Recommended action:** Disable account immediately, invalidate sessions, audit all post-termination access, and review the deprovisioning workflow gap that left it active.

## [HIGH] R2_VOLUME_ANOMALY — user `rsmith`
- **First seen:** 2025-06-07 14:00:00
- **Finding:** 85 chart views on 2025-06-07 (baseline mean 5.9, threshold 38.5) — 85 distinct patients
- **Recommended action:** Interview user and manager; compare accessed patients against assigned caseload; escalate to privacy officer if non-caseload access is confirmed.

## [HIGH] R1_OFF_HOURS_PHI — user `tbrown`
- **First seen:** 2025-06-05 03:00:00
- **Finding:** 6 PHI events between 22:00-06:00 by Billing Specialist (Revenue Cycle), workstation(s): WS-099
- **Recommended action:** Confirm business justification with manager; if none, treat as potential snooping (HIPAA minimum-necessary violation) and preserve logs.
