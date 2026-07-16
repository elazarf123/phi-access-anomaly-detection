# Detection Playbook — Rule Rationale & Framework Mapping

Each detection rule maps to a specific insider-threat or intrusion pattern seen
in healthcare environments, and to the controls that require monitoring for it.

## R1 — Off-hours PHI access by non-clinical roles

**Threat:** Employee snooping (celebrity/family/coworker records) most often
happens outside supervised hours. Non-clinical roles have no night-shift
justification for chart access.
**Logic:** PHI action ∧ role ∉ {Nurse, Physician} ∧ hour ∈ [22:00, 06:00)
**HIPAA:** §164.312(b) Audit controls; §164.502(b) Minimum necessary
**NIST CSF 2.0:** DE.CM-03 (personnel activity monitored), PR.AA-05 (access permissions reviewed)

## R2 — Chart-view volume anomaly (statistical baseline)

**Threat:** Record scraping — bulk viewing of patient charts for identity
theft or data exfiltration. Signature is volume far above the user's peers.
**Logic:** daily VIEW_CHART count > mean + 3σ across all user-days
**Why 3σ:** flags true outliers while tolerating busy clinic days; threshold
is data-driven, not hard-coded, so it adapts as staffing changes.
**HIPAA:** §164.312(b); §164.308(a)(1)(ii)(D) Information system activity review
**NIST CSF 2.0:** DE.AE-02 (events analyzed for anomalies), DE.CM-01

## R3 — Terminated-account activity

**Threat:** Deprovisioning gaps. A terminated employee's active account is
both an insider risk and an unowned attack surface.
**Logic:** any event where user ∈ terminated list ∧ timestamp ≥ termination date
**HIPAA:** §164.308(a)(3)(ii)(C) Termination procedures
**NIST CSF 2.0:** PR.AA-01 (identities managed), ID.AM-08 (lifecycle managed)

## R4 — Failed-login burst (brute force)

**Threat:** Credential attack. ≥5 failures in 10 minutes is beyond typo
territory; a success immediately after failures suggests compromise, which
escalates severity.
**Logic:** ≥5 FAILED LOGIN events within any 10-minute window per user;
flag subsequent SUCCESS.
**HIPAA:** §164.312(a)(2)(i) Unique user identification; §164.308(a)(5)(ii)(C) Log-in monitoring
**NIST CSF 2.0:** DE.CM-09 (unauthorized access monitored), PR.AA-03 (authentication)

## Response severity model

| Severity | Meaning | SLA |
|---|---|---|
| CRITICAL | Active compromise or control failure (R3, R4) | Immediate containment |
| HIGH | Probable policy violation needing investigation (R1, R2) | Same business day |
| MEDIUM | Suspicious but explainable pattern | 3 business days |

## Known limitations / next iterations

Rules are deterministic and threshold-based — a production deployment would add
peer-group baselines per role, patient-relationship checks (was the patient on
the user's caseload?), and streaming evaluation rather than batch. These are
deliberate scope choices for a portfolio-scale project.
