# Triage calibration report

Run: 2026-11-25 11:00 UTC · Jev model: `jev-1.13.0` · 20 labelled sample alerts (`backend/samples/calibration/alerts.json`)

Re-run with `python -m scripts.calibrate_triage` (calls Jev once per alert), or `python -m scripts.calibrate_triage --from-results <results.json>` to re-score without new calls.

## Summary

- Current rule: severity >= 2, escalation >= 0.5, category confidence < 0.6 → review, severity confidence < 0.6 → review
- Recommended: severity >= 2, escalation >= 0.3, category confidence < 0.4 → review, severity confidence < 0.0 → review
- Serious alerts that would skip the AI analysis: **1** with the current rule, **0** with the recommended one.

Labels are a responder's judgement, not ground truth; 20 alerts is a small sample, so treat the recommendation as a starting point to discuss.

## Current vs recommended

| Measure | Current | Recommended |
|---|---|---|
| Category correct |15/20 (75%) | 15/20 (75%) |
| Severity exact |11/20 (55%) | 11/20 (55%) |
| Severity within one level |19/20 (95%) | 19/20 (95%) |
| **Serious alerts that skipped AI** (must be 0) |**1** (cal-09) | **0** |
| Unknown alerts not sent to review |0 | 0 |
| AI runs |15/20 (75%) | 15/20 (75%) |
| AI runs on low-risk alerts without review |0 | 1 |
| Sent to human review |11/20 (55%) | 5/20 (25%) |

To apply the recommendation, set in `backend/.env`:

```
AEGIS_SEVERITY_THRESHOLD=2
AEGIS_ESCALATION_THRESHOLD=0.3
AEGIS_MIN_CATEGORY_CONFIDENCE=0.4
AEGIS_MIN_SEVERITY_CONFIDENCE=0.0
```

## Top 5 settings tried (540 in total)

| Severity ≥ | Escalation ≥ | Min cat. conf. | Min sev. conf. | Missed serious | Unknown not reviewed | AI runs | Reviews |
|---|---|---|---|---|---|---|---|
| 2 | 0.3 | 0.4 | 0.0 | 0 | 0 | 15 | 5 |
| 3 | 0.3 | 0.4 | 0.0 | 0 | 0 | 15 | 5 |
| 2 | 0.3 | 0.0 | 0.0 | 0 | 0 | 15 | 5 |
| 3 | 0.3 | 0.0 | 0.0 | 0 | 0 | 15 | 5 |
| 2 | 0.3 | 0.6 | 0.0 | 0 | 0 | 15 | 7 |

## Every alert (current rule)

| Alert | Expected | Jev says | Escalation | Confidence (cat / sev) | Decision |
|---|---|---|---|---|---|
| cal-01 | application, Critical | unknown, Critical | 0.94 | 0.60 / 1.00 | AI + review |
| cal-02 | database, Critical | database, High | 0.86 | 1.00 / 0.51 | AI + review |
| cal-03 | security, Critical | security, Critical | 0.88 | 1.00 / 0.74 | AI |
| cal-04 | security, Critical | security, Moderate | 0.92 | 1.00 / 0.10 | AI + review |
| cal-05 | infrastructure, Critical | infrastructure, High | 0.84 | 1.00 / 0.99 | AI |
| cal-06 | application, High | application, High | 0.77 | 1.00 / 0.95 | AI |
| cal-07 | dependency, High | dependency, Moderate | 0.38 | 1.00 / 0.59 | AI + review |
| cal-08 | infrastructure, High | dependency, High | 0.78 | 0.44 / 0.81 | AI + review |
| cal-09 | database, High | database, Moderate | 0.46 | 1.00 / 0.77 | skip AI ⚠ missed |
| cal-10 | dependency, High | dependency, High | 0.45 | 1.00 / 0.83 | AI |
| cal-11 | application, Moderate | unknown, Moderate | 0.19 | 0.48 / 0.97 | AI + review |
| cal-12 | infrastructure, Moderate | infrastructure, Low | 0.12 | 0.96 / 0.64 | skip AI |
| cal-13 | application, Moderate | application, Moderate | 0.45 | 0.41 / 0.60 | AI + review |
| cal-14 | database, Moderate | database, Low | 0.12 | 1.00 / 0.99 | skip AI |
| cal-15 | infrastructure, Moderate | infrastructure, Moderate | 0.11 | 0.63 / 0.31 | AI + review |
| cal-16 | infrastructure, Low | application, Low | 0.11 | 0.60 / 0.98 | skip AI |
| cal-17 | application, Low | application, Low | 0.04 | 0.63 / 0.83 | skip AI |
| cal-18 | database, Low | unknown, Low | 0.07 | 0.46 / 1.00 | AI + review |
| cal-19 | unknown, Moderate | unknown, Low | 0.21 | 0.50 / 0.57 | AI + review |
| cal-20 | unknown, Low | unknown, Moderate | 0.25 | 0.51 / 0.79 | AI + review |
