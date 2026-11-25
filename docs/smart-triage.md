# Smart triage (Phase 4: FR-13, FR-14, FR-29)

Phase 4 adds three things to triage:

- related alerts are grouped into one incident, using the service map
- uncertain triage results go to a person instead of being silently skipped
- the service map can be managed through the API

The triage thresholds were also calibrated on 20 labelled sample alerts.

## 1. Grouping related alerts (FR-13)

When a firing alert would open a new incident, AegisFlow first looks at the
active incidents opened in the last `AEGIS_GROUPING_WINDOW_MINUTES` (default
10). It groups the alert into one of them when either:

- the incident is for **the same service**, or
- the two services **share a dependency** within `AEGIS_GROUPING_MAX_HOPS` links (default 2).

For example, checkout-service and order-service both depend on
payment-service, so their alerts become one incident.

```
checkout-service ──┐
                   ├──► payment-service ──► payment-db
order-service ─────┘
```

The shared component closest to both services becomes the incident's
**probable cause**:

- a service counts as depending on itself, so if one service depends on the
  other, the other one is the cause
- the probable cause gets closer as more alerts arrive

The grouped alert:

- gets disposition `grouped`
- shows up in the incident's `grouped_services` and its `probable_cause`
- adds an `alert.grouped` event to the timeline, naming the shared component

A grouped alert does not start a second AI analysis.

**Order of the rules for a firing alert:**

1. Maintenance window: `suppressed`.
2. Repeat of an alert already in an active incident: `deduplicated`. This
   also covers repeats of grouped alerts, even after the grouping window.
3. Related to a recent active incident: `grouped`.
4. Otherwise: `created`, and the analysis is queued.

**Safe by default:**

- If Neo4j can't be reached, the alert opens its own incident. Grouping never
  causes an alert to be lost.
- Alerts with no known service (`unknown-service`) are never grouped.
- Turn grouping off with `AEGIS_GROUPING=0`.

**Known limit:** two related alerts that arrive at exactly the same moment
can still open two incidents. Grouping isn't protected by a database lock the
way duplicate detection is.

## 2. Uncertain triage goes to a person (FR-14)

Jev reports how confident it is in the category and the severity. These
scores are now stored with every analysis (`category_confidence`,
`severity_confidence`). The decision rule lives in one small file,
[`backend/engine/triage_policy.py`](../backend/engine/triage_policy.py):

| Run the AI analysis when | Ask for human review when |
|---|---|
| severity ≥ `AEGIS_SEVERITY_THRESHOLD` (2), or | the category is `unknown`, or |
| escalation ≥ `AEGIS_ESCALATION_THRESHOLD` (0.5), or | category confidence < `AEGIS_MIN_CATEGORY_CONFIDENCE` (0.6), or |
| a review is needed | severity confidence < `AEGIS_MIN_SEVERITY_CONFIDENCE` (0.6) |

An uncertain alert is therefore **never silently skipped**. The AI analysis
still runs, so the reviewer has something to read. The incident gets
`needs_review = true` plus the reasons, and the timeline shows
`triage.review_requested`.

- **Review queue:** `GET /incidents?needs_review=true`
- **Mark reviewed** (responder): `POST /incidents/{id}/review` with `{"note": "..."}`.
  This records who reviewed it and when (`triage.reviewed`). Correcting the
  category or severity is FR-18 (Phase 6).
- A later analysis that is still uncertain flags the incident again. A
  confident one never clears a pending review by itself.

## 3. Calibration

[`docs/calibration/triage-calibration.md`](calibration/triage-calibration.md)
is the report for Checkpoint 1. It was produced by:

```powershell
cd backend
python -m scripts.calibrate_triage
```

The script runs Jev only (no AI analysis) on the 20 labelled alerts in
`backend/samples/calibration/alerts.json`. It scores the current rule, tries
540 threshold combinations and recommends one. The priorities are:

1. no serious alert skips the AI analysis
2. every "unknown" alert reaches a person
3. as few unnecessary AI runs and reviews as possible

To re-score saved results without calling Jev again, add `--from-results <file>`.

The recommendation is **not applied automatically**. To use it, change the
`AEGIS_*` values in `backend/.env`. The labels are one responder's
judgement, so review them with the supervisor.

## 4. Service map management (FR-29)

| | |
|---|---|
| `GET /services` (`?include_retired=true`) | list services |
| `GET /services/{id}` | details, dependencies, dependents and blast radius |
| `GET /services/{id}/dependencies?at=2026-11-24T09:00:00Z` | the dependencies **as they were** at that time |
| `GET /services/{id}/history` | every link it ever had, with start and end dates |
| `POST /services` (admin) | add a service: `{"id": "payment-service", "name": "Payment Service", "tier": "critical"}` |
| `PATCH /services/{id}` (admin) | rename, or change type or tier |
| `POST /services/{id}/retire` (admin) | retire the service and close all its links |
| `PUT /services/{id}/dependencies` (admin) | add or change a link: `{"target_id": "payment-db", "target_kind": "external", "protocol": "TCP"}` |
| `POST /services/{id}/dependencies/remove` (admin) | end a link |

Nothing is ever deleted:

- changing a link's protocol closes the old link and starts a new one
- sending the same link again writes no new history
- every change is recorded on the audit timeline

## Setup and checks

1. Apply `supabase/migrations/20261125000000_phase4_smart_triage.sql` in the
   Supabase SQL Editor. **Do this before running the new code:** saving an
   analysis needs the new columns.
2. Automated tests: `python -m pytest` (the grouping "done when" is in
   `tests/test_grouping.py::TestDoneWhen`).
3. Live tests:
   - service map queries, against your Neo4j (they create and then remove
     their own `it-...` test nodes):
     `$env:AEGIS_RUN_INTEGRATION=1; python -m pytest tests/test_integration_service_map.py -v`
   - grouping, with the server running and the service map seeded:
     `python -m scripts.check_grouping`
