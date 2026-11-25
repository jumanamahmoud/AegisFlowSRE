"""
backend/services/alert_intake.py
=================================
What happens to an alert after it arrives (FR-1 to FR-4, System Workflow
steps 1–2).

1. **Store first.** Every alert is written to ``public.alerts`` before any
   processing, so it can't be lost; anything left unprocessed by a restart is
   picked up again by ``recover()``.
2. **Maintenance window** (FR-4). If the alert's service is in planned
   maintenance, the alert is recorded as ``suppressed``. No incident is
   opened, no analysis runs, and nobody is notified.
3. **Duplicate detection** (FR-3). If an active incident (open, acknowledged
   or mitigating) already has the alert's fingerprint, the alert is attached
   to it as ``deduplicated``. A unique index on ``incidents.fingerprint``
   makes this hold even when a tool retries the same alert concurrently.
4. **New incident.** Otherwise an incident is opened and its analysis is
   queued in the background (AEGIS_AUTO_ANALYZE, default on).

Recovery notices ("resolved" from the source) are attached to the active
incident's timeline but never change its status: resolving and closing stay
human decisions.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from database.alert_store import AlertStore
from database.incident_store import (
    AnalysisAlreadyPendingError,
    DuplicateActiveIncidentError,
    IncidentStore,
)
from models.incident import AuditEventType
from services.alert_sources import NormalizedAlert

logger = logging.getLogger(__name__)


def auto_analyze_enabled() -> bool:
    return os.environ.get("AEGIS_AUTO_ANALYZE", "1").strip().lower() not in ("0", "false", "no", "off")


@dataclass
class IntakeResult:
    alert_id: str
    disposition: str
    service_id: str
    fingerprint: str
    incident_id: Optional[str] = None
    maintenance_window_id: Optional[str] = None
    analysis_queued: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


class AlertIntake:
    def __init__(
        self,
        incidents: IncidentStore,
        alerts: AlertStore,
        queue=None,  # services.analysis_queue.AnalysisQueue; None = never analyse
        auto_analyze: bool | None = None,
    ) -> None:
        self._incidents = incidents
        self._alerts = alerts
        self._queue = queue
        self._auto_analyze = auto_analyze_enabled() if auto_analyze is None else auto_analyze

    # ------------------------------------------------------------------
    def receive(
        self,
        alerts: list[NormalizedAlert],
        actor: str,
        api_key_id: str | None = None,
        request_id: str | None = None,
    ) -> list[IntakeResult]:
        """Store then process a batch. Storage failure raises (the caller
        answers 503 so the tool retries); a processing failure leaves that
        alert ``received`` for ``recover()`` and does not fail the batch."""
        rows = self._alerts.insert_alerts(alerts, received_by=actor, api_key_id=api_key_id)
        results = []
        for row in rows:
            try:
                results.append(self.process(row, actor, request_id))
            except Exception:
                logger.exception("alert processing failed; will retry on restart",
                                 extra={"alert_id": row["id"]})
                results.append(IntakeResult(row["id"], "received", row["service_id"], row["fingerprint"]))
        return results

    # ------------------------------------------------------------------
    def process(self, row: dict, actor: str, request_id: str | None = None) -> IntakeResult:
        alert_id, fp, service_id = row["id"], row["fingerprint"], row["service_id"]
        base = {"alert_id": alert_id, "source": row["source"], "title": row["title"]}

        if row["status"] == "info":
            self._alerts.mark(alert_id, "ignored")
            return IntakeResult(alert_id, "ignored", service_id, fp)

        if row["status"] == "resolved":
            active = self._incidents.find_active_by_fingerprint(fp)
            if active is None:
                self._alerts.mark(alert_id, "ignored")
                return IntakeResult(alert_id, "ignored", service_id, fp)
            self._incidents.append_event(active["id"], AuditEventType.ALERT_RESOLVED_AT_SOURCE, base, actor=actor)
            self._alerts.mark(alert_id, "resolved", incident_id=active["id"])
            return IntakeResult(alert_id, "resolved", service_id, fp, incident_id=active["id"])

        # firing
        window = self._alerts.active_window(service_id, at=row.get("received_at"))
        if window is not None:
            self._incidents.append_event(
                None,
                AuditEventType.ALERT_SUPPRESSED,
                {**base, "service_id": service_id, "maintenance_window_id": window["id"]},
                actor=actor,
            )
            self._alerts.mark(alert_id, "suppressed", maintenance_window_id=window["id"])
            return IntakeResult(alert_id, "suppressed", service_id, fp, maintenance_window_id=window["id"])

        active = self._incidents.find_active_by_fingerprint(fp)
        if active is None:
            try:
                incident = self._incidents.create_incident(
                    service_id,
                    self._incident_text(row),
                    self._incident_metadata(row),
                    actor=actor,
                    source=row["source"],
                    fingerprint=fp,
                )
            except DuplicateActiveIncidentError:
                # Lost a race with a concurrent copy of this alert: use the winner.
                active = self._incidents.find_active_by_fingerprint(fp)
                if active is None:
                    raise
            else:
                self._incidents.append_event(incident["id"], AuditEventType.ALERT_RECEIVED, base, actor=actor)
                self._alerts.mark(alert_id, "created", incident_id=incident["id"])
                queued = self._queue_analysis(incident["id"], actor, request_id)
                return IntakeResult(alert_id, "created", service_id, fp, incident_id=incident["id"],
                                    analysis_queued=queued)

        self._incidents.append_event(active["id"], AuditEventType.ALERT_DEDUPLICATED, base, actor=actor)
        self._alerts.mark(alert_id, "deduplicated", incident_id=active["id"])
        return IntakeResult(alert_id, "deduplicated", service_id, fp, incident_id=active["id"])

    # ------------------------------------------------------------------
    def recover(self) -> int:
        """Process alerts stored by a previous run but never processed."""
        pending = self._alerts.unprocessed()
        for row in pending:
            try:
                self.process(row, actor=row.get("received_by") or "system")
            except Exception:
                logger.exception("could not recover alert", extra={"alert_id": row["id"]})
        if pending:
            logger.warning("recovered unprocessed alerts", extra={"count": len(pending)})
        return len(pending)

    # ------------------------------------------------------------------
    def _queue_analysis(self, incident_id: str, actor: str, request_id: str | None) -> bool:
        if not (self._auto_analyze and self._queue is not None):
            return False
        try:
            self._incidents.enqueue_analysis(incident_id, actor=actor, request_id=request_id)
        except AnalysisAlreadyPendingError:
            return True
        except Exception:
            # The incident exists; a responder can still start the analysis.
            logger.exception("could not queue analysis", extra={"incident_id": incident_id})
            return False
        self._queue.submit(incident_id)
        return True

    @staticmethod
    def _incident_text(row: dict) -> str:
        return NormalizedAlert(
            source=row["source"],
            status=row["status"],
            service_id=row["service_id"],
            title=row["title"],
            fingerprint=row["fingerprint"],
            description=row.get("description") or "",
            source_severity=row.get("source_severity"),
        ).incident_text()

    @staticmethod
    def _incident_metadata(row: dict) -> dict:
        meta = {
            "source": row["source"],
            "first_alert_id": row["id"],
            "labels": row.get("labels") or {},
        }
        for key in ("source_severity", "external_id", "url", "starts_at"):
            if row.get(key):
                meta[key] = row[key]
        return meta
