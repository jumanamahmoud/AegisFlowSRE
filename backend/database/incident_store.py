"""
backend/database/incident_store.py
===================================
All Supabase reads and writes for incidents, analyses and the audit timeline.

Routers and services talk to this module instead of building PostgREST
queries themselves, so the table layout lives in one place (see
``supabase/migrations/*_week1_foundation.sql``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from supabase import Client

from models.incident import (
    ACTIVE_STATUSES,
    AuditEventType,
    IncidentStatus,
    validate_transition,
)

INCIDENTS = "incidents"
ANALYSES = "incident_analyses"
AUDIT_EVENTS = "audit_events"
CHANGE_STATUS_FN = "change_incident_status"

# incidents.analysis_status values (see week2 migration)
ANALYSIS_IDLE = ("none", "completed", "failed")
ANALYSIS_PENDING = ("queued", "running")


class IncidentNotFoundError(LookupError):
    pass


class AnalysisAlreadyPendingError(RuntimeError):
    """An analysis for this incident is already queued or running."""


class ConcurrentUpdateError(RuntimeError):
    """The incident's status changed between our read and our write."""


class DuplicateActiveIncidentError(RuntimeError):
    """Another active incident already tracks this alert fingerprint
    (the ``incidents_active_fingerprint_uidx`` unique index fired)."""


def is_unique_violation(exc: Exception) -> bool:
    """True for Postgres error 23505 as surfaced by PostgREST / supabase-py."""
    return getattr(exc, "code", None) == "23505" or "23505" in str(exc)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


class IncidentStore:
    def __init__(self, client: Client) -> None:
        self._sb = client

    # ------------------------------------------------------------------
    # Audit timeline (FR-17) — insert-only, the DB rejects UPDATE/DELETE
    # ------------------------------------------------------------------

    def append_event(
        self,
        incident_id: str | None,
        event_type: AuditEventType | str,
        payload: dict[str, Any] | None = None,
        actor: str = "system",
        occurred_at: str | None = None,
    ) -> dict:
        row = {
            "incident_id": incident_id,
            "event_type": AuditEventType(event_type).value,
            "actor": actor,
            "payload": payload or {},
            "occurred_at": occurred_at or _now_iso(),
        }
        return self._sb.table(AUDIT_EVENTS).insert(row).execute().data[0]

    def append_events(self, incident_id: str, events: list[dict]) -> list[dict]:
        """Bulk-insert pipeline trace events (each: event_type, payload, occurred_at)."""
        if not events:
            return []
        rows = [
            {
                "incident_id": incident_id,
                "event_type": AuditEventType(e["event_type"]).value,
                "actor": e.get("actor", "system"),
                "payload": e.get("payload", {}),
                "occurred_at": e.get("occurred_at") or _now_iso(),
            }
            for e in events
        ]
        return self._sb.table(AUDIT_EVENTS).insert(rows).execute().data

    def get_timeline(self, incident_id: str) -> list[dict]:
        self.get_incident(incident_id)  # 404 for unknown incidents
        return (
            self._sb.table(AUDIT_EVENTS)
            .select("*")
            .eq("incident_id", incident_id)
            .order("occurred_at")
            .order("id")
            .execute()
            .data
        )

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(
        self,
        service_id: str,
        alert: str,
        metadata: dict | None = None,
        actor: str = "system",
        *,
        source: str | None = None,
        fingerprint: str | None = None,
    ) -> dict:
        """Insert an ``open`` incident and its ``incident.created`` event.

        With a ``fingerprint``, raises ``DuplicateActiveIncidentError`` if an
        active incident already has it (enforced by a unique index, so this
        holds even for concurrent requests).
        """
        row = {
            "service_id": service_id,
            "alert": alert,
            "metadata": metadata or {},
            "status": IncidentStatus.OPEN.value,
        }
        if source is not None:
            row["source"] = source
        if fingerprint is not None:
            row["fingerprint"] = fingerprint
        try:
            incident = self._sb.table(INCIDENTS).insert(row).execute().data[0]
        except Exception as exc:
            if fingerprint is not None and is_unique_violation(exc):
                raise DuplicateActiveIncidentError(fingerprint) from exc
            raise
        payload = {"service_id": service_id, "status": IncidentStatus.OPEN.value}
        if source is not None:
            payload["source"] = source
        self.append_event(incident["id"], AuditEventType.INCIDENT_CREATED, payload, actor=actor)
        return incident

    def find_active_by_fingerprint(self, fingerprint: str) -> dict | None:
        """The open/acknowledged/mitigating incident that owns ``fingerprint``."""
        rows = (
            self._sb.table(INCIDENTS)
            .select("*")
            .eq("fingerprint", fingerprint)
            .in_("status", [s.value for s in ACTIVE_STATUSES])
            .order("created_at", desc=True)
            .limit(1)
            .execute()
            .data
        )
        return rows[0] if rows else None

    def get_incident(self, incident_id: str) -> dict:
        # incidents.id is a Postgres uuid: a malformed value would make the
        # query itself fail (22P02 -> HTTP 500). It can't match any row, so
        # treat it as not found.
        if not _is_uuid(incident_id):
            raise IncidentNotFoundError(incident_id)
        rows =self._sb.table(INCIDENTS).select("*").eq("id", incident_id).execute().data
        if not rows:
            raise IncidentNotFoundError(incident_id)
        return rows[0]

    def change_status(
        self,
        incident_id: str,
        target: IncidentStatus | str,
        actor: str,
        note: str | None = None,
    ) -> dict:
        """Move an incident to ``target`` (FR-15) and record it on the timeline.

        Raises ``InvalidTransitionError`` for illegal jumps and
        ``ConcurrentUpdateError`` if another request changed the status first.
        """
        target = IncidentStatus(target)
        incident = self.get_incident(incident_id)
        current = IncidentStatus(incident["status"])
        validate_transition(current, target)

        # One DB transaction: compare-and-set update (only if the status is
        # still `current`) + the `incident.status_changed` audit event.
        # Either both are written or neither is. First-time timestamps
        # (STATUS_TIMESTAMP_COLUMN) are stamped inside the function.
        # See supabase/migrations/*_atomic_status_change.sql.
        try:
            updated = (
                self._sb.rpc(
                    CHANGE_STATUS_FN,
                    {
                        "p_incident_id": incident_id,
                        "p_from": current.value,
                        "p_to": target.value,
                        "p_actor": actor,
                        "p_note": note,
                    },
                )
                .execute()
                .data
            )
        except Exception as exc:
            if is_unique_violation(exc):
                # Re-opening, while a newer incident already tracks the same alert.
                raise DuplicateActiveIncidentError(
                    f"Cannot re-open incident {incident_id}: another active incident "
                    "already tracks the same alert"
                ) from exc
            if "PGRST202" in str(exc) or "Could not find the function" in str(exc):
                raise RuntimeError(
                    f"Database function {CHANGE_STATUS_FN} is missing. Apply "
                    "supabase/migrations/20261122000000_atomic_status_change.sql."
                ) from exc
            raise
        if not updated:
            raise ConcurrentUpdateError(
                f"Incident {incident_id} changed status while this request was in flight"
            )
        return updated[0]

    # ------------------------------------------------------------------
    # Analyses
    # ------------------------------------------------------------------

    def save_analysis(self, incident_id: str, record: dict) -> dict:
        """Persist one analysis and copy its classification onto the incident."""
        saved = (
            self._sb.table(ANALYSES)
            .insert({"incident_id": incident_id, **record})
            .execute()
            .data[0]
        )
        self._sb.table(INCIDENTS).update(
            {
                "incident_category": record["incident_category"],
                "severity": record["severity"],
            }
        ).eq("id", incident_id).execute()
        return saved

    def list_analyses(self, incident_id: str) -> list[dict]:
        self.get_incident(incident_id)
        return (
            self._sb.table(ANALYSES)
            .select("*")
            .eq("incident_id", incident_id)
            .order("created_at", desc=True)
            .execute()
            .data
        )

    # ------------------------------------------------------------------
    # Background analysis status
    # ------------------------------------------------------------------

    def enqueue_analysis(self, incident_id: str, actor: str, request_id: str | None = None) -> dict:
        """Mark an incident ``queued`` (compare-and-set) and record who asked.

        Raises ``AnalysisAlreadyPendingError`` if a run is already queued or
        running, so double-clicks can't start two analyses of one incident.
        """
        self.get_incident(incident_id)  # 404 for unknown ids
        updated = (
            self._sb.table(INCIDENTS)
            .update({"analysis_status": "queued", "analysis_error": None,
                     "analysis_updated_at": _now_iso()})
            .eq("id", incident_id)
            .in_("analysis_status", list(ANALYSIS_IDLE))
            .execute()
            .data
        )
        if not updated:
            raise AnalysisAlreadyPendingError(f"Analysis already pending for incident {incident_id}")
        self.append_event(
            incident_id, AuditEventType.ANALYSIS_QUEUED, {"request_id": request_id}, actor=actor
        )
        return updated[0]

    def mark_analysis_running(self, incident_id: str) -> bool:
        """queued -> running. False if the job was already taken or cancelled."""
        return bool(
            self._sb.table(INCIDENTS)
            .update({"analysis_status": "running", "analysis_updated_at": _now_iso()})
            .eq("id", incident_id)
            .eq("analysis_status", "queued")
            .execute()
            .data
        )

    def finish_analysis(self, incident_id: str, outcome: str, error: str | None = None) -> None:
        assert outcome in ("completed", "failed")
        self._sb.table(INCIDENTS).update(
            {"analysis_status": outcome, "analysis_error": error, "analysis_updated_at": _now_iso()}
        ).eq("id", incident_id).execute()

    def pending_analyses(self) -> list[str]:
        """Incidents left queued/running (e.g. by a restart), oldest first."""
        rows = (
            self._sb.table(INCIDENTS)
            .select("id")
            .in_("analysis_status", list(ANALYSIS_PENDING))
            .order("analysis_updated_at")
            .execute()
            .data
        )
        return [r["id"] for r in rows]

    def requeue_interrupted(self, incident_id: str) -> None:
        """running -> queued for a job whose worker died with the old process."""
        self._sb.table(INCIDENTS).update(
            {"analysis_status": "queued", "analysis_updated_at": _now_iso()}
        ).eq("id", incident_id).eq("analysis_status", "running").execute()
