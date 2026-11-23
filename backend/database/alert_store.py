"""
backend/database/alert_store.py
================================
Supabase reads and writes for received alerts and maintenance windows
(Week 3, see ``supabase/migrations/*_week3_alert_intake.sql``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from supabase import Client

from services.alert_sources import NormalizedAlert

ALERTS = "alerts"
WINDOWS = "maintenance_windows"

DISPOSITIONS = ("received", "created", "deduplicated", "suppressed", "resolved", "ignored")


class AlertNotFoundError(LookupError):
    pass


class WindowNotFoundError(LookupError):
    pass


class WindowAlreadyCancelledError(RuntimeError):
    pass


def utc_iso(value: datetime | None = None) -> str:
    """One timestamp format everywhere (UTC, ISO 8601)."""
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


class AlertStore:
    def __init__(self, client: Client) -> None:
        self._sb = client

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def insert_alerts(
        self, alerts: list[NormalizedAlert], received_by: str, api_key_id: str | None = None
    ) -> list[dict]:
        """Store alerts *before* any processing (one insert, so all or none)."""
        if not alerts:
            return []
        now = utc_iso()
        rows = [
            {
                "source": a.source,
                "external_id": a.external_id,
                "fingerprint": a.fingerprint,
                "status": a.status,
                "service_id": a.service_id,
                "title": a.title,
                "description": a.description,
                "source_severity": a.source_severity,
                "labels": a.labels,
                "url": a.url,
                "starts_at": a.starts_at,
                "raw": a.raw,
                "disposition": "received",
                "api_key_id": api_key_id,
                "received_by": received_by,
                "received_at": now,
            }
            for a in alerts
        ]
        return self._sb.table(ALERTS).insert(rows).execute().data

    def mark(
        self,
        alert_id: str,
        disposition: str,
        incident_id: str | None = None,
        maintenance_window_id: str | None = None,
    ) -> None:
        assert disposition in DISPOSITIONS and disposition != "received"
        self._sb.table(ALERTS).update(
            {
                "disposition": disposition,
                "incident_id": incident_id,
                "maintenance_window_id": maintenance_window_id,
                "processed_at": utc_iso(),
            }
        ).eq("id", alert_id).execute()

    def get_alert(self, alert_id: str) -> dict:
        if not _is_uuid(alert_id):
            raise AlertNotFoundError(alert_id)
        rows = self._sb.table(ALERTS).select("*").eq("id", alert_id).execute().data
        if not rows:
            raise AlertNotFoundError(alert_id)
        return rows[0]

    def list_alerts(
        self,
        *,
        incident_id: str | None = None,
        source: str | None = None,
        disposition: str | None = None,
        service_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        q = self._sb.table(ALERTS).select("*")
        if incident_id is not None:
            if not _is_uuid(incident_id):
                return []
            q = q.eq("incident_id", incident_id)
        if source is not None:
            q = q.eq("source", source)
        if disposition is not None:
            q = q.eq("disposition", disposition)
        if service_id is not None:
            q = q.eq("service_id", service_id)
        return q.order("received_at", desc=True).limit(limit).execute().data

    def unprocessed(self, limit: int = 500) -> list[dict]:
        """Alerts stored but never processed (e.g. the server stopped), oldest first."""
        return (
            self._sb.table(ALERTS)
            .select("*")
            .eq("disposition", "received")
            .order("received_at")
            .limit(limit)
            .execute()
            .data
        )

    # ------------------------------------------------------------------
    # Maintenance windows (FR-4)
    # ------------------------------------------------------------------

    def create_window(
        self, service_id: str, starts_at: datetime, ends_at: datetime, reason: str | None, created_by: str
    ) -> dict:
        return (
            self._sb.table(WINDOWS)
            .insert(
                {
                    "service_id": service_id,
                    "starts_at": utc_iso(starts_at),
                    "ends_at": utc_iso(ends_at),
                    "reason": reason,
                    "created_by": created_by,
                }
            )
            .execute()
            .data[0]
        )

    def get_window(self, window_id: str) -> dict:
        if not _is_uuid(window_id):
            raise WindowNotFoundError(window_id)
        rows = self._sb.table(WINDOWS).select("*").eq("id", window_id).execute().data
        if not rows:
            raise WindowNotFoundError(window_id)
        return rows[0]

    def list_windows(self, *, service_id: str | None = None, current_or_future: bool = True) -> list[dict]:
        q = self._sb.table(WINDOWS).select("*").is_("cancelled_at", "null")
        if service_id is not None:
            q = q.eq("service_id", service_id)
        if current_or_future:
            q = q.gt("ends_at", utc_iso())
        return q.order("starts_at").execute().data

    def active_window(self, service_id: str, at: str | None = None) -> dict | None:
        """The maintenance window covering ``service_id`` at time ``at`` (default now)."""
        at = at or utc_iso()
        rows = (
            self._sb.table(WINDOWS)
            .select("*")
            .eq("service_id", service_id)
            .is_("cancelled_at", "null")
            .lte("starts_at", at)
            .gt("ends_at", at)
            .order("ends_at", desc=True)
            .limit(1)
            .execute()
            .data
        )
        return rows[0] if rows else None

    def cancel_window(self, window_id: str, cancelled_by: str) -> dict:
        window = self.get_window(window_id)
        if window.get("cancelled_at"):
            raise WindowAlreadyCancelledError(window_id)
        updated = (
            self._sb.table(WINDOWS)
            .update({"cancelled_at": utc_iso(), "cancelled_by": cancelled_by})
            .eq("id", window_id)
            .is_("cancelled_at", "null")
            .execute()
            .data
        )
        if not updated:
            raise WindowAlreadyCancelledError(window_id)
        return updated[0]
