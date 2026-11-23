"""
backend/models/incident.py
===========================
Incident lifecycle rules (FR-15) and audit event vocabulary (FR-17).

Kept free of any I/O so the rules can be unit-tested and reused by the API,
background jobs and (later) Slack actions.
"""

from __future__ import annotations

from enum import Enum


class IncidentStatus(str, Enum):
    """Mirrors the ``public.incident_status`` Postgres enum."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


#: Every legal move. Anything not listed here is rejected.
#: - open → resolved covers false positives that need no mitigation.
#: - resolved → open re-opens an incident that recurred before it was closed.
#: - closed is terminal.
ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED}),
    IncidentStatus.ACKNOWLEDGED: frozenset({IncidentStatus.MITIGATING, IncidentStatus.RESOLVED}),
    IncidentStatus.MITIGATING: frozenset({IncidentStatus.RESOLVED}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED, IncidentStatus.OPEN}),
    IncidentStatus.CLOSED: frozenset(),
}

#: Timestamp column stamped the first time an incident enters each status.
STATUS_TIMESTAMP_COLUMN: dict[IncidentStatus, str] = {
    IncidentStatus.ACKNOWLEDGED: "acknowledged_at",
    IncidentStatus.RESOLVED: "resolved_at",
    IncidentStatus.CLOSED: "closed_at",
}


class InvalidTransitionError(ValueError):
    """Raised when a status change is not in ``ALLOWED_TRANSITIONS``."""

    def __init__(self, current: IncidentStatus, target: IncidentStatus) -> None:
        allowed = sorted(s.value for s in ALLOWED_TRANSITIONS[current])
        super().__init__(
            f"Cannot move incident from '{current.value}' to '{target.value}'. "
            f"Allowed: {allowed or 'none (terminal state)'}"
        )
        self.current = current
        self.target = target


def validate_transition(current: IncidentStatus | str, target: IncidentStatus | str) -> None:
    """Raise ``InvalidTransitionError`` unless ``current → target`` is allowed."""
    current = IncidentStatus(current)
    target = IncidentStatus(target)
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransitionError(current, target)


class AuditEventType(str, Enum):
    """Event types written to ``public.audit_events``."""

    INCIDENT_CREATED = "incident.created"
    STATUS_CHANGED = "incident.status_changed"
    ANALYSIS_QUEUED = "analysis.queued"
    ANALYSIS_STARTED = "analysis.started"
    ALERT_SANITIZED = "alert.sanitized"
    GRAPH_ENRICHED = "graph.enriched"
    TRIAGE_COMPLETED = "triage.completed"
    AI_INVOKED = "ai.invoked"
    AI_SKIPPED = "ai.skipped"
    AI_FALLBACK = "ai.fallback"
    ANALYSIS_SAVED = "analysis.saved"
    ANALYSIS_FAILED = "analysis.failed"
    USER_ROLE_CHANGED = "user.role_changed"
