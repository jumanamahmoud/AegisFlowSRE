"""
backend/routers/incidents.py
=============================
AegisFlow – Incidents router.

Mounts at ``/incidents`` (prefix set in main.py).

Endpoints                                                    minimum role
---------                                                    ------------
GET    /                          — list incidents             viewer
                                    (?needs_review=true is the human review queue, FR-14)
POST   /                          — create an incident         responder
POST   /analyze                   — queue an analysis (202)    responder
GET    /{incident_id}             — incident + analysis_status viewer
POST   /{incident_id}/review      — mark triage reviewed       responder
PATCH  /{incident_id}/status      — lifecycle (FR-15)          responder
GET    /{incident_id}/analyses    — saved analyses             viewer
GET    /{incident_id}/timeline    — audit timeline (FR-17)     viewer

Every endpoint requires a signed-in user (FR-32, see core/auth.py); the
audit ``actor`` is always the authenticated user, never request input.

NOTE: ``POST /analyze`` is defined before ``/{incident_id}`` routes so FastAPI
does not interpret the literal string "analyze" as an ``incident_id``.

"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from supabase import Client

from core.auth import Principal, Role, require_role
from core.logging import request_id_var
from database.incident_store import (
    AnalysisAlreadyPendingError,
    ConcurrentUpdateError,
    DuplicateActiveIncidentError,
    IncidentNotFoundError,
    IncidentStore,
    ReviewNotPendingError,
)
from database.supabase_client import get_supabase
from models.incident import IncidentStatus, InvalidTransitionError
from services.analysis_queue import AnalysisQueue, get_analysis_queue

# ---------------------------------------------------------------------------
# Dependencies (overridden in tests)
# ---------------------------------------------------------------------------


def get_store(client: Client = Depends(get_supabase)) -> IncidentStore:
    return IncidentStore(client)


viewer = require_role(Role.VIEWER)
responder = require_role(Role.RESPONDER)

AnalysisStatus = Literal["none", "queued", "running", "completed", "failed"]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IncidentCreateRequest(BaseModel):
    """Payload for creating a new incident record."""

    service_id: str = Field(min_length=1, max_length=200)
    alert: str = Field(min_length=1, max_length=20000)
    metadata: dict = {}


class IncidentAnalyzeRequest(BaseModel):
    """Payload for triggering a full pipeline analysis.

    Omit ``incident_id`` to create a new incident for this alert; pass it to
    re-analyse an existing incident (its stored alert and service are used).
    """

    service_id: str = Field(min_length=1, max_length=200)
    alert: str = Field(min_length=1, max_length=20000)
    incident_id: Optional[str] = None
    metadata: dict = {}


class IncidentResponse(BaseModel):
    """Shape of an incident record returned from Supabase."""

    id: str
    service_id: str
    alert: str
    metadata: dict
    created_at: str
    status: IncidentStatus = IncidentStatus.OPEN
    incident_category: Optional[str] = None
    severity: Optional[str] = None
    updated_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    closed_at: Optional[str] = None
    analysis_status: AnalysisStatus = "none"
    analysis_error: Optional[str] = None
    analysis_updated_at: Optional[str] = None
    source: Optional[str] = None
    # Phase 4: grouping (FR-13) and human review (FR-14)
    probable_cause: Optional[dict[str, Any]] = None
    grouped_services: list[str] = []
    needs_review: bool = False
    review_reasons: list[str] = []
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None


class ReviewRequest(BaseModel):
    note: Optional[str] = Field(default=None, max_length=2000)


class StatusChangeRequest(BaseModel):
    status: IncidentStatus
    note: Optional[str] = Field(default=None, max_length=2000)


class AnalyzeAcceptedResponse(BaseModel):
    """Returned at once; poll ``status_url`` until analysis_status is
    'completed' (then read /analyses) or 'failed'."""

    incident_id: str
    analysis_status: AnalysisStatus
    status_url: str
    analyses_url: str


class AnalysisResponse(BaseModel):
    id: str
    incident_id: str
    incident_category: str
    severity_score: int
    severity: str
    escalation_noul: float
    needs_escalation: bool
    analysis_source: str
    llm_reasoning: Optional[str] = None
    model_name: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    llm_latency_ms: Optional[int] = None
    category_confidence: Optional[float] = None
    severity_confidence: Optional[float] = None
    needs_review: bool = False
    review_reasons: list[str] = []
    service_context: list = []
    blast_radius: list = []
    started_at: str
    completed_at: str
    created_at: str


class AuditEventResponse(BaseModel):
    id: int
    incident_id: Optional[str]
    event_type: str
    actor: str
    payload: dict[str, Any]
    occurred_at: str
    recorded_at: str


def _incident(record: dict) -> IncidentResponse:
    return IncidentResponse(**{
        **record,
        "metadata": record.get("metadata") or {},
        "grouped_services": record.get("grouped_services") or [],
        "review_reasons": record.get("review_reasons") or [],
        "needs_review": bool(record.get("needs_review")),
    })


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["incidents"])


@router.post(
    "/analyze", status_code=status.HTTP_202_ACCEPTED, response_model=AnalyzeAcceptedResponse
)
def analyze_incident(
    payload: IncidentAnalyzeRequest,
    store: IncidentStore = Depends(get_store),
    queue: AnalysisQueue = Depends(get_analysis_queue),
    user: Principal = Depends(responder),
) -> AnalyzeAcceptedResponse:
    """POST /incidents/analyze — Store the alert, queue the analysis, return 202.

    The incident is written *before* any processing, so an alert is never lost
    even if the analysis later fails or the server restarts (it is resumed).
    Omit ``incident_id`` to create a new incident; pass it to re-analyse one.
    409 if an analysis of that incident is already queued or running.
    """
    try:
        if payload.incident_id is None:
            incident_id = store.create_incident(
                payload.service_id, payload.alert, payload.metadata, actor=user.actor
            )["id"]
        else:
            incident_id = payload.incident_id
        store.enqueue_analysis(incident_id, actor=user.actor, request_id=request_id_var.get())
    except IncidentNotFoundError:
        raise _not_found()
    except AnalysisAlreadyPendingError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))

    queue.submit(incident_id)
    return AnalyzeAcceptedResponse(
        incident_id=incident_id,
        analysis_status="queued",
        status_url=f"/incidents/{incident_id}",
        analyses_url=f"/incidents/{incident_id}/analyses",
    )


@router.get("/", response_model=list[IncidentResponse])
def list_incidents(
    status_filter: Optional[IncidentStatus] = Query(default=None, alias="status"),
    needs_review: Optional[bool] = None,
    service_id: Optional[str] = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(viewer),
) -> list[IncidentResponse]:
    """GET /incidents/ — Newest first. ``?needs_review=true`` lists incidents
    whose triage was uncertain and is waiting for a person (FR-14)."""
    rows = store.list_incidents(
        status=status_filter.value if status_filter else None,
        needs_review=needs_review, service_id=service_id, limit=limit,
    )
    return [_incident(r) for r in rows]


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=IncidentResponse)
def create_incident(
    payload: IncidentCreateRequest,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(responder),
) -> IncidentResponse:
    """POST /incidents/ — Create an incident in status ``open``."""
    created = store.create_incident(payload.service_id, payload.alert, payload.metadata, actor=user.actor)
    return _incident(created)


@router.get("/{incident_id}", status_code=status.HTTP_200_OK, response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(viewer),
) -> IncidentResponse:
    """GET /incidents/{incident_id} — Retrieve a single incident, or 404."""
    try:
        return _incident(store.get_incident(incident_id))
    except IncidentNotFoundError:
        raise _not_found()


@router.post("/{incident_id}/review", response_model=IncidentResponse)
def complete_review(
    incident_id: str,
    payload: ReviewRequest,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(responder),
) -> IncidentResponse:
    """POST /incidents/{incident_id}/review — A person has checked an uncertain
    triage (FR-14). Clears the flag and records who reviewed it and when.
    409 if no review is pending. (Correcting the category or severity is FR-18,
    Phase 6.)"""
    try:
        return _incident(store.complete_review(incident_id, user.actor, payload.note))
    except IncidentNotFoundError:
        raise _not_found()
    except ReviewNotPendingError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This incident is not waiting for review")


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
def change_incident_status(
    incident_id: str,
    payload: StatusChangeRequest,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(responder),
) -> IncidentResponse:
    """PATCH /incidents/{incident_id}/status — Lifecycle transition (FR-15).

    409 when the move is not allowed or the status changed concurrently.
    """
    try:
        updated = store.change_status(incident_id, payload.status, user.actor, payload.note)
    except IncidentNotFoundError:
        raise _not_found()
    except (InvalidTransitionError, ConcurrentUpdateError, DuplicateActiveIncidentError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _incident(updated)


@router.get("/{incident_id}/analyses", response_model=list[AnalysisResponse])
def list_incident_analyses(
    incident_id: str,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(viewer),
) -> list[dict]:
    """GET /incidents/{incident_id}/analyses — Saved analyses, newest first."""
    try:
        return store.list_analyses(incident_id)
    except IncidentNotFoundError:
        raise _not_found()


@router.get("/{incident_id}/timeline", response_model=list[AuditEventResponse])
def get_incident_timeline(
    incident_id: str,
    store: IncidentStore = Depends(get_store),
    user: Principal = Depends(viewer),
) -> list[dict]:
    """GET /incidents/{incident_id}/timeline — Audit events, oldest first (FR-17)."""
    try:
        return store.get_timeline(incident_id)
    except IncidentNotFoundError:
        raise _not_found()
