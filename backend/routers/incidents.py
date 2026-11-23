"""
backend/routers/incidents.py
=============================
AegisFlow – Incidents router.

Mounts at ``/incidents`` (prefix set in main.py).

Endpoints
---------
POST   /                          — create an incident (status ``open``)
POST   /analyze                   — run the pipeline, persist analysis + timeline
GET    /{incident_id}             — retrieve a single incident
PATCH  /{incident_id}/status      — move through the lifecycle (FR-15)
GET    /{incident_id}/analyses    — every saved analysis, newest first
GET    /{incident_id}/timeline    — immutable audit timeline, oldest first (FR-17)

NOTE: ``POST /analyze`` is defined before ``/{incident_id}`` routes so FastAPI
does not interpret the literal string "analyze" as an ``incident_id``.

``actor`` fields are free text until login and roles arrive in Week 2 (FR-32);
they will then come from the authenticated user instead of the request body.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from supabase import Client

from database.incident_store import (
    ConcurrentUpdateError,
    IncidentNotFoundError,
    IncidentStore,
)
from database.supabase_client import get_supabase
from models.incident import IncidentStatus, InvalidTransitionError
from services.incident_service import _default_pipeline, analyze_and_record

# ---------------------------------------------------------------------------
# Dependencies (overridden in tests)
# ---------------------------------------------------------------------------


def get_store(client: Client = Depends(get_supabase)) -> IncidentStore:
    return IncidentStore(client)


def get_pipeline() -> Callable[[str, str], dict]:
    """Return the callable that runs the LangGraph pipeline and yields its full state."""
    return _default_pipeline


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IncidentCreateRequest(BaseModel):
    """Payload for creating a new incident record."""

    service_id: str
    alert: str
    metadata: dict = {}


class IncidentAnalyzeRequest(BaseModel):
    """Payload for triggering a full pipeline analysis.

    Omit ``incident_id`` to create a new incident for this alert; pass it to
    re-analyse an existing incident (its stored alert and service are used).
    """

    service_id: str
    alert: str
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


class StatusChangeRequest(BaseModel):
    status: IncidentStatus
    actor: str = Field(default="api", min_length=1, max_length=200)
    note: Optional[str] = Field(default=None, max_length=2000)


class AnalyzeResponse(BaseModel):
    """Pipeline output plus where it was stored."""

    incident_id: str
    analysis_id: str
    status: IncidentStatus
    incident_category: str
    severity: str
    needs_escalation: bool
    llm_reasoning: Optional[str]
    blast_radius: list
    analysis_source: str
    model_name: Optional[str] = None


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
    return IncidentResponse(**{**record, "metadata": record.get("metadata") or {}})


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["incidents"])


@router.post("/analyze", status_code=status.HTTP_200_OK, response_model=AnalyzeResponse)
def analyze_incident(
    payload: IncidentAnalyzeRequest,
    store: IncidentStore = Depends(get_store),
    pipeline: Callable[[str, str], dict] = Depends(get_pipeline),
) -> AnalyzeResponse:
    """POST /incidents/analyze — Run the pipeline and persist the analysis.

    The incident, the analysis (with model name, token usage and timings) and
    every pipeline step on the audit timeline are written to Supabase.
    """
    try:
        result = analyze_and_record(
            store,
            alert=payload.alert,
            service_id=payload.service_id,
            incident_id=payload.incident_id,
            metadata=payload.metadata,
            pipeline=pipeline,
        )
    except IncidentNotFoundError:
        raise _not_found()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Analysis failed: {type(exc).__name__}",
        ) from exc

    final = result["final_response"]
    analysis = result["analysis"]
    return AnalyzeResponse(
        incident_id=result["incident"]["id"],
        analysis_id=analysis["id"],
        status=result["incident"]["status"],
        incident_category=final["incident_category"],
        severity=final["severity"],
        needs_escalation=final["needs_escalation"],
        llm_reasoning=final["llm_reasoning"],
        blast_radius=final["blast_radius"],
        analysis_source=analysis["analysis_source"],
        model_name=analysis.get("model_name"),
    )


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=IncidentResponse)
def create_incident(
    payload: IncidentCreateRequest,
    store: IncidentStore = Depends(get_store),
) -> IncidentResponse:
    """POST /incidents/ — Create an incident in status ``open``."""
    created = store.create_incident(payload.service_id, payload.alert, payload.metadata, actor="api")
    return _incident(created)


@router.get("/{incident_id}", status_code=status.HTTP_200_OK, response_model=IncidentResponse)
def get_incident(incident_id: str, store: IncidentStore = Depends(get_store)) -> IncidentResponse:
    """GET /incidents/{incident_id} — Retrieve a single incident, or 404."""
    try:
        return _incident(store.get_incident(incident_id))
    except IncidentNotFoundError:
        raise _not_found()


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
def change_incident_status(
    incident_id: str,
    payload: StatusChangeRequest,
    store: IncidentStore = Depends(get_store),
) -> IncidentResponse:
    """PATCH /incidents/{incident_id}/status — Lifecycle transition (FR-15).

    409 when the move is not allowed or the status changed concurrently.
    """
    try:
        updated = store.change_status(incident_id, payload.status, payload.actor, payload.note)
    except IncidentNotFoundError:
        raise _not_found()
    except (InvalidTransitionError, ConcurrentUpdateError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _incident(updated)


@router.get("/{incident_id}/analyses", response_model=list[AnalysisResponse])
def list_incident_analyses(
    incident_id: str, store: IncidentStore = Depends(get_store)
) -> list[dict]:
    """GET /incidents/{incident_id}/analyses — Saved analyses, newest first."""
    try:
        return store.list_analyses(incident_id)
    except IncidentNotFoundError:
        raise _not_found()


@router.get("/{incident_id}/timeline", response_model=list[AuditEventResponse])
def get_incident_timeline(
    incident_id: str, store: IncidentStore = Depends(get_store)
) -> list[dict]:
    """GET /incidents/{incident_id}/timeline — Audit events, oldest first (FR-17)."""
    try:
        return store.get_timeline(incident_id)
    except IncidentNotFoundError:
        raise _not_found()
