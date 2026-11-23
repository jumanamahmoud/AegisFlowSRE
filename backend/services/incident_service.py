"""
backend/services/incident_service.py
=====================================
Glue between the LangGraph pipeline and Supabase.

``analyze_and_record`` is the Week-1 "save every analysis" flow:

    incident (open) ─► analysis.started ─► [pipeline: graph.enriched,
    triage.completed, ai.invoked | ai.fallback | ai.skipped] ─► analysis row
    saved ─► analysis.saved

Every step lands on the incident's immutable audit timeline. If the pipeline
raises, an ``analysis.failed`` event is written before the error propagates,
so failed runs are visible too.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from database.incident_store import IncidentStore
from models.incident import AuditEventType


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_pipeline(alert: str, service_id: str) -> dict:
    from engine.langgraph_pipeline import execute_pipeline  # deferred: import has side effects

    return execute_pipeline(alert, service_id)


def build_analysis_record(state: dict, started_at: str, completed_at: str) -> dict:
    """Map final pipeline state to an ``incident_analyses`` row."""
    jev = state["jev_results"]
    final = state["final_response"]
    meta = state.get("llm_meta") or {}
    return {
        "incident_category": jev["incident_category"],
        "severity_score": jev["severity_score"],
        "severity": final["severity"],
        "escalation_noul": jev["escalation_noul"],
        "needs_escalation": final["needs_escalation"],
        "analysis_source": meta.get("analysis_source", "skipped"),
        "llm_reasoning": final.get("llm_reasoning"),
        "model_name": meta.get("model_name"),
        "prompt_tokens": meta.get("prompt_tokens"),
        "completion_tokens": meta.get("completion_tokens"),
        "total_tokens": meta.get("total_tokens"),
        "llm_latency_ms": meta.get("llm_latency_ms"),
        "service_context": state.get("service_context") or [],
        "blast_radius": final.get("blast_radius") or [],
        "started_at": started_at,
        "completed_at": completed_at,
    }


def analyze_and_record(
    store: IncidentStore,
    alert: str,
    service_id: str,
    incident_id: str | None = None,
    metadata: dict | None = None,
    pipeline: Callable[[str, str], dict] = _default_pipeline,
) -> dict[str, Any]:
    """Run the pipeline for an incident and persist the result + timeline.

    Creates the incident (status ``open``) when ``incident_id`` is not given.
    Returns ``{"incident": ..., "analysis": ..., "final_response": ...}``.
    """
    if incident_id is None:
        incident = store.create_incident(service_id, alert, metadata)
    else:
        incident = store.get_incident(incident_id)
        # Analyse what is stored, not whatever the caller re-sent.
        alert, service_id = incident["alert"], incident["service_id"]
    incident_id = incident["id"]

    started_at = _now_iso()
    store.append_event(
        incident_id, AuditEventType.ANALYSIS_STARTED, {"service_id": service_id}, occurred_at=started_at
    )

    try:
        state = pipeline(alert, service_id)
    except Exception as exc:
        store.append_event(
            incident_id,
            AuditEventType.ANALYSIS_FAILED,
            {"error_type": type(exc).__name__, "error": str(exc)[:500]},
        )
        raise

    completed_at = _now_iso()
    store.append_events(incident_id, state.get("trace") or [])

    analysis = store.save_analysis(
        incident_id, build_analysis_record(state, started_at, completed_at)
    )
    store.append_event(
        incident_id,
        AuditEventType.ANALYSIS_SAVED,
        {
            "analysis_id": analysis["id"],
            "analysis_source": analysis["analysis_source"],
            "model_name": analysis.get("model_name"),
            "total_tokens": analysis.get("total_tokens"),
        },
    )

    return {
        "incident": store.get_incident(incident_id),
        "analysis": analysis,
        "final_response": state["final_response"],
    }
