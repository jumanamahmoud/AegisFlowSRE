"""
backend/routers/alerts.py
==========================
Alert intake (FR-1 to FR-3). Mounted at ``/alerts``.

Endpoints                                   who
---------                                   ---
POST /alerts/webhooks/{source}              monitoring tool, with an API key
POST /alerts                                responder: enter an alert by hand (FR-2)
GET  /alerts                                viewer: recent alerts, filterable
GET  /alerts/{alert_id}                     viewer: one alert, with its raw payload

``source`` is one of alertmanager, grafana, datadog, cloudwatch. Each webhook
call answers 202 with what happened to every alert it carried
(created / deduplicated / grouped / suppressed / resolved / ignored). Set-up for each
tool: docs/alert-intake.md.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Callable, Literal, Optional
from urllib.parse import parse_qs, urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from supabase import Client

from core.api_keys import MachinePrincipal, get_machine_principal
from core.auth import Principal, Role, require_role
from core.logging import request_id_var
from database.alert_store import AlertNotFoundError, AlertStore
from database.incident_store import IncidentStore
from database.neo4j_client import get_neo4j_client
from database.supabase_client import get_supabase
from models.incident import AuditEventType
from services.alert_intake import AlertIntake
from services.alert_sources import SOURCES, PayloadError, manual_alert, parse, sns_message_type
from services.analysis_queue import AnalysisQueue, get_analysis_queue

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alerts"])

AlertSource = Literal["alertmanager", "grafana", "datadog", "cloudwatch"]
Disposition = Literal["received", "created", "deduplicated", "grouped", "suppressed", "resolved", "ignored"]

MAX_BODY_BYTES = int(os.environ.get("AEGIS_WEBHOOK_MAX_BYTES", str(1024 * 1024)))
MAX_ALERTS_PER_CALL = int(os.environ.get("AEGIS_WEBHOOK_MAX_ALERTS", "200"))


# ---------------------------------------------------------------------------
# Dependencies (overridden in tests)
# ---------------------------------------------------------------------------


def get_alert_store(sb: Client = Depends(get_supabase)) -> AlertStore:
    return AlertStore(sb)


def get_service_map():
    """The Neo4j service map used to group related alerts (FR-13). If it can't
    be reached, alerts are still accepted, just not grouped across services."""
    try:
        return get_neo4j_client()
    except Exception:
        logger.warning("service map unavailable; cross-service grouping disabled", exc_info=True)
        return None


def get_alert_intake(
    sb: Client = Depends(get_supabase),
    queue: AnalysisQueue = Depends(get_analysis_queue),
    service_map=Depends(get_service_map),
) -> AlertIntake:
    return AlertIntake(IncidentStore(sb), AlertStore(sb), queue, service_map=service_map)


# --- AWS SNS subscription confirmation -------------------------------------

_SNS_HOST = re.compile(r"^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$")


def valid_sns_subscribe_url(url: str) -> bool:
    """Only ever fetch genuine SNS confirmation links (no SSRF via payloads)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.port in (None, 443)
        and not parsed.username
        and bool(parsed.hostname and _SNS_HOST.match(parsed.hostname))
        and parse_qs(parsed.query).get("Action") == ["ConfirmSubscription"]
    )


def _confirm_with_aws(url: str) -> None:
    resp = httpx.get(url, timeout=5.0, follow_redirects=False)
    resp.raise_for_status()


def get_sns_confirmer() -> Callable[[str], None]:
    return _confirm_with_aws


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class IntakeResultResponse(BaseModel):
    alert_id: str
    disposition: Disposition
    service_id: str
    fingerprint: str
    incident_id: Optional[str] = None
    maintenance_window_id: Optional[str] = None
    analysis_queued: bool = False
    grouped_via: Optional[dict[str, Any]] = None


class WebhookAcceptedResponse(BaseModel):
    source: str
    received: int
    results: list[IntakeResultResponse]


class ManualAlertRequest(BaseModel):
    service_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=8000)
    severity: Optional[str] = Field(default=None, max_length=20)
    fingerprint: Optional[str] = Field(
        default=None, max_length=200,
        description="Optional: alerts with the same fingerprint are treated as repeats. "
                    "Defaults to service + title.",
    )
    labels: dict[str, str] = {}


class AlertResponse(BaseModel):
    id: str
    source: str
    external_id: Optional[str] = None
    fingerprint: str
    status: str
    service_id: str
    title: str
    description: Optional[str] = None
    source_severity: Optional[str] = None
    labels: dict[str, Any] = {}
    url: Optional[str] = None
    starts_at: Optional[str] = None
    disposition: Disposition
    incident_id: Optional[str] = None
    maintenance_window_id: Optional[str] = None
    grouped_via: Optional[dict[str, Any]] = None
    received_by: str
    received_at: str
    processed_at: Optional[str] = None


class AlertDetailResponse(AlertResponse):
    raw: dict[str, Any] = {}


def _alert(row: dict, model=AlertResponse):
    data = {k: row.get(k) for k in model.model_fields}
    data["labels"] = row.get("labels") or {}
    if "raw" in model.model_fields:
        data["raw"] = row.get("raw") or {}
    return model(**data)


# ---------------------------------------------------------------------------
# Webhooks (machine access)
# ---------------------------------------------------------------------------


def _bad(code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


@router.post(
    "/webhooks/{source}",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=WebhookAcceptedResponse,
    responses={200: {"description": "AWS SNS subscription confirmed"}},
)
async def receive_webhook(
    source: AlertSource,
    request: Request,
    machine: MachinePrincipal = Depends(get_machine_principal),
    intake: AlertIntake = Depends(get_alert_intake),
    sb: Client = Depends(get_supabase),
    confirm_sns: Callable[[str], None] = Depends(get_sns_confirmer),
):
    """Receive alerts from a monitoring tool.

    The body is read by hand (not as a typed model) because AWS SNS posts JSON
    with ``Content-Type: text/plain`` and each tool has its own shape.
    """
    if machine.source is not None and machine.source != source:
        raise _bad(status.HTTP_403_FORBIDDEN, f"This API key may only post to /alerts/webhooks/{machine.source}")

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _bad(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Body larger than {MAX_BODY_BYTES} bytes")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise _bad(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, f"Body larger than {MAX_BODY_BYTES} bytes")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise _bad(status.HTTP_400_BAD_REQUEST, "Body is not valid JSON")

    # AWS SNS control messages (CloudWatch alarms delivered through SNS).
    if source == "cloudwatch" and sns_message_type(payload) in ("SubscriptionConfirmation", "UnsubscribeConfirmation"):
        return await run_in_threadpool(_handle_sns_control, payload, machine, sb, confirm_sns)

    try:
        alerts = parse(source, payload)
    except PayloadError as exc:
        raise _bad(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    if len(alerts) > MAX_ALERTS_PER_CALL:
        raise _bad(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                   f"{len(alerts)} alerts in one call; the limit is {MAX_ALERTS_PER_CALL}")

    request_id = request_id_var.get()
    try:
        results = await run_in_threadpool(
            intake.receive, alerts, machine.actor, machine.key_id, request_id
        )
    except Exception:
        logger.exception("could not store alerts", extra={"source": source})
        # 5xx makes the tool retry; duplicate detection absorbs the repeat.
        raise _bad(status.HTTP_503_SERVICE_UNAVAILABLE, "Alerts could not be stored; please retry")

    logger.info(
        "webhook received",
        extra={"source": source, "count": len(results),
               "dispositions": sorted({r.disposition for r in results})},
    )
    return WebhookAcceptedResponse(
        source=source, received=len(results), results=[IntakeResultResponse(**r.as_dict()) for r in results]
    )


def _handle_sns_control(payload: dict, machine: MachinePrincipal, sb: Client, confirm: Callable[[str], None]):
    from fastapi.responses import JSONResponse

    if payload.get("Type") == "UnsubscribeConfirmation":
        logger.warning("SNS topic unsubscribed", extra={"topic": payload.get("TopicArn")})
        return JSONResponse({"subscription": "unsubscribed"}, status_code=200)
    url = str(payload.get("SubscribeURL") or "")
    if not valid_sns_subscribe_url(url):
        raise _bad(status.HTTP_422_UNPROCESSABLE_ENTITY, "SubscribeURL is not an AWS SNS confirmation link")
    try:
        confirm(url)
    except Exception:
        logger.exception("SNS subscription confirmation failed")
        raise _bad(status.HTTP_502_BAD_GATEWAY, "Could not confirm the SNS subscription with AWS")
    IncidentStore(sb).append_event(
        None,
        AuditEventType.INTEGRATION_CONFIRMED,
        {"source": "cloudwatch", "topic_arn": payload.get("TopicArn")},
        actor=machine.actor,
    )
    return JSONResponse({"subscription": "confirmed"}, status_code=200)


# ---------------------------------------------------------------------------
# Manual entry and browsing (signed-in people)
# ---------------------------------------------------------------------------


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=IntakeResultResponse)
@router.post("/", status_code=status.HTTP_202_ACCEPTED, response_model=IntakeResultResponse,
             include_in_schema=False)
def submit_manual_alert(
    payload: ManualAlertRequest,
    intake: AlertIntake = Depends(get_alert_intake),
    user: Principal = Depends(require_role(Role.RESPONDER)),
) -> IntakeResultResponse:
    """Enter an alert by hand (FR-2). Same rules as webhooks: repeats attach to
    the open incident, and maintenance windows are respected."""
    alert = manual_alert(
        payload.service_id, payload.title, payload.description, payload.severity,
        payload.fingerprint, payload.labels,
    )
    try:
        [result] = intake.receive([alert], user.actor, request_id=request_id_var.get())
    except Exception:
        logger.exception("could not store manual alert")
        raise _bad(status.HTTP_503_SERVICE_UNAVAILABLE, "Alert could not be stored; please retry")
    return IntakeResultResponse(**result.as_dict())


@router.get("", response_model=list[AlertResponse])
@router.get("/", response_model=list[AlertResponse], include_in_schema=False)
def list_alerts(
    incident_id: Optional[str] = None,
    source: Optional[str] = Query(default=None, max_length=50),
    disposition: Optional[Disposition] = None,
    service_id: Optional[str] = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    alerts: AlertStore = Depends(get_alert_store),
    user: Principal = Depends(require_role(Role.VIEWER)),
) -> list[AlertResponse]:
    """Recent alerts, newest first."""
    rows = alerts.list_alerts(incident_id=incident_id, source=source, disposition=disposition,
                              service_id=service_id, limit=limit)
    return [_alert(r) for r in rows]


@router.get("/{alert_id}", response_model=AlertDetailResponse)
def get_alert(
    alert_id: str,
    alerts: AlertStore = Depends(get_alert_store),
    user: Principal = Depends(require_role(Role.VIEWER)),
) -> AlertDetailResponse:
    try:
        return _alert(alerts.get_alert(alert_id), AlertDetailResponse)
    except AlertNotFoundError:
        raise _bad(status.HTTP_404_NOT_FOUND, "Alert not found")


__all__ = ["router", "SOURCES"]
