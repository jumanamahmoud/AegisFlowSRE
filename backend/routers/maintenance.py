"""
backend/routers/maintenance.py
===============================
Planned maintenance windows (FR-4). Mounted at ``/maintenance-windows``.

While a window is active for a service, its alerts are recorded (status
``suppressed``) but open no incident, run no analysis and notify nobody.

GET  /maintenance-windows                 viewer     current and upcoming windows
POST /maintenance-windows                 responder  schedule a window (audited)
POST /maintenance-windows/{id}/cancel     responder  end/cancel a window early (audited)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, model_validator
from supabase import Client

from core.auth import Principal, Role, require_role
from database.alert_store import AlertStore, WindowAlreadyCancelledError, WindowNotFoundError
from database.incident_store import IncidentStore
from database.supabase_client import get_supabase
from models.incident import AuditEventType

router = APIRouter(tags=["maintenance"])

MAX_WINDOW = timedelta(days=14)


class WindowCreateRequest(BaseModel):
    service_id: str = Field(min_length=1, max_length=200)
    starts_at: Optional[datetime] = Field(default=None, description="Defaults to now")
    ends_at: datetime
    reason: Optional[str] = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _check_range(self):
        for name in ("starts_at", "ends_at"):
            value = getattr(self, name)
            if value is not None and value.tzinfo is None:
                raise ValueError(f"{name} must include a timezone, e.g. 2026-11-24T22:00:00Z")
        start = self.starts_at or datetime.now(timezone.utc)
        if self.ends_at <= start:
            raise ValueError("ends_at must be after starts_at")
        if self.ends_at <= datetime.now(timezone.utc):
            raise ValueError("ends_at is in the past")
        if self.ends_at - start > MAX_WINDOW:
            raise ValueError("a maintenance window can last at most 14 days")
        return self


class WindowResponse(BaseModel):
    id: str
    service_id: str
    starts_at: str
    ends_at: str
    reason: Optional[str] = None
    created_by: str
    created_at: str
    cancelled_at: Optional[str] = None
    cancelled_by: Optional[str] = None


def get_alert_store(sb: Client = Depends(get_supabase)) -> AlertStore:
    return AlertStore(sb)


def _window(row: dict) -> WindowResponse:
    return WindowResponse(**{k: row.get(k) for k in WindowResponse.model_fields})


@router.get("", response_model=list[WindowResponse])
@router.get("/", response_model=list[WindowResponse], include_in_schema=False)
def list_windows(
    service_id: Optional[str] = Query(default=None, max_length=200),
    store: AlertStore = Depends(get_alert_store),
    user: Principal = Depends(require_role(Role.VIEWER)),
) -> list[WindowResponse]:
    return [_window(r) for r in store.list_windows(service_id=service_id)]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=WindowResponse)
@router.post("/", status_code=status.HTTP_201_CREATED, response_model=WindowResponse, include_in_schema=False)
def create_window(
    payload: WindowCreateRequest,
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(require_role(Role.RESPONDER)),
) -> WindowResponse:
    starts = payload.starts_at or datetime.now(timezone.utc)
    row = AlertStore(sb).create_window(payload.service_id, starts, payload.ends_at, payload.reason, user.actor)
    IncidentStore(sb).append_event(
        None,
        AuditEventType.MAINTENANCE_SCHEDULED,
        {"window_id": row["id"], "service_id": row["service_id"], "starts_at": row["starts_at"],
         "ends_at": row["ends_at"], "reason": row.get("reason")},
        actor=user.actor,
    )
    return _window(row)


@router.post("/{window_id}/cancel", response_model=WindowResponse)
def cancel_window(
    window_id: str,
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(require_role(Role.RESPONDER)),
) -> WindowResponse:
    try:
        row = AlertStore(sb).cancel_window(window_id, user.actor)
    except WindowNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found")
    except WindowAlreadyCancelledError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Maintenance window is already cancelled")
    IncidentStore(sb).append_event(
        None,
        AuditEventType.MAINTENANCE_CANCELLED,
        {"window_id": window_id, "service_id": row["service_id"]},
        actor=user.actor,
    )
    return _window(row)
