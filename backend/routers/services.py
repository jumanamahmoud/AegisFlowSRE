"""
backend/routers/services.py
============================
Service map management (FR-29). Mounted at ``/services``.

Endpoints                                              who
---------                                              ---
GET  /services                                         viewer   list services (?include_retired=true)
GET  /services/{id}                                    viewer   one service, its dependencies,
                                                                 dependents and blast radius
GET  /services/{id}/dependencies?at=<ISO time>         viewer   dependencies now, or at a past moment
GET  /services/{id}/history                            viewer   every dependency link ever, with dates
POST /services                                         admin    add a service
PATCH /services/{id}                                   admin    rename / change type or tier
POST /services/{id}/retire                             admin    retire it (closes all its links)
PUT  /services/{id}/dependencies                       admin    add or change a dependency
POST /services/{id}/dependencies/remove                admin    end a dependency

Nothing is deleted: retiring closes links with an end date, so the map as it
was during any past incident can be read back (``?at=``). Every change is
recorded on the audit timeline.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from supabase import Client

from core.auth import Principal, Role, require_role
from database.incident_store import IncidentStore
from database.neo4j_client import (
    InvalidDependencyError,
    Neo4jClient,
    ServiceExistsError,
    ServiceNotFoundError,
    get_neo4j_client,
)
from database.supabase_client import get_supabase
from models.incident import AuditEventType

router = APIRouter(tags=["services"])

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")
TargetKind = Literal["service", "external"]


class ServiceCreateRequest(BaseModel):
    id: str = Field(description="Lower-case id used in alerts, e.g. payment-service")
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(default="service", min_length=1, max_length=50)
    tier: Optional[str] = Field(default=None, max_length=50)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID.match(v):
            raise ValueError("id must be lower-case letters, digits, '.', '_' or '-' (max 100 characters)")
        return v


class ServiceUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    type: Optional[str] = Field(default=None, min_length=1, max_length=50)
    tier: Optional[str] = Field(default=None, max_length=50)


class DependencyRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=200)
    target_kind: TargetKind = "service"
    protocol: str = Field(default="HTTPS", min_length=1, max_length=30)
    target_type: Optional[str] = Field(default=None, max_length=50,
                                       description="For a new external system, e.g. database or cache")


class DependencyRemoveRequest(BaseModel):
    target_id: str = Field(min_length=1, max_length=200)
    target_kind: TargetKind = "service"


class ServiceResponse(BaseModel):
    id: str
    name: str
    type: str
    tier: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    retired_at: Optional[str] = None


class LinkResponse(BaseModel):
    id: str
    name: str
    type: str
    kind: str
    protocol: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None


class ImpactedResponse(BaseModel):
    id: str
    name: Optional[str] = None
    hops: int


class ServiceDetailResponse(ServiceResponse):
    dependencies: list[LinkResponse]
    dependents: list[LinkResponse]
    blast_radius: list[ImpactedResponse]


class DependencyChangeResponse(BaseModel):
    service_id: str
    target_id: str
    target_kind: str
    result: str  # created | updated | unchanged | removed


def _not_found(what: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Service not found: {what}")


def _audit(sb: Client, event: AuditEventType, payload: dict, actor: str) -> None:
    IncidentStore(sb).append_event(None, event, payload, actor=actor)


viewer = require_role(Role.VIEWER)
admin = require_role(Role.ADMIN)


# ---------------------------------------------------------------------------
# Reading the map
# ---------------------------------------------------------------------------


@router.get("", response_model=list[ServiceResponse])
@router.get("/", response_model=list[ServiceResponse], include_in_schema=False)
def list_services(
    include_retired: bool = False,
    graph: Neo4jClient = Depends(get_neo4j_client),
    user: Principal = Depends(viewer),
) -> list[dict]:
    return graph.list_services(include_retired=include_retired)


@router.get("/{service_id}", response_model=ServiceDetailResponse)
def get_service(
    service_id: str,
    graph: Neo4jClient = Depends(get_neo4j_client),
    user: Principal = Depends(viewer),
) -> dict:
    service = graph.get_service(service_id)
    if service is None:
        raise _not_found(service_id)
    return {
        **service,
        "dependencies": graph.get_dependencies(service_id),
        "dependents": graph.get_dependents(service_id),
        "blast_radius": [] if service.get("retired_at") else graph.get_blast_radius(service_id),
    }


@router.get("/{service_id}/dependencies", response_model=list[LinkResponse])
def get_dependencies(
    service_id: str,
    at: Optional[datetime] = Query(default=None, description="ISO time with timezone; omit for now"),
    graph: Neo4jClient = Depends(get_neo4j_client),
    user: Principal = Depends(viewer),
) -> list[dict]:
    if at is not None and at.tzinfo is None:
        raise HTTPException(status_code=422, detail="'at' must include a timezone, e.g. 2026-11-24T09:00:00Z")
    if graph.get_service(service_id) is None:
        raise _not_found(service_id)
    return graph.get_dependencies(service_id, at=at.isoformat() if at else None)


@router.get("/{service_id}/history", response_model=list[LinkResponse])
def get_history(
    service_id: str,
    graph: Neo4jClient = Depends(get_neo4j_client),
    user: Principal = Depends(viewer),
) -> list[dict]:
    if graph.get_service(service_id) is None:
        raise _not_found(service_id)
    return graph.get_dependency_history(service_id)


# ---------------------------------------------------------------------------
# Changing the map (administrators, audited)
# ---------------------------------------------------------------------------


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ServiceResponse)
@router.post("/", status_code=status.HTTP_201_CREATED, response_model=ServiceResponse, include_in_schema=False)
def create_service(
    payload: ServiceCreateRequest,
    graph: Neo4jClient = Depends(get_neo4j_client),
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(admin),
) -> dict:
    try:
        created = graph.create_service(payload.id, payload.name, payload.type, payload.tier)
    except ServiceExistsError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Service '{payload.id}' already exists (it may be retired)")
    _audit(sb, AuditEventType.SERVICE_CREATED, payload.model_dump(), user.actor)
    return created


@router.patch("/{service_id}", response_model=ServiceResponse)
def update_service(
    service_id: str,
    payload: ServiceUpdateRequest,
    graph: Neo4jClient = Depends(get_neo4j_client),
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(admin),
) -> dict:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Nothing to change")
    try:
        updated = graph.update_service(service_id, changes)
    except ServiceNotFoundError:
        raise _not_found(service_id)
    _audit(sb, AuditEventType.SERVICE_UPDATED, {"service_id": service_id, "changes": changes}, user.actor)
    return updated


@router.post("/{service_id}/retire", response_model=ServiceResponse)
def retire_service(
    service_id: str,
    graph: Neo4jClient = Depends(get_neo4j_client),
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(admin),
) -> dict:
    try:
        closed = graph.retire_service(service_id)
    except ServiceNotFoundError:
        raise _not_found(service_id)
    _audit(sb, AuditEventType.SERVICE_RETIRED, {"service_id": service_id, "links_closed": closed}, user.actor)
    return graph.get_service(service_id)


@router.put("/{service_id}/dependencies", response_model=DependencyChangeResponse)
def set_dependency(
    service_id: str,
    payload: DependencyRequest,
    graph: Neo4jClient = Depends(get_neo4j_client),
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(admin),
) -> DependencyChangeResponse:
    try:
        result = graph.set_dependency(service_id, payload.target_id, payload.target_kind,
                                      payload.protocol, payload.target_type)
    except ServiceNotFoundError as exc:
        raise _not_found(str(exc))
    except InvalidDependencyError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if result != "unchanged":
        _audit(sb, AuditEventType.DEPENDENCY_SET,
               {"service_id": service_id, **payload.model_dump(), "result": result}, user.actor)
    return DependencyChangeResponse(service_id=service_id, target_id=payload.target_id,
                                    target_kind=payload.target_kind, result=result)


@router.post("/{service_id}/dependencies/remove", response_model=DependencyChangeResponse)
def remove_dependency(
    service_id: str,
    payload: DependencyRemoveRequest,
    graph: Neo4jClient = Depends(get_neo4j_client),
    sb: Client = Depends(get_supabase),
    user: Principal = Depends(admin),
) -> DependencyChangeResponse:
    if not graph.remove_dependency(service_id, payload.target_id, payload.target_kind):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"'{service_id}' has no active dependency on '{payload.target_id}'")
    _audit(sb, AuditEventType.DEPENDENCY_REMOVED, {"service_id": service_id, **payload.model_dump()}, user.actor)
    return DependencyChangeResponse(service_id=service_id, target_id=payload.target_id,
                                    target_kind=payload.target_kind, result="removed")
