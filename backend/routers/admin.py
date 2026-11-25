"""
backend/routers/admin.py
=========================
Accounts and roles (FR-32).

GET  /auth/me                      — who am I, and what role do I have (any signed-in user)
GET  /admin/users                  — every account with its role (admin)
PUT  /admin/users/{user_id}/role   — change someone's role (admin, audited)
POST /admin/api-keys               — create a monitoring-tool key, shown once (admin, audited)
GET  /admin/api-keys               — list keys, never the secret itself (admin)
POST /admin/api-keys/{id}/revoke   — revoke a key immediately (admin, audited)

Accounts themselves are created through Supabase Auth (sign-up, or
Dashboard → Authentication → Add user). New accounts start as ``viewer``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from supabase import Client

from core.api_keys import ApiKeyLookup, create_api_key, get_api_key_lookup
from core.auth import Principal, Role, RoleLookup, get_current_user, get_role_lookup, require_role
from database.alert_store import utc_iso
from database.incident_store import IncidentStore
from database.supabase_client import get_supabase
from models.incident import AuditEventType

logger = logging.getLogger(__name__)

auth_router = APIRouter(tags=["auth"])
admin_router = APIRouter(tags=["admin"])


class MeResponse(BaseModel):
    user_id: str
    email: Optional[str]
    role: Role


class UserRoleResponse(BaseModel):
    user_id: str
    email: Optional[str] = None
    role: Role
    updated_at: Optional[str] = None
    updated_by: Optional[str] = None


class RoleChangeRequest(BaseModel):
    role: Role


@auth_router.get("/me", response_model=MeResponse)
def who_am_i(user: Principal = Depends(get_current_user)) -> MeResponse:
    return MeResponse(user_id=user.user_id, email=user.email, role=user.role)


def _emails_by_id(sb: Client) -> dict[str, str | None]:
    """Emails live in auth.users, reachable only through the Auth admin API."""
    emails: dict[str, str | None] = {}
    page = 1
    while True:
        users = sb.auth.admin.list_users(page=page, per_page=200)
        for u in users:
            emails[str(u.id)] = getattr(u, "email", None)
        if len(users) < 200:
            return emails
        page += 1


@admin_router.get("/users", response_model=list[UserRoleResponse])
def list_users(
    sb: Client = Depends(get_supabase),
    admin: Principal = Depends(require_role(Role.ADMIN)),
) -> list[UserRoleResponse]:
    rows = sb.table("user_roles").select("*").execute().data
    emails = _emails_by_id(sb)
    return [
        UserRoleResponse(email=emails.get(r["user_id"]), **r)
        for r in sorted(rows, key=lambda r: (emails.get(r["user_id"]) or "", r["user_id"]))
    ]


@admin_router.put("/users/{user_id}/role", response_model=UserRoleResponse)
def change_user_role(
    user_id: str,
    payload: RoleChangeRequest,
    sb: Client = Depends(get_supabase),
    roles: RoleLookup = Depends(get_role_lookup),
    admin: Principal = Depends(require_role(Role.ADMIN)),
) -> UserRoleResponse:
    try:
        uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user_id == admin.user_id:
        # Prevents an admin from accidentally locking everyone out.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="You cannot change your own role; ask another administrator")

    current = sb.table("user_roles").select("*").eq("user_id", user_id).execute().data
    if not current:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    previous = current[0]["role"]

    updated = (
        sb.table("user_roles")
        .update({"role": payload.role.value, "updated_by": admin.actor})
        .eq("user_id", user_id)
        .execute()
        .data[0]
    )
    roles.invalidate(user_id)  # takes effect on the user's next request
    IncidentStore(sb).append_event(
        None,
        AuditEventType.USER_ROLE_CHANGED,
        {"user_id": user_id, "from": previous, "to": payload.role.value},
        actor=admin.actor,
    )
    logger.info("role changed", extra={"target_user": user_id, "from": previous, "to": payload.role.value})
    return UserRoleResponse(**updated)


# ---------------------------------------------------------------------------
# Machine access keys for monitoring tools (Week 3)
# ---------------------------------------------------------------------------

AlertSource = Literal["alertmanager", "grafana", "datadog", "cloudwatch"]


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    source: Optional[AlertSource] = None  # None = may post to any webhook


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    source: Optional[str] = None
    created_by: str
    created_at: str
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    key: str  # shown exactly once


def _key_response(row: dict) -> ApiKeyResponse:
    return ApiKeyResponse(**{k: row.get(k) for k in ApiKeyResponse.model_fields})


@admin_router.post("/api-keys", status_code=status.HTTP_201_CREATED, response_model=ApiKeyCreatedResponse)
def create_key(
    payload: ApiKeyCreateRequest,
    sb: Client = Depends(get_supabase),
    admin: Principal = Depends(require_role(Role.ADMIN)),
) -> ApiKeyCreatedResponse:
    """Create a key for a monitoring tool. The ``key`` field is returned only
    in this response; store it in the tool's webhook settings straight away."""
    row, plaintext = create_api_key(sb, payload.name.strip(), payload.source, admin.actor)
    IncidentStore(sb).append_event(
        None,
        AuditEventType.API_KEY_CREATED,
        {"key_id": row["id"], "name": row["name"], "source": row.get("source")},
        actor=admin.actor,
    )
    logger.info("api key created", extra={"key_id": row["id"], "source": row.get("source")})
    return ApiKeyCreatedResponse(**_key_response(row).model_dump(), key=plaintext)


@admin_router.get("/api-keys", response_model=list[ApiKeyResponse])
def list_keys(
    sb: Client = Depends(get_supabase),
    admin: Principal = Depends(require_role(Role.ADMIN)),
) -> list[ApiKeyResponse]:
    rows = sb.table("api_keys").select("*").order("created_at", desc=True).execute().data
    return [_key_response(r) for r in rows]


@admin_router.post("/api-keys/{key_id}/revoke", response_model=ApiKeyResponse)
def revoke_key(
    key_id: str,
    sb: Client = Depends(get_supabase),
    lookup: ApiKeyLookup = Depends(get_api_key_lookup),
    admin: Principal = Depends(require_role(Role.ADMIN)),
) -> ApiKeyResponse:
    """Revoke a key. Takes effect immediately; it cannot be un-revoked."""
    try:
        uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    rows = sb.table("api_keys").select("*").eq("id", key_id).execute().data
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    if rows[0].get("revoked_at"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API key is already revoked")
    updated = (
        sb.table("api_keys")
        .update({"revoked_at": utc_iso(), "revoked_by": admin.actor})
        .eq("id", key_id)
        .is_("revoked_at", "null")
        .execute()
        .data
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API key is already revoked")
    lookup.invalidate()
    IncidentStore(sb).append_event(
        None, AuditEventType.API_KEY_REVOKED, {"key_id": key_id, "name": rows[0]["name"]}, actor=admin.actor
    )
    logger.info("api key revoked", extra={"key_id": key_id})
    return _key_response(updated[0])
