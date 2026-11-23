"""
backend/routers/admin.py
=========================
Accounts and roles (FR-32).

GET  /auth/me                      — who am I, and what role do I have (any signed-in user)
GET  /admin/users                  — every account with its role (admin)
PUT  /admin/users/{user_id}/role   — change someone's role (admin, audited)

Accounts themselves are created through Supabase Auth (sign-up, or
Dashboard → Authentication → Add user). New accounts start as ``viewer``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from supabase import Client

from core.auth import Principal, Role, RoleLookup, get_current_user, get_role_lookup, require_role
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
