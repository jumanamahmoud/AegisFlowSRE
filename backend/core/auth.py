"""
backend/core/auth.py
=====================
Login and roles (FR-32).

People sign in with Supabase Auth (the dashboard will do this in Week 5) and
send the access token they receive as ``Authorization: Bearer <token>``.
The backend verifies the token **locally** against the project's public
signing keys (JWKS, ES256/RS256), so no network call is made per request,
then looks up the user's role in ``public.user_roles``.

Roles are ordered: viewer < responder < admin. An endpoint declares the
minimum role it needs with ``Depends(require_role(Role.RESPONDER))``.

    viewer     read incidents, analyses, timelines, topology
    responder  + create/analyse incidents, change status
    admin      + manage the service map and user roles
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from database.supabase_client import get_supabase, supabase_url

logger = logging.getLogger(__name__)

_ALLOWED_ALGORITHMS = ["ES256", "RS256"]  # asymmetric only; never trust "none"/HS* from the header
_AUDIENCE = "authenticated"


class Role(str, Enum):
    VIEWER = "viewer"
    RESPONDER = "responder"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Role.VIEWER: 0, Role.RESPONDER: 1, Role.ADMIN: 2}


@dataclass(frozen=True)
class Principal:
    user_id: str
    email: str | None
    role: Role

    @property
    def actor(self) -> str:
        """How this person appears on the audit timeline."""
        return self.email or f"user:{self.user_id}"

    def has(self, minimum: Role) -> bool:
        return self.role.rank >= minimum.rank


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


class TokenVerifier:
    """Verifies Supabase access tokens against the project's JWKS."""

    def __init__(self, project_url: str, jwks_client: jwt.PyJWKClient | None = None) -> None:
        base = project_url.rstrip("/")
        self.issuer = f"{base}/auth/v1"
        self._jwks = jwks_client or jwt.PyJWKClient(
            f"{self.issuer}/.well-known/jwks.json",
            cache_keys=True,
            lifespan=600,  # re-fetch keys every 10 min to pick up rotation
            timeout=5,
        )

    def verify(self, token: str) -> dict:
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=_ALLOWED_ALGORITHMS,
                audience=_AUDIENCE,
                issuer=self.issuer,
                options={"require": ["exp", "sub", "iss", "aud"]},
                leeway=10,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token expired") from exc
        except (jwt.PyJWTError, jwt.PyJWKClientError) as exc:
            raise AuthError(f"invalid token: {type(exc).__name__}") from exc
        if claims.get("is_anonymous"):
            raise AuthError("anonymous sessions are not allowed")
        return claims


_verifier: TokenVerifier | None = None
_verifier_lock = threading.Lock()


def get_token_verifier() -> TokenVerifier:
    global _verifier
    with _verifier_lock:
        if _verifier is None:
            url = supabase_url()
            if not url:
                raise RuntimeError("Missing required env var: SUPABASE_URL")
            _verifier = TokenVerifier(url)
        return _verifier


# ---------------------------------------------------------------------------
# Role lookup (cached briefly so each request doesn't hit the database)
# ---------------------------------------------------------------------------


class RoleLookup:
    def __init__(self, client_factory: Callable = get_supabase, ttl_seconds: float = 30.0) -> None:
        self._client_factory = client_factory
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, Role | None]] = {}
        self._lock = threading.Lock()

    def role_for(self, user_id: str) -> Role | None:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(user_id)
            if hit and hit[0] > now:
                return hit[1]
        rows = (
            self._client_factory().table("user_roles").select("role").eq("user_id", user_id).execute().data
        )
        role = Role(rows[0]["role"]) if rows else None
        with self._lock:
            self._cache[user_id] = (now + self._ttl, role)
        return role

    def invalidate(self, user_id: str | None = None) -> None:
        with self._lock:
            if user_id is None:
                self._cache.clear()
            else:
                self._cache.pop(user_id, None)


_role_lookup = RoleLookup()


def get_role_lookup() -> RoleLookup:
    return _role_lookup


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    verifier: TokenVerifier = Depends(get_token_verifier),
    roles: RoleLookup = Depends(get_role_lookup),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise _unauthorized("Not authenticated")
    try:
        claims = verifier.verify(credentials.credentials)
    except AuthError as exc:
        logger.info("auth rejected", extra={"reason": str(exc)})
        raise _unauthorized("Invalid or expired token") from None

    user_id = claims["sub"]
    role = roles.role_for(user_id)
    if role is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No role assigned to this account")
    # Sync dependencies run in a worker thread, so a contextvar set here would
    # not reach the access-log middleware; request.state does.
    request.state.user_id = user_id
    return Principal(user_id=user_id, email=claims.get("email"), role=role)


def require_role(minimum: Role) -> Callable[..., Principal]:
    """Dependency factory: the caller must be signed in with at least ``minimum``."""

    def dependency(user: Principal = Depends(get_current_user)) -> Principal:
        if not user.has(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires the '{minimum.value}' role (you are '{user.role.value}')",
            )
        return user

    dependency.__name__ = f"require_{minimum.value}"
    return dependency
