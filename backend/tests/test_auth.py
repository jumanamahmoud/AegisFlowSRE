"""
backend/tests/test_auth.py
===========================
Login and roles (FR-32), exercised with REAL signed tokens.

A throwaway ES256 key pair stands in for the Supabase project's signing key;
the verifier is the production TokenVerifier, only its JWKS source is local.
"""

from __future__ import annotations

import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import (
    AuthError,
    Principal,
    Role,
    RoleLookup,
    TokenVerifier,
    get_current_user,
    get_role_lookup,
    get_token_verifier,
)
from database.supabase_client import get_supabase
from routers.admin import admin_router, auth_router
from tests.fakes import FakeSupabase

PROJECT = "https://test-project.supabase.co"
ISSUER = f"{PROJECT}/auth/v1"
KID = "test-key-1"

_PRIVATE = ec.generate_private_key(ec.SECP256R1())
_OTHER_PRIVATE = ec.generate_private_key(ec.SECP256R1())


class _LocalJWKS:
    """Same interface as jwt.PyJWKClient, serving our test public key."""

    def __init__(self, public_key):
        self._key = public_key

    def get_signing_key_from_jwt(self, token):
        header = jwt.get_unverified_header(token)
        if header.get("kid") != KID:
            raise jwt.PyJWKClientError("Unable to find a signing key that matches")
        return type("SigningKey", (), {"key": self._key})()


def make_token(user_id=None, *, email="alice@example.com", key=_PRIVATE, alg="ES256",
               exp_in=3600, aud="authenticated", iss=ISSUER, kid=KID, **extra):
    now = int(time.time())
    claims = {"sub": user_id or str(uuid.uuid4()), "email": email, "aud": aud, "iss": iss,
              "iat": now, "exp": now + exp_in, "role": "authenticated", **extra}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


VERIFIER = TokenVerifier(PROJECT, jwks_client=_LocalJWKS(_PRIVATE.public_key()))


# ---------------------------------------------------------------------------
# TokenVerifier
# ---------------------------------------------------------------------------


class TestTokenVerifier:
    def test_valid_token(self):
        uid = str(uuid.uuid4())
        claims = VERIFIER.verify(make_token(uid))
        assert claims["sub"] == uid and claims["email"] == "alice@example.com"

    def test_expired_token(self):
        with pytest.raises(AuthError, match="expired"):
            VERIFIER.verify(make_token(exp_in=-120))

    def test_signed_by_another_key(self):
        with pytest.raises(AuthError):
            VERIFIER.verify(make_token(key=_OTHER_PRIVATE))

    def test_wrong_audience(self):
        with pytest.raises(AuthError):
            VERIFIER.verify(make_token(aud="anon"))

    def test_wrong_issuer(self):
        with pytest.raises(AuthError):
            VERIFIER.verify(make_token(iss="https://evil.supabase.co/auth/v1"))

    def test_unknown_key_id(self):
        with pytest.raises(AuthError):
            VERIFIER.verify(make_token(kid="rotated-away"))

    def test_hs256_token_rejected(self):
        """Algorithm confusion: an HMAC token must never be accepted."""
        now = int(time.time())
        forged = jwt.encode({"sub": "x", "aud": "authenticated", "iss": ISSUER, "exp": now + 60},
                            "secret", algorithm="HS256", headers={"kid": KID})
        with pytest.raises(AuthError):
            VERIFIER.verify(forged)

    def test_unsigned_token_rejected(self):
        now = int(time.time())
        unsigned = jwt.encode({"sub": "x", "aud": "authenticated", "iss": ISSUER, "exp": now + 60},
                              None, algorithm="none", headers={"kid": KID})
        with pytest.raises(AuthError):
            VERIFIER.verify(unsigned)

    def test_anonymous_session_rejected(self):
        with pytest.raises(AuthError, match="anonymous"):
            VERIFIER.verify(make_token(is_anonymous=True))

    def test_garbage(self):
        with pytest.raises(AuthError):
            VERIFIER.verify("not.a.jwt")


# ---------------------------------------------------------------------------
# Role lookup
# ---------------------------------------------------------------------------


class TestRoleLookup:
    def test_reads_role_and_caches(self):
        db = FakeSupabase()
        uid = str(uuid.uuid4())
        db.tables["user_roles"] = [{"user_id": uid, "role": "responder"}]
        calls = []
        lookup = RoleLookup(client_factory=lambda: calls.append(1) or db, ttl_seconds=60)
        assert lookup.role_for(uid) is Role.RESPONDER
        assert lookup.role_for(uid) is Role.RESPONDER
        assert len(calls) == 1

    def test_missing_row_is_none(self):
        lookup = RoleLookup(client_factory=FakeSupabase)
        assert lookup.role_for(str(uuid.uuid4())) is None

    def test_invalidate_rereads(self):
        db = FakeSupabase()
        uid = str(uuid.uuid4())
        db.tables["user_roles"] = [{"user_id": uid, "role": "viewer"}]
        lookup = RoleLookup(client_factory=lambda: db, ttl_seconds=60)
        assert lookup.role_for(uid) is Role.VIEWER
        db.tables["user_roles"][0]["role"] = "admin"
        assert lookup.role_for(uid) is Role.VIEWER  # cached
        lookup.invalidate(uid)
        assert lookup.role_for(uid) is Role.ADMIN

    def test_role_ordering(self):
        assert Role.ADMIN.rank > Role.RESPONDER.rank > Role.VIEWER.rank
        p = Principal("u", None, Role.RESPONDER)
        assert p.has(Role.VIEWER) and p.has(Role.RESPONDER) and not p.has(Role.ADMIN)
        assert p.actor == "user:u"


# ---------------------------------------------------------------------------
# End to end through HTTP: real token -> real dependency -> role from DB
# ---------------------------------------------------------------------------


class TestAuthHttp:
    def setup_method(self):
        self.db = FakeSupabase()
        self.db.tables["user_roles"] = []
        self.roles = RoleLookup(client_factory=lambda: self.db, ttl_seconds=60)
        app = FastAPI()
        app.include_router(auth_router, prefix="/auth")
        app.include_router(admin_router, prefix="/admin")
        app.dependency_overrides[get_token_verifier] = lambda: VERIFIER
        app.dependency_overrides[get_role_lookup] = lambda: self.roles
        app.dependency_overrides[get_supabase] = lambda: self.db
        self.client = TestClient(app)

    def add_user(self, role: str, email: str) -> tuple[str, str]:
        uid = str(uuid.uuid4())
        self.db.tables["user_roles"].append(
            {"user_id": uid, "role": role, "updated_at": "2026-11-23T00:00:00+00:00", "updated_by": "test"})
        self.db.auth_users.append({"id": uid, "email": email})
        return uid, make_token(uid, email=email)

    def get(self, path, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.get(path, headers=headers)

    def test_me_returns_identity_and_role(self):
        uid, token = self.add_user("responder", "alice@example.com")
        resp = self.get("/auth/me", token)
        assert resp.status_code == 200
        assert resp.json() == {"user_id": uid, "email": "alice@example.com", "role": "responder"}

    def test_no_header_401(self):
        resp = self.get("/auth/me")
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == "Bearer"

    def test_bad_token_401(self):
        assert self.get("/auth/me", "garbage").status_code == 401
        assert self.get("/auth/me", make_token(exp_in=-100)).status_code == 401

    def test_wrong_scheme_401(self):
        _, token = self.add_user("admin", "a@example.com")
        resp = self.client.get("/auth/me", headers={"Authorization": f"Basic {token}"})
        assert resp.status_code == 401

    def test_valid_token_without_role_row_403(self):
        resp = self.get("/auth/me", make_token(str(uuid.uuid4())))
        assert resp.status_code == 403
        assert resp.json()["detail"] == "No role assigned to this account"

    def test_admin_lists_users_with_emails(self):
        _, admin_token = self.add_user("admin", "boss@example.com")
        self.add_user("viewer", "carol@example.com")
        resp = self.get("/admin/users", admin_token)
        assert resp.status_code == 200
        assert [(u["email"], u["role"]) for u in resp.json()] == [
            ("boss@example.com", "admin"), ("carol@example.com", "viewer"),
        ]

    @pytest.mark.parametrize("role", ["viewer", "responder"])
    def test_non_admin_cannot_list_users(self, role):
        _, token = self.add_user(role, "x@example.com")
        assert self.get("/admin/users", token).status_code == 403

    def test_admin_promotes_user_and_it_is_audited(self):
        _, admin_token = self.add_user("admin", "boss@example.com")
        carol_id, carol_token = self.add_user("viewer", "carol@example.com")
        assert self.get("/auth/me", carol_token).json()["role"] == "viewer"  # cached now

        resp = self.client.put(f"/admin/users/{carol_id}/role", json={"role": "responder"},
                               headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "responder"
        assert resp.json()["updated_by"] == "boss@example.com"
        # cache invalidated: takes effect on carol's next request
        assert self.get("/auth/me", carol_token).json()["role"] == "responder"

        event = self.db.tables["audit_events"][-1]
        assert event["event_type"] == "user.role_changed"
        assert event["incident_id"] is None
        assert event["actor"] == "boss@example.com"
        assert event["payload"] == {"user_id": carol_id, "from": "viewer", "to": "responder"}

    def test_admin_cannot_change_own_role(self):
        admin_id, admin_token = self.add_user("admin", "boss@example.com")
        resp = self.client.put(f"/admin/users/{admin_id}/role", json={"role": "viewer"},
                               headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 409

    def test_change_role_unknown_user_404(self):
        _, admin_token = self.add_user("admin", "boss@example.com")
        headers = {"Authorization": f"Bearer {admin_token}"}
        assert self.client.put(f"/admin/users/{uuid.uuid4()}/role", json={"role": "viewer"},
                               headers=headers).status_code == 404
        assert self.client.put("/admin/users/not-a-uuid/role", json={"role": "viewer"},
                               headers=headers).status_code == 404

    def test_invalid_role_422(self):
        _, admin_token = self.add_user("admin", "boss@example.com")
        target, _ = self.add_user("viewer", "c@example.com")
        resp = self.client.put(f"/admin/users/{target}/role", json={"role": "superuser"},
                               headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 422

    def test_responder_cannot_promote(self):
        _, token = self.add_user("responder", "r@example.com")
        target, _ = self.add_user("viewer", "c@example.com")
        resp = self.client.put(f"/admin/users/{target}/role", json={"role": "admin"},
                               headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        assert self.db.tables["user_roles"][1]["role"] == "viewer"
