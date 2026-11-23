"""
backend/tests/test_main.py
============================
Unit tests for the FastAPI lifespan and GET /health endpoint.

The main challenge: main.py imports ``routers.incidents`` and
``database.neo4j_client`` at module level, both of which touch external
services at import time (Supabase client init, Neo4j singleton).  We must
patch those before ``main`` is imported.

Strategy
--------
- All tests use a module-level import guard: we patch ``supabase.create_client``
  and ``neo4j.GraphDatabase.driver`` ONCE via sys.modules stubs so that
  ``import main`` never fires real network calls.
- For the health endpoint tests we use a minimal ``TestClient`` with
  ``raise_server_exceptions=False`` or direct endpoint mocking.
- For the lifespan test we construct a fresh ``TestClient(app)`` inside the
  test after patching all required env vars and connectivity calls.

Requirements: 5.2, 5.3, 5.4, 5.5, 5.6, 6.6
"""

from __future__ import annotations

import os
import sys
import importlib
from unittest.mock import MagicMock, patch, AsyncMock

import pytest


# ---------------------------------------------------------------------------
# Module-level stubs: prevent real Supabase/Neo4j calls during collection
# ---------------------------------------------------------------------------

def _stub_supabase() -> MagicMock:
    mock_sb = MagicMock()
    mock_sb.table.return_value.select.return_value.limit.return_value.execute.return_value.data = []
    mock_sb.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
    return mock_sb


_SUPABASE_STUB = _stub_supabase()


def _ensure_imports_patched():
    """Patch supabase and neo4j before any import of main or routers."""
    if "main" not in sys.modules:
        with (
            patch("supabase.create_client", return_value=_SUPABASE_STUB),
            patch("neo4j.GraphDatabase.driver", return_value=MagicMock()),
        ):
            import main as _main_mod  # noqa: F401


_ensure_imports_patched()
import main  # noqa: E402  — imported after stubs are in place


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALL_ENV_VARS = {
    "NEO4J_URI": "neo4j://localhost:7687",
    "NEO4J_USER": "neo4j",
    "NEO4J_PASSWORD": "testpassword",
    "GROQ_API_KEY": "test-groq-key",
    "SUPABASE_URL": "https://example.supabase.co",
    "SUPABASE_SECRET_KEY": "sb_secret_test_key",
}


@pytest.fixture
def all_env_vars(monkeypatch):
    """Set every required env var."""
    for k, v in ALL_ENV_VARS.items():
        monkeypatch.setenv(k, v)


# ---------------------------------------------------------------------------
# GET /health — shape and connectivity checks
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    """Tests for the GET /health endpoint (Requirement 6.6)."""

    def test_health_returns_correct_shape(self, all_env_vars):
        """GET /health returns HTTP 200 with neo4j.healthy and supabase.healthy keys."""
        from fastapi.testclient import TestClient

        mock_neo4j_client = MagicMock()
        mock_neo4j_client.verify_connectivity.return_value = True

        mock_sb = _stub_supabase()

        with (
            patch("main.get_neo4j_client", return_value=mock_neo4j_client),
            patch("main.get_supabase", return_value=mock_sb),
        ):
            # bypass_lifespan=True is not available in all versions; use raise_server_exceptions
            client = TestClient(main.app, raise_server_exceptions=True)
            # Health endpoint does not need lifespan — call it directly
            with patch.object(main.app.router, "lifespan_context", None):
                resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert "neo4j" in body
        assert "supabase" in body
        assert "healthy" in body["neo4j"]
        assert "healthy" in body["supabase"]

    def test_health_neo4j_unhealthy_when_connectivity_raises(self, all_env_vars):
        """When Neo4j verify_connectivity raises, neo4j.healthy must be False."""
        from fastapi.testclient import TestClient

        mock_neo4j_client = MagicMock()
        mock_neo4j_client.verify_connectivity.side_effect = ConnectionError("unreachable")
        mock_sb = _stub_supabase()

        with (
            patch("main.get_neo4j_client", return_value=mock_neo4j_client),
            patch("main.get_supabase", return_value=mock_sb),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["neo4j"]["healthy"] is False

    def test_health_supabase_unhealthy_when_client_raises(self, all_env_vars):
        """When the Supabase client cannot be built, supabase.healthy must be False."""
        from fastapi.testclient import TestClient

        mock_neo4j_client = MagicMock()
        mock_neo4j_client.verify_connectivity.return_value = True

        with (
            patch("main.get_neo4j_client", return_value=mock_neo4j_client),
            patch("main.get_supabase", side_effect=Exception("supabase down")),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.json()["supabase"]["healthy"] is False

    def test_health_both_healthy(self, all_env_vars):
        """Both services healthy → both healthy fields are True."""
        from fastapi.testclient import TestClient

        mock_neo4j_client = MagicMock()
        mock_neo4j_client.verify_connectivity.return_value = True
        mock_sb = _stub_supabase()

        with (
            patch("main.get_neo4j_client", return_value=mock_neo4j_client),
            patch("main.get_supabase", return_value=mock_sb),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            resp = client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["neo4j"]["healthy"] is True
        assert body["supabase"]["healthy"] is True


# ---------------------------------------------------------------------------
# Lifespan — startup validation
# ---------------------------------------------------------------------------

class TestLifespan:
    """Tests for the lifespan startup validation (Requirements 5.2–5.5)."""

    def test_lifespan_aborts_on_missing_neo4j_uri(self, monkeypatch):
        """Startup must abort with RuntimeError when NEO4J_URI is missing."""
        from fastapi.testclient import TestClient

        for k, v in ALL_ENV_VARS.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("NEO4J_URI")

        with (
            patch("main.load_dotenv"),  # prevent .env from restoring the var
            patch("main.get_neo4j_client"),
            patch("main.get_supabase", return_value=_stub_supabase()),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            with pytest.raises(Exception):
                # Entering the client context fires the lifespan
                with client:
                    pass

    def test_lifespan_aborts_on_missing_groq_api_key(self, monkeypatch):
        """Startup must abort with RuntimeError when GROQ_API_KEY is missing."""
        from fastapi.testclient import TestClient

        for k, v in ALL_ENV_VARS.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GROQ_API_KEY")

        with (
            patch("main.load_dotenv"),
            patch("main.get_neo4j_client"),
            patch("main.get_supabase", return_value=_stub_supabase()),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            with pytest.raises(Exception):
                with client:
                    pass

    def test_lifespan_succeeds_when_all_vars_set(self, monkeypatch):
        """Lifespan completes startup without raising when all vars are set."""
        from fastapi.testclient import TestClient

        for k, v in ALL_ENV_VARS.items():
            monkeypatch.setenv(k, v)

        mock_neo4j = MagicMock()
        mock_neo4j.verify_connectivity.return_value = True
        mock_neo4j.close = MagicMock()

        with (
            patch("main.load_dotenv"),
            patch("main.get_neo4j_client", return_value=mock_neo4j),
            patch("main.get_supabase", return_value=_stub_supabase()),
        ):
            client = TestClient(main.app, raise_server_exceptions=True)
            # Entering and exiting without exception means startup and shutdown succeeded
            with client:
                resp = client.get("/health")
            assert resp.status_code == 200

    def test_lifespan_aborts_on_missing_supabase_secret_key(self, monkeypatch):
        """The backend must not start without the secret key (no publishable fallback)."""
        from fastapi.testclient import TestClient

        for k, v in ALL_ENV_VARS.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("SUPABASE_SECRET_KEY")
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "sb_publishable_x")

        with (
            patch("main.load_dotenv"),
            patch("main.get_neo4j_client"),
            patch("main.get_supabase", return_value=_stub_supabase()),
        ):
            client = TestClient(main.app, raise_server_exceptions=False)
            with pytest.raises(RuntimeError, match="SUPABASE_SECRET_KEY"):
                with client:
                    pass

    def test_lifespan_accepts_legacy_url_and_service_role_names(self, monkeypatch):
        """NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are accepted aliases."""
        from fastapi.testclient import TestClient

        for k, v in ALL_ENV_VARS.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("SUPABASE_URL")
        monkeypatch.delenv("SUPABASE_SECRET_KEY")
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_URL", "https://example.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "legacy-service-role-jwt")

        mock_neo4j = MagicMock()
        with (
            patch("main.load_dotenv"),
            patch("main.get_neo4j_client", return_value=mock_neo4j),
            patch("main.get_supabase", return_value=_stub_supabase()),
        ):
            with TestClient(main.app) as client:
                assert client.get("/health").status_code == 200
