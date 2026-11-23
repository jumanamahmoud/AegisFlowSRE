"""
backend/tests/test_endpoints.py
=================================
Unit tests for the topology and incidents HTTP endpoints.
Requirements: 6.2, 6.3, 6.5, 10.3; FR-15, FR-17 (Week 1 foundation)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Imports — routers no longer touch Supabase or Neo4j at import time, but the
# Neo4j driver is still patched while importing in case a singleton is built.
# ---------------------------------------------------------------------------

_neo4j_patch = patch("neo4j.GraphDatabase.driver", return_value=MagicMock())
_neo4j_patch.start()

from fastapi import FastAPI
from fastapi.testclient import TestClient
from database.neo4j_client import get_neo4j_client as _orig_get_neo4j_client
from database.supabase_client import get_supabase
from routers.topology import router as topology_router
from routers.incidents import router as incidents_router, get_pipeline
from tests.conftest import make_pipeline_state
from tests.fakes import FakeSupabase

_neo4j_patch.stop()

# ---------------------------------------------------------------------------
# Shared minimal test app (no lifespan)
# ---------------------------------------------------------------------------

_test_app = FastAPI()
_test_app.include_router(topology_router, prefix="/topology")
_test_app.include_router(incidents_router, prefix="/incidents")

client = TestClient(_test_app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Topology router tests (Requirements 6.2, 6.3)
# ---------------------------------------------------------------------------

class TestTopologyIngest:
    """POST /topology/ingest — uses FastAPI dependency_overrides to inject mock Neo4j."""

    def setup_method(self):
        """Install a no-op Neo4jClient override before each test."""
        self._mock = MagicMock()
        self._mock.upsert_service_dependency.return_value = None
        _test_app.dependency_overrides[_orig_get_neo4j_client] = lambda: self._mock

    def teardown_method(self):
        """Remove all dependency overrides after each test."""
        _test_app.dependency_overrides.clear()

    def test_valid_payload_returns_200(self):
        """Requirement 6.2 — valid payload returns HTTP 200 with a message field."""
        resp = client.post(
            "/topology/ingest",
            json={
                "service_id": "payment-service",
                "service_name": "Payment Service",
                "external_system": "Stripe",
            },
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    def test_valid_payload_with_custom_protocol_returns_200(self):
        """An explicit protocol field must also succeed."""
        resp = client.post(
            "/topology/ingest",
            json={
                "service_id": "auth-service",
                "service_name": "Auth Service",
                "external_system": "Okta",
                "protocol": "OAuth2",
            },
        )
        assert resp.status_code == 200

    def test_missing_service_id_returns_422(self):
        """Requirement 6.3 — missing service_id returns HTTP 422."""
        resp = client.post(
            "/topology/ingest",
            json={"service_name": "Payment Service", "external_system": "Stripe"},
        )
        assert resp.status_code == 422

    def test_missing_service_name_returns_422(self):
        """Requirement 6.3 — missing service_name returns HTTP 422."""
        resp = client.post(
            "/topology/ingest",
            json={"service_id": "svc-1", "external_system": "Stripe"},
        )
        assert resp.status_code == 422

    def test_missing_external_system_returns_422(self):
        """Requirement 6.3 — missing external_system returns HTTP 422."""
        resp = client.post(
            "/topology/ingest",
            json={"service_id": "svc-1", "service_name": "Payment Service"},
        )
        assert resp.status_code == 422

    def test_empty_body_returns_422(self):
        """An empty body must return HTTP 422."""
        resp = client.post("/topology/ingest", json={})
        assert resp.status_code == 422

    def test_upsert_called_with_correct_args(self):
        """upsert_service_dependency must receive the exact payload values."""
        client.post(
            "/topology/ingest",
            json={
                "service_id": "svc-1",
                "service_name": "My Service",
                "external_system": "Postgres",
                "protocol": "TCP",
            },
        )
        self._mock.upsert_service_dependency.assert_called_once_with(
            service_id="svc-1",
            service_name="My Service",
            external_system="Postgres",
            protocol="TCP",
        )


# ---------------------------------------------------------------------------
# Incidents router tests (Requirements 6.4, 6.5, 10.3; FR-15, FR-17)
# ---------------------------------------------------------------------------


class _IncidentsTestBase:
    """Wires an in-memory Supabase and a fake pipeline into the app."""

    pipeline_kwargs: dict = {}

    def setup_method(self):
        self.db = FakeSupabase()
        self.pipeline_calls: list[tuple[str, str]] = []

        def fake_pipeline(alert, service_id):
            self.pipeline_calls.append((alert, service_id))
            return make_pipeline_state(**self.pipeline_kwargs)

        self.fake_pipeline = fake_pipeline
        _test_app.dependency_overrides[get_supabase] = lambda: self.db
        _test_app.dependency_overrides[get_pipeline] = lambda: self.fake_pipeline

    def teardown_method(self):
        _test_app.dependency_overrides.clear()

    def _create(self, **overrides) -> dict:
        body = {"service_id": "payment-service", "alert": "HTTP 500 on checkout", **overrides}
        resp = client.post("/incidents/", json=body)
        assert resp.status_code == 201, resp.text
        return resp.json()

    def _analyze(self, **overrides) -> dict:
        body = {"service_id": "payment-service", "alert": "DB pool exhausted", **overrides}
        resp = client.post("/incidents/analyze", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _event_types(self, incident_id: str) -> list[str]:
        resp = client.get(f"/incidents/{incident_id}/timeline")
        assert resp.status_code == 200
        return [e["event_type"] for e in resp.json()]


class TestIncidentsCrud(_IncidentsTestBase):
    """POST /incidents/ and GET /incidents/{id}."""

    def test_get_incident_not_found_returns_404(self):
        resp = client.get("/incidents/nonexistent-uuid")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Incident not found"

    def test_create_incident_returns_201_with_open_status(self):
        created = self._create(metadata={"env": "prod"})
        assert created["id"]
        assert created["status"] == "open"
        assert created["metadata"] == {"env": "prod"}

    def test_created_incident_can_be_read_back(self):
        created = self._create()
        resp = client.get(f"/incidents/{created['id']}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == created["id"]
        assert body["service_id"] == "payment-service"
        assert body["status"] == "open"

    def test_create_incident_writes_audit_event(self):
        created = self._create()
        timeline = client.get(f"/incidents/{created['id']}/timeline").json()
        assert len(timeline) == 1
        assert timeline[0]["event_type"] == "incident.created"
        assert timeline[0]["actor"] == "api"


class TestAnalyzePersistence(_IncidentsTestBase):
    """POST /incidents/analyze persists analysis + timeline (Week 1 'done when')."""

    def test_analyze_returns_pipeline_output_and_ids(self):
        body = self._analyze()
        assert body["incident_id"]
        assert body["analysis_id"]
        assert body["status"] == "open"
        assert body["incident_category"] == "database"
        assert body["severity"] == "Critical"
        assert body["needs_escalation"] is True
        assert body["llm_reasoning"].startswith("Root cause")
        assert body["analysis_source"] == "llm"
        assert body["model_name"] == "openai/gpt-oss-120b"
        assert body["blast_radius"][0]["id"] == "checkout-service"

    def test_analyzed_incident_is_saved_and_read_back(self):
        """End to end: analyse, then read incident, analysis and timeline via the API."""
        body = self._analyze()
        incident_id = body["incident_id"]

        incident = client.get(f"/incidents/{incident_id}").json()
        assert incident["status"] == "open"
        assert incident["incident_category"] == "database"
        assert incident["severity"] == "Critical"

        analyses = client.get(f"/incidents/{incident_id}/analyses").json()
        assert len(analyses) == 1
        a = analyses[0]
        assert a["id"] == body["analysis_id"]
        assert a["severity_score"] == 3
        assert a["escalation_noul"] == 0.9
        assert a["analysis_source"] == "llm"
        assert a["model_name"] == "openai/gpt-oss-120b"
        assert (a["prompt_tokens"], a["completion_tokens"], a["total_tokens"]) == (412, 230, 642)
        assert a["llm_latency_ms"] == 1840
        assert a["service_context"][0]["name"] == "payment-db"
        assert a["started_at"] <= a["completed_at"]

        assert self._event_types(incident_id) == [
            "incident.created",
            "analysis.started",
            "graph.enriched",
            "triage.completed",
            "ai.invoked",
            "analysis.saved",
        ]

    def test_timeline_is_chronological_with_payloads(self):
        incident_id = self._analyze()["incident_id"]
        timeline = client.get(f"/incidents/{incident_id}/timeline").json()
        stamps = [e["occurred_at"] for e in timeline]
        assert stamps == sorted(stamps)
        saved = timeline[-1]
        assert saved["payload"]["analysis_source"] == "llm"
        assert saved["payload"]["total_tokens"] == 642
        assert all(e["incident_id"] == incident_id for e in timeline)

    def test_short_circuit_analysis_recorded_as_skipped(self):
        self.pipeline_kwargs = {"severity_score": 0, "noul": 0.1, "llm_reasoning": None,
                                "source": "skipped", "category": "application"}
        body = self._analyze()
        assert body["llm_reasoning"] is None
        assert body["analysis_source"] == "skipped"
        a = client.get(f"/incidents/{body['incident_id']}/analyses").json()[0]
        assert a["model_name"] is None and a["total_tokens"] is None
        assert "ai.skipped" in self._event_types(body["incident_id"])

    def test_fallback_analysis_recorded(self):
        self.pipeline_kwargs = {"source": "fallback",
                                "llm_reasoning": "[Automated summary: LLM unavailable]"}
        body = self._analyze()
        assert body["analysis_source"] == "fallback"
        assert "ai.fallback" in self._event_types(body["incident_id"])

    def test_reanalyze_existing_incident_uses_stored_alert(self):
        created = self._create(alert="original alert", service_id="order-service")
        body = self._analyze(incident_id=created["id"], alert="ignored", service_id="ignored")
        assert body["incident_id"] == created["id"]
        assert self.pipeline_calls == [("original alert", "order-service")]
        self._analyze(incident_id=created["id"])
        assert len(client.get(f"/incidents/{created['id']}/analyses").json()) == 2

    def test_analyze_unknown_incident_id_returns_404(self):
        resp = client.post("/incidents/analyze",
                           json={"service_id": "s", "alert": "a", "incident_id": "missing"})
        assert resp.status_code == 404

    def test_pipeline_failure_returns_502_and_is_audited(self):
        def boom(alert, service_id):
            raise RuntimeError("Jev API down")

        _test_app.dependency_overrides[get_pipeline] = lambda: boom
        resp = client.post("/incidents/analyze", json={"service_id": "svc", "alert": "x"})
        assert resp.status_code == 502

        incident = self.db.tables["incidents"][0]
        events = self._event_types(incident["id"])
        assert events[-1] == "analysis.failed"
        assert self.db.tables["incident_analyses"] == []
        failed = self.db.tables["audit_events"][-1]
        assert failed["payload"]["error_type"] == "RuntimeError"

    def test_analyze_missing_service_id_returns_422(self):
        resp = client.post("/incidents/analyze", json={"alert": "Some alert"})
        assert resp.status_code == 422

    def test_analyze_missing_alert_returns_422(self):
        resp = client.post("/incidents/analyze", json={"service_id": "svc-1"})
        assert resp.status_code == 422

    def test_analyze_route_not_treated_as_incident_id(self):
        resp = client.post("/incidents/analyze", json={"service_id": "svc-1", "alert": "test"})
        assert resp.status_code not in (404, 405)

    def test_analyses_and_timeline_404_for_unknown_incident(self):
        assert client.get("/incidents/nope/analyses").status_code == 404
        assert client.get("/incidents/nope/timeline").status_code == 404


class TestStatusLifecycle(_IncidentsTestBase):
    """PATCH /incidents/{id}/status (FR-15)."""

    def _patch(self, incident_id, status, **extra):
        return client.patch(f"/incidents/{incident_id}/status", json={"status": status, **extra})

    def test_full_happy_path(self):
        incident_id = self._create()["id"]
        for status in ("acknowledged", "mitigating", "resolved", "closed"):
            resp = self._patch(incident_id, status, actor="alice")
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == status

        final = client.get(f"/incidents/{incident_id}").json()
        assert final["acknowledged_at"] and final["resolved_at"] and final["closed_at"]

        timeline = client.get(f"/incidents/{incident_id}/timeline").json()
        changes = [(e["payload"]["from"], e["payload"]["to"], e["actor"])
                   for e in timeline if e["event_type"] == "incident.status_changed"]
        assert changes == [
            ("open", "acknowledged", "alice"),
            ("acknowledged", "mitigating", "alice"),
            ("mitigating", "resolved", "alice"),
            ("resolved", "closed", "alice"),
        ]

    def test_invalid_jump_returns_409_and_leaves_status(self):
        incident_id = self._create()["id"]
        resp = self._patch(incident_id, "closed")
        assert resp.status_code == 409
        assert "open" in resp.json()["detail"] and "closed" in resp.json()["detail"]
        assert client.get(f"/incidents/{incident_id}").json()["status"] == "open"
        assert "incident.status_changed" not in self._event_types(incident_id)

    def test_closed_is_terminal(self):
        incident_id = self._create()["id"]
        for status in ("resolved", "closed"):
            assert self._patch(incident_id, status).status_code == 200
        assert self._patch(incident_id, "open").status_code == 409

    def test_reopen_after_resolve_keeps_original_resolved_at(self):
        incident_id = self._create()["id"]
        self._patch(incident_id, "resolved")
        first_resolved = client.get(f"/incidents/{incident_id}").json()["resolved_at"]
        assert self._patch(incident_id, "open").status_code == 200
        assert self._patch(incident_id, "resolved").status_code == 200
        assert client.get(f"/incidents/{incident_id}").json()["resolved_at"] == first_resolved

    def test_note_recorded_in_timeline(self):
        incident_id = self._create()["id"]
        self._patch(incident_id, "acknowledged", note="Looking into it")
        event = client.get(f"/incidents/{incident_id}/timeline").json()[-1]
        assert event["payload"]["note"] == "Looking into it"

    def test_unknown_status_value_returns_422(self):
        incident_id = self._create()["id"]
        assert self._patch(incident_id, "on-fire").status_code == 422

    def test_unknown_incident_returns_404(self):
        assert self._patch("missing", "acknowledged").status_code == 404


class TestMalformedIncidentIds(_IncidentsTestBase):
    """Non-UUID ids must be 404, not a 500 from Postgres' uuid parser (22P02)."""

    BAD_IDS = ["does-not-exist", "123", "abc-123", "' or 1=1 --"]

    def test_fake_db_rejects_bad_uuid_like_postgres(self):
        """Guards the guard: without the store check these tests would see a 500."""
        from tests.fakes import InvalidUuidError

        with pytest.raises(InvalidUuidError):
            self.db.table("incidents").select("*").eq("id", "does-not-exist").execute()

    @pytest.mark.parametrize("bad_id", BAD_IDS)
    def test_read_endpoints_return_404(self, bad_id):
        from urllib.parse import quote

        path = f"/incidents/{quote(bad_id, safe='')}"
        for suffix in ("", "/analyses", "/timeline"):
            resp = client.get(path + suffix)
            assert resp.status_code == 404, (suffix, resp.status_code)
            assert resp.json()["detail"] == "Incident not found"

    @pytest.mark.parametrize("bad_id", BAD_IDS)
    def test_status_change_returns_404(self, bad_id):
        from urllib.parse import quote

        resp = client.patch(f"/incidents/{quote(bad_id, safe='')}/status",
                            json={"status": "acknowledged"})
        assert resp.status_code == 404

    def test_analyze_with_bad_incident_id_returns_404_and_runs_nothing(self):
        resp = client.post("/incidents/analyze",
                           json={"service_id": "s", "alert": "a", "incident_id": "not-a-uuid"})
        assert resp.status_code == 404
        assert self.pipeline_calls == []
        assert self.db.tables["audit_events"] == []

    def test_valid_but_unknown_uuid_still_404(self):
        import uuid

        assert client.get(f"/incidents/{uuid.uuid4()}").status_code == 404
