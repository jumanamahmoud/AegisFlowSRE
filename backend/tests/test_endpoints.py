"""
backend/tests/test_endpoints.py
=================================
HTTP tests for the topology and incidents routers.

Authentication is replaced by overriding ``get_current_user`` with a fixed
Principal (real token verification is covered in test_auth.py), and the
analysis queue runs inline so the background job finishes before the
request returns.

Requirements: 6.2, 6.3, 6.5, 10.3; FR-15, FR-17, FR-32
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest

_neo4j_patch = patch("neo4j.GraphDatabase.driver", return_value=MagicMock())
_neo4j_patch.start()

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import Principal, Role, get_current_user
from database.incident_store import IncidentStore
from database.neo4j_client import get_neo4j_client as _orig_get_neo4j_client
from database.supabase_client import get_supabase
from routers.incidents import router as incidents_router
from routers.topology import router as topology_router
from services.analysis_queue import AnalysisQueue, get_analysis_queue
from tests.conftest import make_pipeline_state
from tests.fakes import FakeSupabase

_neo4j_patch.stop()

_test_app = FastAPI()
_test_app.include_router(topology_router, prefix="/topology")
_test_app.include_router(incidents_router, prefix="/incidents")

client = TestClient(_test_app, raise_server_exceptions=True)

ADMIN = Principal(user_id="00000000-0000-0000-0000-00000000000a", email="admin@example.com", role=Role.ADMIN)
RESPONDER = Principal(user_id="00000000-0000-0000-0000-00000000000b", email="alice@example.com", role=Role.RESPONDER)
VIEWER = Principal(user_id="00000000-0000-0000-0000-00000000000c", email="viewer@example.com", role=Role.VIEWER)


def _login_as(principal: Principal | None) -> None:
    if principal is None:
        _test_app.dependency_overrides.pop(get_current_user, None)
    else:
        _test_app.dependency_overrides[get_current_user] = lambda: principal


# ---------------------------------------------------------------------------
# Topology router (Requirements 6.2, 6.3) — administrators only
# ---------------------------------------------------------------------------


class TestTopologyIngest:
    def setup_method(self):
        self._mock = MagicMock()
        self._mock.upsert_service_dependency.return_value = None
        _test_app.dependency_overrides[_orig_get_neo4j_client] = lambda: self._mock
        _login_as(ADMIN)

    def teardown_method(self):
        _test_app.dependency_overrides.clear()

    def test_valid_payload_returns_200(self):
        resp = client.post("/topology/ingest", json={
            "service_id": "payment-service", "service_name": "Payment Service", "external_system": "Stripe",
        })
        assert resp.status_code == 200
        assert "message" in resp.json()

    def test_valid_payload_with_custom_protocol_returns_200(self):
        resp = client.post("/topology/ingest", json={
            "service_id": "auth-service", "service_name": "Auth Service",
            "external_system": "Okta", "protocol": "OAuth2",
        })
        assert resp.status_code == 200

    @pytest.mark.parametrize("missing", ["service_id", "service_name", "external_system"])
    def test_missing_field_returns_422(self, missing):
        body = {"service_id": "svc-1", "service_name": "Payment Service", "external_system": "Stripe"}
        body.pop(missing)
        assert client.post("/topology/ingest", json=body).status_code == 422

    def test_empty_body_returns_422(self):
        assert client.post("/topology/ingest", json={}).status_code == 422

    def test_upsert_called_with_correct_args(self):
        client.post("/topology/ingest", json={
            "service_id": "svc-1", "service_name": "My Service",
            "external_system": "Postgres", "protocol": "TCP",
        })
        self._mock.upsert_service_dependency.assert_called_once_with(
            service_id="svc-1", service_name="My Service", external_system="Postgres", protocol="TCP",
        )

    @pytest.mark.parametrize("who", [RESPONDER, VIEWER])
    def test_non_admin_forbidden(self, who):
        _login_as(who)
        resp = client.post("/topology/ingest", json={
            "service_id": "svc-1", "service_name": "x", "external_system": "y",
        })
        assert resp.status_code == 403
        self._mock.upsert_service_dependency.assert_not_called()

    def test_anonymous_rejected(self):
        _login_as(None)
        resp = client.post("/topology/ingest", json={
            "service_id": "svc-1", "service_name": "x", "external_system": "y",
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Incidents router (Requirements 6.4, 6.5, 10.3; FR-15, FR-17)
# ---------------------------------------------------------------------------


class _IncidentsTestBase:
    """In-memory Supabase, a fake pipeline run inline by the queue, signed in as a responder."""

    pipeline_kwargs: dict = {}

    def setup_method(self):
        self.db = FakeSupabase()
        self.pipeline_calls: list[tuple[str, str]] = []

        def fake_pipeline(alert, service_id):
            self.pipeline_calls.append((alert, service_id))
            return make_pipeline_state(**self.pipeline_kwargs)

        self.queue = AnalysisQueue(
            store_factory=lambda: IncidentStore(self.db), pipeline=fake_pipeline, inline=True
        )
        _test_app.dependency_overrides[get_supabase] = lambda: self.db
        _test_app.dependency_overrides[get_analysis_queue] = lambda: self.queue
        _login_as(RESPONDER)

    def teardown_method(self):
        _test_app.dependency_overrides.clear()

    def use_pipeline(self, fn):
        self.queue = AnalysisQueue(store_factory=lambda: IncidentStore(self.db), pipeline=fn, inline=True)
        _test_app.dependency_overrides[get_analysis_queue] = lambda: self.queue

    def _create(self, **overrides) -> dict:
        body = {"service_id": "payment-service", "alert": "HTTP 500 on checkout", **overrides}
        resp = client.post("/incidents/", json=body)
        assert resp.status_code == 201, resp.text
        return resp.json()

    def _analyze(self, **overrides) -> dict:
        """POST /analyze (202) and return the accepted body plus the result read back."""
        body = {"service_id": "payment-service", "alert": "DB pool exhausted", **overrides}
        resp = client.post("/incidents/analyze", json=body)
        assert resp.status_code == 202, resp.text
        accepted = resp.json()
        incident = client.get(accepted["status_url"]).json()
        analyses = client.get(accepted["analyses_url"]).json()
        return {**accepted, "incident": incident, "analysis": analyses[0] if analyses else None}

    def _event_types(self, incident_id: str) -> list[str]:
        resp = client.get(f"/incidents/{incident_id}/timeline")
        assert resp.status_code == 200
        return [e["event_type"] for e in resp.json()]


class TestIncidentsCrud(_IncidentsTestBase):
    def test_get_incident_not_found_returns_404(self):
        resp = client.get("/incidents/00000000-0000-0000-0000-000000000123")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Incident not found"

    def test_create_incident_returns_201_with_open_status(self):
        created = self._create(metadata={"env": "prod"})
        assert created["id"]
        assert created["status"] == "open"
        assert created["analysis_status"] == "none"
        assert created["metadata"] == {"env": "prod"}

    def test_created_incident_can_be_read_back(self):
        created = self._create()
        body = client.get(f"/incidents/{created['id']}").json()
        assert body["id"] == created["id"]
        assert body["service_id"] == "payment-service"
        assert body["status"] == "open"

    def test_create_incident_audited_with_signed_in_user(self):
        created = self._create()
        timeline = client.get(f"/incidents/{created['id']}/timeline").json()
        assert [e["event_type"] for e in timeline] == ["incident.created"]
        assert timeline[0]["actor"] == "alice@example.com"

    def test_empty_alert_rejected(self):
        assert client.post("/incidents/", json={"service_id": "s", "alert": ""}).status_code == 422


class TestAnalyzeBackground(_IncidentsTestBase):
    """POST /incidents/analyze queues work and returns 202; results are read back."""

    def test_analyze_returns_202_with_polling_urls(self):
        resp = client.post("/incidents/analyze", json={"service_id": "payment-service", "alert": "x"})
        assert resp.status_code == 202
        body = resp.json()
        assert body["analysis_status"] == "queued"
        assert body["status_url"] == f"/incidents/{body['incident_id']}"
        assert body["analyses_url"] == f"/incidents/{body['incident_id']}/analyses"

    def test_analyzed_incident_is_saved_and_read_back(self):
        result = self._analyze()
        incident, a = result["incident"], result["analysis"]
        assert incident["analysis_status"] == "completed"
        assert incident["analysis_error"] is None
        assert incident["incident_category"] == "database"
        assert incident["severity"] == "Critical"

        assert a["severity_score"] == 3
        assert a["escalation_noul"] == 0.9
        assert a["analysis_source"] == "llm"
        assert a["model_name"] == "openai/gpt-oss-120b"
        assert (a["prompt_tokens"], a["completion_tokens"], a["total_tokens"]) == (412, 230, 642)
        assert a["llm_latency_ms"] == 1840
        assert a["service_context"][0]["name"] == "payment-db"
        assert a["blast_radius"][0]["id"] == "checkout-service"
        assert a["started_at"] <= a["completed_at"]

        assert self._event_types(result["incident_id"]) == [
            "incident.created",
            "analysis.queued",
            "analysis.started",
            "alert.sanitized",
            "graph.enriched",
            "triage.completed",
            "ai.invoked",
            "analysis.saved",
        ]

    def test_queued_event_records_requesting_user(self):
        result = self._analyze()
        queued = next(e for e in client.get(f"/incidents/{result['incident_id']}/timeline").json()
                      if e["event_type"] == "analysis.queued")
        assert queued["actor"] == "alice@example.com"

    def test_timeline_is_chronological(self):
        result = self._analyze()
        timeline = client.get(f"/incidents/{result['incident_id']}/timeline").json()
        keys = [(e["occurred_at"], e["id"]) for e in timeline]
        assert keys == sorted(keys)

    def test_short_circuit_analysis_recorded_as_skipped(self):
        self.pipeline_kwargs = {"severity_score": 0, "noul": 0.1, "llm_reasoning": None,
                                "source": "skipped", "category": "application"}
        a = self._analyze()["analysis"]
        assert a["analysis_source"] == "skipped"
        assert a["llm_reasoning"] is None and a["model_name"] is None

    def test_fallback_analysis_recorded(self):
        self.pipeline_kwargs = {"source": "fallback", "llm_reasoning": "[Automated summary: LLM unavailable]"}
        result = self._analyze()
        assert result["analysis"]["analysis_source"] == "fallback"
        assert "ai.fallback" in self._event_types(result["incident_id"])

    def test_reanalyze_existing_incident_uses_stored_alert(self):
        created = self._create(alert="original alert", service_id="order-service")
        result = self._analyze(incident_id=created["id"], alert="ignored", service_id="ignored")
        assert result["incident_id"] == created["id"]
        assert self.pipeline_calls == [("original alert", "order-service")]
        self._analyze(incident_id=created["id"])
        assert len(client.get(f"/incidents/{created['id']}/analyses").json()) == 2

    def test_analyze_unknown_incident_id_returns_404(self):
        resp = client.post("/incidents/analyze", json={
            "service_id": "s", "alert": "a", "incident_id": "00000000-0000-0000-0000-000000000999",
        })
        assert resp.status_code == 404

    def test_already_pending_returns_409(self):
        created = self._create()
        self.db.tables["incidents"][0]["analysis_status"] = "running"
        resp = client.post("/incidents/analyze",
                           json={"service_id": "s", "alert": "a", "incident_id": created["id"]})
        assert resp.status_code == 409
        assert self.pipeline_calls == []

    def test_pipeline_failure_marks_incident_failed_and_audits(self):
        def boom(alert, service_id):
            raise RuntimeError("Jev API down")

        self.use_pipeline(boom)
        resp = client.post("/incidents/analyze", json={"service_id": "svc", "alert": "x"})
        assert resp.status_code == 202  # the request itself succeeded; the job failed

        incident = client.get(resp.json()["status_url"]).json()
        assert incident["analysis_status"] == "failed"
        assert incident["analysis_error"] == "RuntimeError: Jev API down"
        assert self._event_types(incident["id"])[-1] == "analysis.failed"
        assert self.db.tables["incident_analyses"] == []

    def test_failed_incident_can_be_retried(self):
        def boom(alert, service_id):
            raise RuntimeError("temporary")

        self.use_pipeline(boom)
        incident_id = client.post("/incidents/analyze", json={"service_id": "s", "alert": "x"}).json()["incident_id"]
        self.use_pipeline(lambda a, s: make_pipeline_state())
        result = self._analyze(incident_id=incident_id)
        assert result["incident"]["analysis_status"] == "completed"

    @pytest.mark.parametrize("body", [{"alert": "Some alert"}, {"service_id": "svc-1"}])
    def test_analyze_missing_field_returns_422(self, body):
        assert client.post("/incidents/analyze", json=body).status_code == 422

    def test_analyses_and_timeline_404_for_unknown_incident(self):
        missing = "00000000-0000-0000-0000-000000000777"
        assert client.get(f"/incidents/{missing}/analyses").status_code == 404
        assert client.get(f"/incidents/{missing}/timeline").status_code == 404


class TestStatusLifecycle(_IncidentsTestBase):
    """PATCH /incidents/{id}/status (FR-15)."""

    def _patch(self, incident_id, status, **extra):
        return client.patch(f"/incidents/{incident_id}/status", json={"status": status, **extra})

    def test_full_happy_path(self):
        incident_id = self._create()["id"]
        for status in ("acknowledged", "mitigating", "resolved", "closed"):
            resp = self._patch(incident_id, status)
            assert resp.status_code == 200, resp.text
            assert resp.json()["status"] == status

        final = client.get(f"/incidents/{incident_id}").json()
        assert final["acknowledged_at"] and final["resolved_at"] and final["closed_at"]

        timeline = client.get(f"/incidents/{incident_id}/timeline").json()
        changes = [(e["payload"]["from"], e["payload"]["to"], e["actor"])
                   for e in timeline if e["event_type"] == "incident.status_changed"]
        assert changes == [
            ("open", "acknowledged", "alice@example.com"),
            ("acknowledged", "mitigating", "alice@example.com"),
            ("mitigating", "resolved", "alice@example.com"),
            ("resolved", "closed", "alice@example.com"),
        ]

    def test_actor_in_body_is_ignored(self):
        """The timeline actor comes from the login, never from request input."""
        incident_id = self._create()["id"]
        self._patch(incident_id, "acknowledged", actor="someone-else")
        event = client.get(f"/incidents/{incident_id}/timeline").json()[-1]
        assert event["actor"] == "alice@example.com"

    def test_invalid_jump_returns_409_and_leaves_status(self):
        incident_id = self._create()["id"]
        resp = self._patch(incident_id, "closed")
        assert resp.status_code == 409
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
        first = client.get(f"/incidents/{incident_id}").json()["resolved_at"]
        assert self._patch(incident_id, "open").status_code == 200
        assert self._patch(incident_id, "resolved").status_code == 200
        assert client.get(f"/incidents/{incident_id}").json()["resolved_at"] == first

    def test_note_recorded_in_timeline(self):
        incident_id = self._create()["id"]
        self._patch(incident_id, "acknowledged", note="Looking into it")
        event = client.get(f"/incidents/{incident_id}/timeline").json()[-1]
        assert event["payload"]["note"] == "Looking into it"

    def test_unknown_status_value_returns_422(self):
        incident_id = self._create()["id"]
        assert self._patch(incident_id, "on-fire").status_code == 422

    def test_unknown_incident_returns_404(self):
        assert self._patch("00000000-0000-0000-0000-000000000555", "acknowledged").status_code == 404


class TestRoleEnforcement(_IncidentsTestBase):
    """FR-32: viewers read, responders act, nobody gets in without logging in."""

    def _seed(self) -> str:
        return self._create()["id"]

    def test_viewer_can_read(self):
        incident_id = self._seed()
        _login_as(VIEWER)
        for path in ("", "/analyses", "/timeline"):
            assert client.get(f"/incidents/{incident_id}{path}").status_code == 200

    def test_viewer_cannot_change_anything(self):
        incident_id = self._seed()
        _login_as(VIEWER)
        assert client.post("/incidents/", json={"service_id": "s", "alert": "a"}).status_code == 403
        assert client.post("/incidents/analyze", json={"service_id": "s", "alert": "a"}).status_code == 403
        resp = client.patch(f"/incidents/{incident_id}/status", json={"status": "acknowledged"})
        assert resp.status_code == 403
        assert "responder" in resp.json()["detail"]
        assert len(self.db.tables["incidents"]) == 1
        assert self.db.tables["incidents"][0]["status"] == "open"

    @pytest.mark.parametrize("method,path,body", [
        ("get", "/incidents/{id}", None),
        ("get", "/incidents/{id}/analyses", None),
        ("get", "/incidents/{id}/timeline", None),
        ("post", "/incidents/", {"service_id": "s", "alert": "a"}),
        ("post", "/incidents/analyze", {"service_id": "s", "alert": "a"}),
        ("patch", "/incidents/{id}/status", {"status": "acknowledged"}),
    ])
    def test_every_endpoint_requires_login(self, method, path, body):
        incident_id = self._seed()
        _login_as(None)  # real dependency: no Authorization header -> 401
        url = path.format(id=incident_id)
        resp = getattr(client, method)(url, json=body) if body else getattr(client, method)(url)
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == "Bearer"


class TestMalformedIncidentIds(_IncidentsTestBase):
    """Non-UUID ids must be 404, not a 500 from Postgres' uuid parser (22P02)."""

    BAD_IDS = ["does-not-exist", "123", "abc-123", "' or 1=1 --"]

    def test_fake_db_rejects_bad_uuid_like_postgres(self):
        from tests.fakes import InvalidUuidError

        with pytest.raises(InvalidUuidError):
            self.db.table("incidents").select("*").eq("id", "does-not-exist").execute()

    @pytest.mark.parametrize("bad_id", BAD_IDS)
    def test_read_endpoints_return_404(self, bad_id):
        path = f"/incidents/{quote(bad_id, safe='')}"
        for suffix in ("", "/analyses", "/timeline"):
            resp = client.get(path + suffix)
            assert resp.status_code == 404, (suffix, resp.status_code)

    @pytest.mark.parametrize("bad_id", BAD_IDS)
    def test_status_change_returns_404(self, bad_id):
        resp = client.patch(f"/incidents/{quote(bad_id, safe='')}/status", json={"status": "acknowledged"})
        assert resp.status_code == 404

    def test_analyze_with_bad_incident_id_returns_404_and_runs_nothing(self):
        resp = client.post("/incidents/analyze",
                           json={"service_id": "s", "alert": "a", "incident_id": "not-a-uuid"})
        assert resp.status_code == 404
        assert self.pipeline_calls == []
        assert self.db.tables["audit_events"] == []
