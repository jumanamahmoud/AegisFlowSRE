"""
backend/tests/test_services_and_review.py
==========================================
Service map management (FR-29) and the human review queue for uncertain
triage (FR-14), through the HTTP API.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import Principal, Role, get_current_user
from database.incident_store import IncidentStore
from database.neo4j_client import get_neo4j_client
from database.supabase_client import get_supabase
from routers.incidents import router as incidents_router
from routers.services import router as services_router
from services.analysis_queue import AnalysisQueue, get_analysis_queue
from tests.conftest import make_pipeline_state
from tests.fake_graph import FakeServiceGraph
from tests.fakes import FakeSupabase

ADMIN = Principal(user_id="00000000-0000-0000-0000-00000000000a", email="admin@example.com", role=Role.ADMIN)
RESPONDER = Principal(user_id="00000000-0000-0000-0000-00000000000b", email="alice@example.com", role=Role.RESPONDER)
VIEWER = Principal(user_id="00000000-0000-0000-0000-00000000000c", email="viewer@example.com", role=Role.VIEWER)


class Env:
    def __init__(self, pipeline_state=None):
        self.db = FakeSupabase()
        self.graph = FakeServiceGraph()
        self.app = FastAPI()
        self.app.include_router(services_router, prefix="/services")
        self.app.include_router(incidents_router, prefix="/incidents")
        self.state = pipeline_state or (lambda: make_pipeline_state())
        self.queue = AnalysisQueue(store_factory=lambda: IncidentStore(self.db),
                                   pipeline=lambda a, s: self.state(), inline=True)
        self.app.dependency_overrides.update({
            get_supabase: lambda: self.db, get_neo4j_client: lambda: self.graph,
            get_analysis_queue: lambda: self.queue,
        })
        self.client = TestClient(self.app)
        self.login(ADMIN)

    def login(self, who):
        if who is None:
            self.app.dependency_overrides.pop(get_current_user, None)
        else:
            self.app.dependency_overrides[get_current_user] = lambda: who

    def audit(self):
        return [e["event_type"] for e in self.db.tables["audit_events"]]


@pytest.fixture
def env():
    return Env()


# ---------------------------------------------------------------------------
# Service map management (FR-29)
# ---------------------------------------------------------------------------


class TestServiceMap:
    def _setup(self, env):
        c = env.client
        for sid in ("checkout-service", "payment-service"):
            assert c.post("/services", json={"id": sid, "name": sid.title(), "tier": "critical"}).status_code == 201
        assert c.put("/services/checkout-service/dependencies",
                     json={"target_id": "payment-service", "protocol": "gRPC"}).json()["result"] == "created"
        assert c.put("/services/payment-service/dependencies",
                     json={"target_id": "payment-db", "target_kind": "external", "protocol": "TCP",
                           "target_type": "database"}).json()["result"] == "created"

    def test_create_link_and_read_back(self, env):
        self._setup(env)
        env.login(VIEWER)
        svc = env.client.get("/services/payment-service").json()
        assert svc["name"] == "Payment-Service" and svc["tier"] == "critical"
        assert [d["id"] for d in svc["dependencies"]] == ["payment-db"]
        assert svc["dependencies"][0]["kind"] == "external" and svc["dependencies"][0]["type"] == "database"
        assert [d["id"] for d in svc["dependents"]] == ["checkout-service"]
        assert [b["id"] for b in svc["blast_radius"]] == ["checkout-service"]
        assert [s["id"] for s in env.client.get("/services").json()] == ["checkout-service", "payment-service"]

    def test_changes_are_audited(self, env):
        self._setup(env)
        assert env.audit() == ["service.created", "service.created", "dependency.set", "dependency.set"]
        assert all(e["actor"] == "admin@example.com" and e["incident_id"] is None
                   for e in env.db.tables["audit_events"])

    def test_same_dependency_again_writes_no_history(self, env):
        self._setup(env)
        r = env.client.put("/services/checkout-service/dependencies",
                           json={"target_id": "payment-service", "protocol": "gRPC"})
        assert r.json()["result"] == "unchanged"
        assert len(env.client.get("/services/checkout-service/history").json()) == 1
        assert env.audit().count("dependency.set") == 2  # unchanged isn't audited

    def test_protocol_change_keeps_history(self, env):
        self._setup(env)
        assert env.client.put("/services/checkout-service/dependencies",
                              json={"target_id": "payment-service", "protocol": "HTTP"}).json()["result"] == "updated"
        history = env.client.get("/services/checkout-service/history").json()
        assert [(h["protocol"], h["valid_to"] is None) for h in history] == [("HTTP", True), ("gRPC", False)]

    def test_remove_dependency_and_time_travel(self, env):
        self._setup(env)
        before = datetime.now(timezone.utc)
        assert env.client.post("/services/checkout-service/dependencies/remove",
                               json={"target_id": "payment-service"}).json()["result"] == "removed"
        assert env.client.get("/services/checkout-service/dependencies").json() == []
        past = env.client.get("/services/checkout-service/dependencies",
                              params={"at": before.isoformat()}).json()
        assert [d["id"] for d in past] == ["payment-service"]  # the map as it was
        assert env.client.post("/services/checkout-service/dependencies/remove",
                               json={"target_id": "payment-service"}).status_code == 404
        assert "dependency.removed" in env.audit()

    def test_at_needs_timezone(self, env):
        self._setup(env)
        assert env.client.get("/services/checkout-service/dependencies",
                              params={"at": "2026-11-24T09:00:00"}).status_code == 422

    def test_retire_closes_links_but_keeps_history(self, env):
        self._setup(env)
        r = env.client.post("/services/payment-service/retire")
        assert r.status_code == 200 and r.json()["retired_at"]
        assert [s["id"] for s in env.client.get("/services").json()] == ["checkout-service"]
        assert len(env.client.get("/services", params={"include_retired": True}).json()) == 2
        assert env.client.get("/services/checkout-service/dependencies").json() == []  # link into it closed
        assert env.client.get("/services/payment-service/history").json()[0]["valid_to"]  # kept, closed
        assert env.client.get("/services/payment-service").json()["blast_radius"] == []
        ev = env.db.tables["audit_events"][-1]
        assert ev["event_type"] == "service.retired" and ev["payload"]["links_closed"] == 2
        assert env.client.post("/services/payment-service/retire").status_code == 404
        assert env.client.patch("/services/payment-service", json={"name": "x"}).status_code == 404
        assert env.client.put("/services/checkout-service/dependencies",
                              json={"target_id": "payment-service"}).status_code == 404

    def test_update(self, env):
        self._setup(env)
        r = env.client.patch("/services/payment-service", json={"name": "Payments", "tier": "gold"})
        assert r.json()["name"] == "Payments" and r.json()["tier"] == "gold"
        assert env.client.patch("/services/payment-service", json={}).status_code == 422
        ev = env.db.tables["audit_events"][-1]
        assert ev["payload"]["changes"] == {"name": "Payments", "tier": "gold"}

    @pytest.mark.parametrize("body,code", [
        ({"id": "Bad Id", "name": "x"}, 422),
        ({"id": "-starts-with-dash", "name": "x"}, 422),
        ({"id": "ok-id", "name": ""}, 422),
    ])
    def test_create_validation(self, env, body, code):
        assert env.client.post("/services", json=body).status_code == code

    def test_duplicate_and_unknown(self, env):
        self._setup(env)
        assert env.client.post("/services", json={"id": "payment-service", "name": "x"}).status_code == 409
        assert env.client.get("/services/nope").status_code == 404
        assert env.client.get("/services/nope/history").status_code == 404
        assert env.client.put("/services/checkout-service/dependencies",
                              json={"target_id": "nope"}).status_code == 404
        assert env.client.put("/services/checkout-service/dependencies",
                              json={"target_id": "checkout-service"}).status_code == 422
        assert env.client.put("/services/checkout-service/dependencies",
                              json={"target_id": "x", "target_kind": "planet"}).status_code == 422

    def test_roles(self, env):
        self._setup(env)
        for who, code in ((RESPONDER, 403), (VIEWER, 403), (None, 401)):
            env.login(who)
            assert env.client.post("/services", json={"id": "new", "name": "n"}).status_code == code
            assert env.client.post("/services/payment-service/retire").status_code == code
            assert env.client.put("/services/checkout-service/dependencies",
                                  json={"target_id": "payment-service"}).status_code == code
        env.login(VIEWER)
        assert env.client.get("/services").status_code == 200
        env.login(None)
        assert env.client.get("/services").status_code == 401


# ---------------------------------------------------------------------------
# Human review of uncertain triage (FR-14)
# ---------------------------------------------------------------------------


def _analyze(env, alert="Synthetic check status WARN. Code 0x3F."):
    env.login(RESPONDER)
    r = env.client.post("/incidents/analyze", json={"service_id": "payment-service", "alert": alert})
    assert r.status_code == 202
    return r.json()["incident_id"]


class TestReview:
    def uncertain_env(self):
        return Env(pipeline_state=lambda: make_pipeline_state(
            category="unknown", severity_score=0, noul=0.1, source="llm", category_confidence=0.41,
            review_reasons=["category_unknown", "low_category_confidence"]))

    def test_uncertain_triage_flags_incident(self):
        env = self.uncertain_env()
        inc_id = _analyze(env)
        env.login(VIEWER)
        inc = env.client.get(f"/incidents/{inc_id}").json()
        assert inc["needs_review"] is True
        assert inc["review_reasons"] == ["category_unknown", "low_category_confidence"]
        [analysis] = env.client.get(f"/incidents/{inc_id}/analyses").json()
        assert analysis["needs_review"] and analysis["category_confidence"] == 0.41
        assert analysis["analysis_source"] == "llm"  # not silently skipped

    def test_review_queue_and_completion(self):
        env = self.uncertain_env()
        flagged = _analyze(env)
        env.state = lambda: make_pipeline_state()  # confident triage
        confident = _analyze(env, "payment-db pool exhausted")
        env.login(VIEWER)
        queue = env.client.get("/incidents", params={"needs_review": True}).json()
        assert [i["id"] for i in queue] == [flagged]
        assert {i["id"] for i in env.client.get("/incidents").json()} == {flagged, confident}

        env.login(RESPONDER)
        r = env.client.post(f"/incidents/{flagged}/review", json={"note": "checked: synthetic monitor noise"})
        assert r.status_code == 200
        body = r.json()
        assert body["needs_review"] is False and body["reviewed_by"] == "alice@example.com" and body["reviewed_at"]
        assert env.client.get("/incidents", params={"needs_review": True}).json() == []
        ev = [e for e in env.db.tables["audit_events"] if e["event_type"] == "triage.reviewed"]
        assert ev[0]["payload"]["note"] == "checked: synthetic monitor noise" and ev[0]["actor"] == "alice@example.com"
        assert env.client.post(f"/incidents/{flagged}/review", json={}).status_code == 409

    def test_review_roles_and_unknown(self):
        env = self.uncertain_env()
        inc_id = _analyze(env)
        env.login(VIEWER)
        assert env.client.post(f"/incidents/{inc_id}/review", json={}).status_code == 403
        env.login(RESPONDER)
        assert env.client.post("/incidents/not-a-uuid/review", json={}).status_code == 404

    def test_reanalysis_reflags_after_review(self):
        env = self.uncertain_env()
        inc_id = _analyze(env)
        env.client.post(f"/incidents/{inc_id}/review", json={})
        env.client.post("/incidents/analyze", json={"service_id": "x", "alert": "x", "incident_id": inc_id})
        inc = env.client.get(f"/incidents/{inc_id}").json()
        assert inc["needs_review"] is True and inc["reviewed_at"] is None

    def test_confident_reanalysis_does_not_clear_pending_review(self):
        env = self.uncertain_env()
        inc_id = _analyze(env)
        env.state = lambda: make_pipeline_state()
        env.client.post("/incidents/analyze", json={"service_id": "x", "alert": "x", "incident_id": inc_id})
        assert env.client.get(f"/incidents/{inc_id}").json()["needs_review"] is True

    def test_list_filters(self, env):
        _analyze(env)
        env.login(VIEWER)
        assert len(env.client.get("/incidents", params={"status": "open"}).json()) == 1
        assert env.client.get("/incidents", params={"status": "closed"}).json() == []
        assert env.client.get("/incidents", params={"service_id": "other"}).json() == []
        assert env.client.get("/incidents", params={"status": "weird"}).status_code == 422
        assert env.client.get("/incidents", params={"limit": 0}).status_code == 422
        env.login(None)
        assert env.client.get("/incidents").status_code == 401


def test_pipeline_flags_unknown_category_end_to_end(monkeypatch):
    """Real pipeline (Jev, Groq and Neo4j mocked): an 'unknown' low-severity
    alert is NOT skipped and asks for review (FR-14)."""
    from unittest.mock import MagicMock, patch

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    groq = MagicMock()
    completion = MagicMock()
    completion.choices = [MagicMock()]
    completion.choices[0].message.content = "Unclear signal; check the synthetic monitor."
    completion.choices[0].message.reasoning = None
    completion.choices[0].finish_reason = "stop"
    completion.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    groq.chat.completions.create.return_value = completion
    import importlib
    import sys

    sys.modules.pop("engine.langgraph_pipeline", None)
    with patch("groq.Groq", return_value=groq):
        pipeline = importlib.import_module("engine.langgraph_pipeline")
    import engine.jev_check as jev_mod

    response = MagicMock()
    response.choices = {"incident_category": MagicMock(choice="unknown", confidence=0.38)}
    response.scores = {"severity": MagicMock(score=0.2, confidence=0.71)}
    response.nouls = {"needs_escalation": MagicMock(noul=0.1)}
    jev_client = MagicMock()
    jev_client.system_one.return_value = response
    neo4j = MagicMock()
    neo4j.get_service_context.return_value = []
    neo4j.get_blast_radius.return_value = []
    with patch.object(jev_mod, "get_jev_client", return_value=jev_client), \
            patch("database.neo4j_client.get_neo4j_client", return_value=neo4j):
        state = pipeline.execute_pipeline("Synthetic check WARN 0x3F", "payment-service")

    types = [e["event_type"] for e in state["trace"]]
    assert types == ["alert.sanitized", "graph.enriched", "triage.completed", "triage.review_requested", "ai.invoked"]
    assert state["final_response"]["needs_review"] is True
    assert state["final_response"]["review_reasons"] == ["category_unknown", "low_category_confidence"]
    assert state["jev_results"]["category_confidence"] == 0.38
    groq.chat.completions.create.assert_called_once()
