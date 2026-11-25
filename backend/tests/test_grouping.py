"""
backend/tests/test_grouping.py
===============================
Grouping related alerts into one incident through the service map (FR-13).

Phase 4 "done when": *grouped alerts become one incident* — see
``TestDoneWhen``.

Service map used here (mirrors scripts/seed_graph.py):

    api-gateway ──► checkout-service ──► payment-service ──► payment-db (external)
          └───────► order-service ───────┘      └──────────► fraud-service
                         └─► notification-service
    inventory-service (no links)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_keys import ApiKeyLookup, get_api_key_lookup
from core.auth import Principal, Role, get_current_user
from database.alert_store import AlertStore
from database.incident_store import IncidentStore
from database.supabase_client import get_supabase
from routers.admin import admin_router
from routers.alerts import get_service_map
from routers.alerts import router as alerts_router
from routers.incidents import router as incidents_router
from services.alert_intake import AlertIntake, GroupingSettings
from services.alert_sources import manual_alert
from services.analysis_queue import AnalysisQueue, get_analysis_queue
from tests.conftest import make_pipeline_state
from tests.fake_graph import FakeServiceGraph
from tests.fakes import FakeSupabase

ACTOR = "apikey:test"


def seeded_graph() -> FakeServiceGraph:
    g = FakeServiceGraph()
    g.add("api-gateway", "checkout-service", "order-service")
    g.add("checkout-service", "payment-service")
    g.add("order-service", "payment-service", "notification-service")
    g.add("payment-service", "fraud-service")
    g.add("payment-service", "payment-db", kind="external")
    g.add("inventory-service")
    return g


@pytest.fixture
def db():
    return FakeSupabase()


@pytest.fixture
def graph():
    return seeded_graph()


def make_intake(db, graph, **settings):
    queue = AnalysisQueue(store_factory=lambda: IncidentStore(db),
                          pipeline=lambda a, s: make_pipeline_state(), inline=True)
    return AlertIntake(IncidentStore(db), AlertStore(db), queue, auto_analyze=True, service_map=graph,
                       grouping=GroupingSettings(**settings))


@pytest.fixture
def intake(db, graph):
    return make_intake(db, graph)


def send(intake, service, title="something broke"):
    return intake.receive([manual_alert(service, title)], ACTOR)[0]


def events(db, incident_id, type_):
    return [e for e in db.tables["audit_events"] if e["incident_id"] == incident_id and e["event_type"] == type_]


# ---------------------------------------------------------------------------


class TestDoneWhen:
    def test_two_services_sharing_a_dependency_become_one_incident(self, db, intake):
        """checkout-service and order-service both depend on payment-service:
        their alerts are one incident, and payment-service is the probable cause."""
        first = send(intake, "checkout-service", "checkout errors")
        second = send(intake, "order-service", "orders failing")
        assert first.disposition == "created"
        assert second.disposition == "grouped" and second.incident_id == first.incident_id
        assert len(db.tables["incidents"]) == 1

        inc = db.tables["incidents"][0]
        assert inc["probable_cause"]["id"] == "payment-service"
        assert inc["probable_cause"]["hops_a"] == 1 and inc["probable_cause"]["hops_b"] == 1
        assert inc["grouped_services"] == ["order-service"]

        [ev] = events(db, inc["id"], "alert.grouped")
        assert ev["payload"]["shared_component"]["id"] == "payment-service"
        assert ev["actor"] == ACTOR
        # a grouped alert does not start a second analysis
        assert len(events(db, inc["id"], "analysis.queued")) == 1

        alert = db.tables["alerts"][1]
        assert alert["disposition"] == "grouped"
        assert alert["grouped_via"]["shared_component"]["id"] == "payment-service"

    def test_failing_dependency_and_its_dependents_become_one_incident(self, db, intake):
        """The database alerts first, then the services above it."""
        first = send(intake, "payment-service", "pool exhausted")
        for svc in ("checkout-service", "order-service"):
            r = send(intake, svc, f"{svc} errors")
            assert r.disposition == "grouped" and r.incident_id == first.incident_id
        inc = db.tables["incidents"][0]
        assert inc["probable_cause"]["id"] == "payment-service"
        assert sorted(inc["grouped_services"]) == ["checkout-service", "order-service"]


class TestRelations:
    def test_unrelated_services_stay_separate(self, db, intake):
        a = send(intake, "checkout-service")
        b = send(intake, "inventory-service")
        assert b.disposition == "created" and b.incident_id != a.incident_id

    def test_same_service_different_alert_is_grouped(self, db, intake):
        a = send(intake, "inventory-service", "disk full")
        b = send(intake, "inventory-service", "high latency")
        assert b.disposition == "grouped" and b.incident_id == a.incident_id
        assert db.tables["incidents"][0]["probable_cause"]["id"] == "inventory-service"
        assert db.tables["incidents"][0]["grouped_services"] == []  # same service isn't listed twice

    def test_direct_dependency_is_the_cause(self, db, intake):
        send(intake, "checkout-service")
        r = send(intake, "payment-service")
        assert r.disposition == "grouped"
        assert r.grouped_via["shared_component"] == {
            "id": "payment-service", "name": "payment-service", "type": "service", "kind": "service",
            "hops_a": 0, "hops_b": 1}

    def test_external_system_can_be_the_shared_cause(self, db, graph):
        g = FakeServiceGraph().add("a", "shared-db", kind="external").add("b", "shared-db", kind="external")
        intake = make_intake(db, g)
        send(intake, "a")
        r = send(intake, "b")
        assert r.disposition == "grouped" and r.grouped_via["shared_component"]["kind"] == "external"

    def test_too_far_apart_is_not_grouped(self, db, graph):
        # api-gateway -> checkout -> payment -> fraud: 3 links from the gateway to fraud-service
        intake = make_intake(db, graph, max_hops=1)
        send(intake, "api-gateway")
        assert send(intake, "fraud-service").disposition == "created"

    def test_closest_relation_wins_over_newer_incident(self, db, intake):
        pay = send(intake, "payment-service")  # will be 1 hop from order-service
        db.tables["incidents"][0]["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        send(intake, "inventory-service")      # newer, unrelated
        r = send(intake, "order-service")
        assert r.incident_id == pay.incident_id

    def test_probable_cause_tightens_as_alerts_arrive(self, db, intake):
        send(intake, "checkout-service")             # cause unknown yet
        send(intake, "order-service")                # shared: payment-service (1+1)
        send(intake, "payment-service", "db errors")  # payment-service itself (0+1)
        inc = db.tables["incidents"][0]
        assert inc["probable_cause"]["id"] == "payment-service"
        assert inc["probable_cause"]["hops_a"] + inc["probable_cause"]["hops_b"] == 1


class TestLimits:
    def test_window(self, db, intake):
        send(intake, "checkout-service")
        db.tables["incidents"][0]["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
        assert send(intake, "order-service").disposition == "created"

    def test_resolved_incidents_are_not_candidates(self, db, intake):
        a = send(intake, "checkout-service")
        IncidentStore(db).change_status(a.incident_id, "resolved", "alice")
        assert send(intake, "order-service").disposition == "created"

    def test_acknowledged_incidents_are_candidates(self, db, intake):
        a = send(intake, "checkout-service")
        IncidentStore(db).change_status(a.incident_id, "acknowledged", "alice")
        assert send(intake, "order-service").disposition == "grouped"

    def test_disabled(self, db, graph):
        intake = make_intake(db, graph, enabled=False)
        send(intake, "checkout-service")
        assert send(intake, "order-service").disposition == "created"

    def test_env_settings(self, monkeypatch):
        monkeypatch.setenv("AEGIS_GROUPING", "0")
        monkeypatch.setenv("AEGIS_GROUPING_WINDOW_MINUTES", "3")
        monkeypatch.setenv("AEGIS_GROUPING_MAX_HOPS", "4")
        assert GroupingSettings.from_env() == GroupingSettings(enabled=False, window_minutes=3.0, max_hops=4)

    def test_unknown_service_never_groups(self, db, intake):
        send(intake, "unknown-service")
        assert send(intake, "unknown-service", "other").disposition == "created"

    def test_service_map_down_still_creates_incident(self, db, graph, intake):
        send(intake, "checkout-service")
        graph.fail = RuntimeError("neo4j unreachable")
        assert send(intake, "order-service").disposition == "created"

    def test_no_service_map_still_groups_same_service(self, db):
        intake = make_intake(db, None)
        send(intake, "checkout-service", "a")
        assert send(intake, "checkout-service", "b").disposition == "grouped"
        assert send(intake, "order-service").disposition == "created"

    def test_maintenance_beats_grouping(self, db, intake):
        send(intake, "checkout-service")
        now = datetime.now(timezone.utc)
        AlertStore(db).create_window("order-service", now - timedelta(minutes=1), now + timedelta(hours=1),
                                     "deploy", "alice")
        assert send(intake, "order-service").disposition == "suppressed"


class TestRepeatsOfGroupedAlerts:
    def test_repeat_of_grouped_alert_is_deduplicated_into_same_incident(self, db, intake):
        a = send(intake, "checkout-service")
        b = send(intake, "order-service", "orders failing")
        again = send(intake, "order-service", "orders failing")
        assert b.disposition == "grouped"
        assert again.disposition == "deduplicated" and again.incident_id == a.incident_id

    def test_repeat_after_window_still_joins(self, db, intake):
        a = send(intake, "checkout-service")
        send(intake, "order-service", "orders failing")
        db.tables["incidents"][0]["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        again = send(intake, "order-service", "orders failing")
        assert again.disposition == "deduplicated" and again.incident_id == a.incident_id

    def test_recovery_notice_for_grouped_alert_attaches(self, db, intake):
        a = send(intake, "checkout-service")
        send(intake, "order-service", "orders failing")
        notice = manual_alert("order-service", "orders failing")
        notice.status = "resolved"
        r = intake.receive([notice], ACTOR)[0]
        assert r.disposition == "resolved" and r.incident_id == a.incident_id

    def test_repeat_after_incident_resolved_opens_new(self, db, intake):
        a = send(intake, "checkout-service")
        send(intake, "order-service", "orders failing")
        IncidentStore(db).change_status(a.incident_id, "resolved", "alice")
        again = send(intake, "order-service", "orders failing")
        assert again.disposition == "created" and again.incident_id != a.incident_id


# ---------------------------------------------------------------------------
# Through the HTTP API
# ---------------------------------------------------------------------------

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "webhooks"
ADMIN = Principal(user_id="00000000-0000-0000-0000-00000000000a", email="admin@example.com", role=Role.ADMIN)
VIEWER = Principal(user_id="00000000-0000-0000-0000-00000000000c", email="viewer@example.com", role=Role.VIEWER)


def test_webhooks_group_through_the_api():
    db, graph = FakeSupabase(), seeded_graph()
    app = FastAPI()
    for r, prefix in ((alerts_router, "/alerts"), (admin_router, "/admin"), (incidents_router, "/incidents")):
        app.include_router(r, prefix=prefix)
    queue = AnalysisQueue(store_factory=lambda: IncidentStore(db),
                          pipeline=lambda a, s: make_pipeline_state(), inline=True)
    lookup = ApiKeyLookup(client_factory=lambda: db)
    app.dependency_overrides.update({
        get_supabase: lambda: db, get_analysis_queue: lambda: queue,
        get_api_key_lookup: lambda: lookup, get_service_map: lambda: graph,
        get_current_user: lambda: ADMIN,
    })
    client = TestClient(app)
    key = client.post("/admin/api-keys", json={"name": "t"}).json()["key"]
    h = {"Authorization": f"Bearer {key}"}

    # Alertmanager: payment-service; Grafana: checkout-service (depends on payment-service)
    r1 = client.post("/alerts/webhooks/alertmanager", content=(SAMPLES / "alertmanager.json").read_bytes(), headers=h)
    r2 = client.post("/alerts/webhooks/grafana", content=(SAMPLES / "grafana.json").read_bytes(), headers=h)
    [a1], [a2] = r1.json()["results"], r2.json()["results"]
    assert a1["disposition"] == "created"
    assert a2["disposition"] == "grouped" and a2["incident_id"] == a1["incident_id"]
    assert a2["grouped_via"]["shared_component"]["id"] == "payment-service"

    app.dependency_overrides[get_current_user] = lambda: VIEWER
    inc = client.get(f"/incidents/{a1['incident_id']}").json()
    assert inc["probable_cause"]["id"] == "payment-service"
    assert inc["grouped_services"] == ["checkout-service"]
    assert client.get("/alerts", params={"disposition": "grouped"}).json()[0]["grouped_via"]
    timeline = [e["event_type"] for e in client.get(f"/incidents/{a1['incident_id']}/timeline").json()]
    assert "alert.grouped" in timeline
