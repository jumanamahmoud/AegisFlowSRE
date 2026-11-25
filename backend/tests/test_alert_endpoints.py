"""
backend/tests/test_alert_endpoints.py
======================================
HTTP tests for Week 3: machine API keys, monitoring-tool webhooks, manual
alerts, alert browsing and maintenance windows.

Week 3 "done when": *a test alert from each source creates exactly one
incident* — see ``TestDoneWhen``.

People are logged in by overriding ``get_current_user`` (token checks are in
test_auth.py). Machine keys are NOT stubbed: they are created through the
admin endpoint and verified by the real ``get_machine_principal``.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_keys import ApiKeyLookup, get_api_key_lookup, hash_key
from core.auth import Principal, Role, get_current_user
from database.incident_store import IncidentStore
from database.supabase_client import get_supabase
from routers.admin import admin_router
from routers.alerts import get_sns_confirmer
from routers.alerts import router as alerts_router
from routers.incidents import router as incidents_router
from routers.maintenance import router as maintenance_router
from services.analysis_queue import AnalysisQueue, get_analysis_queue
from tests.conftest import make_pipeline_state
from tests.fakes import FakeSupabase

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "webhooks"

ADMIN = Principal(user_id="00000000-0000-0000-0000-00000000000a", email="admin@example.com", role=Role.ADMIN)
RESPONDER = Principal(user_id="00000000-0000-0000-0000-00000000000b", email="alice@example.com", role=Role.RESPONDER)
VIEWER = Principal(user_id="00000000-0000-0000-0000-00000000000c", email="viewer@example.com", role=Role.VIEWER)


def sample_bytes(name: str) -> bytes:
    return (SAMPLES / f"{name}.json").read_bytes()


class Env:
    def __init__(self):
        self.db = FakeSupabase()
        self.confirmed: list[str] = []
        self.app = FastAPI()
        self.app.include_router(alerts_router, prefix="/alerts")
        self.app.include_router(maintenance_router, prefix="/maintenance-windows")
        self.app.include_router(admin_router, prefix="/admin")
        self.app.include_router(incidents_router, prefix="/incidents")
        self.queue = AnalysisQueue(store_factory=lambda: IncidentStore(self.db),
                                   pipeline=lambda a, s: make_pipeline_state(), inline=True)
        self.lookup = ApiKeyLookup(client_factory=lambda: self.db)
        o = self.app.dependency_overrides
        o[get_supabase] = lambda: self.db
        o[get_analysis_queue] = lambda: self.queue
        o[get_api_key_lookup] = lambda: self.lookup
        o[get_sns_confirmer] = lambda: self.confirmed.append
        self.client = TestClient(self.app)

    def login(self, principal: Principal | None):
        if principal is None:
            self.app.dependency_overrides.pop(get_current_user, None)
        else:
            self.app.dependency_overrides[get_current_user] = lambda: principal

    def new_key(self, name="prometheus-prod", source=None) -> str:
        self.login(ADMIN)
        resp = self.client.post("/admin/api-keys", json={"name": name, "source": source})
        assert resp.status_code == 201, resp.text
        self.login(None)
        return resp.json()["key"]

    def post(self, source: str, body, key: str | None, headers: dict | None = None, raw: bool = False):
        h = dict(headers or {})
        if key is not None and not h:
            h["Authorization"] = f"Bearer {key}"
        content = body if raw or isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
        return self.client.post(f"/alerts/webhooks/{source}", content=content, headers=h)


@pytest.fixture
def env():
    return Env()


# ---------------------------------------------------------------------------
# Week 3 done-when
# ---------------------------------------------------------------------------


class TestDoneWhen:
    @pytest.mark.parametrize("source,file,service", [
        ("alertmanager", "alertmanager", "payment-service"),
        ("grafana", "grafana", "checkout-service"),
        ("datadog", "datadog", "inventory-service"),
        ("cloudwatch", "cloudwatch", "auth-service"),
        ("cloudwatch", "cloudwatch_eventbridge", "order-service"),
    ])
    def test_each_source_creates_exactly_one_incident(self, env, source, file, service):
        key = env.new_key(source=source)
        first = env.post(source, sample_bytes(file), key)
        assert first.status_code == 202, first.text
        [r1] = first.json()["results"]
        assert r1["disposition"] == "created" and r1["analysis_queued"]

        # the tool retries / re-sends the same alert
        for _ in range(3):
            again = env.post(source, sample_bytes(file), key)
            assert again.status_code == 202
            [r] = again.json()["results"]
            assert r["disposition"] == "deduplicated" and r["incident_id"] == r1["incident_id"]

        incidents = env.db.tables["incidents"]
        assert len(incidents) == 1
        assert incidents[0]["service_id"] == service and incidents[0]["source"] == source
        assert incidents[0]["analysis_status"] == "completed"
        assert len(env.db.tables["alerts"]) == 4  # every delivery is on record

    def test_all_sources_together(self, env):
        key = env.new_key()  # unrestricted key
        for source, file in [("alertmanager", "alertmanager"), ("grafana", "grafana"),
                             ("datadog", "datadog"), ("cloudwatch", "cloudwatch")]:
            for _ in range(2):
                assert env.post(source, sample_bytes(file), key).status_code == 202
        assert len(env.db.tables["incidents"]) == 4
        assert sorted(i["source"] for i in env.db.tables["incidents"]) == [
            "alertmanager", "cloudwatch", "datadog", "grafana"]


# ---------------------------------------------------------------------------
# Machine access keys
# ---------------------------------------------------------------------------


class TestApiKeys:
    def test_key_shown_once_and_only_hash_stored(self, env):
        key = env.new_key()
        assert key.startswith("afk_") and len(key) > 40
        [row] = env.db.tables["api_keys"]
        assert row["key_hash"] == hash_key(key)
        assert key not in json.dumps(row)
        env.login(ADMIN)
        listed = env.client.get("/admin/api-keys").json()
        assert "key" not in listed[0] and "key_hash" not in listed[0]
        assert listed[0]["key_prefix"] == key[:12]

    def test_creation_and_revocation_audited(self, env):
        env.new_key()
        key_id = env.db.tables["api_keys"][0]["id"]
        env.login(ADMIN)
        assert env.client.post(f"/admin/api-keys/{key_id}/revoke").status_code == 200
        types = [e["event_type"] for e in env.db.tables["audit_events"]]
        assert types == ["api_key.created", "api_key.revoked"]
        assert all(e["actor"] == "admin@example.com" for e in env.db.tables["audit_events"])

    @pytest.mark.parametrize("who,code", [(RESPONDER, 403), (VIEWER, 403), (None, 401)])
    def test_only_admins_manage_keys(self, env, who, code):
        env.login(who)
        assert env.client.post("/admin/api-keys", json={"name": "x"}).status_code == code
        assert env.client.get("/admin/api-keys").status_code == code

    def test_invalid_source_rejected(self, env):
        env.login(ADMIN)
        assert env.client.post("/admin/api-keys", json={"name": "x", "source": "nagios"}).status_code == 422

    def test_revoke_unknown_or_twice(self, env):
        env.login(ADMIN)
        assert env.client.post("/admin/api-keys/not-a-uuid/revoke").status_code == 404
        assert env.client.post("/admin/api-keys/00000000-0000-0000-0000-000000000099/revoke").status_code == 404
        env.new_key()
        key_id = env.db.tables["api_keys"][0]["id"]
        env.login(ADMIN)
        assert env.client.post(f"/admin/api-keys/{key_id}/revoke").status_code == 200
        assert env.client.post(f"/admin/api-keys/{key_id}/revoke").status_code == 409

    def test_revoked_key_stops_working_immediately(self, env):
        key = env.new_key()
        assert env.post("alertmanager", sample_bytes("alertmanager"), key).status_code == 202  # cached now
        key_id = env.db.tables["api_keys"][0]["id"]
        env.login(ADMIN)
        env.client.post(f"/admin/api-keys/{key_id}/revoke")
        env.login(None)
        assert env.post("alertmanager", sample_bytes("alertmanager"), key).status_code == 401

    def test_missing_wrong_and_malformed_keys(self, env):
        env.new_key()
        assert env.post("alertmanager", sample_bytes("alertmanager"), None).status_code == 401
        assert env.post("alertmanager", sample_bytes("alertmanager"), "afk_wrong").status_code == 401
        assert env.post("alertmanager", sample_bytes("alertmanager"), "not-our-format").status_code == 401
        resp = env.post("alertmanager", sample_bytes("alertmanager"), None,
                        headers={"Authorization": "Basic !!!notbase64"})
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        assert env.db.tables["alerts"] == []

    def test_user_login_token_is_not_a_machine_key(self, env):
        env.login(ADMIN)  # a signed-in person still needs a key for webhooks
        assert env.post("alertmanager", sample_bytes("alertmanager"), None).status_code == 401

    @pytest.mark.parametrize("style", ["x-api-key", "bearer", "basic-password", "basic-username"])
    def test_supported_header_styles(self, env, style):
        key = env.new_key()
        headers = {
            "x-api-key": {"X-API-Key": key},
            "bearer": {"Authorization": f"Bearer {key}"},
            "basic-password": {"Authorization": "Basic " + base64.b64encode(f"aegisflow:{key}".encode()).decode()},
            "basic-username": {"Authorization": "Basic " + base64.b64encode(f"{key}:".encode()).decode()},
        }[style]
        assert env.post("alertmanager", sample_bytes("alertmanager"), None, headers=headers).status_code == 202

    def test_source_restricted_key(self, env):
        key = env.new_key(source="grafana")
        resp = env.post("datadog", sample_bytes("datadog"), key)
        assert resp.status_code == 403
        assert env.db.tables["alerts"] == []
        assert env.post("grafana", sample_bytes("grafana"), key).status_code == 202

    def test_machine_actor_on_timeline_and_last_used(self, env):
        key = env.new_key(name="grafana-prod")
        [r] = env.post("grafana", sample_bytes("grafana"), key).json()["results"]
        created = [e for e in env.db.tables["audit_events"] if e["event_type"] == "incident.created"]
        assert created[0]["actor"] == "apikey:grafana-prod"
        assert env.db.tables["alerts"][0]["api_key_id"] == env.db.tables["api_keys"][0]["id"]
        assert env.db.tables["api_keys"][0]["last_used_at"] is not None


# ---------------------------------------------------------------------------
# Webhook request handling
# ---------------------------------------------------------------------------


class TestWebhookRequests:
    def test_unknown_source_404_or_422(self, env):
        key = env.new_key()
        assert env.post("nagios", {"x": 1}, key).status_code == 422

    def test_invalid_json(self, env):
        key = env.new_key()
        assert env.post("alertmanager", b"{not json", key).status_code == 400

    def test_wrong_shape(self, env):
        key = env.new_key()
        resp = env.post("alertmanager", {"alerts": []}, key)
        assert resp.status_code == 422 and "alerts" in resp.json()["detail"]
        assert env.db.tables["alerts"] == []

    def test_body_too_large(self, env, monkeypatch):
        import routers.alerts as mod

        monkeypatch.setattr(mod, "MAX_BODY_BYTES", 100)
        key = env.new_key()
        assert env.post("alertmanager", sample_bytes("alertmanager"), key).status_code == 413

    def test_too_many_alerts(self, env, monkeypatch):
        import routers.alerts as mod

        monkeypatch.setattr(mod, "MAX_ALERTS_PER_CALL", 1)
        body = json.loads(sample_bytes("alertmanager"))
        body["alerts"].append(dict(body["alerts"][0], fingerprint="other"))
        key = env.new_key()
        assert env.post("alertmanager", body, key).status_code == 413
        assert env.db.tables["alerts"] == []

    def test_storage_down_returns_503_so_tool_retries(self, env):
        key = env.new_key()
        env.db.fail_tables["alerts"] = RuntimeError("supabase down")
        assert env.post("alertmanager", sample_bytes("alertmanager"), key).status_code == 503

    def test_sns_plain_text_content_type_accepted(self, env):
        key = env.new_key()
        resp = env.post("cloudwatch", sample_bytes("cloudwatch"), key,
                        headers={"Authorization": f"Bearer {key}", "Content-Type": "text/plain; charset=UTF-8"})
        assert resp.status_code == 202

    def test_resolved_then_firing_batch(self, env):
        key = env.new_key()
        firing = json.loads(sample_bytes("alertmanager"))
        env.post("alertmanager", firing, key)
        resolved = json.loads(sample_bytes("alertmanager"))
        resolved["status"] = "resolved"
        resolved["alerts"][0]["status"] = "resolved"
        [r] = env.post("alertmanager", resolved, key).json()["results"]
        assert r["disposition"] == "resolved"
        assert env.db.tables["incidents"][0]["status"] == "open"


class TestSnsSubscription:
    def _confirmation(self, url):
        return {"Type": "SubscriptionConfirmation", "MessageId": "m", "Token": "t",
                "TopicArn": "arn:aws:sns:eu-west-1:123456789012:aegisflow-alarms",
                "SubscribeURL": url, "Message": "You have chosen to subscribe..."}

    def test_genuine_link_confirmed_and_audited(self, env):
        key = env.new_key(source="cloudwatch")
        url = "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:x&Token=abc"
        resp = env.post("cloudwatch", self._confirmation(url), key)
        assert resp.status_code == 200 and resp.json() == {"subscription": "confirmed"}
        assert env.confirmed == [url]
        assert env.db.tables["audit_events"][-1]["event_type"] == "integration.subscription_confirmed"
        assert env.db.tables["alerts"] == []

    @pytest.mark.parametrize("url", [
        "http://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription",
        "https://sns.eu-west-1.amazonaws.com.evil.com/?Action=ConfirmSubscription",
        "https://evil.com/?Action=ConfirmSubscription",
        "https://169.254.169.254/latest/meta-data",
        "https://sns.eu-west-1.amazonaws.com/?Action=Publish",
        "https://user@sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription",
        "https://sns.eu-west-1.amazonaws.com:8443/?Action=ConfirmSubscription",
        "",
    ])
    def test_anything_else_is_never_fetched(self, env, url):
        key = env.new_key()
        assert env.post("cloudwatch", self._confirmation(url), key).status_code == 422
        assert env.confirmed == []

    def test_confirmation_needs_a_key(self, env):
        url = "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
        assert env.post("cloudwatch", self._confirmation(url), None).status_code == 401
        assert env.confirmed == []

    def test_aws_failure_is_502(self, env):
        def boom(url):
            raise RuntimeError("aws unreachable")

        env.app.dependency_overrides[get_sns_confirmer] = lambda: boom
        key = env.new_key()
        url = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=abc"
        assert env.post("cloudwatch", self._confirmation(url), key).status_code == 502


# ---------------------------------------------------------------------------
# Manual alerts (FR-2) and browsing
# ---------------------------------------------------------------------------


class TestManualAndBrowse:
    def test_responder_submits_alert(self, env):
        env.login(RESPONDER)
        resp = env.client.post("/alerts", json={"service_id": "payment-service", "title": "Payments failing",
                                                "description": "Customers report card declines", "severity": "high"})
        assert resp.status_code == 202
        body = resp.json()
        assert body["disposition"] == "created" and body["analysis_queued"]
        inc = env.db.tables["incidents"][0]
        assert inc["source"] == "manual" and "Payments failing" in inc["alert"]
        created = [e for e in env.db.tables["audit_events"] if e["event_type"] == "incident.created"]
        assert created[0]["actor"] == "alice@example.com"
        again = env.client.post("/alerts", json={"service_id": "payment-service", "title": "payments failing"})
        assert again.json()["disposition"] == "deduplicated"

    def test_viewer_cannot_submit(self, env):
        env.login(VIEWER)
        assert env.client.post("/alerts", json={"service_id": "s", "title": "t"}).status_code == 403
        env.login(None)
        assert env.client.post("/alerts", json={"service_id": "s", "title": "t"}).status_code == 401

    def test_validation(self, env):
        env.login(RESPONDER)
        assert env.client.post("/alerts", json={"service_id": "", "title": "t"}).status_code == 422
        assert env.client.post("/alerts", json={"service_id": "s", "title": "x" * 301}).status_code == 422

    def test_list_and_get_alerts(self, env):
        key = env.new_key()
        env.post("alertmanager", sample_bytes("alertmanager"), key)
        env.post("alertmanager", sample_bytes("alertmanager"), key)
        env.post("datadog", sample_bytes("datadog"), key)
        env.login(VIEWER)
        all_ = env.client.get("/alerts").json()
        assert len(all_) == 3 and "raw" not in all_[0]
        assert len(env.client.get("/alerts", params={"source": "alertmanager"}).json()) == 2
        assert len(env.client.get("/alerts", params={"disposition": "deduplicated"}).json()) == 1
        inc_id = env.db.tables["incidents"][0]["id"]
        assert len(env.client.get("/alerts", params={"incident_id": inc_id}).json()) == 2
        assert env.client.get("/alerts", params={"incident_id": "junk"}).json() == []
        assert env.client.get("/alerts", params={"limit": 1}).status_code == 200
        assert env.client.get("/alerts", params={"limit": 500}).status_code == 422
        detail = env.client.get(f"/alerts/{all_[0]['id']}").json()
        assert detail["raw"]
        assert env.client.get("/alerts/not-a-uuid").status_code == 404
        assert env.client.get("/alerts/00000000-0000-0000-0000-000000000123").status_code == 404

    def test_browsing_needs_login(self, env):
        env.login(None)
        assert env.client.get("/alerts").status_code == 401

    def test_timeline_shows_intake_events(self, env):
        key = env.new_key()
        [r] = env.post("alertmanager", sample_bytes("alertmanager"), key).json()["results"]
        env.post("alertmanager", sample_bytes("alertmanager"), key)
        env.login(VIEWER)
        types = [e["event_type"] for e in env.client.get(f"/incidents/{r['incident_id']}/timeline").json()]
        assert types[:2] == ["incident.created", "alert.received"]
        assert "alert.deduplicated" in types and "analysis.saved" in types

    def test_reopen_conflict_is_409(self, env):
        env.login(RESPONDER)
        first = env.client.post("/alerts", json={"service_id": "s", "title": "t"}).json()
        env.client.patch(f"/incidents/{first['incident_id']}/status", json={"status": "resolved"})
        env.client.post("/alerts", json={"service_id": "s", "title": "t"})  # recurrence
        resp = env.client.patch(f"/incidents/{first['incident_id']}/status", json={"status": "open"})
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Maintenance windows (FR-4)
# ---------------------------------------------------------------------------


def _iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


class TestMaintenanceWindows:
    def test_window_suppresses_webhook_alerts_end_to_end(self, env):
        env.login(RESPONDER)
        resp = env.client.post("/maintenance-windows", json={
            "service_id": "payment-service", "ends_at": _iso(60), "reason": "DB upgrade"})
        assert resp.status_code == 201, resp.text
        window = resp.json()
        assert window["created_by"] == "alice@example.com"

        key = env.new_key()
        [r] = env.post("alertmanager", sample_bytes("alertmanager"), key).json()["results"]
        assert r["disposition"] == "suppressed" and r["maintenance_window_id"] == window["id"]
        assert env.db.tables["incidents"] == []

        # cancel early: alerts open incidents again
        env.login(RESPONDER)
        assert env.client.post(f"/maintenance-windows/{window['id']}/cancel").status_code == 200
        [r2] = env.post("alertmanager", sample_bytes("alertmanager"), key).json()["results"]
        assert r2["disposition"] == "created"

        types = [e["event_type"] for e in env.db.tables["audit_events"] if e["incident_id"] is None]
        assert "maintenance.scheduled" in types and "maintenance.cancelled" in types
        assert "alert.suppressed" in types

    def test_list_shows_current_and_future_only(self, env):
        env.login(RESPONDER)
        env.client.post("/maintenance-windows", json={"service_id": "a", "ends_at": _iso(60)})
        env.client.post("/maintenance-windows", json={"service_id": "b", "starts_at": _iso(60), "ends_at": _iso(120)})
        cancelled = env.client.post("/maintenance-windows", json={"service_id": "c", "ends_at": _iso(60)}).json()
        env.client.post(f"/maintenance-windows/{cancelled['id']}/cancel")
        env.login(VIEWER)
        listed = env.client.get("/maintenance-windows").json()
        assert [w["service_id"] for w in listed] == ["a", "b"]
        assert [w["service_id"] for w in env.client.get("/maintenance-windows", params={"service_id": "b"}).json()] == ["b"]

    @pytest.mark.parametrize("body", [
        {"service_id": "s", "ends_at": "2020-01-01T00:00:00Z"},                       # past
        {"service_id": "s", "starts_at": "2030-01-02T00:00:00Z", "ends_at": "2030-01-01T00:00:00Z"},
        {"service_id": "s", "ends_at": "2099-01-01T00:00:00"},                        # no timezone
        {"service_id": "s", "ends_at": (datetime.now(timezone.utc) + timedelta(days=15)).isoformat()},
        {"service_id": "", "ends_at": "2099-01-01T00:00:00Z"},
    ])
    def test_invalid_windows(self, env, body):
        env.login(RESPONDER)
        assert env.client.post("/maintenance-windows", json=body).status_code == 422

    def test_roles(self, env):
        env.login(VIEWER)
        assert env.client.post("/maintenance-windows", json={"service_id": "s", "ends_at": _iso(5)}).status_code == 403
        assert env.client.get("/maintenance-windows").status_code == 200
        env.login(None)
        assert env.client.get("/maintenance-windows").status_code == 401

    def test_cancel_unknown_and_twice(self, env):
        env.login(RESPONDER)
        assert env.client.post("/maintenance-windows/junk/cancel").status_code == 404
        w = env.client.post("/maintenance-windows", json={"service_id": "s", "ends_at": _iso(5)}).json()
        assert env.client.post(f"/maintenance-windows/{w['id']}/cancel").status_code == 200
        assert env.client.post(f"/maintenance-windows/{w['id']}/cancel").status_code == 409
