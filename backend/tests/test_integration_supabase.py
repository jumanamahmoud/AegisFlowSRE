"""
backend/tests/test_integration_supabase.py
===========================================
Live check against the real Supabase project — the Week-1 "done when":
*an analyzed incident is saved and its timeline can be read back.*

Skipped unless ``AEGIS_RUN_INTEGRATION=1``. Requires:
  * the migration in ``supabase/migrations/`` applied to the project
  * ``SUPABASE_URL`` and ``SUPABASE_SECRET_KEY`` in backend/.env

The pipeline itself is faked so no Groq / Jev / Neo4j quota is used; what is
verified is the real database round trip and its rules. Test incidents are
tagged ``metadata.integration_test = true`` and are not deleted (audit
history is append-only by design).

Run from backend/:
    $env:AEGIS_RUN_INTEGRATION=1; python -m pytest tests/test_integration_supabase.py -v
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

load_dotenv()

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_RUN_INTEGRATION") != "1",
    reason="set AEGIS_RUN_INTEGRATION=1 to run live Supabase tests",
)


@pytest.fixture(scope="module")
def live_client():
    """Real routers + real Supabase + a REAL background worker pool.

    Login is stubbed with a fixed responder (token verification is unit-tested
    in test_auth.py; signing a real Supabase token needs a real account).
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from core.auth import Principal, Role, get_current_user
    from database.incident_store import IncidentStore
    from database.supabase_client import get_supabase, reset_supabase_client
    from routers.incidents import router
    from services.analysis_queue import AnalysisQueue, get_analysis_queue
    from tests.conftest import make_pipeline_state

    reset_supabase_client()
    queue = AnalysisQueue(
        store_factory=lambda: IncidentStore(get_supabase()),
        pipeline=lambda a, s: make_pipeline_state(),
        max_workers=2,
    )
    app = FastAPI()
    app.include_router(router, prefix="/incidents")
    app.dependency_overrides[get_analysis_queue] = lambda: queue
    app.dependency_overrides[get_current_user] = lambda: Principal(
        user_id="00000000-0000-0000-0000-00000000a1e7", email="integration-test@aegisflow.local",
        role=Role.RESPONDER,
    )
    with TestClient(app) as client:
        yield client
    queue.shutdown()
    reset_supabase_client()


def _wait_for_analysis(client, incident_id, timeout=30.0):
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        incident = client.get(f"/incidents/{incident_id}").json()
        if incident["analysis_status"] in ("completed", "failed"):
            return incident
        time.sleep(0.25)
    raise AssertionError(f"analysis still {incident['analysis_status']} after {timeout}s")


def test_analyzed_incident_saved_and_timeline_read_back(live_client):
    resp = live_client.post(
        "/incidents/analyze",
        json={
            "service_id": "payment-service",
            "alert": "[integration test] DB pool exhausted",
            "metadata": {"integration_test": True},
        },
    )
    assert resp.status_code == 202, resp.text
    incident_id = resp.json()["incident_id"]

    incident = _wait_for_analysis(live_client, incident_id)
    assert incident["analysis_status"] == "completed", incident.get("analysis_error")
    assert incident["status"] == "open"
    assert incident["severity"] == "Critical"

    analyses = live_client.get(f"/incidents/{incident_id}/analyses").json()
    assert len(analyses) == 1
    assert analyses[0]["model_name"] == "openai/gpt-oss-120b"
    assert analyses[0]["total_tokens"] == 642

    events = live_client.get(f"/incidents/{incident_id}/timeline").json()
    assert [e["event_type"] for e in events] == [
        "incident.created", "analysis.queued", "analysis.started", "alert.sanitized",
        "graph.enriched", "triage.completed", "ai.invoked", "analysis.saved",
    ]
    assert events[0]["actor"] == "integration-test@aegisflow.local"

    # Lifecycle round trip; the actor comes from the login, not the body
    assert live_client.patch(f"/incidents/{incident_id}/status",
                             json={"status": "acknowledged", "actor": "spoofed"}).status_code == 200
    assert live_client.get(f"/incidents/{incident_id}/timeline").json()[-1]["actor"] ==         "integration-test@aegisflow.local"
    assert live_client.patch(f"/incidents/{incident_id}/status",
                             json={"status": "closed"}).status_code == 409


def test_double_analyze_while_pending_is_409(live_client):
    created = live_client.post("/incidents/", json={
        "service_id": "payment-service", "alert": "[integration test] double click",
        "metadata": {"integration_test": True},
    }).json()
    first = live_client.post("/incidents/analyze", json={
        "service_id": "x", "alert": "x", "incident_id": created["id"]})
    second = live_client.post("/incidents/analyze", json={
        "service_id": "x", "alert": "x", "incident_id": created["id"]})
    assert first.status_code == 202
    # The second either hits the pending job (409) or arrives after it finished (202).
    assert second.status_code in (202, 409)
    _wait_for_analysis(live_client, created["id"])


def test_week2_schema_present():
    """user_roles table and analysis_status column exist (week2 migration applied)."""
    from database.supabase_client import get_supabase

    sb = get_supabase()
    sb.table("user_roles").select("user_id,role,updated_by").limit(1).execute()
    sb.table("incidents").select("analysis_status,analysis_error,analysis_updated_at").limit(1).execute()


def test_user_roles_not_readable_with_publishable_key():
    from supabase import create_client

    from database.supabase_client import supabase_url

    key = os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "").strip()
    if not key:
        pytest.skip("no publishable key in .env to test with")
    public = create_client(supabase_url(), key)
    with pytest.raises(Exception, match="permission denied|42501"):
        public.table("user_roles").select("*").execute()


def test_audit_events_cannot_be_modified_in_database(live_client):
    """The DB trigger must block UPDATE and DELETE even for the secret key."""
    from database.supabase_client import get_supabase

    sb = get_supabase()
    row = sb.table("audit_events").select("id").limit(1).execute().data
    if not row:
        pytest.skip("no audit events yet")
    event_id = row[0]["id"]

    with pytest.raises(Exception, match="append-only"):
        sb.table("audit_events").update({"actor": "tampered"}).eq("id", event_id).execute()
    with pytest.raises(Exception, match="append-only"):
        sb.table("audit_events").delete().eq("id", event_id).execute()


def test_parallel_status_changes_one_winner_one_event(live_client):
    """Concurrent requests: exactly one succeeds, no transport errors, and the
    timeline has exactly one status change (per-thread client + atomic RPC)."""
    import threading

    from fastapi.testclient import TestClient

    created = live_client.post("/incidents/", json={
        "service_id": "payment-service", "alert": "[integration test] race",
        "metadata": {"integration_test": True},
    }).json()
    app = live_client.app
    codes, errors, barrier = [], [], threading.Barrier(6)

    def worker():
        client = TestClient(app)
        barrier.wait()
        try:
            codes.append(client.patch(f"/incidents/{created['id']}/status",
                                      json={"status": "acknowledged", "actor": "racer"}).status_code)
        except Exception as exc:  # transport errors are the bug being guarded
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert errors == []
    assert sorted(codes) == [200] + [409] * 5
    events = live_client.get(f"/incidents/{created['id']}/timeline").json()
    assert [e["event_type"] for e in events].count("incident.status_changed") == 1


def test_status_function_not_callable_with_publishable_key():
    """change_incident_status must be locked to the backend's secret key."""
    from supabase import create_client

    from database.supabase_client import supabase_url

    key = os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "").strip()
    if not key:
        pytest.skip("no publishable key in .env to test with")
    public = create_client(supabase_url(), key)
    # Only a permission error counts: "function not found" (PGRST202) would
    # mean the migration isn't applied, not that the function is locked down.
    with pytest.raises(Exception, match="permission denied|42501"):
        public.rpc("change_incident_status", {
            "p_incident_id": "00000000-0000-0000-0000-000000000000",
            "p_from": "open", "p_to": "acknowledged", "p_actor": "anon",
        }).execute()
