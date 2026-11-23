"""
backend/tests/test_incident_store.py
=====================================
Unit tests for the persistence layer:
  * database/supabase_client.py  — secret-key only client
  * database/incident_store.py   — incidents, analyses, audit timeline
  * services/incident_service.py — analyse-and-record flow
"""

from __future__ import annotations

import pytest

from database import supabase_client
from database.incident_store import ConcurrentUpdateError, IncidentNotFoundError
from models.incident import InvalidTransitionError
from services.incident_service import analyze_and_record, build_analysis_record
from tests.conftest import make_pipeline_state
from tests.fakes import ImmutableTableError


# ---------------------------------------------------------------------------
# Supabase client — secure key handling
# ---------------------------------------------------------------------------


class TestSupabaseClient:
    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        for var in ("SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL",
                    "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY"):
            monkeypatch.delenv(var, raising=False)
        supabase_client.reset_supabase_client()
        yield
        supabase_client.reset_supabase_client()

    def test_missing_url_raises(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_secret_x")
        with pytest.raises(RuntimeError, match="SUPABASE_URL"):
            supabase_client.get_supabase()

    def test_missing_secret_key_raises_even_with_publishable_key(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "sb_publishable_x")
        with pytest.raises(RuntimeError, match="SUPABASE_SECRET_KEY"):
            supabase_client.get_supabase()

    def test_publishable_key_in_secret_slot_rejected(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_publishable_oops")
        with pytest.raises(RuntimeError, match="publishable"):
            supabase_client.get_supabase()

    def test_client_built_with_secret_key_and_cached(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_secret_abc")
        calls = []
        monkeypatch.setattr(
            supabase_client, "create_client", lambda url, key: calls.append((url, key)) or object()
        )
        first = supabase_client.get_supabase()
        assert supabase_client.get_supabase() is first
        assert calls == [("https://x.supabase.co", "sb_secret_abc")]

    def test_legacy_names_are_accepted(self, monkeypatch):
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_URL", "https://y.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "service-role-jwt")
        assert supabase_client.supabase_url() == "https://y.supabase.co"
        assert supabase_client.supabase_secret_key() == "service-role-jwt"


# ---------------------------------------------------------------------------
# IncidentStore
# ---------------------------------------------------------------------------


class TestIncidentStore:
    def test_create_defaults_to_open_and_audits(self, store, fake_supabase):
        incident = store.create_incident("svc", "alert", {"k": "v"})
        assert incident["status"] == "open"
        events = fake_supabase.tables["audit_events"]
        assert len(events) == 1
        assert events[0]["event_type"] == "incident.created"
        assert events[0]["incident_id"] == incident["id"]

    def test_get_unknown_raises(self, store):
        with pytest.raises(IncidentNotFoundError):
            store.get_incident("missing")

    def test_change_status_stamps_time_once(self, store):
        inc = store.create_incident("svc", "alert")
        updated = store.change_status(inc["id"], "acknowledged", actor="bob")
        assert updated["status"] == "acknowledged"
        assert updated["acknowledged_at"]

    def test_invalid_transition_writes_nothing(self, store, fake_supabase):
        inc = store.create_incident("svc", "alert")
        with pytest.raises(InvalidTransitionError):
            store.change_status(inc["id"], "mitigating", actor="bob")
        assert store.get_incident(inc["id"])["status"] == "open"
        assert len(fake_supabase.tables["audit_events"]) == 1

    def test_concurrent_status_change_detected(self, store, fake_supabase):
        """Compare-and-set: if the row changed after validation, nothing is written."""
        inc = store.create_incident("svc", "alert")
        real_get = store.get_incident

        def stale_get(incident_id):
            row = real_get(incident_id)
            # Another request acknowledges it after we read 'open'.
            fake_supabase.tables["incidents"][0]["status"] = "acknowledged"
            return row

        store.get_incident = stale_get
        with pytest.raises(ConcurrentUpdateError):
            store.change_status(inc["id"], "resolved", actor="bob")
        assert fake_supabase.tables["incidents"][0]["status"] == "acknowledged"
        assert [e["event_type"] for e in fake_supabase.tables["audit_events"]] == ["incident.created"]

    def test_audit_events_are_append_only(self, store, fake_supabase):
        inc = store.create_incident("svc", "alert")
        with pytest.raises(ImmutableTableError):
            fake_supabase.table("audit_events").update({"actor": "x"}).eq("incident_id", inc["id"]).execute()
        with pytest.raises(ImmutableTableError):
            fake_supabase.table("audit_events").delete().eq("incident_id", inc["id"]).execute()

    def test_append_events_bulk_preserves_occurred_at(self, store):
        inc = store.create_incident("svc", "alert")
        store.append_events(inc["id"], [
            {"event_type": "triage.completed", "payload": {"a": 1}, "occurred_at": "2030-01-01T00:00:01+00:00"},
            {"event_type": "ai.skipped", "payload": {}, "occurred_at": "2030-01-01T00:00:02+00:00"},
        ])
        timeline = store.get_timeline(inc["id"])
        assert [e["event_type"] for e in timeline][-2:] == ["triage.completed", "ai.skipped"]
        assert timeline[-1]["occurred_at"] == "2030-01-01T00:00:02+00:00"

    def test_append_events_rejects_unknown_type(self, store):
        inc = store.create_incident("svc", "alert")
        with pytest.raises(ValueError):
            store.append_events(inc["id"], [{"event_type": "made.up", "payload": {}}])

    def test_append_events_empty_is_noop(self, store):
        assert store.append_events("anything", []) == []

    def test_save_analysis_updates_incident_classification(self, store):
        inc = store.create_incident("svc", "alert")
        state = make_pipeline_state()
        store.save_analysis(inc["id"], build_analysis_record(state, "t0", "t1"))
        refreshed = store.get_incident(inc["id"])
        assert refreshed["incident_category"] == "database"
        assert refreshed["severity"] == "Critical"
        assert len(store.list_analyses(inc["id"])) == 1


# ---------------------------------------------------------------------------
# analyze_and_record
# ---------------------------------------------------------------------------


class TestAnalyzeAndRecord:
    def test_build_analysis_record_maps_all_columns(self):
        record = build_analysis_record(make_pipeline_state(), "t0", "t1")
        assert record == {
            "incident_category": "database",
            "severity_score": 3,
            "severity": "Critical",
            "escalation_noul": 0.9,
            "needs_escalation": True,
            "analysis_source": "llm",
            "llm_reasoning": "Root cause: connection pool exhausted on payment-db.",
            "model_name": "openai/gpt-oss-120b",
            "prompt_tokens": 412,
            "completion_tokens": 230,
            "total_tokens": 642,
            "llm_latency_ms": 1840,
            "service_context": [{"name": "payment-db", "type": "database", "protocol": "TCP"}],
            "blast_radius": [{"id": "checkout-service", "name": "Checkout Service", "type": "service"}],
            "started_at": "t0",
            "completed_at": "t1",
        }

    def test_creates_incident_and_persists_everything(self, store, fake_supabase):
        result = analyze_and_record(
            store, "alert", "payment-service", pipeline=lambda a, s: make_pipeline_state()
        )
        assert result["incident"]["status"] == "open"
        assert result["analysis"]["incident_id"] == result["incident"]["id"]
        assert len(fake_supabase.tables["incidents"]) == 1
        assert len(fake_supabase.tables["incident_analyses"]) == 1
        assert [e["event_type"] for e in fake_supabase.tables["audit_events"]] == [
            "incident.created", "analysis.started", "graph.enriched",
            "triage.completed", "ai.invoked", "analysis.saved",
        ]

    def test_failure_is_audited_and_reraised(self, store, fake_supabase):
        def boom(alert, service_id):
            raise TimeoutError("groq timeout")

        with pytest.raises(TimeoutError):
            analyze_and_record(store, "alert", "svc", pipeline=boom)
        last = fake_supabase.tables["audit_events"][-1]
        assert last["event_type"] == "analysis.failed"
        assert last["payload"] == {"error_type": "TimeoutError", "error": "groq timeout"}
        assert fake_supabase.tables["incident_analyses"] == []


# ---------------------------------------------------------------------------
# Concurrency fixes: per-thread client + atomic status change
# ---------------------------------------------------------------------------


class TestPerThreadClient:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
        monkeypatch.setenv("SUPABASE_SECRET_KEY", "sb_secret_abc")
        monkeypatch.setattr(supabase_client, "create_client", lambda url, key: object())
        supabase_client.reset_supabase_client()
        yield
        supabase_client.reset_supabase_client()

    def test_same_thread_reuses_client(self):
        assert supabase_client.get_supabase() is supabase_client.get_supabase()

    def test_each_thread_gets_its_own_client(self):
        import threading

        seen = []
        threads = [threading.Thread(target=lambda: seen.append(supabase_client.get_supabase()))
                   for _ in range(4)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        main_client = supabase_client.get_supabase()
        assert len({id(c) for c in seen + [main_client]}) == 5

    def test_reset_rebuilds_client_in_every_thread(self):
        import threading

        holder = {}
        ready, go, done = threading.Event(), threading.Event(), threading.Event()

        def worker():
            holder["before"] = supabase_client.get_supabase()
            ready.set()
            go.wait()
            holder["after"] = supabase_client.get_supabase()
            done.set()

        t = threading.Thread(target=worker)
        t.start()
        ready.wait()
        supabase_client.reset_supabase_client()  # called from another thread
        go.set()
        done.wait()
        t.join()
        assert holder["before"] is not holder["after"]


class TestAtomicStatusChange:
    def test_audit_failure_rolls_back_status(self, store, fake_supabase):
        """If the audit event can't be written, the status must not change."""
        inc = store.create_incident("svc", "alert")
        fake_supabase.fail_tables["audit_events"] = ConnectionError("network blip")
        with pytest.raises(ConnectionError):
            store.change_status(inc["id"], "acknowledged", actor="bob")
        fake_supabase.fail_tables.clear()
        row = store.get_incident(inc["id"])
        assert row["status"] == "open"
        assert row["acknowledged_at"] is None
        assert [e["event_type"] for e in fake_supabase.tables["audit_events"]] == ["incident.created"]

    def test_status_change_uses_single_rpc_call(self, store, fake_supabase, monkeypatch):
        inc = store.create_incident("svc", "alert")
        calls = []
        real_rpc = fake_supabase.rpc
        monkeypatch.setattr(fake_supabase, "rpc",
                            lambda fn, params: calls.append((fn, params)) or real_rpc(fn, params))
        store.change_status(inc["id"], "acknowledged", actor="bob", note="on it")
        assert calls == [("change_incident_status", {
            "p_incident_id": inc["id"], "p_from": "open", "p_to": "acknowledged",
            "p_actor": "bob", "p_note": "on it",
        })]

    def test_missing_db_function_gives_migration_hint(self, store, fake_supabase, monkeypatch):
        inc = store.create_incident("svc", "alert")

        def missing(fn, params):
            raise Exception("{'code': 'PGRST202', 'message': 'Could not find the function'}")

        monkeypatch.setattr(fake_supabase, "rpc", missing)
        with pytest.raises(RuntimeError, match="atomic_status_change.sql"):
            store.change_status(inc["id"], "acknowledged", actor="bob")

    def test_parallel_changes_one_winner_one_event(self, store, fake_supabase):
        import threading

        inc = store.create_incident("svc", "alert")
        outcomes, barrier = [], threading.Barrier(8)

        def worker():
            barrier.wait()
            try:
                store.change_status(inc["id"], "acknowledged", actor="racer")
                outcomes.append("ok")
            except (ConcurrentUpdateError, InvalidTransitionError):
                outcomes.append("rejected")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert outcomes.count("ok") == 1 and outcomes.count("rejected") == 7
        changes = [e for e in fake_supabase.tables["audit_events"]
                   if e["event_type"] == "incident.status_changed"]
        assert len(changes) == 1
