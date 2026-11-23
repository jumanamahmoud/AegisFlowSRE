"""
backend/tests/test_analysis_queue.py
=====================================
Background analysis: real worker threads, restart recovery, failure handling.
"""

from __future__ import annotations

import threading
import time

import pytest

from core.logging import request_id_var
from database.incident_store import AnalysisAlreadyPendingError, IncidentStore
from services.analysis_queue import AnalysisQueue
from tests.conftest import make_pipeline_state


def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def queued(store):
    def make():
        inc = store.create_incident("payment-service", "pool exhausted")
        store.enqueue_analysis(inc["id"], actor="alice@example.com", request_id="req-1")
        return inc["id"]
    return make


class TestEnqueue:
    def test_enqueue_marks_queued_and_audits(self, store, fake_supabase):
        inc = store.create_incident("svc", "alert")
        store.enqueue_analysis(inc["id"], actor="alice@example.com", request_id="abc")
        row = store.get_incident(inc["id"])
        assert row["analysis_status"] == "queued"
        event = fake_supabase.tables["audit_events"][-1]
        assert event["event_type"] == "analysis.queued"
        assert event["actor"] == "alice@example.com"
        assert event["payload"] == {"request_id": "abc"}

    @pytest.mark.parametrize("pending", ["queued", "running"])
    def test_enqueue_refused_while_pending(self, store, fake_supabase, pending):
        inc = store.create_incident("svc", "alert")
        fake_supabase.tables["incidents"][0]["analysis_status"] = pending
        with pytest.raises(AnalysisAlreadyPendingError):
            store.enqueue_analysis(inc["id"], actor="a")

    @pytest.mark.parametrize("idle", ["none", "completed", "failed"])
    def test_enqueue_allowed_when_idle(self, store, fake_supabase, idle):
        inc = store.create_incident("svc", "alert")
        fake_supabase.tables["incidents"][0]["analysis_status"] = idle
        store.enqueue_analysis(inc["id"], actor="a")
        assert store.get_incident(inc["id"])["analysis_status"] == "queued"


class TestWorkers:
    def test_threaded_job_completes(self, store, fake_supabase, queued):
        q = AnalysisQueue(store_factory=lambda: store, pipeline=lambda a, s: make_pipeline_state(),
                          max_workers=2)
        incident_id = queued()
        future = q.submit(incident_id)
        future.result(timeout=5)
        q.shutdown()
        row = store.get_incident(incident_id)
        assert row["analysis_status"] == "completed"
        assert len(fake_supabase.tables["incident_analyses"]) == 1

    def test_submit_returns_before_pipeline_finishes(self, store, queued):
        """The whole point of Week 2: the request is not blocked by the analysis."""
        release = threading.Event()

        def slow_pipeline(alert, service_id):
            release.wait(5)
            return make_pipeline_state()

        q = AnalysisQueue(store_factory=lambda: store, pipeline=slow_pipeline, max_workers=1)
        incident_id = queued()
        started = time.perf_counter()
        future = q.submit(incident_id)
        assert time.perf_counter() - started < 0.5
        assert _wait_for(lambda: store.get_incident(incident_id)["analysis_status"] == "running")
        release.set()
        future.result(timeout=5)
        assert store.get_incident(incident_id)["analysis_status"] == "completed"
        q.shutdown()

    def test_jobs_beyond_pool_size_wait_in_order(self, store, queued):
        order, lock = [], threading.Lock()

        def pipeline(alert, service_id):
            time.sleep(0.02)
            return make_pipeline_state()

        q = AnalysisQueue(store_factory=lambda: store, pipeline=pipeline, max_workers=1)
        ids = [queued() for _ in range(4)]
        futures = []
        for i in ids:
            futures.append(q.submit(i))
            futures[-1].add_done_callback(lambda f, i=i: (lock.acquire(), order.append(i), lock.release()))
        for f in futures:
            f.result(timeout=5)
        q.shutdown()
        assert order == ids
        assert all(store.get_incident(i)["analysis_status"] == "completed" for i in ids)

    def test_failure_marks_failed_with_error(self, store, fake_supabase, queued):
        def boom(alert, service_id):
            raise TimeoutError("groq timeout")

        q = AnalysisQueue(store_factory=lambda: store, pipeline=boom, inline=True)
        incident_id = queued()
        q.submit(incident_id)  # must not raise: worker failures are contained
        row = store.get_incident(incident_id)
        assert row["analysis_status"] == "failed"
        assert row["analysis_error"] == "TimeoutError: groq timeout"
        assert fake_supabase.tables["audit_events"][-1]["event_type"] == "analysis.failed"

    def test_job_not_queued_is_skipped(self, store):
        """A duplicate submit (e.g. recovery racing a live worker) does nothing."""
        calls = []
        q = AnalysisQueue(store_factory=lambda: store,
                          pipeline=lambda a, s: calls.append(1) or make_pipeline_state(), inline=True)
        inc = store.create_incident("svc", "alert")  # analysis_status 'none', never queued
        q.submit(inc["id"])
        assert calls == []

    def test_request_id_reaches_worker_thread(self, store, queued):
        seen = []

        def pipeline(alert, service_id):
            seen.append(request_id_var.get())
            return make_pipeline_state()

        q = AnalysisQueue(store_factory=lambda: store, pipeline=pipeline, max_workers=1)
        incident_id = queued()
        token = request_id_var.set("req-42")
        try:
            q.submit(incident_id).result(timeout=5)
        finally:
            request_id_var.reset(token)
            q.shutdown()
        assert seen == ["req-42"]


class TestRecovery:
    def test_recover_resumes_queued_and_interrupted_jobs(self, store, fake_supabase):
        """After a restart, nothing that was accepted is lost."""
        a = store.create_incident("svc", "queued before restart")
        b = store.create_incident("svc", "running when the process died")
        c = store.create_incident("svc", "finished")
        rows = {r["id"]: r for r in fake_supabase.tables["incidents"]}
        rows[a["id"]]["analysis_status"] = "queued"
        rows[b["id"]]["analysis_status"] = "running"
        rows[c["id"]]["analysis_status"] = "completed"

        ran = []
        q = AnalysisQueue(store_factory=lambda: store,
                          pipeline=lambda alert, s: ran.append(alert) or make_pipeline_state(),
                          inline=True)
        assert q.recover() == 2
        assert sorted(ran) == ["queued before restart", "running when the process died"]
        assert store.get_incident(a["id"])["analysis_status"] == "completed"
        assert store.get_incident(b["id"])["analysis_status"] == "completed"
        assert store.get_incident(c["id"])["analysis_status"] == "completed"
        assert len(fake_supabase.tables["incident_analyses"]) == 2

    def test_recover_with_nothing_pending(self, store):
        q = AnalysisQueue(store_factory=lambda: store, pipeline=lambda a, s: make_pipeline_state(), inline=True)
        assert q.recover() == 0

    def test_shutdown_leaves_unstarted_jobs_queued(self, store, queued):
        release = threading.Event()

        def blocking(alert, service_id):
            release.wait(5)
            return make_pipeline_state()

        q = AnalysisQueue(store_factory=lambda: store, pipeline=blocking, max_workers=1)
        first, second = queued(), queued()
        q.submit(first)
        q.submit(second)
        assert _wait_for(lambda: store.get_incident(first)["analysis_status"] == "running")
        q.shutdown()  # cancels 'second' before it starts
        release.set()
        assert _wait_for(lambda: store.get_incident(first)["analysis_status"] == "completed")
        assert store.get_incident(second)["analysis_status"] == "queued"  # picked up by recover()
