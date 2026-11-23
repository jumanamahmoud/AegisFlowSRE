"""
backend/tests/test_alert_intake.py
===================================
Intake rules on the in-memory database: store first, maintenance windows
(FR-4), duplicate detection (FR-3), recovery notices, automatic analysis and
recovery after a restart.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from database.alert_store import AlertStore
from database.incident_store import IncidentStore
from services.alert_intake import AlertIntake
from services.alert_sources import manual_alert
from services.analysis_queue import AnalysisQueue
from tests.conftest import make_pipeline_state

ACTOR = "apikey:prometheus-prod"


@pytest.fixture
def db(fake_supabase):
    return fake_supabase


@pytest.fixture
def queue(db):
    return AnalysisQueue(store_factory=lambda: IncidentStore(db),
                         pipeline=lambda a, s: make_pipeline_state(), inline=True)


@pytest.fixture
def intake(db, queue):
    return AlertIntake(IncidentStore(db), AlertStore(db), queue, auto_analyze=True)


def alert(title="DB down", service="payment-service", **kw):
    return manual_alert(service, title, **kw)


def events(db, incident_id=None, type_=None):
    return [e for e in db.tables["audit_events"]
            if (incident_id is None or e["incident_id"] == incident_id)
            and (type_ is None or e["event_type"] == type_)]


class TestNewIncident:
    def test_firing_alert_opens_incident_and_queues_analysis(self, db, intake):
        [r] = intake.receive([alert()], ACTOR)
        assert r.disposition == "created" and r.analysis_queued
        [inc] = db.tables["incidents"]
        assert inc["id"] == r.incident_id
        assert inc["fingerprint"] == r.fingerprint and inc["source"] == "manual"
        assert inc["service_id"] == "payment-service"
        assert inc["metadata"]["first_alert_id"] == r.alert_id
        assert inc["analysis_status"] == "completed"  # inline queue ran the (fake) pipeline
        [a] = db.tables["alerts"]
        assert a["disposition"] == "created" and a["incident_id"] == inc["id"]
        assert a["received_by"] == ACTOR and a["processed_at"]
        types = [e["event_type"] for e in events(db, inc["id"])]
        assert types[:3] == ["incident.created", "alert.received", "analysis.queued"]
        assert all(e["actor"] == ACTOR for e in events(db, inc["id"])[:3])

    def test_auto_analyze_off(self, db, queue):
        intake = AlertIntake(IncidentStore(db), AlertStore(db), queue, auto_analyze=False)
        [r] = intake.receive([alert()], ACTOR)
        assert r.disposition == "created" and not r.analysis_queued
        assert db.tables["incidents"][0]["analysis_status"] == "none"

    def test_env_switch(self, db, queue, monkeypatch):
        monkeypatch.setenv("AEGIS_AUTO_ANALYZE", "0")
        [r] = AlertIntake(IncidentStore(db), AlertStore(db), queue).receive([alert()], ACTOR)
        assert not r.analysis_queued

    def test_queue_failure_keeps_incident(self, db, intake):
        with patch.object(IncidentStore, "enqueue_analysis", side_effect=RuntimeError("db blip")):
            [r] = intake.receive([alert()], ACTOR)
        assert r.disposition == "created" and not r.analysis_queued
        assert len(db.tables["incidents"]) == 1


class TestDuplicates:
    def test_repeat_attaches_to_open_incident(self, db, intake):
        first = intake.receive([alert()], ACTOR)[0]
        second = intake.receive([alert()], ACTOR)[0]
        assert second.disposition == "deduplicated"
        assert second.incident_id == first.incident_id
        assert len(db.tables["incidents"]) == 1
        assert len(db.tables["alerts"]) == 2  # both copies are on record
        assert len(events(db, first.incident_id, "alert.deduplicated")) == 1
        # no second analysis for a repeat
        assert len(events(db, first.incident_id, "analysis.queued")) == 1

    def test_repeat_within_one_batch(self, db, intake):
        results = intake.receive([alert(), alert()], ACTOR)
        assert [r.disposition for r in results] == ["created", "deduplicated"]
        assert len(db.tables["incidents"]) == 1

    @pytest.mark.parametrize("status", ["acknowledged", "mitigating"])
    def test_still_active_statuses_dedupe(self, db, intake, status):
        first = intake.receive([alert()], ACTOR)[0]
        IncidentStore(db).change_status(first.incident_id, "acknowledged", "alice")
        if status == "mitigating":
            IncidentStore(db).change_status(first.incident_id, "mitigating", "alice")
        assert intake.receive([alert()], ACTOR)[0].disposition == "deduplicated"

    def test_recurrence_after_resolution_opens_new_incident(self, db, intake):
        first = intake.receive([alert()], ACTOR)[0]
        IncidentStore(db).change_status(first.incident_id, "resolved", "alice")
        again = intake.receive([alert()], ACTOR)[0]
        assert again.disposition == "created" and again.incident_id != first.incident_id

    def test_different_alerts_get_different_incidents(self, db, intake):
        a = intake.receive([alert("DB down")], ACTOR)[0]
        b = intake.receive([alert("Disk full")], ACTOR)[0]
        assert a.incident_id != b.incident_id

    def test_lost_race_falls_back_to_winner(self, db, intake):
        """Two copies processed concurrently: both see no active incident, the
        unique index rejects the second insert, and it attaches to the first."""
        winner = intake.receive([alert()], ACTOR)[0]
        real_find = IncidentStore.find_active_by_fingerprint
        calls = {"n": 0}

        def stale_then_real(self, fp):
            calls["n"] += 1
            return None if calls["n"] == 1 else real_find(self, fp)

        with patch.object(IncidentStore, "find_active_by_fingerprint", stale_then_real):
            loser = intake.receive([alert()], ACTOR)[0]
        assert loser.disposition == "deduplicated" and loser.incident_id == winner.incident_id
        assert len(db.tables["incidents"]) == 1

    def test_reopen_blocked_while_newer_incident_active(self, db, intake):
        from database.incident_store import DuplicateActiveIncidentError

        first = intake.receive([alert()], ACTOR)[0]
        IncidentStore(db).change_status(first.incident_id, "resolved", "alice")
        intake.receive([alert()], ACTOR)  # recurrence: new incident owns the fingerprint
        with pytest.raises(DuplicateActiveIncidentError):
            IncidentStore(db).change_status(first.incident_id, "open", "alice")
        assert IncidentStore(db).get_incident(first.incident_id)["status"] == "resolved"


class TestRecoveryNotices:
    def test_resolved_notice_recorded_but_status_unchanged(self, db, intake):
        first = intake.receive([alert()], ACTOR)[0]
        notice = alert()
        notice.status = "resolved"
        [r] = intake.receive([notice], ACTOR)
        assert r.disposition == "resolved" and r.incident_id == first.incident_id
        assert IncidentStore(db).get_incident(first.incident_id)["status"] == "open"  # humans resolve
        assert len(events(db, first.incident_id, "alert.resolved_at_source")) == 1

    def test_resolved_without_incident_ignored(self, db, intake):
        notice = alert()
        notice.status = "resolved"
        assert intake.receive([notice], ACTOR)[0].disposition == "ignored"
        assert db.tables["incidents"] == []

    def test_info_ignored(self, db, intake):
        info = alert()
        info.status = "info"
        assert intake.receive([info], ACTOR)[0].disposition == "ignored"
        assert db.tables["incidents"] == []


class TestMaintenance:
    def _window(self, db, service="payment-service", start=-10, end=60):
        now = datetime.now(timezone.utc)
        return AlertStore(db).create_window(service, now + timedelta(minutes=start),
                                            now + timedelta(minutes=end), "deploy", "alice")

    def test_alert_suppressed_during_window(self, db, intake):
        w = self._window(db)
        [r] = intake.receive([alert()], ACTOR)
        assert r.disposition == "suppressed" and r.maintenance_window_id == w["id"]
        assert r.incident_id is None and not r.analysis_queued
        assert db.tables["incidents"] == []
        a = db.tables["alerts"][0]
        assert a["disposition"] == "suppressed" and a["maintenance_window_id"] == w["id"]
        [ev] = events(db, None, "alert.suppressed")
        assert ev["incident_id"] is None and ev["payload"]["maintenance_window_id"] == w["id"]

    def test_other_services_unaffected(self, db, intake):
        self._window(db, service="other-service")
        assert intake.receive([alert()], ACTOR)[0].disposition == "created"

    @pytest.mark.parametrize("start,end", [(-120, -60), (30, 90)])
    def test_past_and_future_windows_do_not_suppress(self, db, intake, start, end):
        self._window(db, start=start, end=end)
        assert intake.receive([alert()], ACTOR)[0].disposition == "created"

    def test_cancelled_window_does_not_suppress(self, db, intake):
        w = self._window(db)
        AlertStore(db).cancel_window(w["id"], "alice")
        assert intake.receive([alert()], ACTOR)[0].disposition == "created"

    def test_recovery_notices_still_attach_during_maintenance(self, db, intake):
        first = intake.receive([alert()], ACTOR)[0]
        self._window(db)
        notice = alert()
        notice.status = "resolved"
        assert intake.receive([notice], ACTOR)[0].disposition == "resolved"
        assert first.incident_id


class TestStoreFirstAndRecover:
    def test_storage_failure_raises_and_creates_nothing(self, db, intake):
        db.fail_tables["alerts"] = RuntimeError("supabase down")
        with pytest.raises(RuntimeError):
            intake.receive([alert()], ACTOR)
        assert db.tables["incidents"] == []

    def test_processing_failure_leaves_alert_received(self, db, intake):
        with patch.object(AlertStore, "active_window", side_effect=RuntimeError("blip")):
            [r] = intake.receive([alert()], ACTOR)
        assert r.disposition == "received" and r.incident_id is None
        assert db.tables["alerts"][0]["disposition"] == "received"

    def test_recover_processes_leftovers(self, db, intake):
        with patch.object(AlertStore, "active_window", side_effect=RuntimeError("blip")):
            intake.receive([alert(), alert("Disk full")], ACTOR)
        assert intake.recover() == 2
        assert {a["disposition"] for a in db.tables["alerts"]} == {"created"}
        assert len(db.tables["incidents"]) == 2
        # actor preserved from the original delivery
        assert {e["actor"] for e in events(db, type_="incident.created")} == {ACTOR}
        assert intake.recover() == 0

    def test_recover_survives_a_bad_row(self, db, intake):
        with patch.object(AlertStore, "active_window", side_effect=RuntimeError("blip")):
            intake.receive([alert()], ACTOR)
            assert intake.recover() == 1  # still failing: logged, not raised
