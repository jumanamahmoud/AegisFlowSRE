"""
backend/tests/test_integration_intake.py
=========================================
Live Week 3 check against the real Supabase project: the alert tables exist
and the unique index really prevents a second active incident for the same
alert (the in-memory fake only imitates it).

Skipped unless ``AEGIS_RUN_INTEGRATION=1``; needs the Week 3 migration applied.
Test rows are tagged with a ``integration-test-<run>`` service id and are not
deleted (audit history is append-only by design).

    $env:AEGIS_RUN_INTEGRATION=1; python -m pytest tests/test_integration_intake.py -v
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from dotenv import load_dotenv

load_dotenv()

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_RUN_INTEGRATION") != "1",
    reason="set AEGIS_RUN_INTEGRATION=1 to run live Supabase tests",
)


@pytest.fixture(scope="module")
def live():
    from database.alert_store import AlertStore
    from database.incident_store import IncidentStore
    from database.supabase_client import get_supabase, reset_supabase_client
    from services.alert_intake import AlertIntake

    reset_supabase_client()
    sb = get_supabase()
    return sb, AlertIntake(IncidentStore(sb), AlertStore(sb), queue=None, auto_analyze=False)


def _alert(service: str):
    from services.alert_sources import manual_alert

    return manual_alert(service, "integration test alert", "safe to ignore")


def test_repeat_alert_creates_one_incident(live):
    sb, intake = live
    service = f"integration-test-{uuid.uuid4().hex[:8]}"
    first = intake.receive([_alert(service)], "integration-test")[0]
    second = intake.receive([_alert(service)], "integration-test")[0]
    assert first.disposition == "created"
    assert second.disposition == "deduplicated" and second.incident_id == first.incident_id
    rows = sb.table("incidents").select("id").eq("service_id", service).execute().data
    assert len(rows) == 1


def test_unique_index_blocks_second_active_incident(live):
    from database.incident_store import DuplicateActiveIncidentError, IncidentStore

    sb, _ = live
    store = IncidentStore(sb)
    fp = f"integration-test-{uuid.uuid4().hex}"
    store.create_incident("integration-test", "x", actor="integration-test", source="manual", fingerprint=fp)
    with pytest.raises(DuplicateActiveIncidentError):
        store.create_incident("integration-test", "x", actor="integration-test", source="manual", fingerprint=fp)


def test_maintenance_window_suppresses(live):
    from database.alert_store import AlertStore

    sb, intake = live
    service = f"integration-test-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    window = AlertStore(sb).create_window(service, now - timedelta(minutes=1), now + timedelta(minutes=10),
                                          "integration test", "integration-test")
    [r] = intake.receive([_alert(service)], "integration-test")
    assert r.disposition == "suppressed" and r.maintenance_window_id == window["id"]
    AlertStore(sb).cancel_window(window["id"], "integration-test")
