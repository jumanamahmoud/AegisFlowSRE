"""
backend/tests/test_alert_sources.py
====================================
Each monitoring tool's payload → the common alert format (FR-1), and the
fingerprints that drive duplicate detection (FR-3).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from services.alert_sources import (
    UNKNOWN_SERVICE,
    PayloadError,
    manual_alert,
    parse,
    sns_message_type,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "webhooks"


def sample(name: str):
    return json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Every sample parses into one firing alert for the expected service
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "file,source,service,title,severity",
    [
        ("alertmanager", "alertmanager", "payment-service", "PaymentDBConnectionPoolExhausted", "critical"),
        ("grafana", "grafana", "checkout-service", "CheckoutHighErrorRate", "high"),
        ("datadog", "datadog", "inventory-service", "Inventory API p99 latency above 2s", "P2"),
        ("cloudwatch", "cloudwatch", "auth-service", "auth-service-high-cpu", None),
        ("cloudwatch_eventbridge", "cloudwatch", "order-service", "orders-queue-backlog", None),
    ],
)
def test_samples_normalize(file, source, service, title, severity):
    [alert] = parse(source, sample(file))
    assert alert.source == source
    assert alert.status == "firing"
    assert alert.service_id == service
    assert alert.title == title
    assert alert.source_severity == severity
    assert len(alert.fingerprint) == 40
    assert alert.raw  # original kept for the record
    text = alert.incident_text()
    assert title in text and f"Service: {service}" in text


def test_parse_is_deterministic_so_retries_share_a_fingerprint():
    for file, source in [("alertmanager", "alertmanager"), ("grafana", "grafana"),
                         ("datadog", "datadog"), ("cloudwatch", "cloudwatch")]:
        assert parse(source, sample(file))[0].fingerprint == parse(source, sample(file))[0].fingerprint


def test_same_key_from_different_sources_never_collides():
    payload = sample("alertmanager")
    assert parse("alertmanager", payload)[0].fingerprint != parse("grafana", payload)[0].fingerprint


def test_unknown_source_rejected():
    with pytest.raises(PayloadError):
        parse("nagios", {})


# ---------------------------------------------------------------------------
# Alertmanager / Grafana
# ---------------------------------------------------------------------------


class TestAlertmanager:
    def test_resolved_status(self):
        p = sample("alertmanager")
        p["alerts"][0]["status"] = "resolved"
        assert parse("alertmanager", p)[0].status == "resolved"

    def test_batch_of_alerts(self):
        p = sample("alertmanager")
        second = copy.deepcopy(p["alerts"][0])
        second["labels"]["instance"] = "payment-service-2:8080"
        second["fingerprint"] = "different"
        p["alerts"].append(second)
        alerts = parse("alertmanager", p)
        assert len(alerts) == 2
        assert alerts[0].fingerprint != alerts[1].fingerprint

    def test_fingerprint_from_labels_when_tool_sends_none(self):
        p = sample("alertmanager")
        del p["alerts"][0]["fingerprint"]
        a1 = parse("alertmanager", p)[0]
        p2 = copy.deepcopy(p)
        p2["alerts"][0]["labels"] = dict(reversed(list(p2["alerts"][0]["labels"].items())))
        assert parse("alertmanager", p2)[0].fingerprint == a1.fingerprint  # label order doesn't matter
        p2["alerts"][0]["labels"]["instance"] = "other:8080"
        assert parse("alertmanager", p2)[0].fingerprint != a1.fingerprint
        assert a1.external_id is None

    @pytest.mark.parametrize("label", ["service", "app", "job"])
    def test_service_label_variants(self, label):
        p = sample("alertmanager")
        labels = p["alerts"][0]["labels"]
        p["commonLabels"] = {}
        del labels["service"]
        labels[label] = "billing"
        assert parse("alertmanager", p)[0].service_id == "billing"

    def test_missing_service_label_falls_back(self):
        p = sample("alertmanager")
        p["commonLabels"] = {}
        del p["alerts"][0]["labels"]["service"]
        assert parse("alertmanager", p)[0].service_id == UNKNOWN_SERVICE

    def test_common_labels_fill_in(self):
        p = sample("alertmanager")
        p["commonLabels"]["service"] = "from-common"
        del p["alerts"][0]["labels"]["service"]
        assert parse("alertmanager", p)[0].service_id == "from-common"

    @pytest.mark.parametrize("bad", [[], "text", {"alerts": []}, {"alerts": "x"}, {"alerts": [1]},
                                     {"alerts": [{"labels": {}}]}])
    def test_invalid_payloads(self, bad):
        with pytest.raises(PayloadError):
            parse("alertmanager", bad)

    def test_nested_label_values_dropped_and_long_values_capped(self):
        p = sample("alertmanager")
        p["alerts"][0]["labels"]["nested"] = {"a": 1}
        p["alerts"][0]["labels"]["huge"] = "x" * 5000
        a = parse("alertmanager", p)[0]
        assert "nested" not in a.labels
        assert len(a.labels["huge"]) == 500

    def test_grafana_value_string_in_description(self):
        a = parse("grafana", sample("grafana"))[0]
        assert "value=7.4" in a.description
        assert a.url.startswith("https://grafana.example.internal/alerting")


# ---------------------------------------------------------------------------
# Datadog
# ---------------------------------------------------------------------------


class TestDatadog:
    def test_title_prefix_stripped(self):
        assert not parse("datadog", sample("datadog"))[0].title.startswith("[")

    @pytest.mark.parametrize("transition,expected", [
        ("Triggered", "firing"), ("Re-Triggered", "firing"), ("Warn", "firing"), ("No Data", "firing"),
        ("Recovered", "resolved"), ("Warn Recovered", "resolved"),
    ])
    def test_transitions(self, transition, expected):
        p = sample("datadog")
        p["transition"] = transition
        assert parse("datadog", p)[0].status == expected

    def test_recovery_matches_trigger_fingerprint(self):
        p = sample("datadog")
        rec = dict(p, transition="Recovered", id="other-event", title="[Recovered] Inventory API p99 latency above 2s")
        assert parse("datadog", p)[0].fingerprint == parse("datadog", rec)[0].fingerprint

    def test_different_monitor_groups_differ(self):
        p = sample("datadog")
        other = dict(p, aggregate="another-group")
        assert parse("datadog", p)[0].fingerprint != parse("datadog", other)[0].fingerprint

    def test_tags_as_list_and_hostname_fallback(self):
        p = sample("datadog")
        p["tags"] = ["env:prod", "team:x"]
        a = parse("datadog", p)[0]
        assert a.service_id == "inventory-api-2"
        assert a.labels["env"] == "prod" and a.labels["host"] == "inventory-api-2"

    def test_list_of_events(self):
        p = sample("datadog")
        assert len(parse("datadog", [p, dict(p, aggregate="b")])) == 2

    @pytest.mark.parametrize("bad", [{}, [], {"message": "only text"}, "x"])
    def test_invalid(self, bad):
        with pytest.raises(PayloadError):
            parse("datadog", bad)


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------


class TestCloudWatch:
    def test_sns_envelope_detected(self):
        assert sns_message_type(sample("cloudwatch")) == "Notification"
        assert sns_message_type(sample("alertmanager")) is None

    def test_metric_and_reason_kept(self):
        a = parse("cloudwatch", sample("cloudwatch"))[0]
        assert a.labels["metric"] == "AWS/ECS/CPUUtilization"
        assert "Threshold Crossed" in a.description
        assert a.external_id.endswith(":alarm:auth-service-high-cpu")

    @pytest.mark.parametrize("state,expected", [("ALARM", "firing"), ("OK", "resolved"),
                                                ("INSUFFICIENT_DATA", "info")])
    def test_states(self, state, expected):
        p = sample("cloudwatch")
        alarm = json.loads(p["Message"])
        alarm["NewStateValue"] = state
        p["Message"] = json.dumps(alarm)
        assert parse("cloudwatch", p)[0].status == expected

    def test_raw_alarm_and_sns_agree_on_fingerprint(self):
        p = sample("cloudwatch")
        assert parse("cloudwatch", json.loads(p["Message"]))[0].fingerprint == parse("cloudwatch", p)[0].fingerprint

    def test_eventbridge_ok_resolves(self):
        p = sample("cloudwatch_eventbridge")
        p["detail"]["state"]["value"] = "OK"
        assert parse("cloudwatch", p)[0].status == "resolved"

    def test_first_dimension_used_without_service_dimension(self):
        p = sample("cloudwatch")
        alarm = json.loads(p["Message"])
        alarm["Trigger"]["Dimensions"] = [{"name": "DBInstanceIdentifier", "value": "orders-db"}]
        p["Message"] = json.dumps(alarm)
        assert parse("cloudwatch", p)[0].service_id == "orders-db"

    @pytest.mark.parametrize("mutate", [
        lambda p: p.update(Message="plain text, not json"),
        lambda p: p.update(Type="SubscriptionConfirmation"),
        lambda p: p.update(Message=json.dumps({"NewStateValue": "ALARM"})),
        lambda p: p.update(Message=json.dumps({"AlarmName": "x", "NewStateValue": "WEIRD"})),
    ])
    def test_invalid(self, mutate):
        p = sample("cloudwatch")
        mutate(p)
        with pytest.raises(PayloadError):
            parse("cloudwatch", p)

    def test_unrecognised_body(self):
        with pytest.raises(PayloadError):
            parse("cloudwatch", {"hello": "world"})


# ---------------------------------------------------------------------------
# Manual alerts (FR-2)
# ---------------------------------------------------------------------------


class TestManual:
    def test_same_title_same_service_is_a_repeat(self):
        a = manual_alert("payment-service", "DB down")
        b = manual_alert("payment-service", "  db DOWN ")
        assert a.fingerprint == b.fingerprint
        assert a.source == "manual" and a.status == "firing"

    def test_explicit_fingerprint_key(self):
        assert manual_alert("s", "a", fingerprint_key="k").fingerprint == manual_alert("s", "b", fingerprint_key="k").fingerprint
        assert manual_alert("s", "a").fingerprint != manual_alert("t", "a").fingerprint


# ---------------------------------------------------------------------------
# Timestamps: every source's format becomes UTC ISO 8601 (the DB column is
# timestamptz; Datadog's epoch milliseconds once made Postgres reject the alert)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("1795511700000", "2026-11-24T09:15:00+00:00"),       # Datadog $DATE (epoch ms)
    (1795511700000, "2026-11-24T09:15:00+00:00"),
    ("1795511700", "2026-11-24T09:15:00+00:00"),          # epoch seconds
    ("2026-11-24T09:12:00Z", "2026-11-24T09:12:00+00:00"),
    ("2026-11-24T09:16:02.123+0000", "2026-11-24T09:16:02.123000+00:00"),  # CloudWatch
    ("2026-11-24T11:16:02+02:00", "2026-11-24T09:16:02+00:00"),
    ("2026-11-24T09:12:00", "2026-11-24T09:12:00+00:00"),  # no zone: assume UTC
])
def test_timestamps_normalized(value, expected):
    from services.alert_sources import _timestamp

    assert _timestamp(value) == expected


@pytest.mark.parametrize("value", [None, "", "  ", "yesterday", "0001-01-01T00:00:00Z", "99999999999999999999",
                                   True, {"a": 1}])
def test_unreadable_timestamps_dropped(value):
    from services.alert_sources import _timestamp

    assert _timestamp(value) is None


def test_datadog_sample_start_time_is_iso():
    assert parse("datadog", sample("datadog"))[0].starts_at == "2026-11-24T09:15:00+00:00"


def test_bad_timestamp_never_blocks_an_alert():
    p = sample("alertmanager")
    p["alerts"][0]["startsAt"] = "not a date"
    [a] = parse("alertmanager", p)
    assert a.starts_at is None and a.raw["startsAt"] == "not a date"  # original kept
