"""
backend/services/alert_sources.py
==================================
Convert each monitoring tool's webhook payload into one common alert format
(FR-1). Pure functions, no I/O, so every source is unit-tested on sample
payloads (see ``backend/samples/webhooks/``).

Supported sources
-----------------
alertmanager  Prometheus Alertmanager webhook (version 4)
grafana       Grafana unified alerting webhook contact point (same shape as
              Alertmanager, plus a few Grafana-only fields)
datadog       Datadog Webhooks integration, using the payload template in
              docs/alert-intake.md
cloudwatch    CloudWatch alarm state change, delivered either through SNS
              (HTTPS subscription) or EventBridge (API destination); a raw
              alarm JSON body is accepted too

Common format
-------------
Every alert gets a ``fingerprint``: a stable hash of what makes it "the same
alert" at its source (Alertmanager's fingerprint, Datadog's monitor + group,
the CloudWatch alarm ARN, ...). Repeats with the same fingerprint are attached
to the active incident instead of opening a new one (FR-3).

The ``service_id`` is read from a ``service`` label / tag / dimension when the
tool sends one; label your alerts with ``service=<id>`` (matching the service
map) for the best results.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Callable

SOURCES = ("alertmanager", "grafana", "datadog", "cloudwatch")
MANUAL_SOURCE = "manual"

UNKNOWN_SERVICE = "unknown-service"

#: Label / tag / dimension names that carry the service id, best first.
SERVICE_KEYS = ("service", "service_id", "service_name", "servicename", "app", "application", "job")

MAX_TITLE = 300
MAX_DESCRIPTION = 8000
MAX_LABELS = 64
MAX_LABEL_VALUE = 500


class PayloadError(ValueError):
    """The payload is not a valid webhook body for this source (HTTP 422)."""


@dataclass
class NormalizedAlert:
    source: str
    status: str  # firing | resolved | info
    service_id: str
    title: str
    fingerprint: str
    description: str = ""
    external_id: str | None = None
    source_severity: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    starts_at: str | None = None
    url: str | None = None
    raw: dict = field(default_factory=dict)

    def incident_text(self) -> str:
        """The alert text an incident stores and the triage pipeline reads.

        Still untrusted input: the pipeline sanitizes it (engine/prompt_safety.py).
        """
        lines = [f"[{self.source}] {self.title}"]
        if self.source_severity:
            lines.append(f"Reported severity: {self.source_severity}")
        lines.append(f"Service: {self.service_id}")
        if self.description:
            lines.append(self.description)
        return "\n".join(lines)[:20000]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_fingerprint(source: str, key: str) -> str:
    return hashlib.sha256(f"{source}\x1f{key}".encode("utf-8")).hexdigest()[:40]


def _timestamp(value: Any) -> str | None:
    """Any source timestamp as UTC ISO 8601, or None if missing or unreadable.

    Sources differ: ISO strings (Alertmanager, Grafana), "+0000" offsets
    (CloudWatch), Unix epoch milliseconds (Datadog's $DATE). The database
    column is a timestamptz, so a value it can't read would reject the whole
    alert; an unreadable timestamp is dropped instead (the raw payload keeps it).
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
            n = float(value)
            if n > 1e11:  # milliseconds
                n /= 1000.0
            parsed = datetime.fromtimestamp(n, tz=timezone.utc)
        elif isinstance(value, str) and value.strip():
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    if parsed.year < 2000:
        return None  # e.g. Alertmanager's "0001-01-01" placeholder
    return parsed.astimezone(timezone.utc).isoformat()


def _text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def _labels(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(raw.items())[:MAX_LABELS]:
        if v is None or isinstance(v, (dict, list)):
            continue
        out[_text(k, 100)] = _text(v, MAX_LABEL_VALUE)
    return out


def _service_from(labels: dict[str, str]) -> str | None:
    lowered = {k.lower(): v for k, v in labels.items() if v}
    for key in SERVICE_KEYS:
        if lowered.get(key):
            return lowered[key][:200]
    return None


def _require_dict(payload: Any, source: str) -> dict:
    if not isinstance(payload, dict):
        raise PayloadError(f"{source} webhook body must be a JSON object")
    return payload


# ---------------------------------------------------------------------------
# Prometheus Alertmanager / Grafana
# ---------------------------------------------------------------------------


def _parse_alertmanager_like(payload: Any, source: str) -> list[NormalizedAlert]:
    payload = _require_dict(payload, source)
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not alerts:
        raise PayloadError(f"{source} webhook body must contain a non-empty 'alerts' list")
    common_labels = _labels(payload.get("commonLabels"))
    out = []
    for item in alerts:
        if not isinstance(item, dict):
            raise PayloadError("every item in 'alerts' must be an object")
        labels = {**common_labels, **_labels(item.get("labels"))}
        annotations = _labels(item.get("annotations"))
        if not labels:
            raise PayloadError("alert has no labels")
        raw_status = _text(item.get("status") or payload.get("status"), 20).lower()
        status = "resolved" if raw_status == "resolved" else "firing"

        native_fp = _text(item.get("fingerprint"), 200)
        key = native_fp or json.dumps(sorted(labels.items()))  # labels identify an alert
        title = (
            labels.get("alertname") or annotations.get("summary") or _text(payload.get("title"), MAX_TITLE)
            or "Alert"
        )
        parts = [annotations.get("summary", ""), annotations.get("description", "")]
        if source == "grafana" and item.get("valueString"):
            parts.append(f"Values: {_text(item.get('valueString'), 1000)}")
        description = "\n".join(p for p in dict.fromkeys(parts) if p and p != title)

        out.append(
            NormalizedAlert(
                source=source,
                status=status,
                service_id=_service_from(labels) or UNKNOWN_SERVICE,
                title=_text(title, MAX_TITLE),
                description=_text(description, MAX_DESCRIPTION),
                fingerprint=make_fingerprint(source, key),
                external_id=native_fp or None,
                source_severity=labels.get("severity") or labels.get("priority") or None,
                labels=labels,
                starts_at=_timestamp(item.get("startsAt")),
                url=_text(item.get("generatorURL") or item.get("panelURL") or payload.get("externalURL"), 2000)
                or None,
                raw=item,
            )
        )
    return out


def parse_alertmanager(payload: Any) -> list[NormalizedAlert]:
    return _parse_alertmanager_like(payload, "alertmanager")


def parse_grafana(payload: Any) -> list[NormalizedAlert]:
    return _parse_alertmanager_like(payload, "grafana")


# ---------------------------------------------------------------------------
# Datadog
# ---------------------------------------------------------------------------

_DD_TITLE_PREFIX = re.compile(r"^(\s*\[[^\]]*\]\s*)+")
_DD_RESOLVED = {"recovered", "warn recovered", "no data recovered", "recovery"}


def _datadog_tags(raw: Any) -> dict[str, str]:
    if isinstance(raw, str):
        items = [t.strip() for t in raw.split(",")]
    elif isinstance(raw, list):
        items = [_text(t, MAX_LABEL_VALUE) for t in raw]
    else:
        items = []
    tags: dict[str, str] = {}
    for item in items[:MAX_LABELS]:
        if not item:
            continue
        k, _, v = item.partition(":")
        tags[_text(k, 100)] = _text(v, MAX_LABEL_VALUE) if v else "true"
    return tags


def _parse_datadog_one(item: Any) -> NormalizedAlert:
    item = _require_dict(item, "datadog")
    alert_id = _text(item.get("alert_id"), 100)
    raw_title = _text(item.get("title"), MAX_TITLE)
    if not alert_id and not raw_title:
        raise PayloadError("datadog payload needs at least 'alert_id' or 'title' (see docs/alert-intake.md)")
    tags = _datadog_tags(item.get("tags"))
    hostname = _text(item.get("hostname"), 200)
    if hostname:
        tags.setdefault("host", hostname)

    transition = _text(item.get("transition"), 50).lower()
    alert_type = _text(item.get("alert_type"), 20).lower()
    status = "resolved" if transition in _DD_RESOLVED or alert_type == "success" else "firing"

    aggregate = _text(item.get("aggregate"), 200)
    key = f"{alert_id}:{aggregate}" if alert_id else f"title:{raw_title}:{aggregate or hostname}"
    title = _DD_TITLE_PREFIX.sub("", raw_title) or f"Datadog monitor {alert_id}"
    return NormalizedAlert(
        source="datadog",
        status=status,
        service_id=_service_from(tags) or hostname or UNKNOWN_SERVICE,
        title=title,
        description=_text(item.get("message") or item.get("body"), MAX_DESCRIPTION),
        fingerprint=make_fingerprint("datadog", key),
        external_id=_text(item.get("id"), 100) or alert_id or None,
        source_severity=_text(item.get("priority"), 20) or None,
        labels=tags,
        starts_at=_timestamp(item.get("date")),
        url=_text(item.get("link"), 2000) or None,
        raw=item,
    )


def parse_datadog(payload: Any) -> list[NormalizedAlert]:
    if isinstance(payload, list):
        if not payload:
            raise PayloadError("datadog webhook body is an empty list")
        return [_parse_datadog_one(p) for p in payload]
    return [_parse_datadog_one(payload)]


# ---------------------------------------------------------------------------
# AWS CloudWatch (SNS envelope, EventBridge event, or raw alarm)
# ---------------------------------------------------------------------------

_CW_STATUS = {"ALARM": "firing", "OK": "resolved", "INSUFFICIENT_DATA": "info"}


def sns_message_type(payload: Any) -> str | None:
    """'Notification', 'SubscriptionConfirmation', ... for SNS envelopes, else None."""
    if isinstance(payload, dict) and "TopicArn" in payload and isinstance(payload.get("Type"), str):
        return payload["Type"]
    return None


def _cw_service(dimensions: dict[str, str]) -> str | None:
    return _service_from(dimensions) or next((v for v in dimensions.values() if v), None)


def _cw_alarm(alarm: dict) -> NormalizedAlert:
    name = _text(alarm.get("AlarmName"), MAX_TITLE)
    if not name:
        raise PayloadError("CloudWatch alarm has no 'AlarmName'")
    state = _text(alarm.get("NewStateValue"), 30).upper()
    if state not in _CW_STATUS:
        raise PayloadError(f"unknown CloudWatch alarm state {state!r}")
    trigger = alarm.get("Trigger") if isinstance(alarm.get("Trigger"), dict) else {}
    dims = {
        _text(d.get("name"), 100): _text(d.get("value"), MAX_LABEL_VALUE)
        for d in (trigger.get("Dimensions") or [])
        if isinstance(d, dict) and d.get("name")
    }
    metric = "/".join(p for p in (_text(trigger.get("Namespace"), 100), _text(trigger.get("MetricName"), 100)) if p)
    region = _text(alarm.get("Region"), 100)
    arn = _text(alarm.get("AlarmArn"), 400)
    labels = {**dims, **({"metric": metric} if metric else {}), **({"region": region} if region else {})}
    parts = [_text(alarm.get("AlarmDescription"), 2000), _text(alarm.get("NewStateReason"), 4000)]
    return NormalizedAlert(
        source="cloudwatch",
        status=_CW_STATUS[state],
        service_id=_cw_service(dims) or UNKNOWN_SERVICE,
        title=name,
        description="\n".join(p for p in parts if p)[:MAX_DESCRIPTION],
        fingerprint=make_fingerprint("cloudwatch", arn or f"{region}:{name}"),
        external_id=arn or None,
        source_severity=None,
        labels=labels,
        starts_at=_timestamp(alarm.get("StateChangeTime")),
        url=None,
        raw=alarm,
    )


def _cw_eventbridge(event: dict) -> NormalizedAlert:
    detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
    state = detail.get("state") if isinstance(detail.get("state"), dict) else {}
    config = detail.get("configuration") if isinstance(detail.get("configuration"), dict) else {}
    dims: dict[str, Any] = {}
    namespace = metric_name = ""
    for m in config.get("metrics") or []:
        metric = ((m or {}).get("metricStat") or {}).get("metric") or {}
        if metric:
            dims = metric.get("dimensions") or {}
            namespace, metric_name = metric.get("namespace", ""), metric.get("name", "")
            break
    resources = event.get("resources") or []
    alarm = {
        "AlarmName": detail.get("alarmName"),
        "AlarmDescription": config.get("description"),
        "NewStateValue": state.get("value"),
        "NewStateReason": state.get("reason"),
        "StateChangeTime": state.get("timestamp") or event.get("time"),
        "Region": event.get("region"),
        "AlarmArn": resources[0] if resources else None,
        "Trigger": {
            "Namespace": namespace,
            "MetricName": metric_name,
            "Dimensions": [{"name": k, "value": v} for k, v in _labels(dims).items()],
        },
    }
    parsed = _cw_alarm(alarm)
    parsed.raw = event
    return parsed


def parse_cloudwatch(payload: Any) -> list[NormalizedAlert]:
    payload = _require_dict(payload, "cloudwatch")
    msg_type = sns_message_type(payload)
    if msg_type is not None:
        if msg_type != "Notification":
            raise PayloadError(f"SNS message type {msg_type!r} carries no alarm")
        try:
            alarm = json.loads(payload.get("Message") or "")
        except (TypeError, ValueError):
            raise PayloadError("SNS 'Message' is not a CloudWatch alarm JSON document") from None
        return [_cw_alarm(_require_dict(alarm, "cloudwatch"))]
    if payload.get("detail-type") == "CloudWatch Alarm State Change":
        return [_cw_eventbridge(payload)]
    if "AlarmName" in payload:
        return [_cw_alarm(payload)]
    raise PayloadError("not a CloudWatch alarm (expected an SNS notification, EventBridge event or alarm JSON)")


# ---------------------------------------------------------------------------
# Manual alerts (FR-2) and dispatch
# ---------------------------------------------------------------------------


def manual_alert(
    service_id: str,
    title: str,
    description: str = "",
    severity: str | None = None,
    fingerprint_key: str | None = None,
    labels: dict | None = None,
) -> NormalizedAlert:
    """An alert typed in by a person (dashboard or API). Without an explicit
    ``fingerprint_key``, the same title for the same service counts as a repeat."""
    service_id = _text(service_id, 200)
    title = _text(title, MAX_TITLE)
    key = fingerprint_key or f"{service_id}\x1f{title.lower()}"
    return NormalizedAlert(
        source=MANUAL_SOURCE,
        status="firing",
        service_id=service_id,
        title=title,
        description=_text(description, MAX_DESCRIPTION),
        fingerprint=make_fingerprint(MANUAL_SOURCE, key),
        source_severity=_text(severity, 20) or None,
        labels=_labels(labels or {}),
        raw={"service_id": service_id, "title": title, "description": description, "severity": severity},
    )


PARSERS: dict[str, Callable[[Any], list[NormalizedAlert]]] = {
    "alertmanager": parse_alertmanager,
    "grafana": parse_grafana,
    "datadog": parse_datadog,
    "cloudwatch": parse_cloudwatch,
}


def parse(source: str, payload: Any) -> list[NormalizedAlert]:
    if source not in PARSERS:
        raise PayloadError(f"unknown alert source {source!r}; expected one of {', '.join(SOURCES)}")
    return PARSERS[source](payload)
