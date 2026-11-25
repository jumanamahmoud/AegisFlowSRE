# Alert intake (Week 3: FR-1 to FR-4)

Monitoring tools send alerts to AegisFlow over webhooks. Every alert is
converted to one common format, stored, checked against maintenance windows
and open incidents, and then either opens a new incident (which is analysed
automatically) or is attached to an existing one.

```
tool ──► POST /alerts/webhooks/{source}   (API key)
           │
           ├─ store the alert (public.alerts)          nothing is lost, even on a crash
           ├─ service in a maintenance window?  ──►   suppressed: recorded, no incident, nobody notified
           ├─ same fingerprint as an active incident? ► deduplicated: attached to that incident
           └─ otherwise ──► new incident ──► analysis queued
```

| Disposition    | Meaning |
|----------------|---------|
| `created`      | Opened a new incident |
| `deduplicated` | A repeat of an alert whose incident is still open, acknowledged or mitigating |
| `grouped`      | Phase 4: a different alert, for the same service or one that shares a dependency with a recent incident's service, joined that incident. See [smart-triage.md](smart-triage.md) |
| `suppressed`   | The service was in a maintenance window |
| `resolved`     | The tool reported recovery. This is noted on the incident's timeline, but the status is **not** changed (people resolve incidents) |
| `ignored`      | Information only (e.g. CloudWatch `INSUFFICIENT_DATA`), or a recovery with no open incident |
| `received`     | Stored but not processed yet. It is picked up again automatically on the next start |

**Duplicate detection.** Each alert gets a *fingerprint* from what identifies
it at the source:

| Source | Fingerprint from |
|---|---|
| Alertmanager, Grafana | the alert's `fingerprint`, or its full label set |
| Datadog | monitor id plus group (`aggregate`) |
| CloudWatch | the alarm ARN |
| Manual | service plus title, or an explicit `fingerprint` |

A database unique index allows only one active incident per fingerprint, so
even simultaneous retries open just one incident. When an incident is
resolved, the same alert can open a new incident again.

**Which service?** AegisFlow reads the `service` label, tag or dimension
(falling back to `service_name`, `app`, `job`, …). Use the same id as in the
service map, e.g. `service=payment-service`.

## 1. Apply the migration

Paste `supabase/migrations/20261124000000_week3_alert_intake.sql` into
Supabase → SQL Editor → Run (or run `supabase db push`).

## 2. Create an API key per tool (administrator)

```http
POST /admin/api-keys
Authorization: Bearer <your login token>
Content-Type: application/json

{"name": "prometheus-prod", "source": "alertmanager"}
```

The response contains `key` (`afk_...`). **It is shown only once.** Put it
straight into the tool's settings. Leave `source` out for a key that may post
to every webhook. List keys with `GET /admin/api-keys` and revoke one with
`POST /admin/api-keys/{id}/revoke` (takes effect immediately).

Tools can send the key in any of three ways:
- `Authorization: Bearer afk_...`
- `X-API-Key: afk_...`
- HTTP basic auth with the key as the password

## 3. Point each tool at AegisFlow

Replace `https://aegisflow.example.com` with your backend's address.

### Prometheus Alertmanager

```yaml
receivers:
  - name: aegisflow
    webhook_configs:
      - url: https://aegisflow.example.com/alerts/webhooks/alertmanager
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials: afk_...
```

### Grafana (unified alerting)

Alerting → Contact points → New → **Webhook**:
- URL: `https://aegisflow.example.com/alerts/webhooks/grafana`
- HTTP method: `POST`
- Optional settings → Authorization header: scheme `Bearer`, credentials `afk_...`

Add a `service` label to your alert rules.

### Datadog

Integrations → Webhooks → New:
- URL: `https://aegisflow.example.com/alerts/webhooks/datadog`
- Custom headers: `{"X-API-Key": "afk_..."}`
- Payload:

```json
{
  "id": "$ID",
  "alert_id": "$ALERT_ID",
  "title": "$EVENT_TITLE",
  "message": "$EVENT_MSG",
  "transition": "$ALERT_TRANSITION",
  "priority": "$ALERT_PRIORITY",
  "alert_type": "$ALERT_TYPE",
  "tags": "$TAGS",
  "aggregate": "$AGGREG_KEY",
  "hostname": "$HOSTNAME",
  "link": "$LINK",
  "date": "$DATE"
}
```

Then mention `@webhook-<name>` in your monitors and tag them with `service:<id>`.

### AWS CloudWatch

**Option A: SNS (simplest).** Create an HTTPS subscription on the alarm's SNS
topic, with the key as the basic-auth password in the URL:

```
https://aegisflow:afk_...@aegisflow.example.com/alerts/webhooks/cloudwatch
```

AegisFlow confirms the subscription automatically. It only ever follows
genuine `https://sns.<region>.amazonaws.com` confirmation links.

**Option B: EventBridge.** Create a rule for `CloudWatch Alarm State Change`
with an API destination that posts to the same URL, using an
`X-API-Key: afk_...` header.

Give the alarm's metric a `service` dimension, or AegisFlow uses the first
dimension's value (e.g. the ECS service or queue name).

## Manual alerts (FR-2)

A responder can report an alert without a monitoring tool:

```http
POST /alerts
Authorization: Bearer <login token>

{"service_id": "payment-service", "title": "Card payments failing", "description": "...", "severity": "high"}
```

The same rules apply: repeats attach to the open incident, and maintenance
windows are respected.

## Maintenance windows (FR-4)

```http
POST /maintenance-windows        (responder)
{"service_id": "payment-service", "starts_at": "2026-11-24T22:00:00Z", "ends_at": "2026-11-24T23:30:00Z", "reason": "DB upgrade"}

GET  /maintenance-windows                 current and upcoming windows
POST /maintenance-windows/{id}/cancel     end a window early
```

`starts_at` defaults to now. A window can last at most 14 days, and times
must include a timezone.

## Browsing alerts

- `GET /alerts?source=&disposition=&service_id=&incident_id=&limit=` lists recent alerts.
- `GET /alerts/{id}` returns one alert, with the original payload.

## Checking it works

- Automated: `python -m pytest tests/test_alert_endpoints.py -k DoneWhen`
- Live. Start the backend in one terminal (`cd backend`, then `uvicorn main:app --port 8000`).
  Then, in a second terminal, also from `backend/`:

  ```powershell
  python -m scripts.create_api_key local-test   # prints a $env:AEGIS_API_KEY = "afk_..." line: paste and run it
  python -m scripts.send_test_alerts
  ```

  `create_api_key` is a development shortcut that uses the secret key in
  `.env`. In production, use `POST /admin/api-keys`.

  This sends each source's sample (in `backend/samples/webhooks/`) twice and
  checks that each opens exactly one incident.
- Live database rules: `$env:AEGIS_RUN_INTEGRATION=1; python -m pytest tests/test_integration_intake.py -v`
