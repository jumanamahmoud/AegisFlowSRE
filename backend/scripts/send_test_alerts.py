"""
backend/scripts/send_test_alerts.py
====================================
Live Phase 3 check: send a test alert from each monitoring tool to a running
backend, twice, and confirm the repeat never creates a second incident.

Since Phase 4, the first copy may be "grouped" into another incident instead
of "created" (e.g. checkout-service's alert joins payment-service's incident
because checkout depends on payment). The repeat must still be
"deduplicated" into that same incident.

Every run tags the samples with a fresh run id, so earlier runs' open
incidents don't turn this run's alerts into duplicates.

Usage (from backend/, with the server running):
    python -m scripts.create_api_key local-test   # prints the $env:AEGIS_API_KEY line to paste
    python -m scripts.send_test_alerts [--base-url http://localhost:8000]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import httpx

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "webhooks"

CASES = [
    ("alertmanager", "alertmanager"),
    ("grafana", "grafana"),
    ("datadog", "datadog"),
    ("cloudwatch", "cloudwatch"),
    ("cloudwatch", "cloudwatch_eventbridge"),
]


def tagged(file: str, run: str) -> bytes:
    """The sample with its identity (what dedup keys on) made unique to this run."""
    body = json.loads((SAMPLES / f"{file}.json").read_text(encoding="utf-8"))
    if file in ("alertmanager", "grafana"):
        body["alerts"][0]["fingerprint"] += f"-{run}"
    elif file == "datadog":
        body["aggregate"] += f"-{run}"
    elif file == "cloudwatch":
        alarm = json.loads(body["Message"])
        alarm["AlarmArn"] += f"-{run}"
        body["Message"] = json.dumps(alarm)
    elif file == "cloudwatch_eventbridge":
        body["resources"][0] += f"-{run}"
    return json.dumps(body).encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=os.environ.get("AEGIS_BASE_URL", "http://localhost:8000"))
    args = parser.parse_args()
    key = os.environ.get("AEGIS_API_KEY", "").strip()
    if not key or key == "afk_..." or not key.startswith("afk_"):
        print("AEGIS_API_KEY is not set to a real key. Create one with:\n"
              "    python -m scripts.create_api_key local-test\n"
              "then paste the $env:AEGIS_API_KEY line it prints.", file=sys.stderr)
        return 2

    run = uuid.uuid4().hex[:8]
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    ok = True
    print(f"run {run} -> {args.base_url}\n")
    with httpx.Client(base_url=args.base_url, timeout=10) as client:
        try:
            client.get("/health")
        except httpx.ConnectError:
            print(f"Cannot reach the backend at {args.base_url}. Start it in another terminal first:\n"
                  "    cd backend\n    uvicorn main:app --port 8000", file=sys.stderr)
            return 2
        print(f"{'sample':24} {'1st send':10} {'2nd send':14} incident")
        for source, file in CASES:
            body = tagged(file, run)
            results = []
            for _ in range(2):
                resp = client.post(f"/alerts/webhooks/{source}", content=body, headers=headers)
                if resp.status_code == 401:
                    print("The backend rejected AEGIS_API_KEY (unknown or revoked key). "
                          "Create a new one with: python -m scripts.create_api_key local-test", file=sys.stderr)
                    return 1
                if resp.status_code != 202:
                    print(f"{file:24} HTTP {resp.status_code}: {resp.text[:200]}")
                    ok = False
                    break
                results.append(resp.json()["results"][0])
            else:
                first, second = results
                passed = (first["disposition"] in ("created", "grouped") and second["disposition"] == "deduplicated"
                          and first["incident_id"] == second["incident_id"])
                ok &= passed
                mark = "" if passed else "   <-- FAILED"
                print(f"{file:24} {first['disposition']:10} {second['disposition']:14} "
                      f"{first['incident_id']}{mark}")

    print("\nPASS: no source created a duplicate incident" if ok else "\nFAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
