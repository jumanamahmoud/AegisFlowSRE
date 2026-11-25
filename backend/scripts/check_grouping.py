"""
backend/scripts/check_grouping.py
==================================
Live Phase 4 check ("grouped alerts become one incident"): send three alerts
to a running backend through the Alertmanager webhook and confirm that

  1. checkout-service and order-service (both depend on payment-service in
     the service map) end up in ONE incident, with payment-service as the
     probable cause, and
  2. inventory-service (no link to them) gets an incident of its own.

Needs the service map from scripts/seed_graph.py, and the Phase 4 SQL
migration applied. Each run uses fresh fingerprints.

Usage (from backend/, server running, AEGIS_API_KEY set as for send_test_alerts):
    python -m scripts.check_grouping
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid

import httpx


def alertmanager_body(service: str, name: str, run: str) -> dict:
    return {
        "version": "4", "status": "firing", "receiver": "aegisflow",
        "alerts": [{
            "status": "firing",
            "labels": {"alertname": name, "service": service, "severity": "high", "run": run},
            "annotations": {"summary": f"{service}: {name}"},
            "startsAt": "2026-11-25T09:00:00Z",
            "fingerprint": f"grouping-check-{run}-{service}",
        }],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=os.environ.get("AEGIS_BASE_URL", "http://localhost:8000"))
    args = parser.parse_args()
    key = os.environ.get("AEGIS_API_KEY", "").strip()
    if not key.startswith("afk_"):
        print("Set AEGIS_API_KEY first (python -m scripts.create_api_key local-test)", file=sys.stderr)
        return 2

    run = uuid.uuid4().hex[:8]
    headers = {"Authorization": f"Bearer {key}"}
    sent = {}
    with httpx.Client(base_url=args.base_url, timeout=15) as client:
        try:
            client.get("/health")
        except httpx.ConnectError:
            print(f"Cannot reach the backend at {args.base_url}. Start it first.", file=sys.stderr)
            return 2
        for service, name in (("checkout-service", "CheckoutErrors"), ("order-service", "OrdersFailing"),
                              ("inventory-service", "InventoryDiskFull")):
            resp = client.post("/alerts/webhooks/alertmanager", json=alertmanager_body(service, name, run),
                               headers=headers)
            if resp.status_code != 202:
                print(f"{service}: HTTP {resp.status_code} {resp.text[:300]}", file=sys.stderr)
                return 1
            sent[service] = resp.json()["results"][0]

    print(f"run {run} -> {args.base_url}\n")
    print(f"{'service':20} {'disposition':12} {'shared component':18} incident")
    for service, r in sent.items():
        cause = ((r.get("grouped_via") or {}).get("shared_component") or {}).get("id", "")
        print(f"{service:20} {r['disposition']:12} {cause:18} {r['incident_id']}")

    checkout, order, inventory = sent["checkout-service"], sent["order-service"], sent["inventory-service"]
    together = checkout["incident_id"] == order["incident_id"]
    order_cause = ((order.get("grouped_via") or {}).get("shared_component") or {}).get("id")
    separate = inventory["incident_id"] != checkout["incident_id"]
    checks = [
        ("checkout-service and order-service share one incident", together),
        ("order-service grouped because of payment-service", order["disposition"] == "grouped"
         and order_cause == "payment-service"),
        ("inventory-service kept separate", separate),
    ]
    print()
    for label, passed in checks:
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
    if not together or order_cause is None:
        print("\nIf nothing was grouped: is the service map seeded (python -m scripts.seed_graph)?")
    return 0 if all(p for _, p in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
