"""
backend/scripts/create_api_key.py
==================================
Create a machine API key for a monitoring tool from the command line, for
local development and demos (in production, use POST /admin/api-keys).

It talks to Supabase directly with the secret key in backend/.env, so only
someone who already holds that secret can run it. The creation is recorded on
the audit timeline like a dashboard-created key.

Run from backend/:
    python -m scripts.create_api_key local-test               # key for every source
    python -m scripts.create_api_key grafana-prod --source grafana

The key is printed once; it can't be shown again (only its hash is stored).
"""

from __future__ import annotations

import argparse
import getpass
import sys

from dotenv import load_dotenv

load_dotenv()

from core.api_keys import create_api_key  # noqa: E402
from database.incident_store import IncidentStore  # noqa: E402
from database.supabase_client import get_supabase  # noqa: E402
from models.incident import AuditEventType  # noqa: E402
from services.alert_sources import SOURCES  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("name", help="a label for the tool, e.g. prometheus-prod")
    parser.add_argument("--source", choices=SOURCES, help="limit the key to one webhook (default: any)")
    args = parser.parse_args()

    sb = get_supabase()
    actor = f"script:{getpass.getuser()}"
    try:
        row, key = create_api_key(sb, args.name, args.source, actor)
    except Exception as exc:
        if "api_keys" in str(exc) and ("does not exist" in str(exc) or "PGRST205" in str(exc)):
            print("The api_keys table is missing: apply supabase/migrations/20261124000000_week3_alert_intake.sql",
                  file=sys.stderr)
            return 1
        raise
    IncidentStore(sb).append_event(
        None, AuditEventType.API_KEY_CREATED,
        {"key_id": row["id"], "name": row["name"], "source": row.get("source")}, actor=actor,
    )
    print(f"Created key '{row['name']}' (source: {row.get('source') or 'any'}). Copy it now, it won't be shown again:\n")
    print(key)
    print(f'\nPowerShell:  $env:AEGIS_API_KEY = "{key}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
