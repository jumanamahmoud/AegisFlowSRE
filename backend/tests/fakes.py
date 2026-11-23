"""
backend/tests/fakes.py
=======================
In-memory stand-in for the Supabase client.

Implements only the PostgREST subset AegisFlow uses
(``table().insert/select/update/delete().eq().order().limit().execute()``)
and mirrors the database rules from the Week-1 migration:

* column defaults (uuid ids, timestamps, ``status = 'open'``)
* ``audit_events`` rejects UPDATE and DELETE (append-only)
* ``audit_events.id`` is an increasing integer identity

This lets tests write an incident through the API and read it back through
the API, exercising real store/router code instead of mock call chains.
"""

from __future__ import annotations

import copy
import itertools
import threading
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any


class ImmutableTableError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_DEFAULTS = {
    "incidents": lambda: {
        "id": str(uuid.uuid4()),
        "metadata": {},
        "status": "open",
        "incident_category": None,
        "severity": None,
        "acknowledged_at": None,
        "resolved_at": None,
        "closed_at": None,
        "analysis_status": "none",
        "analysis_error": None,
        "analysis_updated_at": None,
        "created_at": _now(),
        "updated_at": _now(),
    },
    "incident_analyses": lambda: {"id": str(uuid.uuid4()), "created_at": _now()},
    "audit_events": lambda: {"actor": "system", "payload": {}, "recorded_at": _now()},
}

_IMMUTABLE = {"audit_events"}

# Columns typed uuid in the migration; filtering them with a non-uuid fails.
_UUID_COLUMNS = {
    "incidents": ("id",),
    "incident_analyses": ("id", "incident_id"),
    "audit_events": ("incident_id",),
    "user_roles": ("user_id",),
}


class InvalidUuidError(Exception):
    """Mirrors Postgres error 22P02."""


class _Query:
    def __init__(self, db: "FakeSupabase", table: str) -> None:
        self._db = db
        self._table = table
        self._op: str | None = None
        self._payload: Any = None
        self._filters: list[tuple[str, Any]] = []
        self._order: list[tuple[str, bool]] = []
        self._limit: int | None = None

    # --- verbs ---
    def insert(self, rows):
        self._op, self._payload = "insert", rows
        return self

    def select(self, *_cols):
        self._op = "select"
        return self

    def update(self, changes: dict):
        self._op, self._payload = "update", changes
        return self

    def delete(self):
        self._op = "delete"
        return self

    # --- modifiers ---
    def eq(self, col: str, value):
        if col in _UUID_COLUMNS.get(self._table, ()):
            try:
                uuid.UUID(str(value))
            except ValueError:
                # Same failure real Postgres gives for a malformed uuid literal.
                raise InvalidUuidError(f'invalid input syntax for type uuid: "{value}"') from None
        self._filters.append((col, value))
        return self

    def in_(self, col: str, values):
        self._filters.append((col, ("__in__", tuple(values))))
        return self

    def order(self, col: str, desc: bool = False):
        self._order.append((col, desc))
        return self

    def limit(self, n: int):
        self._limit = n
        return self

    # --- execution ---
    def _matches(self, row: dict) -> bool:
        for col, value in self._filters:
            if isinstance(value, tuple) and value and value[0] == "__in__":
                if row.get(col) not in value[1]:
                    return False
            elif row.get(col) != value:
                return False
        return True

    def execute(self):
        rows = self._db.tables.setdefault(self._table, [])
        if self._db.fail_tables.get(self._table):
            raise self._db.fail_tables[self._table]

        if self._op == "insert":
            batch = self._payload if isinstance(self._payload, list) else [self._payload]
            out = []
            for item in batch:
                row = _DEFAULTS.get(self._table, dict)()
                if self._table == "audit_events":
                    row["id"] = next(self._db._audit_ids)
                    row.setdefault("occurred_at", _now())
                row.update(copy.deepcopy(item))
                rows.append(row)
                out.append(copy.deepcopy(row))
            return SimpleNamespace(data=out)

        if self._op in ("update", "delete") and self._table in _IMMUTABLE:
            raise ImmutableTableError(f"{self._table} is append-only ({self._op.upper()} blocked)")

        matched = [r for r in rows if self._matches(r)]

        if self._op == "update":
            for r in matched:
                r.update(copy.deepcopy(self._payload))
                if self._table == "incidents":
                    r["updated_at"] = _now()
            return SimpleNamespace(data=copy.deepcopy(matched))

        if self._op == "delete":
            self._db.tables[self._table] = [r for r in rows if not self._matches(r)]
            return SimpleNamespace(data=copy.deepcopy(matched))

        # select
        result = list(matched)
        for col, desc in reversed(self._order):  # stable multi-key sort
            result.sort(key=lambda r: (r.get(col) is None, r.get(col)), reverse=desc)
        if self._limit is not None:
            result = result[: self._limit]
        return SimpleNamespace(data=copy.deepcopy(result))


class FakeSupabase:
    def __init__(self) -> None:
        self.tables: dict[str, list[dict]] = {
            "incidents": [],
            "incident_analyses": [],
            "audit_events": [],
            "user_roles": [],
        }
        # Stand-in for auth.users, reachable only via the Auth admin API.
        self.auth_users: list[dict] = []
        self.auth = SimpleNamespace(admin=SimpleNamespace(list_users=self._list_users))
        self.fail_tables: dict[str, Exception] = {}
        self._lock = threading.Lock()
        self._audit_ids = itertools.count(1)

    def _list_users(self, page: int | None = None, per_page: int | None = None):
        page, per_page = page or 1, per_page or 50
        chunk = self.auth_users[(page - 1) * per_page: page * per_page]
        return [SimpleNamespace(**u) for u in chunk]

    def table(self, name: str) -> _Query:
        return _Query(self, name)

    def rpc(self, fn: str, params: dict) -> "_Rpc":
        return _Rpc(self, fn, params)


class _Rpc:
    """Mirrors public.change_incident_status (atomic_status_change migration):
    compare-and-set update + audit insert in one transaction."""

    def __init__(self, db: FakeSupabase, fn: str, params: dict) -> None:
        self._db, self._fn, self._p = db, fn, params

    def execute(self):
        if self._fn != "change_incident_status":
            raise RuntimeError(f"PGRST202: Could not find the function public.{self._fn}")
        p = self._p
        uuid.UUID(str(p["p_incident_id"]))  # uuid-typed parameter
        with self._db._lock:  # the transaction
            rows = [r for r in self._db.tables["incidents"]
                    if r["id"] == p["p_incident_id"] and r["status"] == p["p_from"]]
            if not rows:
                return SimpleNamespace(data=[])
            # Audit insert failing must roll back the status change: check first.
            if self._db.fail_tables.get("audit_events"):
                raise self._db.fail_tables["audit_events"]
            row = rows[0]
            row["status"] = p["p_to"]
            col = {"acknowledged": "acknowledged_at", "resolved": "resolved_at",
                   "closed": "closed_at"}.get(p["p_to"])
            if col and not row.get(col):
                row[col] = _now()
            row["updated_at"] = _now()
            payload = {"from": p["p_from"], "to": p["p_to"]}
            if p.get("p_note") is not None:
                payload["note"] = p["p_note"]
            self._db.tables["audit_events"].append({
                "id": next(self._db._audit_ids), "incident_id": p["p_incident_id"],
                "event_type": "incident.status_changed", "actor": p["p_actor"],
                "payload": payload, "occurred_at": _now(), "recorded_at": _now(),
            })
            return SimpleNamespace(data=[copy.deepcopy(row)])
