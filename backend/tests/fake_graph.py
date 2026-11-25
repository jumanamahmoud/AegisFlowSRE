"""
backend/tests/fake_graph.py
============================
In-memory service map: a stand-in for the Neo4j client's service-map API
(database/neo4j_client.py) with the same methods and rules — services and
external systems, DEPENDS_ON links with valid_from/valid_to, nothing ever
deleted. The Cypher itself is checked live in
tests/test_integration_service_map.py.
"""

from __future__ import annotations

from database.neo4j_client import InvalidDependencyError, ServiceExistsError, ServiceNotFoundError
from tests.fakes import _cmp_value, _now


class FakeServiceGraph:
    def __init__(self) -> None:
        self.services: dict[str, dict] = {}
        self.externals: dict[str, dict] = {}
        self.edges: list[dict] = []  # {src, dst, kind, protocol, valid_from, valid_to}
        self.fail: Exception | None = None

    # --- helpers -------------------------------------------------------------
    def _check(self) -> None:
        if self.fail:
            raise self.fail

    def _node(self, kind: str, ident: str) -> dict | None:
        return self.services.get(ident) if kind == "service" else self.externals.get(ident)

    @staticmethod
    def _active(e: dict) -> bool:
        return e["valid_to"] is None

    def _edge_out(self, e: dict, ident: str | None = None, kind: str | None = None) -> dict:
        ident = ident or e["dst"]
        kind = kind or e["kind"]
        node = self._node(kind, ident) or {}
        return {"id": ident, "name": node.get("name", ident),
                "type": node.get("type", "service" if kind == "service" else "external"),
                "kind": kind, "protocol": e["protocol"],
                "valid_from": e["valid_from"], "valid_to": e["valid_to"]}

    def _new_service(self, sid: str, name: str | None = None, type_: str = "service", tier=None) -> dict:
        return {"id": sid, "name": name or sid, "type": type_, "tier": tier,
                "created_at": _now(), "updated_at": None, "retired_at": None}

    # --- convenience for tests -------------------------------------------------
    def add(self, sid: str, *deps: str, kind: str = "service") -> "FakeServiceGraph":
        """``add('checkout-service', 'payment-service')`` — creates nodes as needed."""
        self.services.setdefault(sid, self._new_service(sid))
        for d in deps:
            if kind == "service":
                self.services.setdefault(d, self._new_service(d))
            else:
                self.externals.setdefault(d, {"id": d, "name": d, "type": "database"})
            self.edges.append({"src": sid, "dst": d, "kind": kind, "protocol": "TCP",
                               "valid_from": _now(), "valid_to": None})
        return self

    # --- client API --------------------------------------------------------------
    def list_services(self, include_retired: bool = False) -> list[dict]:
        self._check()
        return [dict(s) for _, s in sorted(self.services.items()) if include_retired or not s["retired_at"]]

    def get_service(self, service_id: str) -> dict | None:
        self._check()
        s = self.services.get(service_id)
        return dict(s) if s else None

    def create_service(self, service_id, name, type_="service", tier=None) -> dict:
        self._check()
        if service_id in self.services:
            raise ServiceExistsError(service_id)
        self.services[service_id] = self._new_service(service_id, name, type_, tier)
        return dict(self.services[service_id])

    def update_service(self, service_id, changes) -> dict:
        self._check()
        s = self.services.get(service_id)
        if not s or s["retired_at"]:
            raise ServiceNotFoundError(service_id)
        s.update({k: v for k, v in changes.items() if k in ("name", "type", "tier")})
        s["updated_at"] = _now()
        return dict(s)

    def retire_service(self, service_id) -> int:
        self._check()
        s = self.services.get(service_id)
        if not s or s["retired_at"]:
            raise ServiceNotFoundError(service_id)
        s["retired_at"] = _now()
        closed = 0
        for e in self.edges:
            if self._active(e) and (e["src"] == service_id or (e["kind"] == "service" and e["dst"] == service_id)):
                e["valid_to"] = _now()
                closed += 1
        return closed

    def set_dependency(self, service_id, target_id, target_kind="service", protocol="HTTPS",
                       target_type=None) -> str:
        self._check()
        if target_kind not in ("service", "external"):
            raise InvalidDependencyError("target_kind must be 'service' or 'external'")
        if target_kind == "service" and target_id == service_id:
            raise InvalidDependencyError("a service cannot depend on itself")
        s = self.services.get(service_id)
        if not s or s["retired_at"]:
            raise ServiceNotFoundError(service_id)
        if target_kind == "service":
            t = self.services.get(target_id)
            if not t or t["retired_at"]:
                raise ServiceNotFoundError(target_id)
        else:
            self.externals.setdefault(target_id, {"id": target_id, "name": target_id,
                                                  "type": target_type or "external"})
        active = [e for e in self.edges if self._active(e) and e["src"] == service_id
                  and e["dst"] == target_id and e["kind"] == target_kind]
        if active and active[0]["protocol"] == protocol:
            return "unchanged"
        for e in active:
            e["valid_to"] = _now()
        self.edges.append({"src": service_id, "dst": target_id, "kind": target_kind, "protocol": protocol,
                           "valid_from": _now(), "valid_to": None})
        return "updated" if active else "created"

    def remove_dependency(self, service_id, target_id, target_kind="service") -> bool:
        self._check()
        if target_kind not in ("service", "external"):
            raise InvalidDependencyError("target_kind must be 'service' or 'external'")
        closed = False
        for e in self.edges:
            if self._active(e) and e["src"] == service_id and e["dst"] == target_id and e["kind"] == target_kind:
                e["valid_to"] = _now()
                closed = True
        return closed

    def get_dependencies(self, service_id, at=None) -> list[dict]:
        self._check()
        out = []
        for e in self.edges:
            if e["src"] != service_id:
                continue
            if at is None:
                ok = self._active(e)
            else:
                t = _cmp_value(at)
                ok = _cmp_value(e["valid_from"]) <= t and (e["valid_to"] is None or _cmp_value(e["valid_to"]) > t)
            if ok:
                out.append(self._edge_out(e))
        return sorted(out, key=lambda d: d["id"])

    def get_dependents(self, service_id) -> list[dict]:
        self._check()
        return sorted(
            (self._edge_out(e, ident=e["src"], kind="service") for e in self.edges
             if self._active(e) and e["kind"] == "service" and e["dst"] == service_id),
            key=lambda d: d["id"],
        )

    def get_dependency_history(self, service_id) -> list[dict]:
        self._check()
        return [self._edge_out(e) for e in reversed(self.edges) if e["src"] == service_id]

    def get_service_context(self, service_id) -> list[dict]:
        return [{"name": d["name"], "type": d["type"], "protocol": d["protocol"]}
                for d in self.get_dependencies(service_id)]

    def _reach(self, start: str, max_hops: int) -> dict:
        """{(kind, id): hops} reachable from ``start`` over active links, itself included."""
        dist = {("service", start): 0}
        frontier = [start]
        for hop in range(1, max_hops + 1):
            nxt = []
            for sid in frontier:
                for e in self.edges:
                    if self._active(e) and e["src"] == sid and (e["kind"], e["dst"]) not in dist:
                        dist[(e["kind"], e["dst"])] = hop
                        if e["kind"] == "service":
                            nxt.append(e["dst"])
            frontier = nxt
        return dist

    def find_shared_dependencies(self, service_id, other_ids, max_hops=2) -> dict:
        self._check()
        if service_id not in self.services:
            return {}
        mine = self._reach(service_id, max_hops)
        out = {}
        for oid in other_ids:
            if oid not in self.services:
                continue
            theirs = self._reach(oid, max_hops)
            shared = [(mine[k] + theirs[k], mine[k], k, theirs[k]) for k in mine if k in theirs]
            if not shared:
                continue
            _, ha, (kind, ident), hb = min(shared, key=lambda x: (x[0], x[1], x[2]))
            node = self._node(kind, ident) or {}
            out[oid] = {"id": ident, "name": node.get("name", ident), "type": node.get("type", kind),
                        "kind": kind, "hops_a": ha, "hops_b": hb}
        return out

    def get_blast_radius(self, failed_service_id, max_hops=3) -> list[dict]:
        out = []
        for sid in self.services:
            d = self._reach(sid, max_hops).get(("service", failed_service_id))
            if sid != failed_service_id and d:
                out.append({"id": sid, "name": self.services[sid]["name"], "type": "Service", "hops": d})
        return sorted(out, key=lambda x: (x["hops"], x["id"]))
