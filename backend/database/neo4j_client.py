"""
backend/database/neo4j_client.py
=================================
Canonical Neo4j graph client for AegisFlow.

Provides a singleton-managed driver with bi-temporal edge modeling for
service dependency graphs. Use ``get_neo4j_client()`` as a FastAPI
``Depends`` dependency to share a single driver pool across requests.
"""

from __future__ import annotations

import os
from typing import Optional

import logging

import neo4j
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

# Timeouts (seconds) so a hung Aura connection can't stall an analysis forever.
_DRIVER_TIMEOUTS = {
    "connection_timeout": float(os.environ.get("NEO4J_CONNECTION_TIMEOUT_S", "10")),
    "connection_acquisition_timeout": float(os.environ.get("NEO4J_ACQUISITION_TIMEOUT_S", "15")),
    "max_transaction_retry_time": 15.0,
}

# Read queries are idempotent, so transient network/cluster errors are retried
# with exponential backoff. Writes are NOT retried (a repeated upsert would
# close and re-create a dependency edge, polluting its history).
_retry_reads = retry(
    retry=retry_if_exception_type((ServiceUnavailable, SessionExpired, TransientError)),
    stop=stop_after_attempt(int(os.environ.get("NEO4J_READ_ATTEMPTS", "3"))),
    wait=wait_exponential(multiplier=0.5, max=4),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)


class Neo4jClient:
    """
    Thin wrapper around the official Neo4j Python driver.

    Responsibilities:
    - Read connection credentials from environment variables at construction time.
    - Expose graph query helpers for topology and incident analysis.
    - Support both explicit close() and async context manager usage.
    """

    def __init__(self) -> None:
        # Validate every required env var before touching the driver.
        for var in ("NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD"):
            if not os.environ.get(var, "").strip():
                raise RuntimeError(f"Missing required env var: {var}")

        uri = os.environ["NEO4J_URI"].strip()
        user = os.environ["NEO4J_USER"].strip()
        password = os.environ["NEO4J_PASSWORD"].strip()

        # Optional: path to a CA bundle (e.g. certifi's cacert.pem) for machines
        # whose OS trust store is missing a root certificate used by Aura.
        ca_bundle = os.environ.get("NEO4J_CA_BUNDLE", "").strip()

        if ca_bundle:
            # Keep routing (neo4j://) so queries reach the cluster member that
            # hosts the database. Custom trusted certificates can't be combined
            # with the "+s" schemes, so any scheme in .env becomes neo4j://host
            # with encrypted=True.
            routed_uri = "neo4j://" + uri.split("://", 1)[-1]
            self.driver: neo4j.Driver = GraphDatabase.driver(
                routed_uri,
                auth=(user, password),
                encrypted=True,
                trusted_certificates=neo4j.TrustCustomCAs(ca_bundle),
                **_DRIVER_TIMEOUTS,
            )
        else:
            self.driver = GraphDatabase.driver(uri, auth=(user, password), **_DRIVER_TIMEOUTS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the driver connection pool. Safe to call even if the driver
        was never successfully initialised."""
        global _client
        if self.driver:
            self.driver.close()
        if _client is self:
            _client = None  # never hand out a closed client again

    def verify_connectivity(self) -> bool:
        """Verify that the Neo4j server is reachable.

        Returns True on success. Raises ConnectionError (wrapping the
        original exception) if the driver cannot reach the server.
        """
        try:
            self.driver.verify_connectivity()
            return True
        except Exception as exc:
            raise ConnectionError(
                f"Neo4j connectivity check failed: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Async context manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "Neo4jClient":
        return self

    async def __aexit__(self, *args) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Graph query methods
    # ------------------------------------------------------------------

    def upsert_service_dependency(
        self,
        service_id: str,
        service_name: str,
        external_system: str,
        protocol: str = "HTTPS",
    ) -> None:
        """Create or update a bi-temporal DEPENDS_ON edge between a Service
        node and an ExternalSystem node.

        If an active edge (valid_to IS NULL) already exists it is closed by
        setting valid_to = datetime() before the new edge is created.
        """
        query = """
        // Merge the Service node
        MERGE (s:Service {id: $service_id})
        ON CREATE SET s.name = $service_name, s.created_at = datetime()
        ON MATCH SET s.name = $service_name

        // Merge the ExternalSystem node
        WITH s
        MERGE (ext:ExternalSystem {name: $external_system})

        // Close any existing active relationship (bi-temporal expiry)
        WITH s, ext
        OPTIONAL MATCH (s)-[r:DEPENDS_ON]->(ext)
        WHERE r.valid_to IS NULL
        SET r.valid_to = datetime()

        // Create a new active bi-temporal edge (no valid_to = active)
        WITH DISTINCT s, ext
        CREATE (s)-[:DEPENDS_ON {
            valid_from: datetime(),
            protocol: $protocol
        }]->(ext)
        """
        with self.driver.session() as session:
            session.run(
                query,
                service_id=service_id,
                service_name=service_name,
                external_system=external_system,
                protocol=protocol,
            )

    @_retry_reads
    def get_blast_radius(
        self, failed_service_id: str, max_hops: int = 3
    ) -> list[dict]:
        """Return the services impacted if *failed_service_id* goes down: every
        service that depends on it, directly or indirectly, through active
        DEPENDS_ON edges up to *max_hops* hops.

        Each entry has ``id``, ``name``, ``type`` and ``hops`` (shortest
        distance). Only edges where valid_to IS NULL are traversed. Returns an
        empty list if nothing depends on the service.

        Note: Neo4j does not support bound parameters for variable-length
        path bounds, so max_hops is interpolated directly into the query
        string after being validated as a positive integer.
        """
        hops = max(1, int(max_hops))

        query = f"""
        MATCH path = (impacted:Service)-[:DEPENDS_ON*1..{hops}]->(:Service {{id: $service_id}})
        WHERE ALL(r IN relationships(path) WHERE r.valid_to IS NULL)
        RETURN impacted.id AS id,
               impacted.name AS name,
               min(length(path)) AS hops
        ORDER BY hops, id
        """
        with self.driver.session() as session:
            result = session.run(query, service_id=failed_service_id)
            return [
                {
                    "id": record["id"],
                    "name": record["name"],
                    "type": "Service",
                    "hops": record["hops"],
                }
                for record in result
            ]

    @_retry_reads
    def get_service_context(self, service_id: str) -> list[dict]:
        """Return the direct active DEPENDS_ON neighbors of *service_id*.

        Each entry contains ``name``, ``type`` (the node's ``type`` property,
        falling back to its label) and ``protocol`` (from the DEPENDS_ON
        relationship). Returns an empty list if the service has no active
        dependencies.
        """
        query = """
        MATCH (:Service {id: $service_id})-[r:DEPENDS_ON]->(target)
        WHERE r.valid_to IS NULL
        RETURN coalesce(target.name, target.id) AS name,
               coalesce(target.type, labels(target)[0]) AS type,
               r.protocol AS protocol
        """
        with self.driver.session() as session:
            result = session.run(query, service_id=service_id)
            return [
                {
                    "name": record["name"],
                    "type": record["type"],
                    "protocol": record["protocol"],
                }
                for record in result
            ]


    # ------------------------------------------------------------------
    # Service map management (FR-29) — nothing is ever deleted: retiring a
    # service or a dependency closes it (valid_to / retired_at), so the map
    # as it was at the time of any incident can still be read back.
    # ------------------------------------------------------------------

    @_retry_reads
    def list_services(self, include_retired: bool = False) -> list[dict]:
        query = """
        MATCH (s:Service)
        WHERE $include_retired OR s.retired_at IS NULL
        RETURN s ORDER BY s.id
        """
        with self.driver.session() as session:
            return [_service_dict(r["s"]) for r in session.run(query, include_retired=include_retired)]

    @_retry_reads
    def get_service(self, service_id: str) -> dict | None:
        with self.driver.session() as session:
            record = session.run("MATCH (s:Service {id: $id}) RETURN s", id=service_id).single()
            return _service_dict(record["s"]) if record else None

    def create_service(self, service_id: str, name: str, type_: str = "service", tier: str | None = None) -> dict:
        def work(tx):
            if tx.run("MATCH (s:Service {id: $id}) RETURN s", id=service_id).single():
                raise ServiceExistsError(service_id)
            record = tx.run(
                "CREATE (s:Service {id: $id, name: $name, type: $type, tier: $tier, created_at: datetime()}) "
                "RETURN s",
                id=service_id, name=name, type=type_, tier=tier,
            ).single()
            return _service_dict(record["s"])

        with self.driver.session() as session:
            return session.execute_write(work)

    def update_service(self, service_id: str, changes: dict) -> dict:
        allowed = {k: v for k, v in changes.items() if k in ("name", "type", "tier")}

        def work(tx):
            record = tx.run(
                "MATCH (s:Service {id: $id}) WHERE s.retired_at IS NULL "
                "SET s += $changes, s.updated_at = datetime() RETURN s",
                id=service_id, changes=allowed,
            ).single()
            if record is None:
                raise ServiceNotFoundError(service_id)
            return _service_dict(record["s"])

        with self.driver.session() as session:
            return session.execute_write(work)

    def retire_service(self, service_id: str) -> int:
        """Mark a service retired and close every active link to or from it.
        Returns how many links were closed."""

        def work(tx):
            if not tx.run("MATCH (s:Service {id: $id}) WHERE s.retired_at IS NULL RETURN s",
                          id=service_id).single():
                raise ServiceNotFoundError(service_id)
            record = tx.run(
                """
                MATCH (s:Service {id: $id})
                SET s.retired_at = datetime()
                WITH s
                OPTIONAL MATCH (s)-[r:DEPENDS_ON]-()
                WHERE r.valid_to IS NULL
                SET r.valid_to = datetime()
                RETURN count(r) AS closed
                """,
                id=service_id,
            ).single()
            return record["closed"]

        with self.driver.session() as session:
            return session.execute_write(work)

    def set_dependency(
        self, service_id: str, target_id: str, target_kind: str = "service", protocol: str = "HTTPS",
        target_type: str | None = None,
    ) -> str:
        """Make ``service_id`` depend on a service or an external system.

        Returns 'created', 'updated' (protocol changed: the old link is closed
        and a new one starts) or 'unchanged' (no new history is written).
        """
        if target_kind not in ("service", "external"):
            raise InvalidDependencyError("target_kind must be 'service' or 'external'")
        if target_kind == "service" and target_id == service_id:
            raise InvalidDependencyError("a service cannot depend on itself")

        def work(tx):
            if not tx.run("MATCH (s:Service {id: $id}) WHERE s.retired_at IS NULL RETURN s",
                          id=service_id).single():
                raise ServiceNotFoundError(service_id)
            if target_kind == "service":
                if not tx.run("MATCH (t:Service {id: $id}) WHERE t.retired_at IS NULL RETURN t",
                              id=target_id).single():
                    raise ServiceNotFoundError(target_id)
                target = "MATCH (t:Service {id: $tid})"
            else:
                tx.run(
                    "MERGE (t:ExternalSystem {name: $tid}) "
                    "ON CREATE SET t.type = coalesce($ttype, 'external'), t.created_at = datetime()",
                    tid=target_id, ttype=target_type,
                )
                target = "MATCH (t:ExternalSystem {name: $tid})"
            existing = tx.run(
                f"MATCH (s:Service {{id: $sid}}) {target} "
                "MATCH (s)-[r:DEPENDS_ON]->(t) WHERE r.valid_to IS NULL RETURN r.protocol AS protocol",
                sid=service_id, tid=target_id,
            ).single()
            if existing is not None and existing["protocol"] == protocol:
                return "unchanged"
            tx.run(
                f"MATCH (s:Service {{id: $sid}}) {target} "
                "OPTIONAL MATCH (s)-[r:DEPENDS_ON]->(t) WHERE r.valid_to IS NULL "
                "SET r.valid_to = datetime() "
                "WITH DISTINCT s, t "
                "CREATE (s)-[:DEPENDS_ON {valid_from: datetime(), protocol: $protocol}]->(t)",
                sid=service_id, tid=target_id, protocol=protocol,
            )
            return "created" if existing is None else "updated"

        with self.driver.session() as session:
            return session.execute_write(work)

    def remove_dependency(self, service_id: str, target_id: str, target_kind: str = "service") -> bool:
        """Close the active link. False if there was none."""
        if target_kind not in ("service", "external"):
            raise InvalidDependencyError("target_kind must be 'service' or 'external'")
        target = "(t:Service {id: $tid})" if target_kind == "service" else "(t:ExternalSystem {name: $tid})"
        query = (
            f"MATCH (s:Service {{id: $sid}})-[r:DEPENDS_ON]->{target} "
            "WHERE r.valid_to IS NULL SET r.valid_to = datetime() RETURN count(r) AS closed"
        )
        with self.driver.session() as session:
            record = session.run(query, sid=service_id, tid=target_id).single()
            return bool(record and record["closed"])

    @_retry_reads
    def get_dependencies(self, service_id: str, at: str | None = None) -> list[dict]:
        """Direct dependencies, active now, or as they were at time ``at``
        (ISO 8601). Includes when each link started and ended."""
        query = """
        MATCH (:Service {id: $id})-[r:DEPENDS_ON]->(t)
        WHERE ($at IS NULL AND r.valid_to IS NULL)
           OR ($at IS NOT NULL AND r.valid_from <= datetime($at)
               AND (r.valid_to IS NULL OR r.valid_to > datetime($at)))
        RETURN coalesce(t.id, t.name) AS id, coalesce(t.name, t.id) AS name,
               coalesce(t.type, labels(t)[0]) AS type,
               CASE WHEN t:Service THEN 'service' ELSE 'external' END AS kind,
               r.protocol AS protocol, r.valid_from AS valid_from, r.valid_to AS valid_to
        ORDER BY id
        """
        with self.driver.session() as session:
            return [_edge_dict(r) for r in session.run(query, id=service_id, at=at)]

    @_retry_reads
    def get_dependents(self, service_id: str) -> list[dict]:
        """Services that directly depend on ``service_id`` right now."""
        query = """
        MATCH (d:Service)-[r:DEPENDS_ON]->(:Service {id: $id})
        WHERE r.valid_to IS NULL
        RETURN d.id AS id, d.name AS name, coalesce(d.type, 'Service') AS type, 'service' AS kind,
               r.protocol AS protocol, r.valid_from AS valid_from, r.valid_to AS valid_to
        ORDER BY id
        """
        with self.driver.session() as session:
            return [_edge_dict(r) for r in session.run(query, id=service_id)]

    @_retry_reads
    def get_dependency_history(self, service_id: str) -> list[dict]:
        """Every dependency link the service ever had, newest first."""
        query = """
        MATCH (:Service {id: $id})-[r:DEPENDS_ON]->(t)
        RETURN coalesce(t.id, t.name) AS id, coalesce(t.name, t.id) AS name,
               coalesce(t.type, labels(t)[0]) AS type,
               CASE WHEN t:Service THEN 'service' ELSE 'external' END AS kind,
               r.protocol AS protocol, r.valid_from AS valid_from, r.valid_to AS valid_to
        ORDER BY r.valid_from DESC
        """
        with self.driver.session() as session:
            return [_edge_dict(r) for r in session.run(query, id=service_id)]

    # ------------------------------------------------------------------
    # Alert grouping (FR-13)
    # ------------------------------------------------------------------

    @_retry_reads
    def find_shared_dependencies(
        self, service_id: str, other_ids: list[str], max_hops: int = 2
    ) -> dict[str, dict]:
        """For each service in ``other_ids``, the closest component that both it
        and ``service_id`` depend on (directly or through up to ``max_hops``
        active links). A service counts as depending on itself, so if one
        service depends on the other, the other is the shared component.

        Returns ``{other_id: {id, name, type, kind, hops_a, hops_b}}`` with
        only the related services; ``hops_a`` is the distance from
        ``service_id``, ``hops_b`` from the other service.
        """
        if not other_ids:
            return {}
        hops = max(1, int(max_hops))
        query = f"""
        MATCH (a:Service {{id: $sid}})
        UNWIND $others AS oid
        MATCH (b:Service {{id: oid}})
        MATCH pa = (a)-[:DEPENDS_ON*0..{hops}]->(c)
        WHERE all(r IN relationships(pa) WHERE r.valid_to IS NULL)
        MATCH pb = (b)-[:DEPENDS_ON*0..{hops}]->(c)
        WHERE all(r IN relationships(pb) WHERE r.valid_to IS NULL)
        WITH oid, c, min(length(pa)) AS ha, min(length(pb)) AS hb
        ORDER BY ha + hb, ha
        WITH oid, collect({{
            id: coalesce(c.id, c.name), name: coalesce(c.name, c.id),
            type: coalesce(c.type, labels(c)[0]),
            kind: CASE WHEN c:Service THEN 'service' ELSE 'external' END,
            hops_a: ha, hops_b: hb
        }})[0] AS best
        RETURN oid, best
        """
        with self.driver.session() as session:
            return {r["oid"]: dict(r["best"]) for r in session.run(query, sid=service_id, others=list(other_ids))}


class ServiceNotFoundError(LookupError):
    pass


class ServiceExistsError(RuntimeError):
    pass


class InvalidDependencyError(ValueError):
    pass


def _iso(value) -> str | None:
    if value is None:
        return None
    if hasattr(value, "iso_format"):  # neo4j.time.DateTime
        return value.iso_format()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _service_dict(node) -> dict:
    props = dict(node)
    return {
        "id": props.get("id"),
        "name": props.get("name") or props.get("id"),
        "type": props.get("type") or "service",
        "tier": props.get("tier"),
        "created_at": _iso(props.get("created_at")),
        "updated_at": _iso(props.get("updated_at")),
        "retired_at": _iso(props.get("retired_at")),
    }


def _edge_dict(record) -> dict:
    return {
        "id": record["id"],
        "name": record["name"],
        "type": record["type"],
        "kind": record["kind"],
        "protocol": record["protocol"],
        "valid_from": _iso(record["valid_from"]),
        "valid_to": _iso(record["valid_to"]),
    }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_client: Optional[Neo4jClient] = None


def get_neo4j_client() -> Neo4jClient:
    """Return the module-level singleton ``Neo4jClient``.

    Initialises the client on first call; subsequent calls return the
    same instance. Designed to be used as a FastAPI ``Depends`` dependency::

        from database.neo4j_client import get_neo4j_client

        @router.get("/blast-radius/{service_id}")
        def blast_radius(service_id: str, client=Depends(get_neo4j_client)):
            return client.get_blast_radius(service_id)
    """
    global _client
    if _client is None:
        _client = Neo4jClient()
    return _client