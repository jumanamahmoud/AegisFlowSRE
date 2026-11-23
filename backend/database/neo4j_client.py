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

import neo4j
from neo4j import GraphDatabase


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
            )
        else:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))

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