"""
backend/routers/topology.py
============================
Topology ingestion router for AegisFlow.

Exposes a single POST /ingest endpoint that records a service-to-external-system
dependency edge in Neo4j via the canonical Neo4jClient singleton.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from database.neo4j_client import get_neo4j_client, Neo4jClient


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TopologyIngestRequest(BaseModel):
    service_id: str
    service_name: str
    external_system: str
    protocol: str = "HTTPS"


class TopologyIngestResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(tags=["topology"])


@router.post("/ingest", response_model=TopologyIngestResponse)
def ingest_topology(
    payload: TopologyIngestRequest,
    client: Neo4jClient = Depends(get_neo4j_client),
) -> TopologyIngestResponse:
    """Record a bi-temporal DEPENDS_ON edge between a Service and an ExternalSystem.

    Pydantic validates the request body automatically; missing required fields
    produce HTTP 422 without any extra handling here.
    """
    client.upsert_service_dependency(
        service_id=payload.service_id,
        service_name=payload.service_name,
        external_system=payload.external_system,
        protocol=payload.protocol,
    )
    return TopologyIngestResponse(message="Dependency ingested successfully")
