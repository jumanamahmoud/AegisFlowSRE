"""
backend/main.py
================
AegisFlow FastAPI application entry point.

Wires together:
- Lifespan context manager (startup validation + shutdown cleanup)
- CORS middleware
- Topology and Incidents routers
- GET /health endpoint

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.6, 6.7
"""


from __future__ import annotations
from dotenv import load_dotenv
load_dotenv()
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database.neo4j_client import get_neo4j_client
from database.supabase_client import get_supabase, supabase_secret_key, supabase_url
from routers.topology import router as topology_router
from routers.incidents import router as incidents_router

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Required environment variables
# ---------------------------------------------------------------------------

_REQUIRED_ENV_VARS = (
    "NEO4J_URI",
    "NEO4J_USER",
    "NEO4J_PASSWORD",
    "GROQ_API_KEY",
)


def _missing_env_vars() -> list[str]:
    """Names of required settings that are unset. Supabase accepts aliases
    (see database/supabase_client.py), so it is checked by resolved value."""
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v, "").strip()]
    if not supabase_url():
        missing.append("SUPABASE_URL")
    if not supabase_secret_key():
        missing.append("SUPABASE_SECRET_KEY")
    return missing


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Startup:
    1. Load .env via dotenv.
    2. Validate required environment variables (Neo4j, Groq, Supabase URL + secret key).
    3. Verify Neo4j connectivity.
    4. Verify Supabase connectivity via a lightweight query.

    Shutdown:
    5. Close the Neo4j driver connection pool.

    Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6
    """
    # 1. .env is loaded at import time (top of this module).

    # 2. Validate all required env vars before touching any external service
    missing = _missing_env_vars()
    if missing:
        msg = f"Missing required env var: {', '.join(missing)}"
        logger.error(msg)
        raise RuntimeError(msg)

    # 3. Verify Neo4j connectivity — raises ConnectionError if unreachable
    try:
        get_neo4j_client().verify_connectivity()
        logger.info("Neo4j connectivity verified.")
    except ConnectionError as exc:
        logger.error("Neo4j connectivity check failed: %s", exc)
        raise

    # 4. Verify Supabase connectivity via a lightweight list query
    try:
        get_supabase().table("incidents").select("id").limit(1).execute()
        logger.info("Supabase connectivity verified.")
    except Exception as exc:
        logger.error("Supabase connectivity check failed: %s", exc)
        raise

    # --- yield: application serves traffic ---
    yield

    # 5. Shutdown: close the Neo4j driver pool
    get_neo4j_client().close()
    logger.info("Neo4j driver closed.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AegisFlow",
    description="Autonomous Enterprise Incident Response System",
    version="0.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------

_cors_env: str = os.environ.get("CORS_ALLOW_ORIGINS", "")
try:
    _origins: list[str] = json.loads(_cors_env) if _cors_env.strip() else ["*"]
except (json.JSONDecodeError, ValueError):
    _origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(topology_router, prefix="/topology")
app.include_router(incidents_router, prefix="/incidents")

# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Shape of the /health response."""

    neo4j: dict  # {"healthy": bool}
    supabase: dict  # {"healthy": bool}


@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """GET /health — Report Neo4j and Supabase connectivity status.

    Returns a JSON object with ``neo4j`` and ``supabase`` keys, each
    containing a boolean ``healthy`` field. Exceptions are caught so the
    endpoint always responds — it is a status check, not a startup gate.

    Requirements: 6.6
    """
    # Neo4j check
    neo4j_ok: bool
    try:
        get_neo4j_client().verify_connectivity()
        neo4j_ok = True
    except Exception:
        neo4j_ok = False

    # Supabase check
    supabase_ok: bool
    try:
        get_supabase().table("incidents").select("id").limit(1).execute()
        supabase_ok = True
    except Exception:
        supabase_ok = False

    return HealthResponse(
        neo4j={"healthy": neo4j_ok},
        supabase={"healthy": supabase_ok},
    )
