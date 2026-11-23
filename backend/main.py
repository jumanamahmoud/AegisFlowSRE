"""
backend/main.py
================
AegisFlow FastAPI application entry point.

Wires together:
- Structured JSON logging with a request id on every line (core/logging.py)
- Lifespan: startup validation, background analysis queue start/resume, shutdown
- Request-id + access-log middleware
- CORS restricted to the dashboard origin(s)
- Routers: incidents, topology, auth/admin (all require login — FR-32)
- GET /health endpoint (public: it reveals only up/down)

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.6, 6.7
"""


from __future__ import annotations
from dotenv import load_dotenv
load_dotenv()
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.logging import configure_logging, request_id_var
from database.neo4j_client import get_neo4j_client
from database.supabase_client import get_supabase, supabase_secret_key, supabase_url
from routers.admin import admin_router, auth_router
from routers.topology import router as topology_router
from routers.incidents import router as incidents_router
from services.analysis_queue import get_analysis_queue

configure_logging()
logger = logging.getLogger("aegisflow")

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

    # 5. Resume analyses interrupted by a previous shutdown (no alert is lost)
    queue = get_analysis_queue()
    try:
        queue.recover()
    except Exception:
        logger.exception("could not resume pending analyses")

    # --- yield: application serves traffic ---
    yield

    # 6. Shutdown: stop the queue (unstarted jobs stay 'queued' in the DB),
    #    then close the Neo4j driver pool
    queue.shutdown()
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
# CORS — only the dashboard may call the API from a browser
# ---------------------------------------------------------------------------

_DEFAULT_ORIGINS = ["http://localhost:3000"]


def _cors_origins() -> list[str]:
    raw = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
    if not raw:
        return list(_DEFAULT_ORIGINS)
    try:
        origins = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        origins = [o.strip() for o in raw.split(",")]
    origins = [o.rstrip("/") for o in origins if isinstance(o, str) and o.strip()]
    if "*" in origins:
        # A wildcard would let any website call the API with a user's token.
        logger.warning("CORS_ALLOW_ORIGINS contains '*'; ignoring it")
        origins = [o for o in origins if o != "*"]
    return origins or list(_DEFAULT_ORIGINS)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

# ---------------------------------------------------------------------------
# Request id + access log
# ---------------------------------------------------------------------------

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Give every request an id (reuse a sane incoming X-Request-ID), expose it
    in the response, and write one structured access-log line per request."""
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
    token = request_id_var.set(request_id)
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                "user_id": getattr(request.state, "user_id", None),
            },
        )
        request_id_var.reset(token)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(topology_router, prefix="/topology")
app.include_router(incidents_router, prefix="/incidents")
app.include_router(auth_router, prefix="/auth")
app.include_router(admin_router, prefix="/admin")

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
