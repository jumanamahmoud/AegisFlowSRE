# Requirements Document

## Introduction

AegisFlow Backend Core initializes the foundational infrastructure for the AegisFlow autonomous incident response platform. This feature delivers three components: the canonical Neo4j graph database client (`backend/database/neo4j_client.py`) with bi-temporal edge modeling, the FastAPI application entry point (`backend/main.py`) with lifespan-managed connections, startup health validation, and two routers, and the LangGraph reasoning pipeline (`backend/engine/langgraph_pipeline.py`) that orchestrates System 1 (Jev deterministic gating) with System 2 (Groq LLM) for incident triage. The legacy `backend/neo4j_client.py` file is superseded by the canonical client and must not be used at runtime.

## Glossary

- **Neo4j_Client**: The module-level singleton at `backend/database/neo4j_client.py` that manages the Neo4j driver connection pool and exposes graph query methods.
- **FastAPI_App**: The FastAPI application instance defined in `backend/main.py`.
- **Lifespan_Manager**: The async context manager registered with FastAPI_App that runs startup and shutdown logic.
- **Topology_Router**: The router mounted at `/topology` that handles service dependency ingestion.
- **Incidents_Router**: The router mounted at `/incidents` that handles incident audit log read/write via Supabase.
- **LangGraph_Pipeline**: The LangGraph `StateGraph` defined in `backend/engine/langgraph_pipeline.py`.
- **Jev_Gate**: The pipeline node that calls the TypeSafe Jev SDK using Choice/Score/Noul primitives to classify and score an incident.
- **DEPENDS_ON**: A Neo4j relationship type that records a service-to-service or service-to-external-system dependency. Carries `valid_from` and `valid_to` temporal properties.
- **Bi-temporal_Edge**: A DEPENDS_ON relationship whose `valid_to` is `NULL`, meaning it is currently active. Expired edges carry a non-null `valid_to` timestamp.
- **Blast_Radius**: The set of Service and ExternalSystem nodes reachable from a failed service via active DEPENDS_ON paths up to a configurable hop depth.
- **Service_Context**: The direct active DEPENDS_ON neighbors of a service node, used to enrich LLM prompts.
- **Groq_Client**: The client wrapping the Groq API, initialized from `GROQ_API_KEY`, used by the `llm_reason` pipeline node.
- **Supabase_Client**: The Supabase client used exclusively for incident audit log operations.
- **Severity_Score**: A 0–3 integer index produced by Jev Score primitive mapping to Low (0), Moderate (1), High (2), Critical (3).
- **Escalation_Noul**: A 0.0–1.0 probability produced by Jev Noul primitive indicating likelihood of immediate escalation need.
- **Short-Circuit**: The pipeline behavior where the `jev_gate` node bypasses `llm_reason` and routes directly to `emit_response` when escalation is not warranted.

---

## Requirements

### Requirement 1: Neo4j Client — Connection and Lifecycle

**User Story:** As a backend developer, I want a well-structured Neo4j client singleton, so that all graph operations share a single managed driver pool without leaking connections.

#### Acceptance Criteria

1. WHEN `backend/database/neo4j_client.py` is imported, THE Neo4j_Client SHALL read `NEO4J_URI`, `NEO4J_USER`, and `NEO4J_PASSWORD` from environment variables to initialize `neo4j.GraphDatabase.driver`.
2. IF any of `NEO4J_URI`, `NEO4J_USER`, or `NEO4J_PASSWORD` is absent or empty, THEN THE Neo4j_Client SHALL raise a `RuntimeError` with a message identifying the missing variable before attempting to create a driver.
3. THE Neo4j_Client SHALL expose a `verify_connectivity()` method that calls `driver.verify_connectivity()` and returns `True` on success.
4. IF `driver.verify_connectivity()` raises an exception, THEN THE Neo4j_Client SHALL propagate a `ConnectionError` with the original cause included in the message.
5. THE Neo4j_Client SHALL implement `__aenter__` and `__aexit__` to support use as an async context manager, closing the driver on exit.
6. THE Neo4j_Client SHALL expose a `close()` method that calls `driver.close()`, making it safe to call from both sync and async contexts.
7. THE Neo4j_Client module SHALL expose a `get_neo4j_client()` function that returns the module-level singleton instance for use as a FastAPI `Depends` dependency.

---

### Requirement 2: Neo4j Client — Bi-temporal Service Dependency Upsert

**User Story:** As a topology ingestion service, I want to record service dependency edges with valid-time intervals, so that the graph accurately reflects the current and historical dependency state.

#### Acceptance Criteria

1. THE Neo4j_Client SHALL expose an `upsert_service_dependency(service_id, service_name, external_system, protocol)` method.
2. WHEN `upsert_service_dependency` is called, THE Neo4j_Client SHALL `MERGE` a `Service` node with `id = service_id` and set `name = service_name`.
3. WHEN `upsert_service_dependency` is called, THE Neo4j_Client SHALL `MERGE` an `ExternalSystem` node with `name = external_system`.
4. WHEN `upsert_service_dependency` is called and an active DEPENDS_ON relationship (where `valid_to IS NULL`) already exists between the service and external system, THE Neo4j_Client SHALL set `valid_to = datetime()` on that existing relationship before creating a new one.
5. WHEN `upsert_service_dependency` creates a new DEPENDS_ON relationship, THE Neo4j_Client SHALL set `valid_from = datetime()`, `valid_to = null`, and `protocol = protocol` on the new relationship.
6. THE Neo4j_Client SHALL use `//` for Cypher inline comments and SHALL use `}->` (closing curly brace) to terminate relationship literals, not `--` or `]->`.

---

### Requirement 3: Neo4j Client — Blast Radius Query

**User Story:** As an incident responder, I want to retrieve all services and external systems downstream of a failed service, so that I can understand the full impact of an outage.

#### Acceptance Criteria

1. THE Neo4j_Client SHALL expose a `get_blast_radius(failed_service_id, max_hops=3)` method.
2. WHEN `get_blast_radius` is called, THE Neo4j_Client SHALL traverse DEPENDS_ON relationships from the specified `Service` node up to `max_hops` hops using a variable-length path pattern `[:DEPENDS_ON*1..max_hops]`.
3. WHEN `get_blast_radius` traverses the graph, THE Neo4j_Client SHALL include only edges where `valid_to IS NULL` (active edges), filtering out all expired relationships.
4. WHEN `get_blast_radius` completes, THE Neo4j_Client SHALL return a list of unique impacted node records, each containing at minimum the node `id`, `name`, and label type (`Service` or `ExternalSystem`).
5. IF no downstream nodes are found, THEN THE Neo4j_Client SHALL return an empty list without raising an exception.

---

### Requirement 4: Neo4j Client — Service Context Query

**User Story:** As the LangGraph pipeline, I want to fetch a service's direct active dependencies, so that the LLM reasoning node has structured graph context in its prompt.

#### Acceptance Criteria

1. THE Neo4j_Client SHALL expose a `get_service_context(service_id)` method.
2. WHEN `get_service_context` is called, THE Neo4j_Client SHALL query the direct DEPENDS_ON neighbors of the `Service` node with `id = service_id`, filtering for `valid_to IS NULL`.
3. WHEN `get_service_context` returns results, THE Neo4j_Client SHALL return a list of dicts each containing `name`, `type` (node label), and `protocol` from the DEPENDS_ON relationship.
4. IF the service node does not exist or has no active dependencies, THEN THE Neo4j_Client SHALL return an empty list without raising an exception.

---

### Requirement 5: FastAPI Application — Startup and Shutdown

**User Story:** As an operator deploying AegisFlow, I want the application to verify all external connections at startup and release them cleanly at shutdown, so that misconfiguration is caught before serving traffic.

#### Acceptance Criteria

1. THE FastAPI_App SHALL use a lifespan context manager registered via `@asynccontextmanager` and passed to `FastAPI(lifespan=...)`.
2. WHEN the FastAPI_App starts up, THE Lifespan_Manager SHALL call `load_dotenv()` to load environment variables from `.env`.
3. WHEN the FastAPI_App starts up, THE Lifespan_Manager SHALL call `Neo4j_Client.verify_connectivity()` and raise a startup error if it fails.
4. WHEN the FastAPI_App starts up, THE Lifespan_Manager SHALL attempt a Supabase_Client connectivity check (e.g., a lightweight list query) and raise a startup error if the Supabase URL or key is missing.
5. IF `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `GROQ_API_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, or `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` is absent at startup, THEN THE Lifespan_Manager SHALL log a descriptive error identifying the missing variable and abort startup.
6. WHEN the FastAPI_App shuts down, THE Lifespan_Manager SHALL call `Neo4j_Client.close()` to release the driver connection pool.

---

### Requirement 6: FastAPI Application — Routers and Endpoints

**User Story:** As a service integrating with AegisFlow, I want well-defined HTTP endpoints for topology ingestion, incident audit, and health checking, so that I can interact with AegisFlow programmatically.

#### Acceptance Criteria

1. THE FastAPI_App SHALL mount the Topology_Router at prefix `/topology` with a `POST /topology/ingest` endpoint that accepts a service dependency payload and calls `upsert_service_dependency`.
2. WHEN `POST /topology/ingest` receives a valid payload, THE Topology_Router SHALL call `Neo4j_Client.upsert_service_dependency` and return HTTP 200 with a confirmation message.
3. IF `POST /topology/ingest` receives a payload missing required fields, THEN THE Topology_Router SHALL return HTTP 422 with Pydantic validation error details.
4. THE FastAPI_App SHALL mount the Incidents_Router at prefix `/incidents` with a `POST /incidents/` endpoint that writes an incident record to Supabase and a `GET /incidents/{incident_id}` endpoint that retrieves it.
5. WHEN `GET /incidents/{incident_id}` is called with an ID that does not exist in Supabase, THE Incidents_Router SHALL return HTTP 404.
6. THE FastAPI_App SHALL expose a `GET /health` endpoint that returns Neo4j and Supabase connectivity status as a JSON object with keys `neo4j` and `supabase`, each with a boolean `healthy` field.
7. THE FastAPI_App SHALL apply CORS middleware with allowed origins configurable via a `CORS_ALLOW_ORIGINS` environment variable, defaulting to `["*"]` when the variable is absent.

---

### Requirement 7: LangGraph Pipeline — Graph Enrichment Node

**User Story:** As the System 2 reasoning layer, I want to enrich incident alerts with Neo4j service context before reasoning, so that the LLM has structured topology information in its prompt.

#### Acceptance Criteria

1. THE LangGraph_Pipeline SHALL define a `StateGraph` with pipeline state containing at minimum: `alert` (str), `service_id` (str), `service_context` (list), `jev_results` (dict), `llm_response` (str), and `final_response` (dict).
2. WHEN the `enrich_with_graph` node executes, THE LangGraph_Pipeline SHALL call `Neo4j_Client.get_service_context(service_id)` and store the result in the pipeline state's `service_context` field.
3. IF `get_service_context` returns an empty list, THE LangGraph_Pipeline SHALL continue pipeline execution with `service_context` set to an empty list rather than raising an error.

---

### Requirement 8: LangGraph Pipeline — Jev Gate Node

**User Story:** As an incident triage operator, I want the Jev deterministic layer to gate LLM usage, so that low-severity incidents are resolved cheaply without calling the Groq API.

#### Acceptance Criteria

1. WHEN the `jev_gate` node executes, THE LangGraph_Pipeline SHALL call `get_jev_client()` and invoke `client.system_one` with the incident alert and the standard Choice (incident_category), Score (severity), and Noul (needs_escalation) questions as defined in `engine/jev_check.py`.
2. WHEN `jev_gate` completes, THE LangGraph_Pipeline SHALL store `incident_category`, `severity_score` (0–3 int), and `escalation_noul` (0.0–1.0 float) in the pipeline state's `jev_results` field.
3. WHEN `severity_score` is less than 2 (i.e., below "High") AND `escalation_noul` is less than 0.5, THE LangGraph_Pipeline SHALL route the pipeline from `jev_gate` directly to `emit_response`, bypassing `llm_reason`.
4. WHEN `severity_score` is 2 or greater OR `escalation_noul` is 0.5 or greater, THE LangGraph_Pipeline SHALL route the pipeline from `jev_gate` to `llm_reason`.
5. IF the Jev API call raises an exception, THEN THE LangGraph_Pipeline SHALL propagate the error and not attempt to call `llm_reason`.

---

### Requirement 9: LangGraph Pipeline — LLM Reason Node

**User Story:** As an incident responder, I want the LLM reasoning node to use Jev scores and graph context to produce a structured root-cause analysis, so that responders get actionable guidance.

#### Acceptance Criteria

1. THE LangGraph_Pipeline SHALL initialize a Groq client using `GROQ_API_KEY` with model `llama3-70b-8192`.
2. WHEN the `llm_reason` node executes, THE LangGraph_Pipeline SHALL construct a structured prompt containing: the original alert text, `service_context` from Neo4j, `incident_category` from Jev, `severity_score` label (Low/Moderate/High/Critical), and `escalation_noul` value.
3. WHEN `llm_reason` completes, THE LangGraph_Pipeline SHALL store the LLM-generated text in the pipeline state's `llm_response` field.
4. IF `GROQ_API_KEY` is absent or empty, THEN THE LangGraph_Pipeline SHALL raise a `RuntimeError` before invoking the Groq client.

---

### Requirement 10: LangGraph Pipeline — Emit Response Node

**User Story:** As a consumer of the incident pipeline, I want a consistently structured final response regardless of whether the LLM was invoked, so that downstream systems can process results uniformly.

#### Acceptance Criteria

1. WHEN the `emit_response` node executes, THE LangGraph_Pipeline SHALL assemble the `final_response` dict containing: `incident_category`, `severity` (string label), `needs_escalation` (bool, true if `escalation_noul >= 0.5`), `llm_reasoning` (the `llm_response` string or `null` if skipped), and `blast_radius` (list from `get_blast_radius`).
2. THE LangGraph_Pipeline SHALL be callable as a FastAPI background task via `BackgroundTasks.add_task` and also directly invokable via a `POST /incidents/analyze` endpoint that returns the `final_response`.
3. WHEN the pipeline is invoked via `POST /incidents/analyze`, THE FastAPI_App SHALL return the `final_response` dict as the HTTP response body with status 200.
