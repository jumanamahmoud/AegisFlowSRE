# Implementation Plan: AegisFlow Backend Core

## Overview

Implement the three foundational layers of the AegisFlow backend in dependency order: the Neo4j graph client singleton (database layer), the LangGraph reasoning pipeline (engine layer), the FastAPI routers (HTTP layer), and the FastAPI application entry point (wiring layer). Property-based tests using `hypothesis` are grouped as optional sub-tasks close to their implementation targets. All new files land under `backend/`; existing `backend/engine/jev_check.py` and `backend/engine/__init__.py` are left untouched.

---

## Tasks

- [x] 1. Set up database package and Neo4j client — connection and lifecycle
  - Create `backend/database/__init__.py` (empty init)
  - Create `backend/database/neo4j_client.py` with the `Neo4jClient` class
  - In `__init__`, read `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` from `os.environ`; raise `RuntimeError("Missing required env var: {VAR_NAME}")` before constructing `neo4j.GraphDatabase.driver` if any is absent or empty
  - Implement `verify_connectivity()` → returns `True` on success; wraps driver exception as `ConnectionError`
  - Implement `close()` with a guard (`if self.driver`) so it is safe to call when the driver was never created
  - Implement `__aenter__` / `__aexit__` for async context manager support (exit calls `close()`)
  - Implement module-level `_client: Neo4jClient | None = None` and `get_neo4j_client()` singleton factory
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

- [x] 2. Implement Neo4j bi-temporal dependency upsert
  - Add `upsert_service_dependency(service_id, service_name, external_system, protocol="HTTPS")` to `Neo4jClient`
  - Use `MERGE` for both `:Service {id}` and `:ExternalSystem {name}` nodes
  - Close any existing active edge (`valid_to IS NULL`) by setting `valid_to = datetime()` before creating a new one
  - Create the new DEPENDS_ON edge with `valid_from = datetime()`, `valid_to = null`, `protocol = protocol`
  - All Cypher comments use `//`; relationship literals close with `}`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 3. Implement Neo4j blast radius and service context queries
  - [x] 3.1 Implement `get_blast_radius(failed_service_id, max_hops=3)` in `Neo4jClient`
    - Variable-length Cypher path `[:DEPENDS_ON*1..$max_hops]` filtering `valid_to IS NULL`
    - Return `DISTINCT` list of dicts with `id`, `name`, and label type (`Service` or `ExternalSystem`)
    - Return empty list when no downstream nodes are found
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  - [x] 3.2 Implement `get_service_context(service_id)` in `Neo4jClient`
    - Query direct DEPENDS_ON neighbors filtered by `valid_to IS NULL`
    - Return list of dicts with keys `name`, `type` (node label), `protocol`
    - Return empty list when service does not exist or has no active dependencies
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 4. Checkpoint — database layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement LangGraph pipeline — state definition and graph enrichment node
  - Create `backend/engine/langgraph_pipeline.py`
  - Define `IncidentState(TypedDict)` with fields: `alert`, `service_id`, `service_context`, `jev_results`, `llm_response`, `final_response`
  - Implement `enrich_with_graph` node: calls `get_neo4j_client().get_service_context(service_id)`, stores result in `service_context`; continues with empty list if result is `[]`
  - _Requirements: 7.1, 7.2, 7.3_

- [x] 6. Implement LangGraph pipeline — Jev gate node and routing
  - Implement `jev_gate` node: calls `get_jev_client()` from `engine.jev_check`, invokes `client.system_one` with the standard `QUESTIONS` dict, stores `incident_category`, `severity_score` (int), `escalation_noul` (float) in `jev_results`
  - Implement `route_after_jev(state)` conditional: returns `"emit_response"` when `severity_score < 2 AND escalation_noul < 0.5`, else `"llm_reason"`
  - Wire `add_conditional_edges` from `jev_gate` using `route_after_jev`
  - Propagate Jev API exceptions without swallowing them
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 7. Implement LangGraph pipeline — LLM reason node
  - Read `GROQ_API_KEY` from environment at module import time; raise `RuntimeError` if absent or empty
  - Initialize `groq.Groq(api_key=GROQ_API_KEY)` with model `llama3-70b-8192`
  - Implement `llm_reason` node: construct prompt containing alert text, `service_context`, `incident_category`, severity label (Low/Moderate/High/Critical mapped from `severity_score`), and `escalation_noul`; call `chat.completions.create`; store response text in `llm_response`
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [x] 8. Implement LangGraph pipeline — emit response node and graph assembly
  - Implement `emit_response` node: calls `get_neo4j_client().get_blast_radius(service_id)`; assembles `final_response` dict with keys `incident_category`, `severity` (string label), `needs_escalation` (`escalation_noul >= 0.5`), `llm_reasoning` (`llm_response` or `null`), `blast_radius`
  - Build the `StateGraph`: add all four nodes, set `enrich_with_graph` as entry point, wire edges `enrich_with_graph → jev_gate`, `jev_gate → (conditional)`, `llm_reason → emit_response`
  - Compile the graph and expose a `run_pipeline(alert: str, service_id: str) -> dict` function that invokes the compiled graph and returns `final_response`
  - _Requirements: 10.1, 10.2_

- [x] 9. Checkpoint — engine layer complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Set up routers package and topology router
  - Create `backend/routers/__init__.py` (empty init)
  - Create `backend/routers/topology.py` with `TopologyIngestRequest` and `TopologyIngestResponse` Pydantic models
  - Implement `POST /ingest` endpoint: validate payload, call `upsert_service_dependency` via injected `Neo4jClient` dependency, return HTTP 200 with confirmation message
  - Pydantic validation errors should propagate as HTTP 422 automatically
  - _Requirements: 6.1, 6.2, 6.3_

- [x] 11. Implement incidents router
  - Create `backend/routers/incidents.py` with `IncidentCreateRequest`, `IncidentAnalyzeRequest`, `IncidentResponse` Pydantic models
  - Initialize Supabase client from `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` within the router module
  - Implement `POST /` endpoint: insert incident record into Supabase `incidents` table, return the created record as `IncidentResponse`
  - Implement `GET /{incident_id}` endpoint: fetch from Supabase; return HTTP 404 when ID is not found
  - Implement `POST /analyze` endpoint: call `run_pipeline(alert, service_id)` and return `final_response` with HTTP 200
  - _Requirements: 6.4, 6.5, 10.2, 10.3_

- [x] 12. Implement FastAPI application entry point and lifespan manager
  - Create `backend/main.py`
  - Implement `lifespan` async context manager: call `load_dotenv()`, validate all six required env vars (`NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `GROQ_API_KEY`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`), log a descriptive error and raise `RuntimeError` if any is absent
  - In lifespan startup: call `get_neo4j_client().verify_connectivity()`; perform lightweight Supabase list query to verify connectivity; abort if either fails
  - In lifespan shutdown: call `get_neo4j_client().close()`
  - Create `FastAPI(lifespan=lifespan)` app instance
  - Apply `CORSMiddleware` with origins from `CORS_ALLOW_ORIGINS` env var (default `["*"]`)
  - Mount `Topology_Router` at `/topology` and `Incidents_Router` at `/incidents`
  - Implement `GET /health` endpoint returning `{"neo4j": {"healthy": bool}, "supabase": {"healthy": bool}}`
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.6, 6.7_

- [x] 13. Checkpoint — full application wired
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Write unit and example tests
  - Create `backend/tests/__init__.py` and `backend/tests/conftest.py`
  - `conftest.py`: fixtures for `monkeypatch` env vars, mocked Neo4j driver (`patch("neo4j.GraphDatabase.driver")`), mocked Supabase client, mocked Groq client, mocked `TypeSafeClient`
  - [ ] 14.1 Unit tests for `Neo4jClient`
    - `__init__` reads correct env vars (example with mocked driver)
    - `verify_connectivity()` returns `True` on success (mocked driver)
    - `verify_connectivity()` raises `ConnectionError` when driver raises (mocked driver)
    - `close()` delegates to `driver.close()` (mocked)
    - Async context manager `__aenter__`/`__aexit__` calls `close()` on exit
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6_
  - [ ] 14.2 Unit tests for FastAPI lifespan and health endpoint
    - Lifespan calls `load_dotenv`, `verify_connectivity`, and Supabase check in order (mocked)
    - `GET /health` returns correct JSON shape with `neo4j` and `supabase` keys
    - _Requirements: 5.2, 5.3, 5.4, 6.6_
  - [ ] 14.3 Unit tests for pipeline nodes
    - `jev_gate` stores all three fields in `jev_results` (mocked `TypeSafeClient`)
    - `llm_reason` stores LLM text in `llm_response` (mocked `groq.Groq`)
    - `GROQ_API_KEY` absent raises `RuntimeError`
    - `route_after_jev` returns `"emit_response"` for `(severity_score=0, escalation_noul=0.0)` and `"llm_reason"` for `(severity_score=2, escalation_noul=0.5)`
    - `emit_response` builds `final_response` with all required keys
    - _Requirements: 8.2, 8.3, 8.4, 9.3, 9.4, 10.1_
  - [ ] 14.4 Unit tests for HTTP endpoints
    - `POST /topology/ingest` returns HTTP 200 on valid payload
    - `POST /topology/ingest` returns HTTP 422 when required fields are missing
    - `GET /incidents/{id}` returns HTTP 404 for unknown IDs
    - `POST /incidents/analyze` returns HTTP 200 and `final_response` body (mocked pipeline)
    - _Requirements: 6.2, 6.3, 6.5, 10.3_

- [ ] 15. Write property-based tests
  - Create `backend/tests/test_properties.py`; configure `hypothesis` with `@settings(max_examples=100)`
  - [ ]* 15.1 Property 1 — Missing env vars always raise RuntimeError
    - **Property 1: Missing environment variables always raise RuntimeError**
    - Generate all non-empty subsets of `{NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD}` with at least one absent/empty; assert `RuntimeError` is raised before any driver construction
    - **Validates: Requirements 1.2**
  - [ ]* 15.2 Property 2 — `get_neo4j_client()` always returns the same singleton
    - **Property 2: get_neo4j_client() always returns the same singleton**
    - Draw a random positive integer N; call `get_neo4j_client()` N times in the same process; assert all returned objects are identical (`is`)
    - **Validates: Requirements 1.7**
  - [ ]* 15.3 Property 3 — Blast radius only contains active-edge descendants
    - **Property 3: Blast radius only contains active-edge descendants**
    - Generate a service graph with a mix of active (`valid_to IS NULL`) and expired edges; call `get_blast_radius()`; assert no returned node is reachable exclusively through expired edges
    - **Validates: Requirements 3.3**
  - [ ]* 15.4 Property 4 — Blast radius result set is unique
    - **Property 4: Blast radius result set is unique**
    - Generate a service graph with multiple paths converging on the same node; assert the list returned by `get_blast_radius()` contains no duplicate `id` values
    - **Validates: Requirements 3.4**
  - [ ]* 15.5 Property 5 — Service context only contains active-edge neighbors
    - **Property 5: Service context only contains active-edge neighbors**
    - Generate a `Service` node with mixed active/expired DEPENDS_ON edges; call `get_service_context()`; assert only active-edge neighbors appear
    - **Validates: Requirements 4.2**
  - [ ]* 15.6 Property 6 — Service context records always contain required fields
    - **Property 6: Service context records always contain required fields**
    - Generate any service with active DEPENDS_ON relationships; assert every dict in the returned list contains keys `name`, `type`, `protocol`
    - **Validates: Requirements 4.3**
  - [ ]* 15.7 Property 7 — Missing required env vars always abort startup
    - **Property 7: Missing required env vars always abort startup**
    - Generate subsets of the six required env vars with at least one absent; assert the lifespan startup aborts without yielding
    - **Validates: Requirements 5.5**
  - [ ]* 15.8 Property 8 — Valid topology ingest payload always returns HTTP 200
    - **Property 8: Valid topology ingest payload always returns HTTP 200**
    - Generate `TopologyIngestRequest` instances with non-empty `service_id`, `service_name`, `external_system`; assert `POST /topology/ingest` returns HTTP 200
    - **Validates: Requirements 6.2**
  - [ ]* 15.9 Property 9 — Incomplete topology payload always returns HTTP 422
    - **Property 9: Incomplete topology payload always returns HTTP 422**
    - Generate request bodies omitting one or more of `service_id`, `service_name`, `external_system`; assert `POST /topology/ingest` returns HTTP 422
    - **Validates: Requirements 6.3**
  - [ ]* 15.10 Property 10 — Routing decision is a pure function of severity_score and escalation_noul
    - **Property 10: Routing decision is a pure function of severity_score and escalation_noul**
    - Generate all `(severity_score: int[0..3], escalation_noul: float[0.0..1.0])` pairs including boundary values `(2, 0.5)`; assert `route_after_jev` returns exactly `"emit_response"` iff `severity_score < 2 AND escalation_noul < 0.5`, else `"llm_reason"`
    - **Validates: Requirements 8.3, 8.4**
  - [ ]* 15.11 Property 11 — LLM prompt always contains all required context fields
    - **Property 11: LLM prompt always contains all required context fields**
    - Generate `(alert, service_context, jev_results)` triples with non-empty alert and populated jev results; capture the prompt string passed to the mocked Groq client; assert it contains alert text, service context, `incident_category`, severity label, and `escalation_noul`
    - **Validates: Requirements 9.2**
  - [ ]* 15.12 Property 12 — final_response always contains all required keys
    - **Property 12: final_response always contains all required keys**
    - Generate pipeline state covering both the short-circuit path and the full LLM path; assert `final_response` always contains `incident_category`, `severity`, `needs_escalation`, `llm_reasoning`, `blast_radius`
    - **Validates: Requirements 10.1**
  - [ ]* 15.13 Property 13 — needs_escalation is true iff escalation_noul >= 0.5
    - **Property 13: needs_escalation is true iff escalation_noul >= 0.5**
    - Generate floats across `[0.0, 1.0]` including boundary `0.5`; assert `final_response["needs_escalation"]` equals `escalation_noul >= 0.5` exactly
    - **Validates: Requirements 10.1**

- [ ] 16. Final checkpoint — all layers integrated
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- `backend/engine/jev_check.py` and `backend/engine/__init__.py` must not be modified
- `backend/neo4j_client.py` (legacy) must not be deleted but must not be imported anywhere in new code
- All new Python files are created from scratch; never overwrite the existing engine files
- Property tests use `hypothesis`; add it to `requirements.txt` as `hypothesis==6.100.0` before running
- Run tests from the `backend/` directory: `python -m pytest tests/ -v`
- Each property test references its design document property number via the tag comment:
  `# Feature: aegisflow-backend-core, Property N: <text>`

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2", "3.1", "3.2"] },
    { "id": 2, "tasks": ["5"] },
    { "id": 3, "tasks": ["6", "7"] },
    { "id": 4, "tasks": ["8"] },
    { "id": 5, "tasks": ["10", "11"] },
    { "id": 6, "tasks": ["12"] },
    { "id": 7, "tasks": ["14.1", "14.2", "14.3", "14.4"] },
    { "id": 8, "tasks": ["15.1", "15.2", "15.3", "15.4", "15.5", "15.6", "15.7", "15.8", "15.9", "15.10", "15.11", "15.12", "15.13"] }
  ]
}
```
