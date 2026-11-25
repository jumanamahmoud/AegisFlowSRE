import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from tests.fakes import FakeSupabase


@pytest.fixture(autouse=True)
def _supabase_url_default(monkeypatch):
    """The token verifier needs a project URL; tests must not depend on .env."""
    import os

    if not (os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")):
        monkeypatch.setenv("SUPABASE_URL", "https://test-project.supabase.co")


@pytest.fixture
def neo4j_env(monkeypatch):
    """Set all three Neo4j env vars, and clear the optional CA bundle so a
    value loaded from the developer's real .env cannot change driver args."""
    monkeypatch.setenv("NEO4J_URI", "neo4j://localhost:7687")
    monkeypatch.setenv("NEO4J_USER", "neo4j")
    monkeypatch.setenv("NEO4J_PASSWORD", "testpassword")
    monkeypatch.delenv("NEO4J_CA_BUNDLE", raising=False)


@pytest.fixture
def mock_neo4j_driver():
    """Mock neo4j.GraphDatabase.driver — returns a MagicMock driver."""
    with patch("neo4j.GraphDatabase.driver") as mock_driver:
        yield mock_driver


@pytest.fixture
def fake_supabase():
    """Fresh in-memory Supabase per test."""
    return FakeSupabase()


@pytest.fixture
def store(fake_supabase):
    from database.incident_store import IncidentStore

    return IncidentStore(fake_supabase)


def _now():
    return datetime.now(timezone.utc).isoformat()


def make_pipeline_state(
    *,
    category="database",
    severity_score=3,
    noul=0.9,
    llm_reasoning="Root cause: connection pool exhausted on payment-db.",
    source="llm",
    model="openai/gpt-oss-120b",
    blast_radius=None,
    category_confidence=0.9,
    severity_confidence=0.85,
    review_reasons=None,
):
    """Build a realistic final pipeline state (what execute_pipeline returns).

    Call it *inside* a fake pipeline so trace timestamps fall after
    ``analysis.started``, as they do in a real run.
    """
    labels = {0: "Low", 1: "Moderate", 2: "High", 3: "Critical"}
    meta = {"analysis_source": source, "model_name": model if source == "llm" else None}
    if source == "llm":
        meta.update(prompt_tokens=412, completion_tokens=230, total_tokens=642, llm_latency_ms=1840)
    jev = {"incident_category": category, "severity_score": severity_score, "escalation_noul": noul,
           "category_confidence": category_confidence, "severity_confidence": severity_confidence,
           "needs_review": bool(review_reasons), "review_reasons": list(review_reasons or [])}
    ai_event = {"llm": "ai.invoked", "fallback": "ai.fallback", "skipped": "ai.skipped"}[source]
    return {
        "alert": "alert",
        "service_id": "payment-service",
        "service_context": [{"name": "payment-db", "type": "database", "protocol": "TCP"}],
        "jev_results": jev,
        "llm_response": llm_reasoning or "",
        "llm_meta": meta,
        "trace": [
            {"event_type": "alert.sanitized", "payload": {"redacted_total": 0, "suspected_injection": False},
             "occurred_at": _now()},
            {"event_type": "graph.enriched", "payload": {"dependency_count": 1},
             "occurred_at": _now()},
            {"event_type": "triage.completed", "payload": jev,
             "occurred_at": _now()},
            {"event_type": ai_event, "payload": dict(meta),
             "occurred_at": _now()},
        ],
        "final_response": {
            "incident_category": category,
            "severity": labels[severity_score],
            "needs_escalation": noul >= 0.5,
            "llm_reasoning": llm_reasoning,
            "blast_radius": blast_radius if blast_radius is not None else [
                {"id": "checkout-service", "name": "Checkout Service", "type": "service"}
            ],
        },
    }
