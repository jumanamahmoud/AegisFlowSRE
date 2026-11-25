"""
backend/tests/test_pipeline.py
================================
Unit tests for the LangGraph pipeline nodes and routing logic.

Tests cover:
  - jev_gate           : stores all three result fields with correct types
  - route_after_jev    : correct short-circuit and LLM routing, boundary values
  - llm_reason         : stores LLM-generated text in state
  - emit_response      : assembles all required keys; needs_escalation bool;
                         llm_reasoning is None on short-circuit path

NOTE: langgraph_pipeline.py validates GROQ_API_KEY and constructs groq.Groq
at module import time.  To prevent that from touching the real Groq SDK we
patch ``groq.Groq`` before the module is imported, and ensure the env var is
set via monkeypatch.  Because pytest imports modules once per session, the
relevant fixtures use ``importlib.reload`` to get a fresh module state.

engine/jev_check.py calls sys.exit() at module level if typesafe_sdk is not
installed.  We stub the entire typesafe_sdk package into sys.modules before
the first import of jev_check so that the ImportError branch is never reached.

Requirements: 8.2, 8.3, 8.4, 9.3, 9.4, 10.1
"""

from __future__ import annotations

import importlib
import sys
import os
from unittest.mock import MagicMock, patch, PropertyMock


# ---------------------------------------------------------------------------
# Stub typesafe_sdk so jev_check.py can be imported without the real package.
# This must happen before any test that touches engine.jev_check is collected.
# ---------------------------------------------------------------------------
def _stub_typesafe_sdk() -> None:
    """Inject a minimal MagicMock for typesafe_sdk into sys.modules."""
    if "typesafe_sdk" in sys.modules:
        return
    mock_sdk = MagicMock()
    # Provide the names imported by jev_check at the top level so that
    # ``from typesafe_sdk import Choice, ...`` succeeds.
    mock_sdk.Choice = MagicMock
    mock_sdk.Score = MagicMock
    mock_sdk.Noul = MagicMock
    mock_sdk.TypeSafeClient = MagicMock
    mock_sdk.TypeSafeAuthenticationError = Exception
    mock_sdk.TypeSafeError = Exception
    sys.modules["typesafe_sdk"] = mock_sdk


_stub_typesafe_sdk()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_pipeline():
    """Force a fresh import of langgraph_pipeline so module-level code reruns."""
    mod_name = "engine.langgraph_pipeline"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    return importlib.import_module(mod_name)


def _make_jev_response(category="application", severity_score=2.1, noul=0.8):
    """Build a minimal mock Jev response object."""
    response = MagicMock()
    response.choices = {
        "incident_category": MagicMock(choice=category)
    }
    response.scores = {
        "severity": MagicMock(score=severity_score)
    }
    response.nouls = {
        "needs_escalation": MagicMock(noul=noul)
    }
    return response


def _base_state(**overrides) -> dict:
    """Return a minimal valid pipeline state dict."""
    state = {
        "alert": "Payment service returning HTTP 500 for 12 minutes.",
        "service_id": "payment-service",
        "service_context": [
            {"name": "postgres", "type": "ExternalSystem", "protocol": "TCP"}
        ],
        "jev_results": {
            "incident_category": "application",
            "severity_score": 2,
            "escalation_noul": 0.8,
        },
        "llm_response": "some analysis",
        "final_response": {},
    }
    state.update(overrides)
    return state


# ---------------------------------------------------------------------------
# jev_gate tests
# ---------------------------------------------------------------------------

class TestJevGate:
    """Tests for the jev_gate pipeline node (Requirements 8.2)."""

    def _load_modules(self, monkeypatch):
        """Return (pipeline_module, jev_check_module) with both safely loaded."""
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        # Ensure jev_check is loaded with the stub in place, then reload pipeline
        if "engine.jev_check" in sys.modules:
            del sys.modules["engine.jev_check"]
        import engine.jev_check as jev_check_mod  # noqa: F401 — load with stub
        with patch("groq.Groq", return_value=MagicMock()):
            pipeline = _reload_pipeline()
        return pipeline, jev_check_mod

    def test_jev_gate_stores_all_three_fields(self, monkeypatch):
        """jev_gate must write incident_category (str), severity_score (int),
        and escalation_noul (float) into jev_results."""
        pipeline, jev_mod = self._load_modules(monkeypatch)

        mock_client = MagicMock()
        mock_client.system_one.return_value = _make_jev_response(
            category="application",
            severity_score=2.1,
            noul=0.8,
        )
        mock_client.close = MagicMock()

        # Patch get_jev_client on the already-imported module object directly
        original = jev_mod.get_jev_client
        jev_mod.get_jev_client = lambda: mock_client
        try:
            result = pipeline.jev_gate(_base_state())
        finally:
            jev_mod.get_jev_client = original

        jev = result["jev_results"]
        assert "incident_category" in jev
        assert "severity_score" in jev
        assert "escalation_noul" in jev

        assert isinstance(jev["incident_category"], str)
        assert isinstance(jev["severity_score"], int)
        assert isinstance(jev["escalation_noul"], float)

        assert jev["incident_category"] == "application"
        assert jev["severity_score"] == 2        # round(2.1) == 2
        assert jev["escalation_noul"] == 0.8

    def test_jev_gate_propagates_api_exception(self, monkeypatch):
        """jev_gate must not swallow Jev API exceptions (Requirement 8.5)."""
        import pytest
        pipeline, jev_mod = self._load_modules(monkeypatch)

        mock_client = MagicMock()
        mock_client.system_one.side_effect = RuntimeError("Jev API down")
        mock_client.close = MagicMock()

        original = jev_mod.get_jev_client
        jev_mod.get_jev_client = lambda: mock_client
        try:
            with pytest.raises(RuntimeError, match="Jev API down"):
                pipeline.jev_gate(_base_state())
        finally:
            jev_mod.get_jev_client = original


# ---------------------------------------------------------------------------
# route_after_jev tests
# ---------------------------------------------------------------------------

class TestRouteAfterJev:
    """Tests for route_after_jev routing logic (Requirements 8.3, 8.4)."""

    def _get_route_fn(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        with patch("groq.Groq", return_value=MagicMock()):
            pipeline = _reload_pipeline()
        return pipeline.route_after_jev

    def test_route_after_jev_emits_short_circuit(self, monkeypatch):
        """severity_score=1 and escalation_noul=0.3 → short-circuit to emit_response."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 1, "escalation_noul": 0.3}})
        assert result == "emit_response"

    def test_route_after_jev_emits_llm_reason_on_high_severity(self, monkeypatch):
        """severity_score=2 and escalation_noul=0.3 → route to llm_reason."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 2, "escalation_noul": 0.3}})
        assert result == "llm_reason"

    def test_route_after_jev_boundary_severity_2(self, monkeypatch):
        """Boundary: severity_score==2 (High) with low noul must still route to llm_reason."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 2, "escalation_noul": 0.0}})
        assert result == "llm_reason"

    def test_route_after_jev_boundary_noul_0_5(self, monkeypatch):
        """Boundary: escalation_noul==0.5 must trigger LLM even with low severity_score."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 0, "escalation_noul": 0.5}})
        assert result == "llm_reason"

    def test_route_after_jev_zero_zero_emits_short_circuit(self, monkeypatch):
        """severity_score=0 and escalation_noul=0.0 → pure short-circuit case."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 0, "escalation_noul": 0.0}})
        assert result == "emit_response"

    def test_route_after_jev_critical_severity_emits_llm(self, monkeypatch):
        """severity_score=3 (Critical) always routes to llm_reason."""
        route = self._get_route_fn(monkeypatch)
        result = route({"jev_results": {"severity_score": 3, "escalation_noul": 0.0}})
        assert result == "llm_reason"


# ---------------------------------------------------------------------------
# llm_reason tests
# ---------------------------------------------------------------------------

class TestLlmReason:
    """Tests for the llm_reason pipeline node (Requirements 9.3, 9.4)."""

    def test_llm_reason_stores_llm_text(self, monkeypatch):
        """llm_reason must store the LLM-generated string in llm_response."""
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        mock_groq_instance = MagicMock()
        mock_completion = MagicMock()
        mock_completion.choices = [MagicMock()]
        mock_completion.choices[0].message.content = "Analysis result"
        mock_groq_instance.chat.completions.create.return_value = mock_completion

        with patch("groq.Groq", return_value=mock_groq_instance):
            pipeline = _reload_pipeline()

        # Replace the module-level client with our mock
        pipeline._groq_client = mock_groq_instance

        state = _base_state()
        result = pipeline.llm_reason(state)

        assert result["llm_response"] == "Analysis result"

    def test_llm_reason_uses_all_prompt_components(self, monkeypatch):
        """The prompt passed to Groq must contain alert, context, category,
        severity label, and escalation_noul (Requirement 9.2)."""
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        mock_groq_instance = MagicMock()
        mock_completion = MagicMock()
        mock_completion.choices = [MagicMock()]
        mock_completion.choices[0].message.content = "Result"
        mock_groq_instance.chat.completions.create.return_value = mock_completion

        with patch("groq.Groq", return_value=mock_groq_instance):
            pipeline = _reload_pipeline()

        pipeline._groq_client = mock_groq_instance

        state = _base_state(
            alert="DB timeout in production",
            service_context=[{"name": "redis", "type": "ExternalSystem", "protocol": "TCP"}],
            jev_results={
                "incident_category": "database",
                "severity_score": 2,
                "escalation_noul": 0.75,
            },
        )
        pipeline.llm_reason(state)

        call_args = mock_groq_instance.chat.completions.create.call_args
        messages = call_args[1]["messages"]
        assert messages[0]["role"] == "system"
        prompt_text = messages[1]["content"]

        assert "DB timeout in production" in prompt_text
        assert "database" in prompt_text
        assert "High" in prompt_text          # severity label for score 2
        assert "0.7500" in prompt_text        # escalation_noul formatted to 4 dp
        assert "redis" in prompt_text


# ---------------------------------------------------------------------------
# emit_response tests
# ---------------------------------------------------------------------------

class TestEmitResponse:
    """Tests for the emit_response pipeline node (Requirements 10.1)."""

    def _get_emit_fn(self, monkeypatch, blast_radius_return=None):
        """Return emit_response with the Neo4j client patched."""
        if blast_radius_return is None:
            blast_radius_return = [
                {"id": "db-1", "name": "postgres", "type": "ExternalSystem"}
            ]
        monkeypatch.setenv("GROQ_API_KEY", "test-key")

        with patch("groq.Groq", return_value=MagicMock()):
            pipeline = _reload_pipeline()

        mock_neo4j = MagicMock()
        mock_neo4j.get_blast_radius.return_value = blast_radius_return

        return pipeline, mock_neo4j

    def test_emit_response_all_required_keys(self, monkeypatch):
        """final_response must contain all five required keys."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(_base_state())

        fr = result["final_response"]
        assert "incident_category" in fr
        assert "severity" in fr
        assert "needs_escalation" in fr
        assert "llm_reasoning" in fr
        assert "blast_radius" in fr

    def test_emit_response_needs_escalation_false_when_noul_below_threshold(
        self, monkeypatch
    ):
        """needs_escalation must be False when escalation_noul=0.3 (< 0.5)."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        state = _base_state(
            jev_results={
                "incident_category": "infrastructure",
                "severity_score": 1,
                "escalation_noul": 0.3,
            }
        )
        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(state)

        assert result["final_response"]["needs_escalation"] is False

    def test_emit_response_needs_escalation_true_at_threshold(self, monkeypatch):
        """needs_escalation must be True when escalation_noul == 0.5 (boundary)."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        state = _base_state(
            jev_results={
                "incident_category": "infrastructure",
                "severity_score": 1,
                "escalation_noul": 0.5,
            }
        )
        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(state)

        assert result["final_response"]["needs_escalation"] is True

    def test_emit_response_llm_reasoning_none_on_short_circuit(self, monkeypatch):
        """llm_reasoning must be None when llm_response is empty (short-circuit path)."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        state = _base_state(llm_response="")

        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(state)

        assert result["final_response"]["llm_reasoning"] is None

    def test_emit_response_llm_reasoning_populated_on_full_path(self, monkeypatch):
        """llm_reasoning must be the actual LLM text when llm_response is non-empty."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        state = _base_state(llm_response="Root cause: memory leak in the payment service.")

        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(state)

        assert (
            result["final_response"]["llm_reasoning"]
            == "Root cause: memory leak in the payment service."
        )

    def test_emit_response_blast_radius_included(self, monkeypatch):
        """blast_radius in final_response must match what get_blast_radius returns."""
        expected = [
            {"id": "db-1", "name": "postgres", "type": "ExternalSystem"},
            {"id": "cache-1", "name": "redis", "type": "ExternalSystem"},
        ]
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch, blast_radius_return=expected)

        with patch("database.neo4j_client.get_neo4j_client", return_value=mock_neo4j):
            result = pipeline.emit_response(_base_state())

        assert result["final_response"]["blast_radius"] == expected

    def test_emit_response_severity_label_mapping(self, monkeypatch):
        """severity string label must correspond to the integer severity_score."""
        pipeline, mock_neo4j = self._get_emit_fn(monkeypatch)

        for score, expected_label in [(0, "Low"), (1, "Moderate"), (2, "High"), (3, "Critical")]:
            state = _base_state(
                jev_results={
                    "incident_category": "application",
                    "severity_score": score,
                    "escalation_noul": 0.1,
                }
            )
            with patch(
                "database.neo4j_client.get_neo4j_client", return_value=mock_neo4j
            ):
                result = pipeline.emit_response(state)

            assert result["final_response"]["severity"] == expected_label, (
                f"Expected '{expected_label}' for score {score}, "
                f"got '{result['final_response']['severity']}'"
            )


# ---------------------------------------------------------------------------
# Week 1: analysis metadata + step trace (feeds persistence and FR-17 timeline)
# ---------------------------------------------------------------------------


def _groq_completion(content="Analysis result", usage=(100, 50, 150)):
    completion = MagicMock()
    completion.choices = [MagicMock()]
    completion.choices[0].message.content = content
    completion.choices[0].message.reasoning = None
    completion.usage = MagicMock(
        prompt_tokens=usage[0], completion_tokens=usage[1], total_tokens=usage[2]
    )
    return completion


def _pipeline_with_groq(monkeypatch, groq_instance, models="model-a,model-b"):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setenv("GROQ_MODELS", models)
    monkeypatch.setenv("AEGIS_VERBOSE", "0")
    with patch("groq.Groq", return_value=groq_instance):
        pipeline = _reload_pipeline()
    pipeline._groq_client = groq_instance
    return pipeline


class TestAnalysisMetadata:
    def test_call_llm_returns_text_model_and_usage(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = _groq_completion(usage=(10, 20, 30))
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        text, model, reasoning, meta = pipeline._call_llm("prompt")

        assert text == "Analysis result"
        assert model == "model-a"
        assert meta["prompt_tokens"] == 10
        assert meta["completion_tokens"] == 20
        assert meta["total_tokens"] == 30
        assert isinstance(meta["llm_latency_ms"], int)

    def test_call_llm_all_models_fail_returns_four_nones(self, monkeypatch):
        """Regression: the all-fail path used to return 2 values while callers unpack 4."""
        groq = MagicMock()
        groq.chat.completions.create.return_value = _groq_completion(content="")
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        assert pipeline._call_llm("prompt") == (None, None, None, {})
        assert groq.chat.completions.create.call_count == 2  # both models tried

    def test_llm_reason_records_model_and_tokens(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = _groq_completion()
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        result = pipeline.llm_reason(_base_state(trace=[]))

        meta = result["llm_meta"]
        assert meta["analysis_source"] == "llm"
        assert meta["model_name"] == "model-a"
        assert meta["total_tokens"] == 150
        assert [e["event_type"] for e in result["trace"]] == ["ai.invoked"]
        assert result["trace"][0]["payload"]["model_name"] == "model-a"

    def test_llm_reason_falls_back_when_all_models_fail(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = _groq_completion(content=None)
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        result = pipeline.llm_reason(_base_state(trace=[]))

        assert result["llm_response"].startswith("[Automated summary: LLM unavailable]")
        assert result["llm_meta"] == {"analysis_source": "fallback", "model_name": None}
        assert result["trace"][0]["event_type"] == "ai.fallback"
        assert result["trace"][0]["payload"]["models_tried"] == ["model-a", "model-b"]

    def test_llm_reason_handles_missing_usage(self, monkeypatch):
        groq = MagicMock()
        completion = _groq_completion()
        completion.usage = None
        groq.chat.completions.create.return_value = completion
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        meta = pipeline.llm_reason(_base_state(trace=[]))["llm_meta"]
        assert meta["prompt_tokens"] is None and meta["total_tokens"] is None


class TestPipelineTrace:
    def _load(self, monkeypatch):
        return _pipeline_with_groq(monkeypatch, MagicMock())

    def test_trace_appends_without_mutating_state(self, monkeypatch):
        pipeline = self._load(monkeypatch)
        state = {"trace": [{"event_type": "x", "payload": {}, "occurred_at": "t"}]}
        new = pipeline._trace(state, "triage.completed", {"a": 1})
        assert len(state["trace"]) == 1
        assert [e["event_type"] for e in new] == ["x", "triage.completed"]
        assert new[-1]["occurred_at"]

    def test_enrich_with_graph_traces_dependency_count(self, monkeypatch):
        pipeline = self._load(monkeypatch)
        neo4j = MagicMock()
        neo4j.get_service_context.return_value = [{"name": "db"}, {"name": "cache"}]
        with patch("database.neo4j_client.get_neo4j_client", return_value=neo4j):
            result = pipeline.enrich_with_graph(_base_state(trace=[]))
        assert result["trace"][0]["event_type"] == "graph.enriched"
        assert result["trace"][0]["payload"] == {"dependency_count": 2}

    def test_jev_gate_traces_triage_scores(self, monkeypatch):
        pipeline = self._load(monkeypatch)
        import engine.jev_check as jev_mod

        mock_client = MagicMock()
        mock_client.system_one.return_value = _make_jev_response("network", 1.2, 0.3)
        with patch.object(jev_mod, "get_jev_client", return_value=mock_client):
            result = pipeline.jev_gate(_base_state(trace=[]))
        event = result["trace"][0]
        assert event["event_type"] == "triage.completed"
        assert event["payload"] == {
            "incident_category": "network", "severity_score": 1, "escalation_noul": 0.3,
            "category_confidence": None, "severity_confidence": None,  # mock reports none
            "decision": "severity 1 < 2 and escalation 0.30 < 0.5",
        }

    def test_emit_response_marks_short_circuit_as_skipped(self, monkeypatch):
        pipeline = self._load(monkeypatch)
        neo4j = MagicMock()
        neo4j.get_blast_radius.return_value = []
        with patch("database.neo4j_client.get_neo4j_client", return_value=neo4j):
            result = pipeline.emit_response(_base_state(llm_response="", trace=[]))
        assert result["llm_meta"]["analysis_source"] == "skipped"
        assert result["trace"][-1]["event_type"] == "ai.skipped"

    def test_emit_response_keeps_llm_meta_on_full_path(self, monkeypatch):
        pipeline = self._load(monkeypatch)
        neo4j = MagicMock()
        neo4j.get_blast_radius.return_value = []
        with patch("database.neo4j_client.get_neo4j_client", return_value=neo4j):
            result = pipeline.emit_response(_base_state(llm_response="text", trace=[]))
        assert "llm_meta" not in result and "trace" not in result


class TestExecutePipeline:
    """Full compiled graph with external services mocked."""

    def _run(self, monkeypatch, severity, noul, groq_content="Root cause: X"):
        groq = MagicMock()
        groq.chat.completions.create.return_value = _groq_completion(content=groq_content)
        pipeline = _pipeline_with_groq(monkeypatch, groq)
        import engine.jev_check as jev_mod

        jev_client = MagicMock()
        jev_client.system_one.return_value = _make_jev_response("database", severity, noul)
        neo4j = MagicMock()
        neo4j.get_service_context.return_value = [{"name": "payment-db", "type": "db", "protocol": "TCP"}]
        neo4j.get_blast_radius.return_value = [{"id": "checkout", "name": "Checkout", "type": "service"}]
        with (
            patch.object(jev_mod, "get_jev_client", return_value=jev_client),
            patch("database.neo4j_client.get_neo4j_client", return_value=neo4j),
        ):
            return pipeline, pipeline.execute_pipeline("alert text", "payment-service"), groq

    def test_full_llm_path_state(self, monkeypatch):
        _, state, groq = self._run(monkeypatch, severity=3.0, noul=0.9)
        assert [e["event_type"] for e in state["trace"]] == [
            "alert.sanitized", "graph.enriched", "triage.completed", "ai.invoked",
        ]
        assert state["llm_meta"]["analysis_source"] == "llm"
        assert state["final_response"]["llm_reasoning"] == "Root cause: X"
        assert state["final_response"]["severity"] == "Critical"
        groq.chat.completions.create.assert_called_once()

    def test_short_circuit_path_state(self, monkeypatch):
        _, state, groq = self._run(monkeypatch, severity=0.2, noul=0.1)
        assert [e["event_type"] for e in state["trace"]] == [
            "alert.sanitized", "graph.enriched", "triage.completed", "ai.skipped",
        ]
        assert state["llm_meta"]["analysis_source"] == "skipped"
        assert state["final_response"]["llm_reasoning"] is None
        groq.chat.completions.create.assert_not_called()

    def test_run_pipeline_still_returns_final_response_only(self, monkeypatch):
        pipeline, state, _ = self._run(monkeypatch, severity=0.0, noul=0.0)
        with patch.object(pipeline, "execute_pipeline", return_value=state):
            assert pipeline.run_pipeline("a", "s") == state["final_response"]


class TestOutputLimit:
    """Answers that hit max_tokens must be flagged, not saved silently cut off."""

    def _completion(self, finish_reason):
        completion = _groq_completion(content="Root cause: pool exhausted. Steps: 1) restart")
        completion.choices[0].finish_reason = finish_reason
        return completion

    def test_max_tokens_defaults_to_4096(self, monkeypatch):
        monkeypatch.delenv("GROQ_MAX_TOKENS", raising=False)
        groq = MagicMock()
        groq.chat.completions.create.return_value = self._completion("stop")
        pipeline = _pipeline_with_groq(monkeypatch, groq)
        pipeline._call_llm("prompt")
        assert groq.chat.completions.create.call_args.kwargs["max_tokens"] == 4096

    def test_max_tokens_configurable(self, monkeypatch):
        monkeypatch.setenv("GROQ_MAX_TOKENS", "6000")
        groq = MagicMock()
        groq.chat.completions.create.return_value = self._completion("stop")
        pipeline = _pipeline_with_groq(monkeypatch, groq)
        pipeline._call_llm("prompt")
        assert groq.chat.completions.create.call_args.kwargs["max_tokens"] == 6000

    def test_complete_answer_not_flagged(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = self._completion("stop")
        pipeline = _pipeline_with_groq(monkeypatch, groq)
        text, _, _, meta = pipeline._call_llm("prompt")
        assert meta["truncated"] is False
        assert "cut off" not in text

    def test_truncated_answer_flagged_and_annotated(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = self._completion("length")
        pipeline = _pipeline_with_groq(monkeypatch, groq)

        result = pipeline.llm_reason(_base_state(trace=[]))

        assert result["llm_meta"]["truncated"] is True
        assert result["llm_response"].startswith("Root cause: pool exhausted.")
        assert result["llm_response"].endswith(pipeline._TRUNCATION_NOTICE)
        assert result["trace"][0]["payload"]["truncated"] is True  # visible on the timeline

    def test_prompt_asks_for_bounded_answer(self, monkeypatch):
        groq = MagicMock()
        groq.chat.completions.create.return_value = self._completion("stop")
        pipeline = _pipeline_with_groq(monkeypatch, groq)
        pipeline.llm_reason(_base_state(trace=[]))
        prompt = groq.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        assert "under 350 words" in prompt
