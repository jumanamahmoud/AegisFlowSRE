"""
backend/tests/test_triage_policy.py
====================================
The triage rule (FR-6, FR-14) and calibration scoring (Phase 4).
"""

from __future__ import annotations

import pytest

from engine.calibration import evaluate, render_report, sweep
from engine.triage_policy import (
    REASON_LOW_CATEGORY,
    REASON_LOW_SEVERITY,
    REASON_UNKNOWN,
    TriagePolicy,
)

POLICY = TriagePolicy()


def jev(category="database", sev=1, noul=0.2, cat_conf=0.9, sev_conf=0.9):
    return {"incident_category": category, "severity_score": sev, "escalation_noul": noul,
            "category_confidence": cat_conf, "severity_confidence": sev_conf}


class TestDecision:
    def test_low_risk_and_confident_skips_ai(self):
        d = POLICY.decide(jev(sev=1, noul=0.2))
        assert not d.run_ai and not d.needs_review and d.reasons == []
        assert "severity 1 < 2" in d.explanation

    @pytest.mark.parametrize("sev,noul", [(2, 0.0), (3, 0.0), (0, 0.5), (1, 0.99)])
    def test_serious_runs_ai(self, sev, noul):
        d = POLICY.decide(jev(sev=sev, noul=noul))
        assert d.run_ai and not d.needs_review

    def test_unknown_category_goes_to_review_and_is_not_silently_skipped(self):
        d = POLICY.decide(jev(category="unknown", sev=0, noul=0.1))
        assert d.needs_review and d.run_ai  # FR-14: never silently skipped
        assert d.reasons == [REASON_UNKNOWN]
        assert "uncertain" in d.explanation

    def test_unknown_is_case_insensitive(self):
        assert POLICY.decide(jev(category="Unknown")).needs_review

    @pytest.mark.parametrize("cat_conf,sev_conf,reasons", [
        (0.59, 0.9, [REASON_LOW_CATEGORY]),
        (0.9, 0.3, [REASON_LOW_SEVERITY]),
        (0.1, 0.1, [REASON_LOW_CATEGORY, REASON_LOW_SEVERITY]),
        (0.6, 0.6, []),  # threshold itself is confident enough
    ])
    def test_low_confidence(self, cat_conf, sev_conf, reasons):
        d = POLICY.decide(jev(cat_conf=cat_conf, sev_conf=sev_conf))
        assert d.reasons == reasons and d.needs_review == bool(reasons)

    @pytest.mark.parametrize("value", [None, "high", True])
    def test_missing_or_odd_confidence_is_ignored(self, value):
        assert not POLICY.decide(jev(cat_conf=value, sev_conf=value)).needs_review

    def test_old_results_without_confidence_or_category(self):
        assert not POLICY.decide({"severity_score": 0, "escalation_noul": 0.0}).run_ai

    def test_serious_and_uncertain(self):
        d = POLICY.decide(jev(sev=3, cat_conf=0.2))
        assert d.run_ai and d.needs_review and "severity 3 >= 2" in d.explanation

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_SEVERITY_THRESHOLD", "1")
        monkeypatch.setenv("AEGIS_ESCALATION_THRESHOLD", "0.7")
        monkeypatch.setenv("AEGIS_MIN_CATEGORY_CONFIDENCE", "0.3")
        monkeypatch.setenv("AEGIS_MIN_SEVERITY_CONFIDENCE", "0.4")
        assert TriagePolicy.from_env() == TriagePolicy(1, 0.7, 0.3, 0.4)
        assert TriagePolicy.from_env().decide(jev(sev=1, noul=0.0)).run_ai

    def test_defaults_match_spec(self):
        # Spec FR-6: AI runs when severity >= 2 or escalation likelihood >= 50%.
        p = TriagePolicy()
        assert (p.severity_threshold, p.escalation_threshold) == (2, 0.5)


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def sample(id_, exp_cat, exp_sev, cat, sev, noul=0.1, cat_conf=0.9, sev_conf=0.9):
    return {"id": id_, "expected_category": exp_cat, "expected_severity": exp_sev,
            **jev(cat, sev, noul, cat_conf, sev_conf)}


RESULTS = [
    sample("a", "database", 3, "database", 3, 0.9),        # correct, serious
    sample("b", "application", 2, "application", 1, 0.3),  # serious but under-scored -> missed by default
    sample("c", "infrastructure", 0, "infrastructure", 0),  # fine
    sample("d", "unknown", 1, "application", 1, cat_conf=0.45),  # unknown, low confidence
]


class TestCalibration:
    def test_evaluate_current_policy(self):
        m = evaluate(RESULTS, POLICY)
        assert m.total == 4
        assert m.category_correct == 3 and m.severity_exact == 3 and m.severity_within_one == 4
        assert m.missed_serious == ["b"]
        assert m.unknown_not_reviewed == []  # d flagged by low confidence
        assert m.reviews == 1 and m.ai_runs == 2

    def test_unknown_not_reviewed_counted(self):
        m = evaluate(RESULTS, TriagePolicy(min_category_confidence=0.0))
        assert m.unknown_not_reviewed == ["d"]

    def test_unnecessary_ai(self):
        m = evaluate([sample("x", "application", 0, "application", 0, noul=0.6)], POLICY)
        assert m.unnecessary_ai == ["x"]

    def test_sweep_puts_zero_missed_first(self):
        ranked = sweep(RESULTS, POLICY)
        best_policy, best = ranked[0]
        assert best.missed_serious == [] and best.unknown_not_reviewed == []
        # 'b' has severity 1 and escalation 0.3: catching it needs a lower bar
        assert best_policy.severity_threshold == 1 or best_policy.escalation_threshold <= 0.3
        keys = [(len(m.missed_serious), len(m.unknown_not_reviewed), m.cost) for _, m in ranked]
        assert keys == sorted(keys)

    def test_ties_prefer_current_setting(self):
        clean = [sample("a", "database", 3, "database", 3, 0.9), sample("c", "infrastructure", 0, "infrastructure", 0)]
        assert sweep(clean, POLICY)[0][0] == POLICY

    def test_report_renders(self):
        ranked = sweep(RESULTS, POLICY)
        text = render_report(RESULTS, POLICY, ranked, model="jev-test", run_at="2026-11-25 10:00 UTC")
        assert "# Triage calibration report" in text
        assert "Serious alerts that skipped AI" in text
        assert "AEGIS_SEVERITY_THRESHOLD=" in text  # recommendation differs from current
        assert "| b |" in text and "⚠ missed" in text
        assert "0.45" in text  # confidences shown

    def test_report_when_current_is_best(self):
        clean = [sample("a", "database", 3, "database", 3, 0.9)]
        text = render_report(clean, POLICY, sweep(clean, POLICY), model="m", run_at="t")
        assert "(same as current)" in text and "AEGIS_SEVERITY_THRESHOLD=" not in text


def test_calibration_samples_are_well_formed():
    import json
    from pathlib import Path

    data = json.loads((Path(__file__).resolve().parent.parent / "samples" / "calibration" / "alerts.json")
                      .read_text(encoding="utf-8"))
    alerts = data["alerts"]
    assert len(alerts) == 20
    assert len({a["id"] for a in alerts}) == 20
    cats = {"infrastructure", "application", "database", "dependency", "security", "unknown"}
    assert {a["expected_category"] for a in alerts} == cats  # every category represented
    assert {a["expected_severity"] for a in alerts} == {0, 1, 2, 3}
    assert all(a["alert"] and a["service_id"] for a in alerts)
