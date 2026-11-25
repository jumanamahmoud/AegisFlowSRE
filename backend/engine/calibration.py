"""
backend/engine/calibration.py
==============================
Measure how well the triage rule (engine/triage_policy.py) works on labelled
sample alerts, and search for better thresholds (Phase 4: "calibrate the
triage thresholds on 20 sample alerts").

Pure functions over already-collected Jev results, so the scoring is tested
without calling Jev; scripts/calibrate_triage.py collects the results and
writes the report.

What "better" means, in priority order:
1. **No missed serious alerts**: an alert labelled High or Critical must
   never skip the AI analysis. This is the costly mistake (spec, Section 13:
   "serious incident skipped").
2. **Unknown alerts reach a human**: an alert labelled "unknown" must be
   flagged for review (FR-14).
3. **Little wasted effort**: few AI runs on low-risk alerts and few reviews.
4. Ties go to the setting closest to the current one (fewer surprises).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import product

from engine.triage_policy import TriagePolicy

SEVERITY_NAMES = {0: "Low", 1: "Moderate", 2: "High", 3: "Critical"}

DEFAULT_GRID = {
    "severity_threshold": [1, 2, 3],
    "escalation_threshold": [0.3, 0.4, 0.5, 0.6, 0.7],
    "min_category_confidence": [0.0, 0.4, 0.5, 0.6, 0.7, 0.8],
    "min_severity_confidence": [0.0, 0.4, 0.5, 0.6, 0.7, 0.8],
}


@dataclass
class Metrics:
    total: int
    category_correct: int
    severity_exact: int
    severity_within_one: int
    ai_runs: int
    reviews: int
    missed_serious: list[str]
    unnecessary_ai: list[str]
    unknown_not_reviewed: list[str]

    @property
    def cost(self) -> int:
        return len(self.unnecessary_ai) + self.reviews

    def as_dict(self) -> dict:
        return {**asdict(self), "cost": self.cost}


def evaluate(results: list[dict], policy: TriagePolicy) -> Metrics:
    """``results``: one dict per sample with id, expected_category,
    expected_severity and Jev's incident_category, severity_score,
    escalation_noul, category_confidence, severity_confidence."""
    m = Metrics(len(results), 0, 0, 0, 0, 0, [], [], [])
    for r in results:
        decision = policy.decide(r)
        serious = r["expected_severity"] >= 2
        m.category_correct += r["incident_category"] == r["expected_category"]
        m.severity_exact += r["severity_score"] == r["expected_severity"]
        m.severity_within_one += abs(r["severity_score"] - r["expected_severity"]) <= 1
        m.ai_runs += decision.run_ai
        m.reviews += decision.needs_review
        if serious and not decision.run_ai:
            m.missed_serious.append(r["id"])
        if not serious and decision.run_ai and not decision.needs_review:
            m.unnecessary_ai.append(r["id"])
        if r["expected_category"] == "unknown" and not decision.needs_review:
            m.unknown_not_reviewed.append(r["id"])
    return m


def _distance(a: TriagePolicy, b: TriagePolicy) -> float:
    return (abs(a.severity_threshold - b.severity_threshold)
            + abs(a.escalation_threshold - b.escalation_threshold) * 10
            + abs(a.min_category_confidence - b.min_category_confidence) * 10
            + abs(a.min_severity_confidence - b.min_severity_confidence) * 10)


def rank_key(metrics: Metrics, policy: TriagePolicy, current: TriagePolicy) -> tuple:
    return (len(metrics.missed_serious), len(metrics.unknown_not_reviewed), metrics.cost,
            round(_distance(policy, current), 6))


def sweep(results: list[dict], current: TriagePolicy, grid: dict | None = None) -> list[tuple[TriagePolicy, Metrics]]:
    """Every threshold combination in ``grid``, best first."""
    grid = grid or DEFAULT_GRID
    keys = list(grid)
    scored = []
    for values in product(*(grid[k] for k in keys)):
        policy = TriagePolicy(**dict(zip(keys, values)))
        scored.append((policy, evaluate(results, policy)))
    scored.sort(key=lambda pm: rank_key(pm[1], pm[0], current))
    return scored


def _pct(n: int, total: int) -> str:
    return f"{n}/{total} ({100 * n / total:.0f}%)" if total else "0/0"


def _policy_line(p: TriagePolicy) -> str:
    return (f"severity >= {p.severity_threshold}, escalation >= {p.escalation_threshold}, "
            f"category confidence < {p.min_category_confidence} → review, "
            f"severity confidence < {p.min_severity_confidence} → review")


def _metrics_rows(m: Metrics) -> list[str]:
    t = m.total
    return [
        f"| Category correct | {_pct(m.category_correct, t)} |",
        f"| Severity exact | {_pct(m.severity_exact, t)} |",
        f"| Severity within one level | {_pct(m.severity_within_one, t)} |",
        f"| **Serious alerts that skipped AI** (must be 0) | **{len(m.missed_serious)}** "
        f"{('(' + ', '.join(m.missed_serious) + ')') if m.missed_serious else ''} |",
        f"| Unknown alerts not sent to review | {len(m.unknown_not_reviewed)} "
        f"{('(' + ', '.join(m.unknown_not_reviewed) + ')') if m.unknown_not_reviewed else ''} |",
        f"| AI runs | {_pct(m.ai_runs, t)} |",
        f"| AI runs on low-risk alerts without review | {len(m.unnecessary_ai)} |",
        f"| Sent to human review | {_pct(m.reviews, t)} |",
    ]


def render_report(results: list[dict], current: TriagePolicy, ranked: list[tuple[TriagePolicy, Metrics]],
                  *, model: str, run_at: str, top: int = 5) -> str:
    cur = evaluate(results, current)
    best_policy, best = ranked[0]
    same = best_policy == current
    lines = [
        "# Triage calibration report",
        "",
        f"Run: {run_at} · Jev model: `{model}` · {len(results)} labelled sample alerts "
        "(`backend/samples/calibration/alerts.json`)",
        "",
        "Re-run with `python -m scripts.calibrate_triage` (calls Jev once per alert), or "
        "`python -m scripts.calibrate_triage --from-results <results.json>` to re-score "
        "without new calls.",
        "",
        "## Summary",
        "",
        f"- Current rule: {_policy_line(current)}",
        f"- Recommended: {_policy_line(best_policy)}" + (" (same as current)" if same else ""),
        f"- Serious alerts that would skip the AI analysis: **{len(cur.missed_serious)}** with the "
        f"current rule, **{len(best.missed_serious)}** with the recommended one.",
        "",
        "Labels are a responder's judgement, not ground truth; 20 alerts is a small "
        "sample, so treat the recommendation as a starting point to discuss.",
        "",
        "## Current vs recommended",
        "",
        "| Measure | Current | Recommended |",
        "|---|---|---|",
    ]
    for c_row, b_row in zip(_metrics_rows(cur), _metrics_rows(best)):
        label, c_val = c_row.strip("|").split("|", 1)
        _, b_val = b_row.strip("|").split("|", 1)
        lines.append(f"|{label}|{c_val.strip()} | {b_val.strip()} |")

    if not same:
        lines += ["", "To apply the recommendation, set in `backend/.env`:", "", "```",
                  f"AEGIS_SEVERITY_THRESHOLD={best_policy.severity_threshold}",
                  f"AEGIS_ESCALATION_THRESHOLD={best_policy.escalation_threshold}",
                  f"AEGIS_MIN_CATEGORY_CONFIDENCE={best_policy.min_category_confidence}",
                  f"AEGIS_MIN_SEVERITY_CONFIDENCE={best_policy.min_severity_confidence}", "```"]

    lines += ["", f"## Top {top} settings tried ({len(ranked)} in total)", "",
              "| Severity ≥ | Escalation ≥ | Min cat. conf. | Min sev. conf. | Missed serious | "
              "Unknown not reviewed | AI runs | Reviews |",
              "|---|---|---|---|---|---|---|---|"]
    for p, m in ranked[:top]:
        lines.append(f"| {p.severity_threshold} | {p.escalation_threshold} | {p.min_category_confidence} | "
                     f"{p.min_severity_confidence} | {len(m.missed_serious)} | {len(m.unknown_not_reviewed)} | "
                     f"{m.ai_runs} | {m.reviews} |")

    lines += ["", "## Every alert (current rule)", "",
              "| Alert | Expected | Jev says | Escalation | Confidence (cat / sev) | Decision |",
              "|---|---|---|---|---|---|"]
    for r in results:
        d = current.decide(r)
        verdict = ("AI + review" if d.needs_review else "AI") if d.run_ai else "skip AI"
        flag = " ⚠ missed" if r["id"] in cur.missed_serious else ""
        conf = " / ".join("–" if r.get(k) is None else f"{r[k]:.2f}"
                          for k in ("category_confidence", "severity_confidence"))
        lines.append(
            f"| {r['id']} | {r['expected_category']}, {SEVERITY_NAMES[r['expected_severity']]} | "
            f"{r['incident_category']}, {SEVERITY_NAMES.get(r['severity_score'], r['severity_score'])} | "
            f"{r['escalation_noul']:.2f} | {conf} | {verdict}{flag} |")
    return "\n".join(lines) + "\n"
