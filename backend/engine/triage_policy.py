"""
backend/engine/triage_policy.py
================================
The triage decision rule, in one place (FR-6, FR-14).

After System 1 (Jev) classifies an alert, this rule decides two things:

1. **Run the AI analysis?** Yes when the alert is serious enough:
       severity_score >= SEVERITY_THRESHOLD   (default 2 = High)
    or escalation_noul >= ESCALATION_THRESHOLD (default 0.5)
   and also whenever a human review is needed (point 2), so the reviewer has
   an analysis to read instead of a silently skipped one.

2. **Ask a human to review the triage?** Yes when Jev is unsure:
       category is "unknown"
    or category confidence  < MIN_CATEGORY_CONFIDENCE
    or severity confidence  < MIN_SEVERITY_CONFIDENCE

Every threshold can be changed with an environment variable (below) without
touching code; scripts/calibrate_triage.py measures how well a setting works
on labelled sample alerts and suggests values.

    AEGIS_SEVERITY_THRESHOLD          default 2
    AEGIS_ESCALATION_THRESHOLD        default 0.5
    AEGIS_MIN_CATEGORY_CONFIDENCE     default 0.6
    AEGIS_MIN_SEVERITY_CONFIDENCE     default 0.6

Pure functions only (no I/O), so the rule is unit-tested directly.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field

UNKNOWN_CATEGORY = "unknown"

# Reasons a review is requested (stored on the incident and its timeline).
REASON_UNKNOWN = "category_unknown"
REASON_LOW_CATEGORY = "low_category_confidence"
REASON_LOW_SEVERITY = "low_severity_confidence"


def _number(value) -> float | None:
    """Only real numbers count (mocks and None are 'not reported')."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


@dataclass(frozen=True)
class TriageDecision:
    run_ai: bool
    needs_review: bool
    reasons: list[str] = field(default_factory=list)
    explanation: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TriagePolicy:
    severity_threshold: int = 2
    escalation_threshold: float = 0.5
    min_category_confidence: float = 0.6
    min_severity_confidence: float = 0.6

    @classmethod
    def from_env(cls) -> "TriagePolicy":
        env = os.environ.get
        return cls(
            severity_threshold=int(env("AEGIS_SEVERITY_THRESHOLD", "2")),
            escalation_threshold=float(env("AEGIS_ESCALATION_THRESHOLD", "0.5")),
            min_category_confidence=float(env("AEGIS_MIN_CATEGORY_CONFIDENCE", "0.6")),
            min_severity_confidence=float(env("AEGIS_MIN_SEVERITY_CONFIDENCE", "0.6")),
        )

    def review_reasons(self, jev: dict) -> list[str]:
        reasons = []
        if str(jev.get("incident_category", "")).lower() == UNKNOWN_CATEGORY:
            reasons.append(REASON_UNKNOWN)
        cat_conf = _number(jev.get("category_confidence"))
        if cat_conf is not None and cat_conf < self.min_category_confidence:
            reasons.append(REASON_LOW_CATEGORY)
        sev_conf = _number(jev.get("severity_confidence"))
        if sev_conf is not None and sev_conf < self.min_severity_confidence:
            reasons.append(REASON_LOW_SEVERITY)
        return reasons

    def is_serious(self, jev: dict) -> bool:
        return (jev["severity_score"] >= self.severity_threshold
                or jev["escalation_noul"] >= self.escalation_threshold)

    def decide(self, jev: dict) -> TriageDecision:
        """``jev`` holds severity_score, escalation_noul and, when available,
        incident_category, category_confidence and severity_confidence."""
        reasons = self.review_reasons(jev)
        serious = self.is_serious(jev)
        if serious:
            why = (f"severity {jev['severity_score']} >= {self.severity_threshold}"
                   if jev["severity_score"] >= self.severity_threshold
                   else f"escalation {jev['escalation_noul']:.2f} >= {self.escalation_threshold}")
        elif reasons:
            why = "low-risk scores, but triage is uncertain: " + ", ".join(reasons)
        else:
            why = (f"severity {jev['severity_score']} < {self.severity_threshold} and "
                   f"escalation {jev['escalation_noul']:.2f} < {self.escalation_threshold}")
        return TriageDecision(run_ai=serious or bool(reasons), needs_review=bool(reasons),
                              reasons=reasons, explanation=why)
