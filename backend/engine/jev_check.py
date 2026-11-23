"""
backend/engine/jev_check.py
===========================
AegisFlow – TypeSafe Jev SDK integration verifier.

Initialises a TypeSafeClient from the environment and runs a single
batched request that exercises all three Jev primitives:

  • Choice  – pick one option from a defined set
  • Score   – position on an ordered scale
  • Noul    – probability of a yes/no proposition

The test state is a synthetic incident alert that is realistic for the
dual-engine incident response use-case.

Environment variables
---------------------
TYPESAFE_API_KEY   (required)  Official SDK variable.
JEV_API_KEY        (alias)     Accepted as a fallback for convenience.
                               If both are set, TYPESAFE_API_KEY wins.
TYPESAFE_DEFAULT_MODEL         Defaults to "jev-1.13.0" if not set.

Usage
-----
    # From the backend/ directory:
    python -m engine.jev_check

    # Or directly:
    python backend/engine/jev_check.py
"""

from __future__ import annotations

import os
import sys
import textwrap

# ---------------------------------------------------------------------------
# Key resolution: honour both TYPESAFE_API_KEY and JEV_API_KEY
# ---------------------------------------------------------------------------
_typesafe_key = os.environ.get("TYPESAFE_API_KEY", "").strip()
_jev_alias = os.environ.get("JEV_API_KEY", "").strip()

if not _typesafe_key and _jev_alias:
    # Promote the alias so the SDK picks it up automatically.
    os.environ["TYPESAFE_API_KEY"] = _jev_alias
    print("[jev_check] JEV_API_KEY promoted to TYPESAFE_API_KEY.")

# ---------------------------------------------------------------------------
# SDK imports (must come after key promotion)
# ---------------------------------------------------------------------------
try:
    from typesafe_sdk import (
        Choice,
        Noul,
        Score,
        TypeSafeClient,
        TypeSafeAuthenticationError,
        TypeSafeError,
    )
except ImportError as exc:
    sys.exit(
        "[jev_check] ERROR: typesafe-sdk is not installed.\n"
        "  Run:  pip install typesafe-sdk==0.7.5\n"
        f"  Detail: {exc}"
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
JEV_MODEL = os.environ.get("TYPESAFE_DEFAULT_MODEL", "jev-1.13.0")

# Confidence threshold below which a decision is flagged for human review.
REVIEW_THRESHOLD = 0.75

# ---------------------------------------------------------------------------
# Test state – a synthetic incident alert
# ---------------------------------------------------------------------------
INCIDENT_STATE = {
    "alert": (
        "Production payment service has been returning HTTP 500 errors for the "
        "last 12 minutes. Approximately 35% of checkout requests are failing. "
        "The on-call engineer restarted the service once with no improvement. "
        "Revenue impact is estimated at $4,000/minute."
    ),
    "system": {
        "name": "payment-service",
        "environment": "production",
        "tier": "critical",
    },
}

# ---------------------------------------------------------------------------
# Questions (one per primitive)
# ---------------------------------------------------------------------------
QUESTIONS = {
    # --- Choice: classify the incident category ---
    "incident_category": Choice(
        instructions=(
            "Based on `alert`, what is the primary category of this incident?"
        ),
        criteria={
            "infrastructure": "Hardware, network, or cloud-provider failure.",
            "application": "Bug or regression in application code.",
            "database": "Database connectivity, query, or data-integrity issue.",
            "dependency": "A downstream third-party or internal service is failing.",
            "security": "Potential breach, DDoS, or abnormal access pattern.",
            "unknown": "Cannot be determined from the available information.",
        },
    ),

    # --- Score: measure incident severity on a 4-level scale ---
    "severity": Score(
        instructions=(
            "How severe is the incident described in `alert`? "
            "Consider customer impact, revenue loss, and blast radius."
        ),
        criteria=[
            "Low – minor impact, no customer-facing disruption.",
            "Moderate – degraded experience for some users.",
            "High – significant customer impact, partial outage.",
            "Critical – full or near-full outage with major business impact.",
        ],
    ),

    # --- Noul: should the incident be escalated immediately? ---
    "needs_escalation": Noul(
        instructions=(
            "Does `alert` describe a situation that requires immediate escalation "
            "to the incident response team right now, without waiting for further diagnosis?"
        ),
    ),
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_verification() -> int:
    """
    Execute the Jev verification call and print a structured summary.

    Returns 0 on success, 1 on failure — suitable for use as a process exit code.
    """
    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    if not api_key:
        print(
            "[jev_check] ERROR: No API key found.\n"
            "  Set TYPESAFE_API_KEY or JEV_API_KEY in your environment or .env file.\n"
            "  Obtain a key at https://console.typesafe.ai/keys"
        )
        return 1

    print(f"[jev_check] Using model : {JEV_MODEL}")
    print(f"[jev_check] API key     : {api_key[:8]}{'*' * (len(api_key) - 8)}")
    print()

    try:
        with TypeSafeClient(model=JEV_MODEL) as client:
            response = client.system_one(
                state=INCIDENT_STATE,
                questions=QUESTIONS,
            )
    except TypeSafeAuthenticationError:
        print(
            "[jev_check] ERROR: Authentication failed.\n"
            "  Your API key was rejected. Check that TYPESAFE_API_KEY is correct."
        )
        return 1
    except TypeSafeError as exc:
        print(f"[jev_check] ERROR: Jev API call failed — {type(exc).__name__}: {exc}")
        return 1

    # -----------------------------------------------------------------------
    # Parse results
    # -----------------------------------------------------------------------
    category_ans = response.choices["incident_category"]
    severity_ans = response.scores["severity"]
    escalation_ans = response.nouls["needs_escalation"]

    severity_labels = {
        0: "Low",
        1: "Moderate",
        2: "High",
        3: "Critical",
    }
    severity_label = severity_labels.get(round(severity_ans.score), "Unknown")

    needs_review = (
        category_ans.confidence < REVIEW_THRESHOLD
        or severity_ans.confidence < REVIEW_THRESHOLD
    )

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("  AegisFlow · Jev SDK Verification")
    print("=" * 60)
    print(f"  Model responded   : {response.model}")
    print(
        f"  Tokens used       : "
        f"{response.usage.input_tokens or 0} input / "
        f"{response.usage.output_tokens or 0} output"
    )
    print()

    print("  ── Choice ──────────────────────────────────────────")
    print(f"  Incident category : {category_ans.choice}")
    print(f"  Confidence        : {category_ans.confidence:.2f}")
    print("  Probabilities     :")
    for label, prob in sorted(
        category_ans.probabilities.items(), key=lambda x: x[1], reverse=True
    ):
        bar = "█" * int(prob * 20)
        print(f"    {label:<16} {prob:.3f}  {bar}")
    print()

    print("  ── Score ───────────────────────────────────────────")
    print(f"  Severity          : {severity_ans.score:.2f}  ({severity_label})")
    print(f"  Confidence        : {severity_ans.confidence:.2f}")
    print("  Level breakdown   :")
    for level_idx, prob in sorted(severity_ans.probabilities.items()):
        label = severity_labels.get(level_idx, str(level_idx))
        bar = "█" * int(prob * 20)
        print(f"    [{level_idx}] {label:<12} {prob:.3f}  {bar}")
    print()

    print("  ── Noul ────────────────────────────────────────────")
    print(f"  Needs escalation  : {escalation_ans.noul:.3f}  ", end="")
    if escalation_ans.noul >= 0.8:
        print("→  ESCALATE NOW")
    elif escalation_ans.noul >= 0.5:
        print("→  monitor closely")
    else:
        print("→  no immediate escalation needed")
    print()

    print("  ── Routing Decision ────────────────────────────────")
    if needs_review:
        print("  ⚠  Low confidence — flagged for human review.")
    else:
        print("  ✓  Confidence within threshold — ready for automated routing.")
    print("=" * 60)

    return 0


# ---------------------------------------------------------------------------
# FastAPI integration helper
# ---------------------------------------------------------------------------

def get_jev_client() -> TypeSafeClient:
    """
    Dependency factory for FastAPI routes.

    Usage in a route::

        from engine.jev_check import get_jev_client
        from typesafe_sdk import TypeSafeClient

        @router.post("/triage")
        def triage(payload: IncidentPayload, client: TypeSafeClient = Depends(get_jev_client)):
            ...

    The caller is responsible for closing the client (use as a context manager
    or call client.close() after the request).
    """
    api_key = os.environ.get("TYPESAFE_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "TYPESAFE_API_KEY is not set. "
            "Add it to your .env file or set it as an environment variable."
        )
    # Retries transient failures (timeouts, connection errors, 429/5xx) with
    # exponential backoff; JEV_TIMEOUT_S bounds each attempt.
    from typesafe_sdk import RetryPolicy

    timeout = float(os.environ.get("JEV_TIMEOUT_S", "10"))
    retry = RetryPolicy(
        max_retries=int(os.environ.get("JEV_MAX_RETRIES", "3")),
        backoff_initial=0.5,
        backoff_max=4.0,
        http_statuses={408, 429, 500, 502, 503, 504},
        timeout=timeout,
    )
    return TypeSafeClient(model=JEV_MODEL, retry=retry, timeout=timeout)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Load .env from the backend directory if present.
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass  # python-dotenv is optional when running in a managed environment.

    sys.exit(run_verification())
