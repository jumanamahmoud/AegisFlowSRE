"""
backend/scripts/calibrate_triage.py
====================================
Phase 4 calibration: run System 1 (Jev) on the 20 labelled sample alerts,
score the current triage rule, search for better thresholds and write a
report to docs/calibration/.

Only Jev is called (one request per alert); the AI analysis (Groq) is not.

Run from backend/:
    python -m scripts.calibrate_triage                         # call Jev, write report
    python -m scripts.calibrate_triage --from-results FILE     # re-score saved results, no calls
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from engine.calibration import render_report, sweep  # noqa: E402
from engine.prompt_safety import sanitize_alert  # noqa: E402
from engine.triage_policy import TriagePolicy  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples" / "calibration" / "alerts.json"
OUT_DIR = ROOT.parent / "docs" / "calibration"


def collect(samples: list[dict]) -> list[dict]:
    from engine.jev_check import classify

    results = []
    for i, s in enumerate(samples, 1):
        clean = sanitize_alert(s["alert"]).text  # same input the live pipeline gives Jev
        jev = classify(clean, s["service_id"])
        results.append({**{k: s[k] for k in ("id", "service_id", "expected_category", "expected_severity")}, **jev})
        print(f"  {i:2}/{len(samples)} {s['id']}: {jev['incident_category']}, severity {jev['severity_score']}, "
              f"escalation {jev['escalation_noul']:.2f}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from-results", type=Path, help="re-score a saved results JSON instead of calling Jev")
    args = parser.parse_args()

    run_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    model = os.environ.get("TYPESAFE_DEFAULT_MODEL", "jev-1.13.0")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.from_results:
        saved = json.loads(args.from_results.read_text(encoding="utf-8"))
        results, model = saved["results"], saved.get("model", model)
    else:
        samples = json.loads(SAMPLES.read_text(encoding="utf-8"))["alerts"]
        print(f"Calling Jev ({model}) on {len(samples)} sample alerts...")
        results = collect(samples)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
        raw = OUT_DIR / f"results-{stamp}.json"
        raw.write_text(json.dumps({"model": model, "run_at": run_at, "results": results}, indent=2),
                       encoding="utf-8")
        print(f"Raw results: {raw}")

    current = TriagePolicy.from_env()
    ranked = sweep(results, current)
    report = OUT_DIR / "triage-calibration.md"
    report.write_text(render_report(results, current, ranked, model=model, run_at=run_at), encoding="utf-8")

    best_policy, best = ranked[0]
    print(f"\nReport: {report}")
    print(f"Recommended: severity >= {best_policy.severity_threshold}, escalation >= "
          f"{best_policy.escalation_threshold}, min confidence {best_policy.min_category_confidence} / "
          f"{best_policy.min_severity_confidence}; missed serious alerts: {len(best.missed_serious)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
