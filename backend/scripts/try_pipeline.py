"""Manual smoke run of the pipeline (no DB writes). Run from backend/: python -m scripts.try_pipeline"""
from dotenv import load_dotenv
load_dotenv()

import json
from engine.langgraph_pipeline import _compiled_pipeline

CASES = [
    ("HIGH: expect LLM path",
     "CRITICAL: Database connection pool completely exhausted across all microservices, "
     "triggering cascading gateway timeouts and data corruption risks.",
     "payment-service"),
    ("LOW: expect short-circuit",
     "INFO: Scheduled log rotation completed successfully.",
     "payment-service"),
    ("UNKNOWN SERVICE: expect empty blast_radius",
     "WARNING: Elevated latency on checkout.",
     "does-not-exist"),
]

for label, alert, service_id in CASES:
    print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
    state = {
        "alert": alert, "service_id": service_id, "service_context": [],
        "jev_results": {}, "llm_response": "", "llm_meta": {}, "trace": [],
        "final_response": {},
    }
    for step in _compiled_pipeline.stream(state):
        for node, update in step.items():
            print(f"\n--- {node} ---")
            print(json.dumps(update, indent=2, default=str)[:1500])
