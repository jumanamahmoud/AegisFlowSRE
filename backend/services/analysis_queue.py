"""
backend/services/analysis_queue.py
===================================
Runs analyses in the background so ``POST /incidents/analyze`` returns at once.

Flow
----
1. The request stores the incident (so the alert can never be lost) and marks
   it ``analysis_status = 'queued'`` in the database, then hands the incident
   id to this queue and returns 202.
2. A worker thread picks it up, marks it ``running``, runs the pipeline via
   ``analyze_and_record`` and marks it ``completed`` or ``failed``.
3. On startup, ``recover()`` re-queues anything left ``queued`` or ``running``
   by a previous process (crash, deploy, restart).

The pool is small and bounded (``AEGIS_ANALYSIS_WORKERS``, default 2): extra
jobs wait in FIFO order, which protects the free-tier AI quotas during bursts.
This is an in-process queue for a single backend instance; a shared queue
(e.g. Redis) would be needed to run several instances.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from database.incident_store import IncidentStore
from services.incident_service import _default_pipeline, analyze_and_record

logger = logging.getLogger(__name__)


class AnalysisQueue:
    def __init__(
        self,
        store_factory: Callable[[], IncidentStore],
        pipeline: Callable[[str, str], dict] = _default_pipeline,
        max_workers: int | None = None,
        inline: bool = False,
    ) -> None:
        """``inline=True`` runs jobs synchronously in the caller's thread (tests)."""
        self._store_factory = store_factory
        self._pipeline = pipeline
        self._inline = inline
        self._max_workers = max_workers or int(os.environ.get("AEGIS_ANALYSIS_WORKERS", "2"))
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def _pool(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers, thread_name_prefix="analysis"
                )
            return self._executor

    def submit(self, incident_id: str) -> Future | None:
        """Schedule an incident whose status is already ``queued`` in the DB."""
        if self._inline:
            self._run(incident_id)
            return None
        # Carry the request id into the worker so its logs correlate.
        ctx = contextvars.copy_context()
        return self._pool().submit(ctx.run, self._run, incident_id)

    def _run(self, incident_id: str) -> None:
        store = self._store_factory()  # per-thread Supabase client
        try:
            if not store.mark_analysis_running(incident_id):
                logger.info("analysis job skipped: no longer queued", extra={"incident_id": incident_id})
                return
            logger.info("analysis started", extra={"incident_id": incident_id})
            result = analyze_and_record(store, alert="", service_id="", incident_id=incident_id,
                                        pipeline=self._pipeline)
            store.finish_analysis(incident_id, "completed")
            logger.info(
                "analysis completed",
                extra={"incident_id": incident_id,
                       "analysis_source": result["analysis"]["analysis_source"]},
            )
        except Exception as exc:  # the worker must never die silently
            logger.exception("analysis failed", extra={"incident_id": incident_id})
            try:
                store.finish_analysis(incident_id, "failed", error=f"{type(exc).__name__}: {exc}"[:500])
            except Exception:
                logger.exception("could not record analysis failure", extra={"incident_id": incident_id})

    def recover(self) -> int:
        """Re-queue work interrupted by a previous shutdown. Returns the count."""
        store = self._store_factory()
        pending = store.pending_analyses()
        for incident_id in pending:
            store.requeue_interrupted(incident_id)
            self.submit(incident_id)
        if pending:
            logger.warning("resumed interrupted analyses", extra={"count": len(pending)})
        return len(pending)

    def shutdown(self) -> None:
        """Stop accepting work. Unstarted jobs stay 'queued' in the DB and are
        resumed by ``recover()`` on the next start."""
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
                self._executor = None


# ---------------------------------------------------------------------------
# Application-wide instance (FastAPI dependency, overridden in tests)
# ---------------------------------------------------------------------------

_queue: AnalysisQueue | None = None


def get_analysis_queue() -> AnalysisQueue:
    global _queue
    if _queue is None:
        from database.supabase_client import get_supabase

        _queue = AnalysisQueue(store_factory=lambda: IncidentStore(get_supabase()))
    return _queue

