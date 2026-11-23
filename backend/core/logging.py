"""
backend/core/logging.py
========================
Structured (JSON) logging with request correlation.

Every log line carries the ``request_id`` of the HTTP request that caused it,
including lines written later by the background analysis worker, so one
alert can be followed from intake to saved analysis.

Environment variables
---------------------
AEGIS_LOG_LEVEL    DEBUG | INFO (default) | WARNING | ERROR
AEGIS_LOG_FORMAT   json (default) | text   — text is easier to read locally
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
user_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("user_id", default=None)

# Attributes every LogRecord has; anything else was passed via ``extra=``.
_STANDARD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.user_id = user_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and value is not None:
                entry[key] = value
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extras = {
            k: v for k, v in vars(record).items()
            if k not in _STANDARD_ATTRS and v is not None and k not in ("request_id", "user_id")
        }
        rid = getattr(record, "request_id", None)
        line = f"{record.levelname:<7} {record.name}: {record.getMessage()}"
        if rid:
            line = f"[{rid[:8]}] " + line
        if extras:
            line += "  " + " ".join(f"{k}={v}" for k, v in extras.items())
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


_configured = False


def configure_logging() -> None:
    """Install the handler on the root logger once (idempotent)."""
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_ContextFilter())
    fmt = os.environ.get("AEGIS_LOG_FORMAT", "json").strip().lower()
    handler.setFormatter(TextFormatter() if fmt == "text" else JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.environ.get("AEGIS_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    # Third-party request logs are noisy at INFO and duplicate our access log.
    for noisy in ("httpx", "httpcore", "hpack", "neo4j", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True
