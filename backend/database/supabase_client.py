"""
backend/database/supabase_client.py
====================================
Supabase client for the backend — one per thread.

The backend authenticates with the **secret** (service-role) key, never the
publishable key. Row Level Security is enabled on every AegisFlow table, so
the publishable key — which ships to browsers — cannot read or write incident
data; only this server-side key can.

Why one client per thread
-------------------------
FastAPI runs ``def`` endpoints in a thread pool, so requests execute in
parallel threads. supabase-py's sync client holds a single HTTP/2 connection,
which is not safe to share across threads: under concurrent requests it fails
with read errors (seen on Windows as ``WinError 10035``). Each thread therefore
gets its own cached client; creating one does no network I/O.

Environment variables
---------------------
SUPABASE_URL          Project URL (falls back to NEXT_PUBLIC_SUPABASE_URL).
SUPABASE_SECRET_KEY   Secret key (``sb_secret_...``) from
                      Dashboard → Project Settings → API Keys.
                      ``SUPABASE_SERVICE_ROLE_KEY`` (legacy JWT key) is
                      accepted as a fallback.
"""

from __future__ import annotations

import os
import threading

from supabase import Client, create_client

_local = threading.local()
# Bumped by reset_supabase_client() so every thread rebuilds its client.
_generation = 0


def supabase_url() -> str:
    return (
        os.environ.get("SUPABASE_URL", "").strip()
        or os.environ.get("NEXT_PUBLIC_SUPABASE_URL", "").strip()
    )


def supabase_secret_key() -> str:
    return (
        os.environ.get("SUPABASE_SECRET_KEY", "").strip()
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    )


def _build_client() -> Client:
    url = supabase_url()
    key = supabase_secret_key()
    if not url:
        raise RuntimeError("Missing required env var: SUPABASE_URL")
    if not key:
        raise RuntimeError("Missing required env var: SUPABASE_SECRET_KEY")
    if key.startswith("sb_publishable_"):
        raise RuntimeError(
            "SUPABASE_SECRET_KEY holds a publishable key. The backend needs the "
            "secret key (sb_secret_...) from Project Settings → API Keys."
        )
    return create_client(url, key)


def get_supabase() -> Client:
    """Return this thread's Supabase client, creating it on first call.

    Usable directly or as a FastAPI dependency (tests override it with
    ``app.dependency_overrides[get_supabase]``).
    """
    if getattr(_local, "generation", None) != _generation or getattr(_local, "client", None) is None:
        _local.client = _build_client()
        _local.generation = _generation
    return _local.client


def reset_supabase_client() -> None:
    """Drop cached clients in all threads (used by tests and after key rotation)."""
    global _generation
    _generation += 1
    _local.client = None
