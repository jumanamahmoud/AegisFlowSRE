"""
backend/core/api_keys.py
=========================
Machine access keys for monitoring tools (NFR security: "Machine access uses
secret keys").

People sign in (core/auth.py); monitoring tools can't, so each integration
gets its own long random key, created by an administrator. The key is shown
once and only its SHA-256 hash is stored. A key can be limited to one source
(e.g. only ``/alerts/webhooks/grafana``) and revoked at any time.

A tool can send its key in any of these ways (whichever the tool supports):

    X-API-Key: afk_...                      (Datadog custom headers)
    Authorization: Bearer afk_...           (Alertmanager, Grafana)
    https://aegisflow:afk_...@host/...      (basic auth — AWS SNS)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from supabase import Client

from database.supabase_client import get_supabase

logger = logging.getLogger(__name__)

API_KEYS = "api_keys"
KEY_PREFIX = "afk_"  # AegisFlow key
_DISPLAY_CHARS = 12
_TOUCH_EVERY_S = 300  # write last_used_at at most every 5 minutes per key
_CACHE_TTL_S = 30.0
_CACHE_MAX = 1000


@dataclass(frozen=True)
class MachinePrincipal:
    key_id: str
    name: str
    source: str | None  # None = any source

    @property
    def actor(self) -> str:
        """How this integration appears on the audit timeline."""
        return f"apikey:{self.name}"


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Lookup (cached briefly; revocation clears the cache entry)
# ---------------------------------------------------------------------------


class ApiKeyLookup:
    def __init__(self, client_factory: Callable[[], Client] = get_supabase, ttl_seconds: float = _CACHE_TTL_S):
        self._client_factory = client_factory
        self._ttl = ttl_seconds
        self._cache: dict[str, tuple[float, dict | None]] = {}
        self._touched: dict[str, float] = {}
        self._lock = threading.Lock()

    def find(self, key: str) -> dict | None:
        """The active (non-revoked) key row for ``key``, or None."""
        digest = hash_key(key)
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(digest)
            if hit and hit[0] > now:
                return hit[1]
        rows = (
            self._client_factory()
            .table(API_KEYS)
            .select("id,name,source,revoked_at")
            .eq("key_hash", digest)
            .is_("revoked_at", "null")
            .limit(1)
            .execute()
            .data
        )
        row = rows[0] if rows else None
        with self._lock:
            if len(self._cache) >= _CACHE_MAX:
                self._cache.clear()  # bounded: random-key floods can't grow memory
            self._cache[digest] = (now + self._ttl, row)
        if row:
            self._touch(row["id"])
        return row

    def _touch(self, key_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._touched.get(key_id, -_TOUCH_EVERY_S) < _TOUCH_EVERY_S:
                return
            self._touched[key_id] = now
        try:
            from database.alert_store import utc_iso

            self._client_factory().table(API_KEYS).update({"last_used_at": utc_iso()}).eq("id", key_id).execute()
        except Exception:  # usage stats must never block an alert
            logger.warning("could not update api key last_used_at", exc_info=True)

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()


_lookup = ApiKeyLookup()


def get_api_key_lookup() -> ApiKeyLookup:
    return _lookup


# ---------------------------------------------------------------------------
# Admin operations
# ---------------------------------------------------------------------------


def create_api_key(sb: Client, name: str, source: str | None, created_by: str) -> tuple[dict, str]:
    """Create a key. Returns (stored row, plaintext key). The plaintext is
    never stored or logged; the caller must show it once and forget it."""
    plaintext = generate_key()
    row = (
        sb.table(API_KEYS)
        .insert(
            {
                "name": name,
                "key_prefix": plaintext[:_DISPLAY_CHARS],
                "key_hash": hash_key(plaintext),
                "source": source,
                "created_by": created_by,
            }
        )
        .execute()
        .data[0]
    )
    return row, plaintext


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer, Basic realm="aegisflow"'},
    )


def extract_key(request: Request) -> str | None:
    header = request.headers.get("x-api-key", "").strip()
    if header:
        return header
    auth = request.headers.get("authorization", "").strip()
    scheme, _, value = auth.partition(" ")
    value = value.strip()
    if scheme.lower() == "bearer" and value:
        return value
    if scheme.lower() == "basic" and value:
        try:
            user, _, password = base64.b64decode(value, validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        # The key may be given as the password (usual) or as the user name.
        for candidate in (password, user):
            if candidate.startswith(KEY_PREFIX):
                return candidate
    return None


def get_machine_principal(
    request: Request, lookup: ApiKeyLookup = Depends(get_api_key_lookup)
) -> MachinePrincipal:
    key = extract_key(request)
    if not key:
        raise _unauthorized("Missing API key")
    if not key.startswith(KEY_PREFIX) or len(key) > 200:
        raise _unauthorized("Invalid API key")
    row = lookup.find(key)
    if row is None:
        logger.info("api key rejected")  # never log any part of a presented key
        raise _unauthorized("Invalid API key")
    principal = MachinePrincipal(key_id=row["id"], name=row["name"], source=row.get("source"))
    request.state.user_id = principal.actor  # shows up in the access log
    return principal
