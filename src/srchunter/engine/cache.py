"""Simple in-memory result cache with TTL.

Why: crt.sh has no hard rate-limit, but repeated queries for the same
domain within a short window waste time and look sloppy.  This cache
lets an Agent re-query without penalty while a session is active.

Thread-safe?  No — MCP stdio servers are single-threaded per session.
"""

from __future__ import annotations

import time
from typing import Any

# Default TTL in seconds — 10 minutes is long enough for a single
# Agent session but short enough that new subdomains show up on the
# next run.
DEFAULT_TTL = 600


class SimpleCache:
    """A dict-backed cache with per-key expiry."""

    def __init__(self, ttl: int = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)


# Module-level singleton shared across all recon tools.
_cache = SimpleCache()


def get_cache() -> SimpleCache:
    return _cache
