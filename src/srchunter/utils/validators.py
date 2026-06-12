"""Input validation utilities for SRC Hunter tools.

All user-provided target strings MUST pass validation before any
network I/O — this prevents SSRF, command injection, and accidental
scanning of internal infrastructure.
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import urlparse

# ---------------------------------------------------------------
# Domain / hostname validation
# ---------------------------------------------------------------

# Loosely matches valid hostnames (excludes bare IPs — those go
# through is_valid_ip).  Allows wildcard prefixes like *.example.com
# that appear in crt.sh results.
_HOSTNAME_RE = re.compile(
    r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}|"
    r"\*\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$"
)

# Reserved / internal-use TLDs and domains that should never be
# scanned by a user-controlled tool without explicit opt-in.
_BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".corp",
    ".home",
    ".lan",
    ".localhost",
    ".intranet",
)

_BLOCKED_DOMAINS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }
)

# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------


def is_valid_domain(value: str, /) -> bool:
    """Return True if *value* looks like a valid, scannable domain name."""
    if not value or len(value) > 253:
        return False
    if value.lower() in _BLOCKED_DOMAINS:
        return False
    if value.lower().endswith(_BLOCKED_SUFFIXES):
        return False
    return bool(_HOSTNAME_RE.match(value))


def validate_domain(value: str, /) -> str:
    """Validate and normalise a domain name; raise ValueError on failure."""
    cleaned = value.strip().lower().rstrip(".")
    if not is_valid_domain(cleaned):
        raise ValueError(f"invalid or blocked domain: {value!r}")
    return cleaned


def is_valid_ip(value: str, /) -> bool:
    """Return True for a well-formed IPv4 or IPv6 address."""
    try:
        ip_address(value)
    except ValueError:
        return False
    # Reject loopback / link-local / private?  For now we allow but
    # the caller (recon tools) can refuse private ranges if needed.
    return True


def is_valid_url(value: str, /) -> bool:
    """Return True for an http/https URL with a valid host."""
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if host in _BLOCKED_DOMAINS:
        return False
    if host.endswith(_BLOCKED_SUFFIXES):
        return False
    return bool(_HOSTNAME_RE.match(host))


def validate_url(value: str, /) -> str:
    """Validate a URL; raise ValueError on failure."""
    cleaned = value.strip()
    if not is_valid_url(cleaned):
        raise ValueError(f"invalid or blocked URL: {value!r}")
    return cleaned
