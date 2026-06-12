"""Reconnaissance tools — asset discovery phase.

Tool list (ordered by typical workflow):
    subdomain_enum   — discover subdomains via crt.sh certificate logs
    resolve_targets  — batch DNS resolution + CDN detection  [future]
    port_scan        — port discovery on live hosts           [future]
    http_probe       — HTTP liveness probe with metadata      [future]
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from mcp.types import Tool, TextContent

from ..engine.cache import get_cache
from ..utils.validators import validate_domain

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT = 30.0
MAX_RETRIES = 2
RETRY_BACKOFF = 1.5
USER_AGENT = "srchunter-mcp/0.1.0"

# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------

RECON_TOOLS = [
    Tool(
        name="subdomain_enum",
        description=(
            "Enumerate subdomains of a domain via Certificate Transparency "
            "logs (crt.sh).  Use this as the FIRST step when mapping an "
            "attack surface.  Discovers known subdomains from publicly-issued "
            "TLS certificates."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": (
                        "Target domain name, e.g. 'example.com'.  Do NOT "
                        "include protocol, port, or path."
                    ),
                },
            },
            "required": ["domain"],
        },
    ),
]

# ---------------------------------------------------------------
# crt.sh query logic
# ---------------------------------------------------------------


async def _fetch_crtsh(domain: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Query crt.sh certificate transparency logs for *domain*."""
    url = CRTSH_URL.format(domain=domain)
    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await client.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                return []
            return data
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1))
        except Exception as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1))

    raise RuntimeError(
        f"crt.sh query failed after {MAX_RETRIES + 1} attempts: {last_error}"
    )


def _parse_crtsh_entries(
    raw: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Extract unique subdomain entries from raw crt.sh JSON."""
    seen: set[str] = set()
    results: list[dict[str, Any]] = []

    for entry in raw:
        names: set[str] = set()

        cn = (entry.get("common_name") or "").strip().lower()
        if cn:
            names.add(cn)

        nv = (entry.get("name_value") or "").strip()
        if nv:
            for line in nv.splitlines():
                name = line.strip().lower()
                if name:
                    names.add(name)

        for name in names:
            if name not in seen and not name.startswith("*."):
                seen.add(name)
                results.append({"domain": name, "source": "crtsh"})

    results.sort(key=lambda x: x["domain"])
    return results


# ---------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------


async def handle_subdomain_enum(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute subdomain_enum and return MCP TextContent result."""
    domain = validate_domain(arguments["domain"])

    # --- cache check ---
    cache = get_cache()
    cache_key = f"subdomain_enum:{domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        cached["cached"] = True
        import json
        return [TextContent(type="text", text=json.dumps(cached, indent=2, ensure_ascii=False))]

    # --- query ---
    t0 = asyncio.get_event_loop().time()

    async with httpx.AsyncClient() as client:
        raw = await _fetch_crtsh(domain, client)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    entries = _parse_crtsh_entries(raw)

    result: dict[str, Any] = {
        "query_domain": domain,
        "subdomains": entries,
        "count": len(entries),
        "elapsed": elapsed,
        "cached": False,
    }

    cache.set(cache_key, result.copy())

    import json
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


async def dispatch_recon_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Route a recon tool call to the correct handler."""
    if name == "subdomain_enum":
        return await handle_subdomain_enum(arguments)

    raise ValueError(f"unknown recon tool: {name!r}")
