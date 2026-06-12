"""SRC Hunter MCP Server entry point.

Start with:
    python -m srchunter.server
"""

from __future__ import annotations

import asyncio
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tools.recon import RECON_TOOLS, dispatch_recon_tool
from .tools.fingerprint import FINGERPRINT_TOOLS, dispatch_fingerprint_tool
from .tools.vuln import VULN_TOOLS, dispatch_vuln_tool
from .tools.report import REPORT_TOOLS, dispatch_report_tool


def create_server() -> Server:
    """Create and configure the SRC Hunter MCP Server — 12 tools, 4 modules."""
    server = Server("srchunter")

    all_tools: list[Tool] = []
    all_tools.extend(RECON_TOOLS)        # 4: subdomain_enum, resolve_targets, port_scan, http_probe
    all_tools.extend(FINGERPRINT_TOOLS)  # 3: tech_detect, fingerprint_services, identify_waf
    all_tools.extend(VULN_TOOLS)         # 3: check_misconfig, run_nuclei, check_exploitable
    all_tools.extend(REPORT_TOOLS)       # 2: analyze_surface, generate_report

    recon_names       = {t.name for t in RECON_TOOLS}
    fingerprint_names = {t.name for t in FINGERPRINT_TOOLS}
    vuln_names        = {t.name for t in VULN_TOOLS}
    report_names      = {t.name for t in REPORT_TOOLS}

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return all_tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name in recon_names:
            return await dispatch_recon_tool(name, arguments)
        if name in fingerprint_names:
            return await dispatch_fingerprint_tool(name, arguments)
        if name in vuln_names:
            return await dispatch_vuln_tool(name, arguments)
        if name in report_names:
            return await dispatch_report_tool(name, arguments)
        raise ValueError(f"unknown tool: {name!r}")

    return server


async def run_server() -> None:
    server = create_server()
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main() -> None:
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"srchunter: fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
