"""SRC Hunter MCP Server entry point.

Start with:
    python -m srchunter.server
    # or via the console_script entrypoint:
    srchunter
"""

from __future__ import annotations

import asyncio
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tools.recon import RECON_TOOLS, dispatch_recon_tool
from .tools.report import REPORT_TOOLS, dispatch_report_tool
from .tools.fingerprint import FINGERPRINT_TOOLS, dispatch_fingerprint_tool


def create_server() -> Server:
    """Create and configure the SRC Hunter MCP Server."""
    server = Server("srchunter")

    # Aggregate all tool definitions from every module.
    all_tools: list[Tool] = []
    all_tools.extend(RECON_TOOLS)
    all_tools.extend(REPORT_TOOLS)
    all_tools.extend(FINGERPRINT_TOOLS)
    # Future: all_tools.extend(VULN_TOOLS)

    # Build name sets for fast dispatch lookups.
    recon_names = {t.name for t in RECON_TOOLS}
    report_names = {t.name for t in REPORT_TOOLS}
    fingerprint_names = {t.name for t in FINGERPRINT_TOOLS}

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return all_tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name in recon_names:
            return await dispatch_recon_tool(name, arguments)
        if name in report_names:
            return await dispatch_report_tool(name, arguments)
        if name in fingerprint_names:
            return await dispatch_fingerprint_tool(name, arguments)
        # Future: vuln dispatch
        raise ValueError(f"unknown tool: {name!r}")

    return server


async def run_server() -> None:
    """Run the MCP server over stdio."""
    server = create_server()
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main() -> None:
    """Console-script entry point."""
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"srchunter: fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
