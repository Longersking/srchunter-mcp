"""Integration tests — exercise the full tool dispatch pipeline.

These tests import the actual handler functions and run them with
synthetic arguments so we can validate end-to-end behaviour without
needing a live MCP connection (or a network round-trip to crt.sh).

For tests that DO hit crt.sh, see the :func:`test_live_crtsh` helper
— skipped by default; run with ``pytest --run-live``.
"""

from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------


@pytest.fixture
def valid_args() -> dict:
    return {"domain": "example.com"}


# ---------------------------------------------------------------
# Tool dispatch (offline — no network)
# ---------------------------------------------------------------


class TestSubdomainEnumDispatch:
    """Test the dispatch layer for subdomain_enum."""

    async def test_dispatch_unknown_tool_raises(self) -> None:
        from srchunter.tools.recon import dispatch_recon_tool

        with pytest.raises(ValueError, match="unknown recon tool"):
            await dispatch_recon_tool("nonexistent_tool", {})


# ---------------------------------------------------------------
# Tool definitions shape
# ---------------------------------------------------------------


class TestToolDefinitions:
    """Ensure every registered tool has a valid definition."""

    def test_all_tools_have_name_and_schema(self) -> None:
        from srchunter.tools.recon import RECON_TOOLS

        for tool in RECON_TOOLS:
            assert tool.name, f"Tool missing name: {tool}"
            assert tool.description, f"Tool {tool.name} missing description"
            schema = tool.inputSchema
            assert schema.get("type") == "object", (
                f"Tool {tool.name}: inputSchema.type must be 'object'"
            )
            assert "properties" in schema, (
                f"Tool {tool.name}: inputSchema missing 'properties'"
            )

    def test_subdomain_enum_schema(self) -> None:
        from srchunter.tools.recon import RECON_TOOLS

        tool = next(t for t in RECON_TOOLS if t.name == "subdomain_enum")
        required = tool.inputSchema.get("required", [])
        assert "domain" in required


# ---------------------------------------------------------------
# Live crt.sh test (opt-in)
# ---------------------------------------------------------------


@pytest.mark.skipif(
    "not config.getoption('--run-live')",
    reason="use --run-live to hit crt.sh",
)
class TestLiveCrtsh:
    """End-to-end test hitting the real crt.sh API."""

    async def test_enum_example_com(self) -> None:
        from srchunter.tools.recon import handle_subdomain_enum

        result = await handle_subdomain_enum({"domain": "example.com"})
        assert len(result) == 1
        content = result[0]
        assert content.type == "text"

        data = json.loads(content.text)
        assert data["query_domain"] == "example.com"
        assert data["count"] > 0
        assert isinstance(data["subdomains"], list)
        assert any("example.com" in s["domain"] for s in data["subdomains"])
