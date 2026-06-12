"""Tests for report.py — analyze_surface & generate_report (offline)."""

from __future__ import annotations

import json

import pytest

from srchunter.tools.report import (
    _score_target,
    dispatch_report_tool,
    REPORT_TOOLS,
)


class TestScoreTarget:
    def test_empty_everything(self) -> None:
        score, priority = _score_target("test.com", [], [], [])
        assert priority == "low"
        assert score == 0

    def test_live_urls_bump(self) -> None:
        live = [{"url": "https://test.com", "status_code": 200}]
        score, priority = _score_target("test.com", live, [], [])
        assert score == 1

    def test_non_200_status_bump(self) -> None:
        live = [{"url": "https://test.com", "status_code": 500}]
        score, priority = _score_target("test.com", live, [], [])
        assert score == 3  # 1 base + 2 for non-200

    def test_critical_vuln_high_priority(self) -> None:
        vulns = [{"severity": "critical", "type": "rce"}]
        score, priority = _score_target("test.com", [], [], vulns)
        assert priority == "high"
        assert score >= 100


class TestDispatchReport:
    async def test_analyze_surface_empty(self) -> None:
        result = await dispatch_report_tool("analyze_surface", {})
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data["summary"]["total_targets"] == 0

    async def test_analyze_surface_with_data(self) -> None:
        result = await dispatch_report_tool(
            "analyze_surface",
            {
                "live_urls": [
                    {"url": "https://test.com", "status_code": 200, "title": "Test"}
                ],
                "vuln_findings": [
                    {"url": "https://test.com", "type": "cors", "severity": "low"}
                ],
            },
        )
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data["summary"]["total_targets"] == 1
        surf = data["attack_surface"][0]
        assert surf["priority"] in ("low", "medium", "high")
        assert len(surf["vulnerabilities"]) == 1

    async def test_generate_report_markdown(self) -> None:
        findings = [
            {
                "type": "cors_misconfig",
                "severity": "low",
                "url": "https://test.com",
                "description": "CORS allows * origin",
                "evidence": "Access-Control-Allow-Origin: *",
                "remediation": "Restrict CORS to trusted origins",
            }
        ]
        result = await dispatch_report_tool(
            "generate_report",
            {"findings": findings, "target": "test.com", "format": "md"},
        )
        text = result[0].text
        assert "# SRC Vulnerability Report: test.com" in text
        assert "CORS allows" in text
        assert "Access-Control-Allow-Origin" in text

    async def test_generate_report_json(self) -> None:
        findings = [{"type": "xss", "severity": "high", "url": "https://x.com"}]
        result = await dispatch_report_tool(
            "generate_report",
            {"findings": findings, "target": "x.com", "format": "json"},
        )
        data = json.loads(result[0].text)
        assert data["target"] == "x.com"
        assert len(data["findings"]) == 1

    async def test_generate_report_empty(self) -> None:
        result = await dispatch_report_tool(
            "generate_report",
            {"findings": [], "target": "empty.com"},
        )
        assert "No findings to report" in result[0].text

    async def test_unknown_tool_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown report tool"):
            await dispatch_report_tool("nonexistent", {})


class TestToolDefinitions:
    def test_report_tools_have_schema(self) -> None:
        for tool in REPORT_TOOLS:
            assert tool.name
            assert tool.description
            assert tool.inputSchema["type"] == "object"
            assert "properties" in tool.inputSchema
