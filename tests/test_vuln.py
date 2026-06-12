"""Tests for vuln.py — misconfig, nuclei, and exploitable check logic (offline / no network)."""

from __future__ import annotations

import json

import pytest

from srchunter.tools.vuln import (
    _build_url,
    _check_reflection,
    _inject_payload,
    _NUCLEI_CHECKS,
    _AVAILABLE_CHECKS,
    _XSS_PAYLOADS,
    _SQLI_PAYLOADS,
    _SSRF_PAYLOADS,
    _MISCONFIG_SEVERITY,
    _REMEDIATION,
    EXPLOITABLE_ENABLED,
    VULN_TOOLS,
)


# ---------------------------------------------------------------
# Tool definitions — structural validation
# ---------------------------------------------------------------


class TestVulnToolDefinitions:
    """Ensure VULN_TOOLS matches the spec in TOOLS_SPEC.md Phase 3."""

    def test_three_tools_defined(self) -> None:
        names = {t.name for t in VULN_TOOLS}
        assert names == {"check_misconfig", "run_nuclei", "check_exploitable"}

    def test_check_misconfig_input_schema(self) -> None:
        tool = next(t for t in VULN_TOOLS if t.name == "check_misconfig")
        schema = tool.inputSchema
        assert schema["type"] == "object"
        assert "urls" in schema["properties"]
        assert "checks" in schema["properties"]
        assert "urls" in schema["required"]

    def test_run_nuclei_input_schema(self) -> None:
        tool = next(t for t in VULN_TOOLS if t.name == "run_nuclei")
        schema = tool.inputSchema
        assert schema["type"] == "object"
        assert "urls" in schema["properties"]
        assert "severity" in schema["properties"]
        assert "urls" in schema["required"]

    def test_check_exploitable_input_schema(self) -> None:
        tool = next(t for t in VULN_TOOLS if t.name == "check_exploitable")
        schema = tool.inputSchema
        assert schema["type"] == "object"
        assert "vuln_type" in schema["properties"]
        props = schema["properties"]["vuln_type"]
        assert "enum" in props
        assert set(props["enum"]) == {"xss", "sqli", "ssrf"}

    def test_check_exploitable_has_description_warning(self) -> None:
        tool = next(t for t in VULN_TOOLS if t.name == "check_exploitable")
        assert "DISABLED" in tool.description or "默认" in tool.description


# ---------------------------------------------------------------
# check_exploitable — safety constraints
# ---------------------------------------------------------------


class TestExploitableSafety:
    """Verify that check_exploitable respects safety constraints."""

    def test_disabled_by_default(self) -> None:
        """The EXPLOITABLE_ENABLED flag must be False in committed code."""
        assert EXPLOITABLE_ENABLED is False, (
            "check_exploitable must be disabled by default. "
            "Enable only with explicit authorization."
        )

    def test_payloads_are_hardcoded(self) -> None:
        """All verification payloads must be hardcoded constants — not
        constructed from user input at runtime."""
        assert isinstance(_XSS_PAYLOADS, list)
        assert isinstance(_SQLI_PAYLOADS, list)
        assert isinstance(_SSRF_PAYLOADS, list)
        assert len(_XSS_PAYLOADS) > 0
        assert len(_SQLI_PAYLOADS) > 0
        assert len(_SSRF_PAYLOADS) > 0
        # Each entry must be a 2-tuple of (payload, description)
        for entry in _XSS_PAYLOADS:
            assert isinstance(entry, tuple) and len(entry) == 2
        for entry in _SQLI_PAYLOADS:
            assert isinstance(entry, tuple) and len(entry) == 2
        for entry in _SSRF_PAYLOADS:
            assert isinstance(entry, tuple) and len(entry) == 2

    def test_payloads_do_not_execute_commands(self) -> None:
        """No payload should contain command execution patterns."""
        all_payloads = (
            [p[0] for p in _XSS_PAYLOADS]
            + [p[0] for p in _SQLI_PAYLOADS]
            + [p[0] for p in _SSRF_PAYLOADS]
        )
        dangerous = ["cmd.exe", "/bin/bash", "exec(", "os.system", "subprocess", "rm -rf"]
        for payload in all_payloads:
            payload_lower = payload.lower()
            for pattern in dangerous:
                assert pattern not in payload_lower, (
                    f"Payload contains dangerous pattern '{pattern}': {payload!r}"
                )


# ---------------------------------------------------------------
# _inject_payload
# ---------------------------------------------------------------


class TestInjectPayload:
    def test_injects_into_existing_param(self) -> None:
        params = {"q": "test", "page": "1"}
        result = _inject_payload(params, "q", "<script>alert(1)</script>")
        assert result["q"] == "<script>alert(1)</script>"
        assert result["page"] == "1"  # Unchanged

    def test_does_not_mutate_original(self) -> None:
        params = {"q": "test"}
        _inject_payload(params, "q", "PAYLOAD")
        assert params["q"] == "test"  # Original unchanged

    def test_handles_empty_params(self) -> None:
        params: dict[str, str] = {}
        result = _inject_payload(params, "id", "' OR 1=1--")
        assert result["id"] == "' OR 1=1--"
        assert params == {}


# ---------------------------------------------------------------
# _check_reflection
# ---------------------------------------------------------------


class TestCheckReflection:
    def test_xss_reflection_detected(self) -> None:
        """Raw payload in response body should be detected."""
        response = "<div><script>alert(1)</script></div>"
        assert _check_reflection("<script>alert(1)</script>", response, "xss") is True

    def test_xss_partial_reflection(self) -> None:
        """Partial reflection (e.g. alert(1)) should also be caught."""
        response = "<div>alert(1)</div>"
        assert _check_reflection("<img src=x onerror=alert(1)>", response, "xss") is True

    def test_xss_no_reflection(self) -> None:
        """Clean response with no payload reflection."""
        response = "<div>Hello World</div>"
        assert _check_reflection("<script>alert(1)</script>", response, "xss") is False

    def test_sqli_error_detection(self) -> None:
        """SQL error messages in response should be detected."""
        response = "Error: You have an error in your SQL syntax..."
        assert _check_reflection("' OR '1'='1", response, "sqli") is True

    def test_sqli_mysql_fetch_detection(self) -> None:
        response = "Warning: mysql_fetch_array() expects parameter 1..."
        assert _check_reflection("' OR 1=1--", response, "sqli") is True

    def test_sqli_payload_reflection(self) -> None:
        """If payload is reflected, that's also evidence."""
        response = "Search results for: ' OR '1'='1"
        assert _check_reflection("' OR '1'='1", response, "sqli") is True

    def test_sqli_no_indicator(self) -> None:
        response = "No results found."
        assert _check_reflection("' UNION SELECT NULL--", response, "sqli") is False

    def test_ssrf_aws_metadata_detection(self) -> None:
        response = '{"ami-id": "ami-12345678"}'
        assert _check_reflection(
            "http://169.254.169.254/latest/meta-data/", response, "ssrf"
        ) is True

    def test_ssrf_gcp_metadata_detection(self) -> None:
        response = "computeMetadata/instance/id"
        assert _check_reflection(
            "http://metadata.google.internal/", response, "ssrf"
        ) is True

    def test_ssrf_no_indicator(self) -> None:
        response = "Connection refused"
        assert _check_reflection(
            "http://169.254.169.254/latest/meta-data/", response, "ssrf"
        ) is False


# ---------------------------------------------------------------
# _build_url
# ---------------------------------------------------------------


class TestBuildUrl:
    def test_appends_path(self) -> None:
        assert _build_url("https://example.com", "/.git/HEAD") == "https://example.com/.git/HEAD"

    def test_handles_trailing_slash(self) -> None:
        assert _build_url("https://example.com/", "/.git/HEAD") == "https://example.com/.git/HEAD"

    def test_root_path(self) -> None:
        assert _build_url("https://example.com", "/") == "https://example.com/"


# ---------------------------------------------------------------
# check_misconfig — constants
# ---------------------------------------------------------------


class TestMisconfigConstants:
    def test_all_check_types_have_severity(self) -> None:
        """Every misconfig type must have a severity mapping."""
        check_types = {"git_exposure", "ds_store_exposure", "backup_exposure",
                       "cors_misconfig", "directory_listing"}
        for ct in check_types:
            assert ct in _MISCONFIG_SEVERITY, f"Missing severity for {ct}"
            assert _MISCONFIG_SEVERITY[ct] in {"info", "low", "medium", "high", "critical"}

    def test_all_check_types_have_remediation(self) -> None:
        check_types = {"git_exposure", "ds_store_exposure", "backup_exposure",
                       "cors_misconfig", "directory_listing"}
        for ct in check_types:
            assert ct in _REMEDIATION, f"Missing remediation for {ct}"
            assert len(_REMEDIATION[ct]) > 0

    def test_available_checks_set(self) -> None:
        assert _AVAILABLE_CHECKS == {"git", "ds_store", "backup", "cors", "directory_listing"}


# ---------------------------------------------------------------
# run_nuclei — built-in checks
# ---------------------------------------------------------------


class TestNucleiChecks:
    def test_all_checks_have_required_fields(self) -> None:
        required = {"template_id", "name", "severity", "template_category", "paths", "match"}
        for check in _NUCLEI_CHECKS:
            for field in required:
                assert field in check, f"Check {check.get('template_id', '?')} missing '{field}'"

    def test_all_severities_are_valid(self) -> None:
        valid = {"info", "low", "medium", "high", "critical"}
        for check in _NUCLEI_CHECKS:
            assert check["severity"] in valid, (
                f"Invalid severity in {check['template_id']}: {check['severity']}"
            )

    def test_all_categories_are_valid(self) -> None:
        valid = {"cves", "exposures", "misconfig", "tech"}
        for check in _NUCLEI_CHECKS:
            assert check["template_category"] in valid, (
                f"Invalid category in {check['template_id']}: {check['template_category']}"
            )

    def test_template_ids_are_unique(self) -> None:
        ids = [c["template_id"] for c in _NUCLEI_CHECKS]
        assert len(ids) == len(set(ids)), f"Duplicate template_ids found: {ids}"


# ---------------------------------------------------------------
# dispatch_vuln_tool — routing
# ---------------------------------------------------------------


class TestDispatchVulnTool:
    """Smoke-test that dispatch routes correctly (no network calls)."""

    async def test_unknown_tool_raises(self) -> None:
        from srchunter.tools.vuln import dispatch_vuln_tool

        with pytest.raises(ValueError, match="unknown vuln tool"):
            await dispatch_vuln_tool("nonexistent_tool", {})

    async def test_check_misconfig_empty_urls_raises(self) -> None:
        from srchunter.tools.vuln import dispatch_vuln_tool

        with pytest.raises(ValueError, match="urls must not be empty"):
            await dispatch_vuln_tool("check_misconfig", {"urls": []})

    async def test_check_misconfig_bad_check_raises(self) -> None:
        from srchunter.tools.vuln import dispatch_vuln_tool

        with pytest.raises(ValueError, match="unknown check"):
            await dispatch_vuln_tool(
                "check_misconfig",
                {"urls": ["https://example.com"], "checks": ["bad_check"]},
            )

    async def test_run_nuclei_empty_urls_raises(self) -> None:
        from srchunter.tools.vuln import dispatch_vuln_tool

        with pytest.raises(ValueError, match="urls must not be empty"):
            await dispatch_vuln_tool("run_nuclei", {"urls": []})

    async def test_run_nuclei_bad_severity_raises(self) -> None:
        from srchunter.tools.vuln import dispatch_vuln_tool

        with pytest.raises(ValueError, match="unknown severity"):
            await dispatch_vuln_tool(
                "run_nuclei",
                {"urls": ["https://example.com"], "severity": "extreme"},
            )

    async def test_check_exploitable_returns_disabled(self) -> None:
        """When disabled, check_exploitable returns a disabled message."""
        from srchunter.tools.vuln import dispatch_vuln_tool

        result = await dispatch_vuln_tool(
            "check_exploitable",
            {
                "url": "https://example.com/search",
                "vuln_type": "xss",
                "method": "GET",
                "params": {"q": "test"},
            },
        )
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data["is_vulnerable"] is False
        assert "DISABLED" in data.get("error", "")


# ---------------------------------------------------------------
# Validator integration smoke tests
# ---------------------------------------------------------------


class TestValidatorIntegration:
    def test_validate_url_accepts_valid(self) -> None:
        from srchunter.utils.validators import validate_url

        assert validate_url("https://example.com") == "https://example.com"

    def test_validate_url_rejects_ftp(self) -> None:
        from srchunter.utils.validators import validate_url

        with pytest.raises(ValueError):
            validate_url("ftp://example.com")

    def test_validate_url_rejects_localhost(self) -> None:
        from srchunter.utils.validators import validate_url

        with pytest.raises(ValueError):
            validate_url("https://localhost/admin")
