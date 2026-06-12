"""Tests for recon.py — subdomain_enum tool logic (offline / no network)."""

from __future__ import annotations

import pytest

from srchunter.tools.recon import _parse_crtsh_entries


# ---------------------------------------------------------------
# _parse_crtsh_entries
# ---------------------------------------------------------------


class TestParseCrtshEntries:
    """Unit tests for crt.sh response parsing — no network needed."""

    def test_empty_response(self) -> None:
        result = _parse_crtsh_entries([], "example.com")
        assert result == []

    def test_single_common_name(self) -> None:
        raw = [{"common_name": "www.example.com", "name_value": ""}]
        result = _parse_crtsh_entries(raw, "example.com")
        assert len(result) == 1
        assert result[0]["domain"] == "www.example.com"

    def test_name_value_with_newlines(self) -> None:
        raw = [
            {
                "common_name": "example.com",
                "name_value": "www.example.com\nmail.example.com\ndev.example.com",
            }
        ]
        result = _parse_crtsh_entries(raw, "example.com")
        domains = {r["domain"] for r in result}
        assert "example.com" in domains
        assert "www.example.com" in domains
        assert "mail.example.com" in domains
        assert "dev.example.com" in domains

    def test_deduplication(self) -> None:
        """Same domain appearing across multiple certs should only
        appear once in output."""
        raw = [
            {"common_name": "api.example.com"},
            {"common_name": "api.example.com"},
            {"name_value": "api.example.com\ncdn.example.com"},
        ]
        result = _parse_crtsh_entries(raw, "example.com")
        domains = [r["domain"] for r in result]
        assert domains == ["api.example.com", "cdn.example.com"]

    def test_wildcard_excluded(self) -> None:
        """Wildcard entries (*.example.com) represent a set of names,
        not a concrete host, so we skip them."""
        raw = [{"common_name": "*.example.com"}]
        result = _parse_crtsh_entries(raw, "example.com")
        assert result == []

    def test_casing_normalised(self) -> None:
        raw = [{"common_name": "WWW.Example.COM"}]
        result = _parse_crtsh_entries(raw, "example.com")
        assert result[0]["domain"] == "www.example.com"

    def test_whitespace_stripped(self) -> None:
        raw = [{"name_value": "  admin.example.com  \n  "}]
        result = _parse_crtsh_entries(raw, "example.com")
        assert len(result) == 1
        assert result[0]["domain"] == "admin.example.com"

    def test_missing_fields(self) -> None:
        """Entries without common_name or name_value should be skipped
        gracefully."""
        raw = [{"issuer": "Let's Encrypt"}]  # no domain fields
        result = _parse_crtsh_entries(raw, "example.com")
        assert result == []

    def test_unrelated_domains_filtered(self) -> None:
        """Domains not belonging to the target should be filtered out.

        crt.sh returns SAN entries that may include names from other
        organisations that share a CDN or TLS certificate.
        """
        raw = [
            {"common_name": "www.example.com"},
            {"name_value": "www.example.com\nsni.cloudflaressl.com\ncdn.other.org"},
        ]
        result = _parse_crtsh_entries(raw, "example.com")
        domains = {r["domain"] for r in result}
        assert "www.example.com" in domains
        assert "sni.cloudflaressl.com" not in domains
        assert "cdn.other.org" not in domains
        assert len(result) == 1


# ---------------------------------------------------------------
# validate_domain (import smoke test — heavy validation is in
# validators.py but we exercise the integration here)
# ---------------------------------------------------------------


class TestValidateDomain:
    def test_valid_domain_passes(self) -> None:
        from srchunter.utils.validators import validate_domain

        assert validate_domain("example.com") == "example.com"

    def test_dot_stripped(self) -> None:
        from srchunter.utils.validators import validate_domain

        assert validate_domain("example.com.") == "example.com"

    def test_blocked_localhost_rejected(self) -> None:
        from srchunter.utils.validators import validate_domain

        with pytest.raises(ValueError, match="blocked"):
            validate_domain("localhost")

    def test_blocked_internal_tld_rejected(self) -> None:
        from srchunter.utils.validators import validate_domain

        with pytest.raises(ValueError, match="blocked"):
            validate_domain("company.local")

    def test_empty_string_rejected(self) -> None:
        from srchunter.utils.validators import validate_domain

        with pytest.raises(ValueError):
            validate_domain("")
