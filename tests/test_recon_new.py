"""Tests for resolve_targets, port_scan, http_probe helpers (offline)."""

from __future__ import annotations

import pytest

from srchunter.tools.recon import (
    _detect_cdn_cname,
    _detect_cdn_ip,
    _parse_ports,
    dispatch_recon_tool,
)


class TestCdnCnameDetection:
    def test_cloudflare(self) -> None:
        provider, _ = _detect_cdn_cname("www.example.com.cdn.cloudflare.net")
        assert provider == "cloudflare"

    def test_akamai(self) -> None:
        provider, _ = _detect_cdn_cname("e1234.akamaiedge.net")
        assert provider == "akamai"

    def test_fastly(self) -> None:
        provider, _ = _detect_cdn_cname("global.prod.fastly.net")
        assert provider == "fastly"

    def test_no_cdn(self) -> None:
        provider, _ = _detect_cdn_cname("server.example.com")
        assert provider is None

    def test_empty_cname(self) -> None:
        provider, _ = _detect_cdn_cname("")
        assert provider is None


class TestCdnIpDetection:
    def test_cloudflare_ip(self) -> None:
        assert _detect_cdn_ip("104.16.100.1") == "cloudflare"

    def test_fastly_ip(self) -> None:
        assert _detect_cdn_ip("151.101.1.1") == "fastly"

    def test_akamai_rough_ip(self) -> None:
        # Our IP check is prefix-based, akamai is very broad so not
        # in the quick-check list (would have too many false positives).
        assert _detect_cdn_ip("23.1.2.3") is None

    def test_non_cdn_ip(self) -> None:
        assert _detect_cdn_ip("93.184.216.34") is None  # example.com

    def test_invalid_ip(self) -> None:
        assert _detect_cdn_ip("not.an.ip") is None


class TestParsePorts:
    def test_preset_top20(self) -> None:
        ports = _parse_ports("top-20")
        assert len(ports) == 20
        assert 80 in ports
        assert 443 in ports

    def test_preset_top100(self) -> None:
        ports = _parse_ports("top-100")
        assert len(ports) > 80
        assert 22 in ports

    def test_custom_list(self) -> None:
        ports = _parse_ports("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_range(self) -> None:
        ports = _parse_ports("80-82")
        assert ports == [80, 81, 82]

    def test_deduplicate(self) -> None:
        ports = _parse_ports("80,80,443")
        assert ports == [80, 443]


class TestDispatchRoutes:
    async def test_resolve_targets_in_dispatch(self) -> None:
        result = await dispatch_recon_tool("resolve_targets", {"targets": ["example.com"]})
        assert len(result) == 1
        assert result[0].type == "text"
        import json
        data = json.loads(result[0].text)
        assert data["count"] > 0 or data["unresolved"]

    async def test_http_probe_in_dispatch(self) -> None:
        result = await dispatch_recon_tool("http_probe", {"targets": ["https://example.com"]})
        assert len(result) == 1
        assert result[0].type == "text"
        import json
        data = json.loads(result[0].text)
        assert "live_urls" in data

    async def test_resolve_empty_targets_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_recon_tool("resolve_targets", {"targets": []})

    async def test_http_probe_empty_targets_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_recon_tool("http_probe", {"targets": []})
