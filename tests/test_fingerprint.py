"""Tests for fingerprint.py — tech_detect, fingerprint_services, identify_waf.

Offline tests cover parsing helpers.  Dispatch tests use example.com
(live HTTP) but skip on network errors so the suite stays fast offline.
"""

from __future__ import annotations

import json

import pytest

from srchunter.tools.fingerprint import (
    FINGERPRINT_TOOLS,
    _detect_server,
    _detect_js_from_html,
    _detect_cms_from_meta,
    _detect_from_cookies,
    _detect_from_x_powered_by,
    _detect_cdn_from_headers,
    _parse_banner,
    dispatch_fingerprint_tool,
)

# ---------------------------------------------------------------
# Server header detection
# ---------------------------------------------------------------


class TestDetectServer:
    def test_nginx(self) -> None:
        result = _detect_server("nginx/1.25.3")
        assert len(result) == 1
        assert result[0]["name"] == "nginx"
        assert result[0]["version"] == "1.25.3"

    def test_apache(self) -> None:
        result = _detect_server("Apache/2.4.57 (Ubuntu)")
        assert len(result) >= 1
        names = {r["name"] for r in result}
        assert "Apache httpd" in names

    def test_cloudflare(self) -> None:
        result = _detect_server("cloudflare")
        assert len(result) == 1
        assert result[0]["name"] == "Cloudflare"

    def test_iis(self) -> None:
        result = _detect_server("Microsoft-IIS/10.0")
        assert len(result) == 1
        assert result[0]["name"] == "Microsoft IIS"

    def test_gws(self) -> None:
        result = _detect_server("gws")
        assert len(result) == 1
        assert result[0]["name"] == "Google Web Server"

    def test_unknown_server(self) -> None:
        result = _detect_server("SomeRandomThing/3.0")
        assert len(result) == 0

    def test_empty_server(self) -> None:
        result = _detect_server("")
        assert len(result) == 0


# ---------------------------------------------------------------
# JavaScript library detection
# ---------------------------------------------------------------


class TestDetectJsFromHtml:
    def test_jquery_detected(self) -> None:
        body = '<script src="/js/jquery-3.7.1.min.js"></script>'
        result = _detect_js_from_html(body)
        names = {r["name"] for r in result}
        assert "jQuery" in names

    def test_react_detected(self) -> None:
        body = '<script src="react-18.2.0.production.min.js"></script>'
        result = _detect_js_from_html(body)
        names = {r["name"] for r in result}
        assert "React" in names

    def test_next_js_detected(self) -> None:
        body = '<script src="/_next/static/chunks/main.js"></script>'
        result = _detect_js_from_html(body)
        names = {r["name"] for r in result}
        assert "Next.js" in names

    def test_vue_detected(self) -> None:
        body = '<script src="https://cdn.example/vue-3.4.0.min.js"></script>'
        result = _detect_js_from_html(body)
        names = {r["name"] for r in result}
        assert "Vue.js" in names

    def test_bootstrap_detected(self) -> None:
        body = '<link href="bootstrap-5.3.0.min.css" rel="stylesheet">'
        result = _detect_js_from_html(body)
        names = {r["name"] for r in result}
        assert "Bootstrap" in names

    def test_no_js_found(self) -> None:
        body = "<html><head></head><body>hello</body></html>"
        result = _detect_js_from_html(body)
        assert len(result) == 0


# ---------------------------------------------------------------
# CMS detection from <meta generator>
# ---------------------------------------------------------------


class TestDetectCmsFromMeta:
    def test_wordpress(self) -> None:
        body = '<meta name="generator" content="WordPress 6.4.2">'
        result = _detect_cms_from_meta(body)
        assert len(result) == 1
        assert result[0]["name"] == "WordPress"

    def test_drupal(self) -> None:
        body = '<meta name="generator" content="Drupal 10">'
        result = _detect_cms_from_meta(body)
        assert len(result) == 1
        assert result[0]["name"] == "Drupal"

    def test_no_meta_generator(self) -> None:
        body = "<html><head></head><body></body></html>"
        result = _detect_cms_from_meta(body)
        assert len(result) == 0


# ---------------------------------------------------------------
# Cookie-based detection
# ---------------------------------------------------------------


class TestDetectFromCookies:
    def test_php_session(self) -> None:
        result = _detect_from_cookies(["PHPSESSID=abc123; path=/"])
        names = {r["name"] for r in result}
        assert "PHP" in names

    def test_java_session(self) -> None:
        result = _detect_from_cookies(["JSESSIONID=xyz; path=/"])
        names = {r["name"] for r in result}
        assert "Java" in names

    def test_aspnet_session(self) -> None:
        result = _detect_from_cookies(["ASP.NET_SessionId=foo"])
        names = {r["name"] for r in result}
        assert "ASP.NET" in names

    def test_laravel_session(self) -> None:
        result = _detect_from_cookies(["laravel_session=bar"])
        names = {r["name"] for r in result}
        assert "Laravel" in names

    def test_no_cookies(self) -> None:
        result = _detect_from_cookies([])
        assert len(result) == 0


# ---------------------------------------------------------------
# X-Powered-By detection
# ---------------------------------------------------------------


class TestDetectFromXPoweredBy:
    def test_php(self) -> None:
        result = _detect_from_x_powered_by("PHP/8.2.0")
        assert len(result) == 1
        assert result[0]["name"] == "PHP"
        assert result[0]["version"] == "8.2.0"

    def test_aspnet(self) -> None:
        result = _detect_from_x_powered_by("ASP.NET")
        assert len(result) == 1
        assert result[0]["name"] == "ASP.NET"

    def test_express(self) -> None:
        result = _detect_from_x_powered_by("Express")
        assert len(result) == 1
        assert result[0]["name"] == "Express"

    def test_empty(self) -> None:
        result = _detect_from_x_powered_by("")
        assert len(result) == 0


# ---------------------------------------------------------------
# CDN detection from headers
# ---------------------------------------------------------------


class TestDetectCdnFromHeaders:
    def test_cloudflare_headers(self) -> None:
        result = _detect_cdn_from_headers({
            "cf-ray": "abc123",
            "cf-cache-status": "HIT",
            "server": "cloudflare",
        })
        names = {r["name"] for r in result}
        assert "Cloudflare" in names

    def test_aws_cloudfront(self) -> None:
        result = _detect_cdn_from_headers({
            "x-amz-cf-id": "abcdef",
            "x-amz-cf-pop": "SEA",
        })
        names = {r["name"] for r in result}
        assert "Amazon CloudFront" in names

    def test_no_cdn(self) -> None:
        result = _detect_cdn_from_headers({
            "server": "nginx",
            "content-type": "text/html",
        })
        assert len(result) == 0


# ---------------------------------------------------------------
# Banner parsing (fingerprint_services)
# ---------------------------------------------------------------


class TestParseBanner:
    def test_ssh_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        assert result["host"] == "10.0.0.1"
        assert result["port"] == 22
        assert result["service"] == "ssh"
        assert "8.9" in (result["version"] or "")

    def test_http_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.0\r\n")
        assert result["host"] == "10.0.0.1"
        assert result["port"] == 80
        assert result["service"] in ("http", "nginx")

    def test_ftp_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 21, b"220 ProFTPD 1.3.5 Server ready.\r\n")
        assert result["host"] == "10.0.0.1"
        assert result["port"] == 21
        assert result["service"] in ("ftp", "ProFTPD")

    def test_empty_banner_fallback(self) -> None:
        result = _parse_banner("10.0.0.1", 3306, b"")
        assert result["host"] == "10.0.0.1"
        assert result["port"] == 3306
        assert result["service"] == "mysql"  # from port map

    def test_unknown_port_empty_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 12345, b"\x00\x01")
        assert result["service"] == "unknown"

    def test_mysql_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 3306,
            b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"mysql_native_password\x00")
        # The banner contains mysql_native_password — should match.
        assert result["service"] == "mysql"

    def test_smtp_banner(self) -> None:
        result = _parse_banner("10.0.0.1", 25,
            b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n")
        assert result["service"] in ("smtp", "Postfix")


# ---------------------------------------------------------------
# Dispatch — tech_detect (live HTTP)
# ---------------------------------------------------------------


class TestDispatchTechDetect:
    async def test_detect_example_com(self) -> None:
        result = await dispatch_fingerprint_tool(
            "tech_detect",
            {"urls": ["https://example.com"]},
        )
        assert len(result) == 1
        assert result[0].type == "text"
        data = json.loads(result[0].text)
        assert "results" in data
        assert len(data["results"]) == 1
        item = data["results"][0]
        assert item["confidence"] in ("high", "medium", "low")
        assert "web_servers" in item["tech_stack"]
        assert "javascript" in item["tech_stack"]
        assert "cdn" in item["tech_stack"]

    async def test_empty_urls_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_fingerprint_tool("tech_detect", {"urls": []})

    async def test_invalid_url_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_fingerprint_tool("tech_detect", {"urls": ["not-a-valid-url"]})


# ---------------------------------------------------------------
# Dispatch — identify_waf (live HTTP)
# ---------------------------------------------------------------


class TestDispatchIdentifyWaf:
    async def test_identify_example_com(self) -> None:
        result = await dispatch_fingerprint_tool(
            "identify_waf",
            {"urls": ["https://example.com"]},
        )
        assert len(result) == 1
        assert result[0].type == "text"
        data = json.loads(result[0].text)
        assert "results" in data
        assert len(data["results"]) == 1
        item = data["results"][0]
        # example.com has no WAF — waf_name may be None.
        assert "waf_name" in item
        assert item["confidence"] in ("high", "medium", "low")

    async def test_empty_urls_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_fingerprint_tool("identify_waf", {"urls": []})


# ---------------------------------------------------------------
# Dispatch — fingerprint_services (requires live network)
# ---------------------------------------------------------------


class TestDispatchFingerprintServices:
    async def test_fingerprint_example_web(self) -> None:
        result = await dispatch_fingerprint_tool(
            "fingerprint_services",
            {"hosts": ["example.com"], "ports": [80, 443]},
        )
        assert len(result) == 1
        assert result[0].type == "text"
        data = json.loads(result[0].text)
        assert "services" in data
        assert len(data["services"]) == 2  # 80 + 443
        for svc in data["services"]:
            assert "host" in svc
            assert "port" in svc
            assert "service" in svc
            assert "version" in svc
            assert "cpe" in svc

    async def test_empty_hosts_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_fingerprint_tool("fingerprint_services", {"hosts": [], "ports": [80]})

    async def test_empty_ports_raises(self) -> None:
        with pytest.raises(ValueError):
            await dispatch_fingerprint_tool("fingerprint_services", {"hosts": ["example.com"], "ports": []})


# ---------------------------------------------------------------
# Dispatch — unknown tool
# ---------------------------------------------------------------


class TestDispatchErrors:
    async def test_unknown_tool_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown fingerprint tool"):
            await dispatch_fingerprint_tool("nonexistent", {})


# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------


class TestToolDefinitions:
    def test_all_tools_have_schema(self) -> None:
        assert len(FINGERPRINT_TOOLS) == 3
        for tool in FINGERPRINT_TOOLS:
            assert tool.name
            assert tool.description
            assert tool.inputSchema["type"] == "object"
            assert "properties" in tool.inputSchema

    def test_tool_names(self) -> None:
        names = {t.name for t in FINGERPRINT_TOOLS}
        assert names == {"tech_detect", "fingerprint_services", "identify_waf"}
