"""Vulnerability detection tools — misconfig checks, nuclei scanning, exploit verification.

Tool list (ordered by typical workflow):
    check_misconfig   — detect common misconfigurations (.git, CORS, backups, ...)
    run_nuclei        — run nuclei templates against live URLs
    check_exploitable — send minimal verification payloads (DISABLED by default)
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx
from mcp.types import Tool, TextContent

from ..engine.cache import get_cache
from ..utils.validators import validate_url

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

REQUEST_TIMEOUT = 15.0
MAX_RETRIES = 1
RETRY_BACKOFF = 1.0
USER_AGENT = "srchunter-mcp/0.2.0"

# --- check_exploitable safety controls ---
# This tool is DISABLED by default per SRC Hunter safety policy.
# Enable only when the user has explicit authorization to perform
# active vulnerability verification against the target.
EXPLOITABLE_ENABLED: bool = False

# Hardcoded verification payloads — models CANNOT supply custom payloads.
# Each entry: (payload, test_description)
_XSS_PAYLOADS: list[tuple[str, str]] = [
    ("<script>alert(1)</script>", "Basic script tag injection"),
    ('"><script>alert(1)</script>', "Attribute-break + script injection"),
    ("<img src=x onerror=alert(1)>", "IMG onerror handler"),
    ("javascript:alert(1)", "javascript: protocol handler"),
]

_SQLI_PAYLOADS: list[tuple[str, str]] = [
    ("' OR '1'='1", "Basic OR tautology"),
    ("' OR 1=1--", "OR tautology with comment"),
    ("' UNION SELECT NULL--", "UNION SELECT probe"),
    ("'; WAITFOR DELAY '0:0:5'--", "Time-based blind (MSSQL)"),
]

_SSRF_PAYLOADS: list[tuple[str, str]] = [
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint"),
    ("http://metadata.google.internal/", "GCP metadata endpoint"),
]

_AVAILABLE_CHECKS: frozenset[str] = frozenset(
    {"git", "ds_store", "backup", "cors", "directory_listing"}
)

# Severity mapping for misconfig types
_MISCONFIG_SEVERITY: dict[str, str] = {
    "git_exposure": "high",
    "ds_store_exposure": "medium",
    "backup_exposure": "medium",
    "cors_misconfig": "low",
    "directory_listing": "low",
}

# Remediation advice per misconfig type
_REMEDIATION: dict[str, str] = {
    "git_exposure": "在 Web 服务器配置中禁止访问 .git 目录，确保部署流程不包含版本控制元数据",
    "ds_store_exposure": "在 Web 服务器配置中禁止访问 .DS_Store 文件，macOS 开发环境应配置 .gitignore",
    "backup_exposure": "禁止通过 Web 服务器访问备份文件（.bak, .old, .swp 等），将备份存放在非 Web 目录",
    "cors_misconfig": "将 Access-Control-Allow-Origin 限制为受信任的域名，避免使用 * 通配符",
    "directory_listing": "在 Web 服务器配置中关闭目录浏览功能（nginx: autoindex off, Apache: Options -Indexes）",
}

# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------

VULN_TOOLS = [
    Tool(
        name="check_misconfig",
        description=(
            "Detect common security misconfigurations on target URLs. "
            "Checks include: .git exposure, .DS_Store files, backup files "
            "(.bak/.old/.swp), CORS misconfiguration, and directory listing. "
            "Use this after http_probe to find low-hanging vulnerabilities "
            "on live web servers."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of live URLs to check, e.g. ['https://www.example.com']",
                },
                "checks": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["git", "ds_store", "backup", "cors", "directory_listing"],
                    },
                    "description": (
                        "Which misconfig checks to run. Available: "
                        "git, ds_store, backup, cors, directory_listing. "
                        "Defaults to all checks if not specified."
                    ),
                },
            },
            "required": ["urls"],
        },
    ),
    Tool(
        name="run_nuclei",
        description=(
            "Run vulnerability detection using nuclei-style template checks. "
            "Currently uses a built-in lightweight Python check suite; full "
            "nuclei integration requires the external nuclei binary. Supports "
            "filtering by severity level (info, low, medium, high, critical)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs to scan, e.g. ['https://www.example.com']",
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Template categories to run. Available: "
                        "cves, exposures, misconfig, tech. Defaults to all."
                    ),
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Comma-separated severity filter. Example: 'medium,critical,high'. "
                        "Available: info, low, medium, high, critical."
                    ),
                },
            },
            "required": ["urls"],
        },
    ),
    Tool(
        name="check_exploitable",
        description=(
            "⚠️ DISABLED by default — requires explicit authorization. "
            "Send minimal, hardcoded verification payloads to confirm a "
            "suspected vulnerability is actually exploitable. Supports XSS, "
            "SQLi, and SSRF verification. Payloads are locked in code — "
            "models cannot supply custom payloads. Only GET/POST methods "
            "are supported. No command execution, file writes, or sensitive "
            "path reads are performed."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL with the suspected vulnerable endpoint.",
                },
                "vuln_type": {
                    "type": "string",
                    "enum": ["xss", "sqli", "ssrf"],
                    "description": "Vulnerability type to verify: xss, sqli, or ssrf.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method to use for the verification request.",
                },
                "params": {
                    "type": "object",
                    "description": (
                        "Query string or form parameters to inject payloads into. "
                        "Keys are parameter names, values are placeholder values "
                        "that will be replaced with verification payloads. "
                        "Example: {\"q\": \"test\", \"id\": \"1\"}"
                    ),
                },
            },
            "required": ["url", "vuln_type", "params"],
        },
    ),
]

# ---------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------


async def _http_get(
    client: httpx.AsyncClient,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    """Wrapper that adds User-Agent and retries on transient errors."""
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", USER_AGENT)
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)

    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await client.get(url, **kwargs)
            return resp
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1))
        except Exception as exc:
            last_error = exc
            break

    raise RuntimeError(
        f"HTTP request to {url!r} failed after {MAX_RETRIES + 1} attempts: {last_error}"
    )


def _build_url(base: str, path: str) -> str:
    """Append a path to a base URL, handling trailing slashes."""
    base = base.rstrip("/")
    return f"{base}{path}"


# ---------------------------------------------------------------
# check_misconfig — individual check functions
# ---------------------------------------------------------------


async def _check_git_exposure(
    client: httpx.AsyncClient, url: str
) -> list[dict[str, Any]]:
    """Check for .git directory exposure."""
    findings: list[dict[str, Any]] = []
    head_url = _build_url(url, "/.git/HEAD")
    try:
        resp = await _http_get(client, head_url, follow_redirects=False)
        if resp.status_code == 200 and "ref:" in resp.text.lower():
            findings.append(
                {
                    "url": url,
                    "type": "git_exposure",
                    "severity": _MISCONFIG_SEVERITY["git_exposure"],
                    "description": ".git 目录可通过 /.git/HEAD 访问",
                    "evidence": resp.text.strip()[:200],
                    "remediation": _REMEDIATION["git_exposure"],
                }
            )
    except RuntimeError:
        pass  # Connection failed — not a finding
    return findings


async def _check_ds_store(
    client: httpx.AsyncClient, url: str
) -> list[dict[str, Any]]:
    """Check for .DS_Store file exposure."""
    findings: list[dict[str, Any]] = []
    ds_url = _build_url(url, "/.DS_Store")
    try:
        resp = await _http_get(client, ds_url, follow_redirects=False)
        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append(
                {
                    "url": url,
                    "type": "ds_store_exposure",
                    "severity": _MISCONFIG_SEVERITY["ds_store_exposure"],
                    "description": ".DS_Store 文件可通过 Web 公开访问，可能泄露目录结构信息",
                    "evidence": f"HTTP {resp.status_code}, 内容长度: {len(resp.content)} bytes",
                    "remediation": _REMEDIATION["ds_store_exposure"],
                }
            )
    except RuntimeError:
        pass
    return findings


async def _check_backup_files(
    client: httpx.AsyncClient, url: str
) -> list[dict[str, Any]]:
    """Check for exposed backup / editor temp files."""
    findings: list[dict[str, Any]] = []
    # Common backup / temp extensions applied to common filenames
    candidates = [
        "/index.html.bak",
        "/index.html.old",
        "/index.html.swp",
        "/index.php.bak",
        "/index.php.old",
        "/.index.html.swp",
        "/config.php.bak",
        "/config.php.old",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/web.config.bak",
        "/web.config.old",
        "/app.js.bak",
        "/app.js.old",
    ]
    for path in candidates:
        check_url = _build_url(url, path)
        try:
            resp = await _http_get(client, check_url, follow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append(
                    {
                        "url": url,
                        "type": "backup_exposure",
                        "severity": _MISCONFIG_SEVERITY["backup_exposure"],
                        "description": f"备份/临时文件可通过 Web 访问: {path}",
                        "evidence": f"{check_url} → HTTP {resp.status_code}, {len(resp.content)} bytes",
                        "remediation": _REMEDIATION["backup_exposure"],
                    }
                )
                break  # One finding per URL for backup category
        except RuntimeError:
            continue
    return findings


async def _check_cors(
    client: httpx.AsyncClient, url: str
) -> list[dict[str, Any]]:
    """Check for overly permissive CORS configuration."""
    findings: list[dict[str, Any]] = []
    try:
        # Send a cross-origin-style request to check CORS headers
        resp = await _http_get(
            client,
            url,
            headers={"Origin": "https://evil.example.com"},
            follow_redirects=False,
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            findings.append(
                {
                    "url": url,
                    "type": "cors_misconfig",
                    "severity": _MISCONFIG_SEVERITY["cors_misconfig"],
                    "description": "CORS 配置为 Access-Control-Allow-Origin: * (允许任意来源)",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "remediation": _REMEDIATION["cors_misconfig"],
                }
            )
        elif acao == "https://evil.example.com" and acac.lower() == "true":
            findings.append(
                {
                    "url": url,
                    "type": "cors_misconfig",
                    "severity": _MISCONFIG_SEVERITY["cors_misconfig"],
                    "description": f"CORS 反射了 Origin 头且允许 credentials: {acao}",
                    "evidence": f"Origin反射: {acao}, Credentials: {acac}",
                    "remediation": _REMEDIATION["cors_misconfig"],
                }
            )
    except RuntimeError:
        pass
    return findings


async def _check_directory_listing(
    client: httpx.AsyncClient, url: str
) -> list[dict[str, Any]]:
    """Check for directory listing / browsing enabled."""
    findings: list[dict[str, Any]] = []
    indicators = [
        "Index of /",
        "Directory Listing",
        "<title>Index of",
        "Parent Directory</a>",
        "[To Parent Directory]",
    ]
    test_paths = ["/images/", "/uploads/", "/assets/", "/css/", "/js/"]
    for path in test_paths:
        check_url = _build_url(url, path)
        try:
            resp = await _http_get(client, check_url, follow_redirects=False)
            if resp.status_code == 200:
                text_lower = resp.text.lower()[:1024]
                for indicator in indicators:
                    if indicator.lower() in text_lower:
                        findings.append(
                            {
                                "url": url,
                                "type": "directory_listing",
                                "severity": _MISCONFIG_SEVERITY["directory_listing"],
                                "description": f"目录浏览功能开启: {path}",
                                "evidence": f"{check_url} → HTTP 200, 检测到 '{indicator}' 特征",
                                "remediation": _REMEDIATION["directory_listing"],
                            }
                        )
                        return findings  # One finding per URL
        except RuntimeError:
            continue
    return findings


# Handler registry for check types
_CHECK_HANDLERS: dict[str, Any] = {
    "git": _check_git_exposure,
    "ds_store": _check_ds_store,
    "backup": _check_backup_files,
    "cors": _check_cors,
    "directory_listing": _check_directory_listing,
}

# ---------------------------------------------------------------
# check_misconfig handler
# ---------------------------------------------------------------


async def handle_check_misconfig(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute check_misconfig and return MCP TextContent result."""
    raw_urls: list[str] = arguments["urls"]
    if not raw_urls:
        raise ValueError("urls must not be empty")

    urls = [validate_url(u) for u in raw_urls]
    requested_checks: list[str] = arguments.get("checks", list(_AVAILABLE_CHECKS))

    # Validate check names
    for check in requested_checks:
        if check not in _AVAILABLE_CHECKS:
            raise ValueError(
                f"unknown check: {check!r}, available: {sorted(_AVAILABLE_CHECKS)}"
            )

    # --- cache check ---
    cache = get_cache()
    cache_key = f"check_misconfig:{':'.join(sorted(urls))}:{':'.join(sorted(requested_checks))}"
    cached = cache.get(cache_key)
    if cached is not None:
        import json as _json
        return [TextContent(type="text", text=_json.dumps(cached, indent=2, ensure_ascii=False))]

    # --- execute checks ---
    t0 = asyncio.get_event_loop().time()
    all_findings: list[dict[str, Any]] = []

    async with httpx.AsyncClient() as client:
        for url in urls:
            for check_name in requested_checks:
                handler = _CHECK_HANDLERS.get(check_name)
                if handler is None:
                    continue
                findings = await handler(client, url)
                all_findings.extend(findings)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)

    result: dict[str, Any] = {
        "findings": all_findings,
        "total_checks": len(requested_checks),
        "findings_count": len(all_findings),
        "elapsed": elapsed,
    }

    cache.set(cache_key, result.copy())
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# run_nuclei handler — built-in lightweight checks
# ---------------------------------------------------------------

# Built-in template-like checks that don't require external nuclei binary.
# These will be replaced with real nuclei calls via engine/executor.py when ready.
_NUCLEI_CHECKS: list[dict[str, Any]] = [
    {
        "template_id": "exposed-git-head",
        "name": "Exposed .git/HEAD",
        "severity": "medium",
        "template_category": "exposures",
        "paths": ["/.git/HEAD"],
        "match": "ref:",
    },
    {
        "template_id": "exposed-env-file",
        "name": "Exposed .env File",
        "severity": "high",
        "template_category": "exposures",
        "paths": ["/.env", "/.env.local", "/.env.production"],
        "match": None,  # Any 200 response
    },
    {
        "template_id": "exposed-config-json",
        "name": "Exposed config.json",
        "severity": "low",
        "template_category": "misconfig",
        "paths": ["/config.json", "/config.js", "/settings.json"],
        "match": None,
    },
    {
        "template_id": "phpinfo-exposed",
        "name": "Exposed phpinfo()",
        "severity": "low",
        "template_category": "misconfig",
        "paths": ["/phpinfo.php", "/info.php", "/test.php", "/php_info.php"],
        "match": "<title>phpinfo()</title>",
    },
    {
        "template_id": "debug-endpoints",
        "name": "Debug Endpoints Exposed",
        "severity": "medium",
        "template_category": "misconfig",
        "paths": [
            "/debug",
            "/debug/",
            "/actuator",
            "/actuator/health",
            "/.vscode/sftp.json",
        ],
        "match": None,
    },
    {
        "template_id": "swagger-ui-exposed",
        "name": "Swagger UI Exposed",
        "severity": "low",
        "template_category": "misconfig",
        "paths": [
            "/swagger-ui.html",
            "/swagger/index.html",
            "/api-docs",
            "/api/docs",
            "/swagger.json",
        ],
        "match": None,
    },
    {
        "template_id": "backup-files-exposed",
        "name": "Backup / Temp Files Exposed",
        "severity": "medium",
        "template_category": "exposures",
        "paths": [
            "/backup.zip",
            "/backup.tar.gz",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/db_backup.sql",
            "/site.tar.gz",
            "/www.tar.gz",
            "/archive.zip",
        ],
        "match": None,
    },
    {
        "template_id": "clickjacking-missing-header",
        "name": "Missing X-Frame-Options Header",
        "severity": "low",
        "template_category": "misconfig",
        "paths": [""],  # Check root
        "match": None,
        "header_check": "x-frame-options",  # Check for missing header
    },
    {
        "template_id": "hsts-missing-header",
        "name": "Missing Strict-Transport-Security Header",
        "severity": "low",
        "template_category": "misconfig",
        "paths": [""],
        "match": None,
        "https_only": True,
        "header_check": "strict-transport-security",
    },
    {
        "template_id": "csp-missing-header",
        "name": "Missing Content-Security-Policy Header",
        "severity": "info",
        "template_category": "misconfig",
        "paths": [""],
        "match": None,
        "header_check": "content-security-policy",
    },
]


async def handle_run_nuclei(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute run_nuclei and return MCP TextContent result.

    Currently uses built-in lightweight checks. When engine/executor.py
    is available, this will delegate to the real nuclei binary for
    comprehensive template-based scanning.
    """
    raw_urls: list[str] = arguments["urls"]
    if not raw_urls:
        raise ValueError("urls must not be empty")

    urls = [validate_url(u) for u in raw_urls]
    templates: list[str] = arguments.get("templates", [])
    severity_filter: str = arguments.get("severity", "")

    allowed_severities: set[str] | None = None
    if severity_filter:
        allowed_severities = {
            s.strip().lower()
            for s in severity_filter.split(",")
            if s.strip()
        }
        valid_severities = {"info", "low", "medium", "high", "critical"}
        unknown = allowed_severities - valid_severities
        if unknown:
            raise ValueError(
                f"unknown severity value(s): {sorted(unknown)}, "
                f"valid: {sorted(valid_severities)}"
            )

    allowed_templates: set[str] | None = None
    if templates:
        allowed_templates = {t.strip().lower() for t in templates}

    # --- cache check ---
    cache = get_cache()
    cache_key = (
        f"run_nuclei:{':'.join(sorted(urls))}:"
        f"{':'.join(sorted(templates)) if templates else 'all'}:"
        f"{severity_filter or 'all'}"
    )
    cached = cache.get(cache_key)
    if cached is not None:
        import json as _json
        return [TextContent(type="text", text=_json.dumps(cached, indent=2, ensure_ascii=False))]

    # --- filter checks ---
    active_checks = _NUCLEI_CHECKS
    if allowed_templates:
        active_checks = [
            c for c in active_checks if c["template_category"] in allowed_templates
        ]
    if allowed_severities:
        active_checks = [
            c for c in active_checks if c["severity"] in allowed_severities
        ]

    # --- execute ---
    t0 = asyncio.get_event_loop().time()
    all_findings: list[dict[str, Any]] = []

    async with httpx.AsyncClient() as client:
        for url in urls:
            for check in active_checks:
                for path in check["paths"]:
                    check_url = url.rstrip("/") + path if path else url
                    try:
                        resp = await _http_get(
                            client, check_url, follow_redirects=False
                        )
                    except RuntimeError:
                        continue

                    is_match = False

                    # Header absence check (e.g., missing X-Frame-Options)
                    if "header_check" in check:
                        hdr = check["header_check"]
                        if resp.headers.get(hdr) is None:
                            # For https_only checks, only flag HTTPS URLs
                            if check.get("https_only") and not url.startswith("https://"):
                                continue
                            is_match = True

                    # Content match check
                    elif check["match"] is not None:
                        if check["match"].lower() in resp.text.lower():
                            is_match = True
                    else:
                        # Any 200 response is a match
                        if 200 <= resp.status_code < 300:
                            is_match = True

                    if is_match:
                        all_findings.append(
                            {
                                "url": url,
                                "template_id": check["template_id"],
                                "name": check["name"],
                                "severity": check["severity"],
                                "matched_at": check_url,
                                "description": (
                                    f"模板 {check['template_id']} 在 {check_url} 匹配成功 "
                                    f"(HTTP {resp.status_code})"
                                ),
                                "remediation": "检查并修复相关配置，限制敏感路径的公开访问",
                            }
                        )
                        break  # One finding per check per URL

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)

    result: dict[str, Any] = {
        "findings": all_findings,
        "findings_count": len(all_findings),
        "elapsed": elapsed,
    }

    cache.set(cache_key, result.copy())
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# check_exploitable handler (DISABLED by default)
# ---------------------------------------------------------------

# Hardcoded payload map — models cannot inject custom payloads
_VULN_PAYLOADS: dict[str, list[tuple[str, str]]] = {
    "xss": _XSS_PAYLOADS,
    "sqli": _SQLI_PAYLOADS,
    "ssrf": _SSRF_PAYLOADS,
}


def _inject_payload(
    params: dict[str, Any], param_name: str, payload: str
) -> dict[str, Any]:
    """Return a copy of params with payload injected into param_name."""
    injected = dict(params)
    injected[param_name] = payload
    return injected


def _check_reflection(
    payload: str, response_text: str, vuln_type: str
) -> bool:
    """Check if the payload is reflected in the response body."""
    if vuln_type == "xss":
        # For XSS, check if the payload appears unescaped (rough heuristic)
        # We look for the raw payload or HTML-entity-encoded variants
        if payload in response_text:
            return True
        # Check for common partial reflections
        if "<script>alert(1)</script>" in response_text:
            return True
        if "alert(1)" in response_text:
            return True
    elif vuln_type == "sqli":
        # For SQLi, look for SQL error messages or data leakage patterns
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "postgresql",
            "sqlite",
            "unclosed quotation mark",
            "syntax error",
            "column",
            "table",
        ]
        text_lower = response_text.lower()
        for err in sql_errors:
            if err in text_lower:
                return True
        # Also check for payload reflection
        if payload in response_text:
            return True
    elif vuln_type == "ssrf":
        # For SSRF, check if metadata-like content is in the response
        ssrf_indicators = [
            "ami-id",
            "instance-id",
            "security-groups",
            "meta-data",
            "computemetadata",
        ]
        text_lower = response_text.lower()
        for ind in ssrf_indicators:
            if ind in text_lower:
                return True

    return False


async def handle_check_exploitable(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute check_exploitable and return MCP TextContent result.

    ⚠️ This tool is DISABLED by default (EXPLOITABLE_ENABLED = False).
    It sends minimal verification payloads using only hardcoded payloads
    defined in this module. Models cannot supply custom payloads.
    """
    if not EXPLOITABLE_ENABLED:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "error": "check_exploitable is DISABLED",
                        "message": (
                            "主动漏洞验证功能默认关闭。如需启用，请将 "
                            "src/srchunter/tools/vuln.py 中的 "
                            "EXPLOITABLE_ENABLED 设置为 True，并确保已获得"
                            "对目标进行安全测试的明确授权。"
                        ),
                        "is_vulnerable": False,
                        "confidence": "none",
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
            )
        ]

    url = validate_url(arguments["url"])
    vuln_type: str = arguments["vuln_type"].lower()
    method: str = arguments.get("method", "GET").upper()
    params: dict[str, Any] = arguments["params"]

    if vuln_type not in _VULN_PAYLOADS:
        raise ValueError(
            f"unsupported vuln_type: {vuln_type!r}, "
            f"available: {sorted(_VULN_PAYLOADS)}"
        )

    if method not in ("GET", "POST"):
        raise ValueError(
            f"unsupported HTTP method: {method!r}, only GET and POST are allowed"
        )

    payloads = _VULN_PAYLOADS[vuln_type]

    async with httpx.AsyncClient() as client:
        for param_name, param_value in params.items():
            for payload, desc in payloads:
                injected_params = _inject_payload(params, param_name, payload)

                try:
                    if method == "GET":
                        resp = await client.get(
                            url,
                            params=injected_params,
                            headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT,
                            follow_redirects=False,
                        )
                    else:  # POST
                        resp = await client.post(
                            url,
                            data=injected_params,
                            headers={"User-Agent": USER_AGENT},
                            timeout=REQUEST_TIMEOUT,
                            follow_redirects=False,
                        )
                except httpx.HTTPError:
                    continue  # Connection errors are not vulnerability evidence

                request_dump = (
                    f"{method} {url} HTTP/1.1\n"
                    f"Host: {resp.request.url.host}\n"
                    f"Params: {json.dumps(injected_params)}"
                )
                response_snippet = resp.text[:1000]

                is_vuln = _check_reflection(payload, resp.text, vuln_type)

                if is_vuln:
                    confidence = "high"
                else:
                    confidence = "low"
                    # Continue to next payload — maybe another works
                    continue

                poc = (
                    f"{method} {url}"
                    f"{'?' + '&'.join(f'{k}={v}' for k, v in injected_params.items()) if method == 'GET' else ''}"
                    f" HTTP/1.1"
                )

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(
                            {
                                "is_vulnerable": True,
                                "confidence": confidence,
                                "vuln_type": vuln_type,
                                "poc": poc,
                                "evidence": (
                                    f"payload '{payload}' ({desc}) 在响应中反射/触发, "
                                    f"参数: {param_name}"
                                ),
                                "request_dump": request_dump,
                                "response_snippet": response_snippet,
                            },
                            indent=2,
                            ensure_ascii=False,
                        ),
                    )
                ]

    # No payload triggered a vulnerability
    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "is_vulnerable": False,
                    "confidence": "medium",
                    "vuln_type": vuln_type,
                    "poc": None,
                    "evidence": f"所有 {len(payloads)} 个 {vuln_type} 载荷均未触发漏洞特征",
                    "request_dump": (
                        f"{method} {url} — 已尝试 {len(payloads)} 个载荷, "
                        f"{len(params)} 个参数"
                    ),
                    "response_snippet": None,
                },
                indent=2,
                ensure_ascii=False,
            ),
        )
    ]


# ---------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------


async def dispatch_vuln_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Route a vuln tool call to the correct handler."""
    if name == "check_misconfig":
        return await handle_check_misconfig(arguments)
    if name == "run_nuclei":
        return await handle_run_nuclei(arguments)
    if name == "check_exploitable":
        return await handle_check_exploitable(arguments)

    raise ValueError(f"unknown vuln tool: {name!r}")
