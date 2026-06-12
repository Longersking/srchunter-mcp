"""Fingerprint detection tools — technology, service, and WAF identification.

Tool list (ordered by typical workflow):
    tech_detect          — identify technology stack from HTTP responses
    fingerprint_services — banner-grab open ports to identify services & versions
    identify_waf         — detect WAF/CDN presence from HTTP headers

All three tools are pure-Python (no external binary dependencies) so they
work without subfinder / whatweb / nuclei installed.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx
from mcp.types import Tool, TextContent

from ..utils.validators import validate_url

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

REQUEST_TIMEOUT = 15.0
BANNER_TIMEOUT = 3.0
USER_AGENT = "srchunter-mcp/0.2.0"

# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------

FINGERPRINT_TOOLS = [
    Tool(
        name="tech_detect",
        description=(
            "Detect the technology stack of live URLs by analysing HTTP "
            "response headers (Server, X-Powered-By, Set-Cookie) and HTML "
            "body content (script/link/meta tags).  Use this AFTER "
            "http_probe to fingerprint the tech behind each live endpoint."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of live URLs to fingerprint, e.g. "
                        "['https://www.example.com', 'https://api.example.com']."
                    ),
                },
            },
            "required": ["urls"],
        },
    ),
    Tool(
        name="fingerprint_services",
        description=(
            "Identify services and versions running on open ports via TCP "
            "banner grabbing.  Use this AFTER port_scan on open ports to "
            "determine exact service/version/CPE for vulnerability lookup."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "IP addresses or hostnames with open ports, e.g. "
                        "['93.184.216.34', '10.0.0.1']."
                    ),
                },
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": (
                        "Port numbers to fingerprint, e.g. [80, 443, 22, 3306]. "
                        "Usually taken from port_scan.open_ports."
                    ),
                },
            },
            "required": ["hosts", "ports"],
        },
    ),
    Tool(
        name="identify_waf",
        description=(
            "Detect WAF (Web Application Firewall) or CDN presence by "
            "analysing HTTP response headers, cookies, and body patterns.  "
            "Use this AFTER http_probe to know which targets are behind a "
            "WAF and may need bypass techniques."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of URLs to check for WAF presence, e.g. "
                        "['https://www.example.com']."
                    ),
                },
            },
            "required": ["urls"],
        },
    ),
]

# ---------------------------------------------------------------
# Technology signature databases
# ---------------------------------------------------------------

# Server header → canonical name mapping (case-insensitive key).
_SERVER_SIGNATURES: dict[str, str] = {
    "nginx": "nginx",
    "nginx/": "nginx",
    "apache": "Apache httpd",
    "apache/": "Apache httpd",
    "caddy": "Caddy",
    "iis": "Microsoft IIS",
    "microsoft-iis": "Microsoft IIS",
    "liteSpeed": "LiteSpeed",
    "litespeed": "LiteSpeed",
    "cloudflare": "Cloudflare",
    "gws": "Google Web Server",
    "gse": "Google Search Engine",
    "envoy": "Envoy",
    "varnish": "Varnish",
    "squid": "Squid",
    "haproxy": "HAProxy",
    "traefik": "Traefik",
    "tomcat": "Apache Tomcat",
    "jetty": "Jetty",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "waitress": "Waitress",
    "werkzeug": "Werkzeug",
    "node.js": "Node.js",
    "express": "Express",
    "aws ecs": "AWS ECS",
    "awselb": "AWS ELB",
    "amazons3": "Amazon S3",
    "openresty": "OpenResty",
    "bigip": "F5 BIG-IP",
    "akamai": "Akamai",
    "akamaighost": "Akamai",
    "fastly": "Fastly",
    "tengine": "Tengine",
    "kestrel": "Kestrel",
    "simplehttpserver": "Python SimpleHTTP",
}

# JavaScript library signatures from <script src="..."> patterns.
_JS_LIB_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jQuery", re.compile(r"jquery[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("jQuery UI", re.compile(r"jquery[.-]ui[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("React", re.compile(r"react(?:[.-](\d[\d.]*))?(?:\.production)?(?:\.min)?\.js", re.IGNORECASE)),
    ("React DOM", re.compile(r"react-dom(?:[.-](\d[\d.]*))?(?:\.production)?(?:\.min)?\.js", re.IGNORECASE)),
    ("Vue.js", re.compile(r"vue[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Angular", re.compile(r"angular[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Bootstrap", re.compile(r"bootstrap[.-](\d[\d.]*)(?:\.min)?\.(?:js|css)", re.IGNORECASE)),
    ("Tailwind CSS", re.compile(r"tailwind[.-](\d[\d.]*)", re.IGNORECASE)),
    ("Lodash", re.compile(r"lodash[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Moment.js", re.compile(r"moment[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("D3.js", re.compile(r"d3[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Three.js", re.compile(r"three[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Axios", re.compile(r"axios[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Alpine.js", re.compile(r"alpine[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("htmx", re.compile(r"htmx[.-](\d[\d.]*)(?:\.min)?\.js", re.IGNORECASE)),
    ("Next.js", re.compile(r"/_next/static/", re.IGNORECASE)),
    ("Nuxt.js", re.compile(r"/_nuxt/", re.IGNORECASE)),
]

# <meta generator> patterns for CMS / framework detection.
_META_GENERATOR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("WordPress", re.compile(r"wordpress\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Drupal", re.compile(r"drupal\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Joomla", re.compile(r"joomla!\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Ghost", re.compile(r"ghost\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Hugo", re.compile(r"hugo\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Gatsby", re.compile(r"gatsby\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Jekyll", re.compile(r"jekyll\s*(\d[\d.]*)?", re.IGNORECASE)),
    ("Adobe Dreamweaver", re.compile(r"dreamweaver", re.IGNORECASE)),
    ("Microsoft FrontPage", re.compile(r"frontpage", re.IGNORECASE)),
    ("Wix", re.compile(r"wix\.com", re.IGNORECASE)),
]

# Cookie-based technology detection.
_COOKIE_TECH: list[tuple[str, str, re.Pattern]] = [
    ("PHP", "PHPSESSID", re.compile(r"PHPSESSID", re.IGNORECASE)),
    ("Java", "JSESSIONID", re.compile(r"JSESSIONID", re.IGNORECASE)),
    ("ASP.NET", "ASP.NET_SessionId", re.compile(r"ASP\.NET_SessionId", re.IGNORECASE)),
    ("ASP.NET", ".AspNet.", re.compile(r"\.AspNet\.", re.IGNORECASE)),
    ("Laravel", "laravel_session", re.compile(r"laravel_session", re.IGNORECASE)),
    ("Django", "sessionid", re.compile(r"^(?!.*csrftoken)sessionid", re.IGNORECASE)),
    ("Rails", "_session_id", re.compile(r"_session_id", re.IGNORECASE)),
    ("Flask", "session", re.compile(r"^session=", re.IGNORECASE)),
    ("Express", "connect.sid", re.compile(r"connect\.sid", re.IGNORECASE)),
]

# X-Powered-By header detection.
_X_POWERED_BY: list[tuple[str, re.Pattern]] = [
    ("PHP", re.compile(r"php/(\d[\d.]*)", re.IGNORECASE)),
    ("ASP.NET", re.compile(r"asp\.net", re.IGNORECASE)),
    ("Express", re.compile(r"express", re.IGNORECASE)),
    ("Next.js", re.compile(r"next\.js", re.IGNORECASE)),
    ("Nuxt.js", re.compile(r"nuxt", re.IGNORECASE)),
    ("Shopify", re.compile(r"shopify", re.IGNORECASE)),
    ("Remix", re.compile(r"remix", re.IGNORECASE)),
]

# ---------------------------------------------------------------
# Service banner signatures (for fingerprint_services)
# ---------------------------------------------------------------

# Regex patterns matched against TCP banner data (first 1024 bytes).
# Each entry: (service_name, version_regex, cpe_prefix)
_BANNER_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    # SSH
    ("ssh", re.compile(rb"SSH-([\d.]+)[- ](?P<extra>.+)"), "cpe:/a:openbsd:openssh"),
    # HTTP / HTTPS
    ("http", re.compile(rb"^HTTP/[\d.]+ \d+"), "cpe:/a:http"),
    ("nginx", re.compile(rb"^Server: nginx/([\d.]+)", re.IGNORECASE | re.MULTILINE), "cpe:/a:nginx:nginx"),
    ("Apache httpd", re.compile(rb"^Server: Apache/([\d.]+)", re.IGNORECASE | re.MULTILINE), "cpe:/a:apache:http_server"),
    ("Apache Tomcat", re.compile(rb"^Server: Apache-Coyote", re.IGNORECASE | re.MULTILINE), "cpe:/a:apache:tomcat"),
    # MySQL
    ("mysql", re.compile(rb"mysql_native_password|caching_sha2_password|MariaDB", re.IGNORECASE), "cpe:/a:mysql:mysql"),
    # PostgreSQL
    ("postgresql", re.compile(rb"^E\x00\x00\x00", re.IGNORECASE), "cpe:/a:postgresql:postgresql"),
    # Redis
    ("redis", re.compile(rb"-ERR invalid|redis_version|^\+PONG|^\+OK", re.IGNORECASE), "cpe:/a:redis:redis"),
    # MongoDB
    ("mongodb", re.compile(rb"mongodb|ismaster", re.IGNORECASE), "cpe:/a:mongodb:mongodb"),
    # FTP
    ("ftp", re.compile(rb"^220[\s\-].*FTP", re.IGNORECASE), "cpe:/a:ftp"),
    ("vsftpd", re.compile(rb"^220.*vsftpd\s*([\d.]+)", re.IGNORECASE), "cpe:/a:vsftpd:vsftpd"),
    ("ProFTPD", re.compile(rb"^220.*ProFTPD\s*([\d.]+)", re.IGNORECASE), "cpe:/a:proftpd:proftpd"),
    # SMTP
    ("smtp", re.compile(rb"^220[\s\-].*(?:SMTP|ESMTP|Postfix|Exim|Sendmail)", re.IGNORECASE), "cpe:/a:smtp"),
    ("Postfix", re.compile(rb"^220.*Postfix", re.IGNORECASE), "cpe:/a:postfix:postfix"),
    ("Exim", re.compile(rb"^220.*Exim\s*([\d.]+)", re.IGNORECASE), "cpe:/a:exim:exim"),
    # POP3 / IMAP
    ("pop3", re.compile(rb"^\+OK.*POP3|^\+OK.*ready", re.IGNORECASE), "cpe:/a:dovecot:dovecot"),
    ("imap", re.compile(rb"^\* OK.*IMAP", re.IGNORECASE), "cpe:/a:dovecot:dovecot"),
    # DNS
    ("dns", re.compile(rb"", re.IGNORECASE), "cpe:/a:isc:bind"),  # fallback — no banner
    # RDP
    ("rdp", re.compile(rb"^\x03\x00\x00", re.IGNORECASE), "cpe:/a:microsoft:rdp"),
    # VNC
    ("vnc", re.compile(rb"^RFB\s*([\d.]+)", re.IGNORECASE), "cpe:/a:realvnc:realvnc"),
    # Telnet
    ("telnet", re.compile(rb"\xff\xfb|\xff\xfd|\xff\xfc", re.IGNORECASE), "cpe:/a:telnet"),
    # Memcached
    ("memcached", re.compile(rb"^STAT\s|^VERSION\s", re.IGNORECASE), "cpe:/a:memcached:memcached"),
    # Elasticsearch
    ("elasticsearch", re.compile(rb"\"cluster_name\"\s*:\s*\"", re.IGNORECASE), "cpe:/a:elastic:elasticsearch"),
    # RabbitMQ
    ("rabbitmq", re.compile(rb"AMQP\x00", re.IGNORECASE), "cpe:/a:vmware:rabbitmq"),
    # Docker
    ("docker", re.compile(rb"^HTTP/[\d.]+ \d+.*Docker", re.IGNORECASE), "cpe:/a:docker:docker"),
    # Jenkins
    ("jenkins", re.compile(rb"X-Jenkins:", re.IGNORECASE), "cpe:/a:jenkins:jenkins"),
]

# Well-known port → service mapping (fallback when banner is unreadable).
_PORT_SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3128: "squid",
    3306: "mysql",
    3389: "rdp",
    4369: "epmd",
    4848: "glassfish",
    5353: "mdns",
    5432: "postgresql",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "k8s-api",
    7001: "weblogic",
    8000: "http-alt",
    8009: "ajp",
    8080: "http-proxy",
    8443: "https-alt",
    8983: "solr",
    9000: "http-alt",
    9042: "cassandra",
    9090: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    37777: "http-alt",
    50000: "sap",
    50030: "hadoop",
    50070: "hadoop",
    61616: "activemq",
}

# ---------------------------------------------------------------
# WAF detection signatures
# ---------------------------------------------------------------

# Each entry: (waf_name, check_type, pattern, confidence)
# check_type: "header_name", "header_value", "cookie", "body", "status"
_WAF_SIGNATURES: list[tuple[str, str, re.Pattern, str]] = [
    # Cloudflare
    ("Cloudflare", "header_name", re.compile(r"^cf-ray$", re.IGNORECASE), "high"),
    ("Cloudflare", "header_name", re.compile(r"^cf-cache-status$", re.IGNORECASE), "high"),
    ("Cloudflare", "header_value", re.compile(r"cloudflare", re.IGNORECASE), "medium"),
    ("Cloudflare", "cookie", re.compile(r"__cfduid|__cf_bm|cf_clearance", re.IGNORECASE), "high"),
    # Akamai
    ("Akamai", "header_name", re.compile(r"^x-akamai-", re.IGNORECASE), "high"),
    ("Akamai", "header_name", re.compile(r"^akamai-", re.IGNORECASE), "high"),
    ("Akamai", "cookie", re.compile(r"ak_bmsc|akamai_", re.IGNORECASE), "high"),
    # AWS CloudFront / WAF
    ("AWS CloudFront", "header_name", re.compile(r"^x-amz-cf-", re.IGNORECASE), "high"),
    ("AWS WAF", "header_name", re.compile(r"^x-amzn-waf-", re.IGNORECASE), "high"),
    ("AWS CloudFront", "header_value", re.compile(r"cloudfront", re.IGNORECASE), "medium"),
    # Fastly
    ("Fastly", "header_name", re.compile(r"^x-served-by$", re.IGNORECASE), "medium"),
    ("Fastly", "header_name", re.compile(r"^x-cache$", re.IGNORECASE), "medium"),
    ("Fastly", "header_value", re.compile(r"fastly", re.IGNORECASE), "medium"),
    # Sucuri
    ("Sucuri", "header_name", re.compile(r"^x-sucuri-", re.IGNORECASE), "high"),
    ("Sucuri", "header_value", re.compile(r"sucuri", re.IGNORECASE), "medium"),
    # Incapsula / Imperva
    ("Imperva Incapsula", "header_name", re.compile(r"^x-cdn$", re.IGNORECASE), "low"),
    ("Imperva Incapsula", "cookie", re.compile(r"incap_ses_|visid_incap_|nlbi_", re.IGNORECASE), "high"),
    ("Imperva Incapsula", "header_value", re.compile(r"incapsula", re.IGNORECASE), "medium"),
    # F5 BIG-IP ASM
    ("F5 BIG-IP ASM", "header_name", re.compile(r"^x-wa-info$", re.IGNORECASE), "high"),
    ("F5 BIG-IP ASM", "cookie", re.compile(r"^TS[0-9a-f]{6,}|^F5_ST", re.IGNORECASE), "medium"),
    ("F5 BIG-IP", "header_value", re.compile(r"bigip", re.IGNORECASE), "medium"),
    # Fortinet FortiWeb
    ("FortiWeb", "header_name", re.compile(r"^fortiweb-", re.IGNORECASE), "high"),
    ("FortiWeb", "cookie", re.compile(r"^fortiwafw_", re.IGNORECASE), "high"),
    # Barracuda
    ("Barracuda WAF", "header_name", re.compile(r"^barracuda-", re.IGNORECASE), "high"),
    ("Barracuda WAF", "cookie", re.compile(r"barra_counter_", re.IGNORECASE), "high"),
    # ModSecurity
    ("ModSecurity", "header_name", re.compile(r"^x-modsecurity-", re.IGNORECASE), "high"),
    ("ModSecurity", "header_value", re.compile(r"mod.?security", re.IGNORECASE), "medium"),
    # NAXSI
    ("NAXSI", "header_name", re.compile(r"^x-naxsi-", re.IGNORECASE), "high"),
    # Wallarm
    ("Wallarm", "header_name", re.compile(r"^x-wallarm-", re.IGNORECASE), "high"),
    # Reblaze
    ("Reblaze", "cookie", re.compile(r"^rbzid=", re.IGNORECASE), "high"),
    ("Reblaze", "header_name", re.compile(r"^reblaze-", re.IGNORECASE), "high"),
    # Distil Networks
    ("Distil Networks", "cookie", re.compile(r"^distil_", re.IGNORECASE), "high"),
    # Radware
    ("Radware", "header_name", re.compile(r"^x-radware-", re.IGNORECASE), "high"),
    # Citrix NetScaler
    ("Citrix NetScaler", "header_name", re.compile(r"^x-ns-", re.IGNORECASE), "medium"),
    ("Citrix NetScaler", "cookie", re.compile(r"ns_gx_", re.IGNORECASE), "high"),
    # Wordfence (WordPress WAF)
    ("Wordfence", "cookie", re.compile(r"wfvt_|wordfence_", re.IGNORECASE), "high"),
    # Cloudbric
    ("Cloudbric", "cookie", re.compile(r"^cbsess_", re.IGNORECASE), "high"),
    # AWS Shield / generic
    ("AWS Shield", "header_value", re.compile(r"awselb", re.IGNORECASE), "low"),
    # Generic WAF block-page body patterns
    ("Generic WAF", "body", re.compile(r"the request has been blocked|request rejected|access denied by (waf|firewall)", re.IGNORECASE), "medium"),
    ("Generic WAF", "body", re.compile(r"your request has been blocked by", re.IGNORECASE), "medium"),
    ("Generic WAF", "status", re.compile(r"406", re.IGNORECASE), "low"),
]

# Confidence priority (for sorting).
_CONFIDENCE_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1}

# ---------------------------------------------------------------
# tech_detect — HTTP technology stack detection
# ---------------------------------------------------------------


def _detect_server(value: str) -> list[dict[str, Any]]:
    """Parse Server header value and return list of {name, version} dicts."""
    found: list[dict[str, Any]] = []
    lower = value.strip().lower()
    # Try exact substring matches, longest first.
    for key, name in sorted(_SERVER_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if key in lower:
            # Try to extract version from the raw value.
            ver_match = re.search(r"([\d]+\.?[\d.]*)", value)
            version = ver_match.group(1) if ver_match and ver_match.group(1) else None
            found.append({"name": name, "version": version})
            break  # one server
    return found


def _detect_js_from_html(body: str) -> list[dict[str, Any]]:
    """Scan HTML body for JS library references."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, pattern in _JS_LIB_PATTERNS:
        m = pattern.search(body)
        if m and name not in seen:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            found.append({"name": name, "version": version})
            seen.add(name)
    return found


def _detect_cms_from_meta(body: str) -> list[dict[str, Any]]:
    """Scan HTML body for <meta generator> tags."""
    found: list[dict[str, Any]] = []
    # First capture all meta generator values.
    for m in re.finditer(
        r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        body, re.IGNORECASE,
    ):
        content = m.group(1)
        for name, pattern in _META_GENERATOR_PATTERNS:
            pm = pattern.search(content)
            if pm:
                version = pm.group(1) if pm.lastindex and pm.lastindex >= 1 else None
                found.append({"name": name, "version": version})
                break
    return found


def _detect_from_cookies(cookies: list[str]) -> list[dict[str, Any]]:
    """Detect tech from Set-Cookie names."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cookie_str in cookies:
        for tech, cookie_name, pattern in _COOKIE_TECH:
            if tech in seen:
                continue
            if pattern.search(cookie_str):
                found.append({"name": tech, "version": None})
                seen.add(tech)
    return found


def _detect_from_x_powered_by(value: str) -> list[dict[str, Any]]:
    """Detect tech from X-Powered-By header."""
    found: list[dict[str, Any]] = []
    for name, pattern in _X_POWERED_BY:
        m = pattern.search(value)
        if m:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
            found.append({"name": name, "version": version})
            break
    return found


def _detect_cdn_from_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Detect CDN from response headers (cf-ray, x-cache, server, etc.)."""
    found: list[dict[str, Any]] = []
    header_keys = {k.lower() for k in headers}
    # Cloudflare
    if "cf-ray" in header_keys or "cf-cache-status" in header_keys:
        found.append({"name": "Cloudflare", "version": None})
    # Akamai
    if any(k.startswith("x-akamai-") or k.startswith("akamai-") for k in header_keys):
        found.append({"name": "Akamai", "version": None})
    # Fastly
    if "x-served-by" in header_keys and "x-cache" in header_keys:
        found.append({"name": "Fastly", "version": None})
    # AWS CloudFront
    if any(k.startswith("x-amz-cf-") for k in header_keys):
        found.append({"name": "Amazon CloudFront", "version": None})
    # StackPath
    if any(k.startswith("x-stackpath-") for k in header_keys):
        found.append({"name": "StackPath", "version": None})
    # BunnyCDN
    if any(k.startswith("bunny-") for k in header_keys):
        found.append({"name": "BunnyCDN", "version": None})
    # Azure CDN
    if "x-azure-ref" in header_keys:
        found.append({"name": "Azure CDN", "version": None})
    # Alibaba CDN
    if "x-cache" in header_keys:
        cache_val = headers.get("x-cache", "").lower()
        if "aliyun" in cache_val or "alibaba" in cache_val:
            found.append({"name": "Alibaba CDN", "version": None})
    return found


async def handle_tech_detect(arguments: dict[str, Any]) -> list[TextContent]:
    urls = arguments["urls"]
    if not urls or not isinstance(urls, list):
        raise ValueError("urls must be a non-empty list")

    # Validate URLs.
    validated = [validate_url(u) for u in urls]

    t0 = asyncio.get_event_loop().time()
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
    ) as client:
        for url in validated:
            try:
                resp = await client.get(url)
            except Exception:
                results.append({
                    "url": url,
                    "tech_stack": {
                        "web_servers": [],
                        "javascript": [],
                        "cdn": [],
                    },
                    "confidence": "low",
                    "error": "request failed",
                })
                continue

            body = resp.text[:32768]  # read first 32 KB for parsing
            headers = dict(resp.headers)

            # Aggregate tech stack.
            web_servers: list[dict[str, Any]] = []
            javascript: list[dict[str, Any]] = []
            cdn: list[dict[str, Any]] = []
            indicator_count = 0

            # Server header.
            server_val = headers.get("server", "")
            if server_val:
                servers = _detect_server(server_val)
                web_servers.extend(servers)
                indicator_count += len(servers)

            # X-Powered-By.
            xpb = headers.get("x-powered-by", "")
            if xpb:
                xpb_techs = _detect_from_x_powered_by(xpb)
                # Classify: if it's a "language/framework" put in web_servers-like
                # but spec has web_servers / javascript / cdn — these go to
                # web_servers as a proxy for "backend tech".
                web_servers.extend(xpb_techs)
                indicator_count += len(xpb_techs)

            # JavaScript from script src / link tags.
            js_libs = _detect_js_from_html(body)
            if js_libs:
                javascript.extend(js_libs)
                indicator_count += len(js_libs)

            # CMS from meta generator.
            cms_techs = _detect_cms_from_meta(body)
            if cms_techs:
                # CMS goes in web_servers as "server-side tech".
                web_servers.extend(cms_techs)
                indicator_count += len(cms_techs)

            # Cookies.
            set_cookies = resp.headers.get_list("set-cookie")
            if set_cookies:
                cookie_techs = _detect_from_cookies(set_cookies)
                web_servers.extend(cookie_techs)
                indicator_count += len(cookie_techs)

            # CDN detection from headers.
            cdn_techs = _detect_cdn_from_headers(headers)
            if cdn_techs:
                cdn.extend(cdn_techs)
                indicator_count += len(cdn_techs)

            # Confidence heuristic.
            if indicator_count >= 4:
                confidence = "high"
            elif indicator_count >= 2:
                confidence = "medium"
            else:
                confidence = "low"

            results.append({
                "url": url,
                "tech_stack": {
                    "web_servers": web_servers,
                    "javascript": javascript,
                    "cdn": cdn,
                },
                "confidence": confidence,
            })

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    return [TextContent(type="text", text=json.dumps({"results": results, "elapsed": elapsed}, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# fingerprint_services — TCP banner grabbing
# ---------------------------------------------------------------


def _parse_banner(host: str, port: int, banner: bytes) -> dict[str, Any]:
    """Match banner bytes against known service signatures.

    Returns a service dict with host, port, service, version, cpe.
    """
    for service_name, pattern, cpe_prefix in _BANNER_SIGNATURES:
        # Skip empty patterns (DNS fallback).
        if pattern.pattern == b"":
            continue
        m = pattern.search(banner)
        if m:
            version = None
            # Try to find a version group — either named or first numeric group.
            for g_name in ("version", "extra"):
                try:
                    version = m.group(g_name).decode("utf-8", errors="replace")
                    break
                except (IndexError, AttributeError):
                    pass
            if version is None:
                # Try any numeric group.
                for g in m.groups():
                    if g is not None:
                        try:
                            vs = g.decode("utf-8", errors="replace")
                            if re.search(r"\d", vs):
                                version = vs
                                break
                        except Exception:
                            pass

            cpe = f"{cpe_prefix}:{version}" if version else cpe_prefix

            return {
                "host": host,
                "port": port,
                "service": service_name,
                "version": version,
                "cpe": cpe,
            }

    # Fallback: use port-to-service map.
    fallback_service = _PORT_SERVICE_MAP.get(port, "unknown")
    return {
        "host": host,
        "port": port,
        "service": fallback_service,
        "version": None,
        "cpe": None,
    }


async def _grab_banner(host: str, port: int) -> bytes:
    """Connect to host:port, read initial banner bytes."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=BANNER_TIMEOUT,
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
        except asyncio.TimeoutError:
            banner = b""
        writer.close()
        await writer.wait_closed()
        return banner
    except Exception:
        return b""


# HTTP probe for web ports — sends a GET request to grab Server header.
async def _grab_http_banner(host: str, port: int) -> bytes:
    """Send a minimal HTTP GET to grab server banner from web ports."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=BANNER_TIMEOUT, headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = await client.get(url)
            # Build a synthetic banner from HTTP response headers.
            lines = [f"HTTP/{resp.http_version} {resp.status_code}".encode()]
            server = resp.headers.get("server", "")
            if server:
                lines.append(f"Server: {server}".encode())
            for k, v in resp.headers.items():
                if k.lower() in ("x-powered-by", "x-generator", "x-aspnet-version"):
                    lines.append(f"{k}: {v}".encode())
            return b"\n".join(lines)
    except Exception:
        return b""


async def handle_fingerprint_services(arguments: dict[str, Any]) -> list[TextContent]:
    hosts = arguments["hosts"]
    ports = arguments["ports"]

    if not hosts or not isinstance(hosts, list):
        raise ValueError("hosts must be a non-empty list")
    if not ports or not isinstance(ports, list):
        raise ValueError("ports must be a non-empty list")

    t0 = asyncio.get_event_loop().time()

    # Build all host:port tasks.
    web_ports = {80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 9443, 3000, 4000, 5000, 5555, 7000}

    async def fingerprint_one(host: str, port: int) -> dict[str, Any]:
        if port in web_ports:
            banner = await _grab_http_banner(host, port)
        else:
            banner = await _grab_banner(host, port)
        return _parse_banner(host, port, banner)

    tasks = [fingerprint_one(h, p) for h in hosts for p in ports]
    services = await asyncio.gather(*tasks)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    result: dict[str, Any] = {
        "services": list(services),
        "elapsed": elapsed,
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# identify_waf — WAF/CDN detection from HTTP headers
# ---------------------------------------------------------------

_WAF_BYPASS_TIPS: dict[str, str] = {
    "Cloudflare": "尝试通过源服务器 IP 直连（使用 resolve_targets 的结果），或使用 Cloudflare 缓存欺骗技术",
    "Akamai": "尝试通过 Akamai 不支持的方法绕过（如 PATCH/CUSTOM），或寻找源 IP",
    "AWS CloudFront": "尝试通过 CloudFront 的缓存行为漏洞绕过，或寻找源 IP",
    "AWS WAF": "尝试 AWS WAF 规则绕过（如编码绕过、大小写混淆）",
    "Fastly": "尝试通过 Fastly 缓存欺骗绕过，或寻找源 IP",
    "Sucuri": "尝试通过 Sucuri 的 IP 白名单绕过，或寻找源 IP",
    "Imperva Incapsula": "尝试通过 Incapsula 的 cookie 注入绕过，或使用 IPv6 源",
    "F5 BIG-IP ASM": "尝试通过 BIG-IP iRule 绕过，或 HTTP 请求走私",
    "FortiWeb": "尝试通过 HTTP 走私或分块传输绕过",
    "Barracuda WAF": "尝试通过 Barracuda 的路径规范化问题绕过",
    "ModSecurity": "尝试通过编码绕过（URL 编码、Unicode 规范化）",
    "NAXSI": "尝试通过 NAXSI 白名单规则绕过，或使用不常见的 HTTP 方法",
    "Wallarm": "尝试通过 Wallarm 的 AI 检测盲点绕过",
    "Reblaze": "尝试通过 Reblaze 的 TLS 指纹伪造绕过",
    "Distil Networks": "尝试通过 Distil 的 Cookie 重播攻击绕过",
    "Radware": "尝试通过 Radware 的规则集盲点绕过",
    "Citrix NetScaler": "尝试通过 Citrix ADC 的路径穿透绕过，或 CVE-2019-19781",
    "Wordfence": "尝试通过 WordPress 插件绕过，或直接攻击非 WordPress 路径",
    "Cloudbric": "尝试通过 Cloudbric 的 WAF 规则组切换绕过",
    "Generic WAF": "尝试通用 WAF 绕过：分块传输编码、HTTP 参数污染、编码绕过",
}


async def handle_identify_waf(arguments: dict[str, Any]) -> list[TextContent]:
    urls = arguments["urls"]
    if not urls or not isinstance(urls, list):
        raise ValueError("urls must be a non-empty list")

    validated = [validate_url(u) for u in urls]

    t0 = asyncio.get_event_loop().time()
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
    ) as client:
        for url in validated:
            try:
                resp = await client.get(url)
            except Exception:
                results.append({
                    "url": url,
                    "waf_name": None,
                    "confidence": "low",
                    "indicators": [],
                    "bypass_suggestion": None,
                    "error": "request failed",
                })
                continue

            headers = dict(resp.headers)
            status_code = str(resp.status_code)
            body = resp.text[:4096]
            set_cookies = resp.headers.get_list("set-cookie")

            indicators: list[str] = []
            best_waf: str | None = None
            best_confidence = 0  # 3=high, 2=medium, 1=low
            waf_hits: dict[str, list[str]] = {}  # waf_name → indicators

            # Check header names.
            for waf_name, check_type, pattern, conf in _WAF_SIGNATURES:
                if check_type == "header_name":
                    for h_name in headers:
                        if pattern.search(h_name):
                            waf_hits.setdefault(waf_name, []).append(f"header: {h_name}")
                elif check_type == "header_value":
                    for h_name, h_value in headers.items():
                        if pattern.search(h_value):
                            waf_hits.setdefault(waf_name, []).append(f"header: {h_name}={h_value[:80]}")
                elif check_type == "cookie":
                    for cookie_str in set_cookies:
                        if pattern.search(cookie_str):
                            waf_hits.setdefault(waf_name, []).append(f"cookie: {cookie_str[:80]}")
                elif check_type == "body":
                    if pattern.search(body):
                        waf_hits.setdefault(waf_name, []).append(f"body pattern matched")
                elif check_type == "status":
                    if pattern.search(status_code):
                        waf_hits.setdefault(waf_name, []).append(f"status: {status_code}")

            # Pick the best WAF match (most indicators, then confidence).
            for waf_name, hits in waf_hits.items():
                # Find the highest confidence for this WAF name.
                conf_scores = []
                for sig_name, _ct, _pat, conf in _WAF_SIGNATURES:
                    if sig_name == waf_name and conf in _CONFIDENCE_ORDER:
                        conf_scores.append(_CONFIDENCE_ORDER[conf])
                max_conf = max(conf_scores) if conf_scores else 1

                if max_conf > best_confidence or (
                    max_conf == best_confidence and len(hits) > len(indicators)
                ):
                    best_confidence = max_conf
                    best_waf = waf_name
                    indicators = hits

            # Map confidence back to label.
            conf_label = {3: "high", 2: "medium", 1: "low"}.get(best_confidence, "low")

            bypass = _WAF_BYPASS_TIPS.get(best_waf) if best_waf else None

            results.append({
                "url": url,
                "waf_name": best_waf,
                "confidence": conf_label,
                "indicators": indicators,
                "bypass_suggestion": bypass,
            })

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    return [TextContent(type="text", text=json.dumps({"results": results, "elapsed": elapsed}, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------


async def dispatch_fingerprint_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Route a fingerprint tool call to the correct handler."""
    if name == "tech_detect":
        return await handle_tech_detect(arguments)
    if name == "fingerprint_services":
        return await handle_fingerprint_services(arguments)
    if name == "identify_waf":
        return await handle_identify_waf(arguments)

    raise ValueError(f"unknown fingerprint tool: {name!r}")
