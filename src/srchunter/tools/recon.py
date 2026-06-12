"""Reconnaissance tools — asset discovery phase.

Tool list (ordered by typical workflow):
    subdomain_enum   — discover subdomains via crt.sh certificate logs
    resolve_targets  — batch DNS resolution + CDN detection
    port_scan        — port discovery on live hosts
    http_probe       — HTTP liveness probe with metadata
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import httpx
from mcp.types import Tool, TextContent

from ..engine.cache import get_cache
from ..utils.validators import validate_domain, validate_url

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT = 30.0
MAX_RETRIES = 2
RETRY_BACKOFF = 1.5
USER_AGENT = "srchunter-mcp/0.1.0"

# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------

RECON_TOOLS = [
    Tool(
        name="subdomain_enum",
        description=(
            "Enumerate subdomains of a domain via Certificate Transparency "
            "logs (crt.sh).  Use this as the FIRST step when mapping an "
            "attack surface.  Discovers known subdomains from publicly-issued "
            "TLS certificates."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": (
                        "Target domain name, e.g. 'example.com'.  Do NOT "
                        "include protocol, port, or path."
                    ),
                },
            },
            "required": ["domain"],
        },
    ),
    Tool(
        name="resolve_targets",
        description=(
            "Resolve domain names to IP addresses via DNS.  Optionally "
            "detects CDN/WAF presence by checking resolved IPs and CNAME "
            "records against known CDN ranges and patterns.  Use this "
            "AFTER subdomain_enum to identify which hosts are directly "
            "accessible."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of domain names to resolve, e.g. "
                        "['www.example.com', 'api.example.com']."
                    ),
                },
                "use_cdn_check": {
                    "type": "boolean",
                    "description": (
                        "When true, check resolved IPs against known CDN "
                        "ranges and CNAMEs against known CDN patterns. "
                        "Default: true."
                    ),
                },
            },
            "required": ["targets"],
        },
    ),
    Tool(
        name="port_scan",
        description=(
            "Perform TCP connect scan on target hosts to discover open ports "
            "and services.  Use this AFTER resolve_targets on non-CDN IPs "
            "to map the attack surface.  Limited to common ports for speed."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IP addresses or hostnames to scan.",
                },
                "ports": {
                    "type": "string",
                    "description": (
                        "Port specification: 'top-20', 'top-100', 'top-1000', "
                        "or a comma-separated list like '80,443,8080'. "
                        "Default: 'top-100'."
                    ),
                },
            },
            "required": ["hosts"],
        },
    ),
    Tool(
        name="http_probe",
        description=(
            "Probe URLs or host:port pairs over HTTP/HTTPS to determine "
            "liveness, response status, page title, server header, and "
            "content length.  Use this AFTER port_scan (or resolve_targets) "
            "to find which targets serve HTTP content."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of targets as URLs ('https://example.com') or "
                        "host:port ('192.168.1.1:8080').  If scheme is omitted, "
                        "both http:// and https:// are tried."
                    ),
                },
            },
            "required": ["targets"],
        },
    ),
]

# ---------------------------------------------------------------
# crt.sh query logic
# ---------------------------------------------------------------


async def _fetch_crtsh(domain: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Query crt.sh certificate transparency logs for *domain*."""
    url = CRTSH_URL.format(domain=domain)
    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await client.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                return []
            return data
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1))
        except Exception as exc:
            last_error = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF * (attempt + 1))

    raise RuntimeError(
        f"crt.sh query failed after {MAX_RETRIES + 1} attempts: {last_error}"
    )


def _parse_crtsh_entries(
    raw: list[dict[str, Any]],
    domain: str,
) -> list[dict[str, Any]]:
    """Extract unique subdomain entries from raw crt.sh JSON.

    Only includes names that genuinely belong to *domain* — i.e. they
    equal *domain* or end with ``.domain``.  This filters out unrelated
    domains that appear in SAN fields of shared certificates.
    """
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    domain = domain.lower()

    def _belongs(name: str) -> bool:
        """True if *name* is *domain* or a subdomain of *domain*."""
        return name == domain or name.endswith(f".{domain}")

    for entry in raw:
        names: set[str] = set()

        cn = (entry.get("common_name") or "").strip().lower()
        if cn:
            names.add(cn)

        nv = (entry.get("name_value") or "").strip()
        if nv:
            for line in nv.splitlines():
                name = line.strip().lower()
                if name:
                    names.add(name)

        for name in names:
            if name not in seen and not name.startswith("*.") and _belongs(name):
                seen.add(name)
                results.append({"domain": name, "source": "crtsh"})

    results.sort(key=lambda x: x["domain"])
    return results


# ---------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------


async def handle_subdomain_enum(arguments: dict[str, Any]) -> list[TextContent]:
    """Execute subdomain_enum and return MCP TextContent result."""
    domain = validate_domain(arguments["domain"])

    # --- cache check ---
    cache = get_cache()
    cache_key = f"subdomain_enum:{domain}"
    cached = cache.get(cache_key)
    if cached is not None:
        cached["cached"] = True
        return [TextContent(type="text", text=json.dumps(cached, indent=2, ensure_ascii=False))]

    # --- query ---
    t0 = asyncio.get_event_loop().time()

    async with httpx.AsyncClient() as client:
        raw = await _fetch_crtsh(domain, client)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    entries = _parse_crtsh_entries(raw, domain)

    result: dict[str, Any] = {
        "query_domain": domain,
        "subdomains": entries,
        "count": len(entries),
        "elapsed": elapsed,
        "cached": False,
    }

    cache.set(cache_key, result.copy())
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# CDN detection helpers
# ---------------------------------------------------------------

# Known CDN CNAME patterns — suffix match against DNS CNAME chain.
_CDN_CNAME_PATTERNS: list[tuple[str, str]] = [
    ("cloudflare", ".cdn.cloudflare.net"),
    ("cloudflare", ".cfarg.net"),
    ("akamai", ".akamaiedge.net"),
    ("akamai", ".akadns.net"),
    ("akamai", ".edgekey.net"),
    ("fastly", ".fastly.net"),
    ("amazon cloudfront", ".cloudfront.net"),
    ("amazon cloudfront", ".awsglobalaccelerator.com"),
    ("incapsula", ".incapdns.net"),
    ("sucuri", ".sucuri.net"),
    ("stackpath", ".stackpathcdn.com"),
    ("azure cdn", ".azureedge.net"),
    ("azure cdn", ".vo.msecnd.net"),
    ("cdn77", ".cdn77.org"),
    ("keycdn", ".kxcdn.com"),
    ("bunnycdn", ".b-cdn.net"),
    ("alibaba cdn", ".alicdn.com"),
    ("alibaba cdn", ".cdngslb.com"),
    ("tencent cdn", ".cdn.dnsv1.com"),
    ("baidu cdn", ".bdydns.com"),
    ("qiniu cdn", ".qiniucdn.com"),
    ("ucloud cdn", ".ucloud.com.cn"),
]

# Well-known CDN ASN / IP range prefixes (first-octet ranges for quick checks).
# This is a heuristic — not exhaustive.
_CDN_ASN_RANGES: list[tuple[str, str]] = [
    ("cloudflare", "104.16.0.0/12"),
    ("cloudflare", "172.64.0.0/13"),
    ("cloudflare", "131.0.72.0/22"),
    ("fastly", "151.101.0.0/16"),
    ("fastly", "199.232.0.0/16"),
    ("akamai", "23.0.0.0/8"),   # partial
    ("akamai", "104.64.0.0/10"), # partial
]


def _detect_cdn_cname(cname: str) -> tuple[str | None, str | None]:
    """Check a CNAME against known CDN patterns.

    Returns ``(provider, matched_pattern)`` or ``(None, None)``.
    """
    cname_lower = cname.lower().rstrip(".")
    for provider, suffix in _CDN_CNAME_PATTERNS:
        if cname_lower.endswith(suffix):
            return provider, suffix
    return None, None


def _detect_cdn_ip(ip: str) -> str | None:
    """Quick CDN check via private-IP prefix matching.

    Returns provider name or None.  Does NOT do whois/ASN lookup —
    that would be too slow for batch resolution.
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        first_two = int(parts[0]) * 256 + int(parts[1])
    except (ValueError, IndexError):
        return None

    if 2620 <= first_two <= 2623:  # 10.0.0.0/8 range
        pass  # reserved, skip

    # Cloudflare: 104.16-31.x.x, 172.64-71.x.x
    if int(parts[0]) == 104 and 16 <= int(parts[1]) <= 31:
        return "cloudflare"
    if int(parts[0]) == 172 and 64 <= int(parts[1]) <= 71:
        return "cloudflare"

    # Fastly: 151.101.x.x, 199.232.x.x
    if int(parts[0]) == 151 and int(parts[1]) == 101:
        return "fastly"
    if int(parts[0]) == 199 and int(parts[1]) == 232:
        return "fastly"

    return None


# ---------------------------------------------------------------
# resolve_targets
# ---------------------------------------------------------------


async def _resolve_single(host: str) -> dict[str, Any]:
    """Resolve a single hostname to IPs using asyncio thread pool."""
    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM),
        )
        # getaddrinfo returns [(family, type, proto, canonname, sockaddr)]
        ips = sorted({a[4][0] for a in addrs})
        cname = None
        # canonname is part of getaddrinfo result — try to extract
        for a in addrs:
            if a[3] and a[3] != host:
                cname = a[3]
                break
        return {"domain": host, "ips": ips, "cdn": False, "cdn_provider": None, "cname": cname}
    except (socket.gaierror, OSError) as exc:
        return {"domain": host, "ips": [], "cdn": False, "cdn_provider": None, "cname": None, "error": str(exc)}


async def handle_resolve_targets(arguments: dict[str, Any]) -> list[TextContent]:
    targets = arguments["targets"]
    use_cdn = arguments.get("use_cdn_check", True)

    if not targets or not isinstance(targets, list):
        raise ValueError("targets must be a non-empty list")

    t0 = asyncio.get_event_loop().time()

    # Resolve all targets in parallel.
    results = await asyncio.gather(*[_resolve_single(t) for t in targets])

    resolved: list[dict[str, Any]] = []
    unresolved: list[str] = []

    for r in results:
        if not r["ips"]:
            unresolved.append(r["domain"])
            continue

        # CDN check.
        cdn = False
        cdn_provider = None
        if use_cdn:
            # Check CNAME first.
            if r.get("cname"):
                provider, _ = _detect_cdn_cname(r["cname"])
                if provider:
                    cdn = True
                    cdn_provider = provider
            # Then check IPs.
            if not cdn:
                for ip in r["ips"]:
                    provider = _detect_cdn_ip(ip)
                    if provider:
                        cdn = True
                        cdn_provider = provider
                        break

        r["cdn"] = cdn
        r["cdn_provider"] = cdn_provider
        resolved.append(r)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    result = {
        "resolved": resolved,
        "unresolved": unresolved,
        "count": len(resolved),
        "elapsed": elapsed,
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# port_scan
# ---------------------------------------------------------------

_PORT_SETS: dict[str, list[int]] = {
    "top-20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top-100": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 194, 443, 445, 465, 514, 587,
        636, 873, 989, 990, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1900, 2049, 2082,
        2083, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3260, 3306, 3389, 4000, 4369, 4443,
        4444, 4567, 4848, 5000, 5060, 5222, 5353, 5432, 5555, 5672, 5900, 5984, 6000, 6379,
        6443, 7001, 7077, 7443, 7777, 8000, 8008, 8009, 8080, 8081, 8083, 8443, 8888, 8983,
        9000, 9042, 9090, 9200, 9300, 9443, 9999, 10000, 11211, 15672, 27017, 28017, 37777,
        50000, 50030, 50070, 61616,
    ],
}


def _parse_ports(ports_spec: str) -> list[int]:
    """Parse a port specification string into a sorted, unique port list."""
    spec = ports_spec.strip().lower()
    if spec in _PORT_SETS:
        return sorted(_PORT_SETS[spec])
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


_SERVICE_BANNERS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 194: "irc", 443: "https", 445: "smb",
    465: "smtps", 514: "shell", 587: "submission", 636: "ldaps",
    873: "rsync", 989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1900: "upnp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2222: "ssh", 2375: "docker", 2376: "docker-ssl", 2483: "oracle",
    3000: "http", 3128: "squid", 3260: "iscsi", 3306: "mysql",
    3389: "rdp", 4000: "http", 4369: "epmd", 4443: "https", 4444: "http",
    4567: "http", 4848: "glassfish", 5000: "http", 5060: "sip", 5222: "xmpp",
    5353: "mdns", 5432: "postgresql", 5555: "http", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6000: "x11", 6379: "redis",
    6443: "k8s-api", 7001: "weblogic", 7077: "spark", 7443: "https",
    7777: "http", 8000: "http", 8008: "http", 8009: "ajp", 8080: "http",
    8081: "http", 8083: "https", 8443: "https", 8888: "http",
    8983: "solr", 9000: "http", 9042: "cassandra", 9090: "http",
    9200: "elasticsearch", 9300: "elasticsearch", 9443: "https",
    9999: "http", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 28017: "mongodb-web", 37777: "http",
    50000: "sap", 50030: "hadoop", 50070: "hadoop", 61616: "activemq",
}


async def _scan_port(host: str, port: int, timeout: float = 2.0) -> dict[str, Any] | None:
    """Attempt a TCP connect to host:port. Returns port info or None."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        service = _SERVICE_BANNERS.get(port, "unknown")
        return {"host": host, "port": port, "service": service, "banner": f"{service}/{port}"}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def handle_port_scan(arguments: dict[str, Any]) -> list[TextContent]:
    hosts = arguments["hosts"]
    ports_spec = arguments.get("ports", "top-100")

    if not hosts or not isinstance(hosts, list):
        raise ValueError("hosts must be a non-empty list")

    ports = _parse_ports(ports_spec)

    cache = get_cache()
    # Build scan tasks for all host:port pairs.
    tasks: list[tuple[str, int]] = [(host, port) for host in hosts for port in ports]

    t0 = asyncio.get_event_loop().time()
    results = await asyncio.gather(*[_scan_port(h, p) for h, p in tasks])
    elapsed = round(asyncio.get_event_loop().time() - t0, 2)

    open_ports = [r for r in results if r is not None]
    result = {
        "open_ports": open_ports,
        "scan_time": elapsed,
        "hosts_scanned": len(hosts),
        "ports_scanned": len(ports),
        "open_count": len(open_ports),
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ---------------------------------------------------------------
# http_probe
# ---------------------------------------------------------------

_HTTP_PORTS = [80, 443, 8080, 8443]


async def _probe_target(client: httpx.AsyncClient, target: str) -> dict[str, Any] | None:
    """Probe a single target. Returns dict with HTTP response metadata or None."""
    # Normalise to URL.
    urls: list[str] = []
    if target.startswith("http://") or target.startswith("https://"):
        urls.append(target.rstrip("/"))
    elif ":" in target and not target.startswith("http"):
        host, port = target.rsplit(":", 1)
        try:
            p = int(port)
            scheme = "https" if p in (443, 8443) else "http"
            urls.append(f"{scheme}://{host}:{p}")
        except ValueError:
            urls.append(f"http://{target}")
            urls.append(f"https://{target}")
    else:
        for port in _HTTP_PORTS:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{target}:{port}")

    for url in urls:
        try:
            resp = await client.get(url, timeout=10.0, follow_redirects=True)
            # Extract title from HTML.
            title = ""
            body = resp.text[:4096]
            import re as _re
            m = _re.search(r"<title>(.+?)</title>", body, _re.IGNORECASE)
            if m:
                title = m.group(1).strip()
            return {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "title": title,
                "content_length": int(resp.headers.get("content-length", 0)),
                "server": resp.headers.get("server", ""),
                "redirect_url": str(resp.url) if resp.url != url else "",
            }
        except Exception:
            continue

    return None


async def handle_http_probe(arguments: dict[str, Any]) -> list[TextContent]:
    targets = arguments["targets"]
    if not targets or not isinstance(targets, list):
        raise ValueError("targets must be a non-empty list")

    t0 = asyncio.get_event_loop().time()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        tasks = [_probe_target(client, t) for t in targets]
        results = await asyncio.gather(*tasks)

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)
    live = [r for r in results if r is not None]
    dead = [t for t, r in zip(targets, results) if r is None]
    result = {
        "live_urls": live,
        "dead": dead,
        "live_count": len(live),
        "elapsed": elapsed,
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


async def dispatch_recon_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Route a recon tool call to the correct handler."""
    if name == "subdomain_enum":
        return await handle_subdomain_enum(arguments)
    if name == "resolve_targets":
        return await handle_resolve_targets(arguments)
    if name == "port_scan":
        return await handle_port_scan(arguments)
    if name == "http_probe":
        return await handle_http_probe(arguments)

    raise ValueError(f"unknown recon tool: {name!r}")
