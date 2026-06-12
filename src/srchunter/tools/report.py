"""Result output tools — attack surface analysis & SRC reporting.

Tool list:
    analyze_surface  — correlate recon + fingerprint + vuln results
    generate_report  — format findings as markdown / JSON SRC report
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mcp.types import Tool, TextContent

from ..engine.cache import get_cache

# ---------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------

REPORT_TOOLS = [
    Tool(
        name="analyze_surface",
        description=(
            "Correlate results from earlier recon, fingerprint, and "
            "vulnerability tools into a unified attack-surface analysis, "
            "sorted by priority.  Use this AFTER running discovery tools "
            "to help the Agent decide what to investigate next."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "subdomains": {
                    "type": "array",
                    "description": "Output from subdomain_enum.subdomains",
                },
                "live_urls": {
                    "type": "array",
                    "description": "Output from http_probe.live_urls",
                },
                "tech_results": {
                    "type": "array",
                    "description": "Output from tech_detect.results",
                },
                "vuln_findings": {
                    "type": "array",
                    "description": "Output from check_misconfig.findings",
                },
            },
            "required": [],
        },
    ),
    Tool(
        name="generate_report",
        description=(
            "Generate a formatted SRC vulnerability report from collected "
            "findings.  Outputs markdown (default) or JSON suitable for "
            "submission to bug bounty platforms."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "description": "List of finding objects from any tool.",
                },
                "target": {
                    "type": "string",
                    "description": "Target domain / scope identifier.",
                },
                "format": {
                    "type": "string",
                    "description": "Output format: 'md' (default) or 'json'.",
                },
            },
            "required": ["findings", "target"],
        },
    ),
]


# ---------------------------------------------------------------
# Priority scoring
# ---------------------------------------------------------------

_SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 80,
    "medium": 50,
    "low": 20,
    "info": 5,
}


def _score_target(
    target: str,
    live: list[dict[str, Any]],
    tech: list[dict[str, Any]],
    vulns: list[dict[str, Any]],
) -> tuple[int, str]:
    """Score a target for prioritization.

    Returns ``(score, priority_label)``.
    """
    score = 0

    # Live URLs are interesting.
    for lu in live:
        score += 1
        # Non-200s might indicate something worth investigating.
        if lu.get("status_code") not in (200, 301, 302):
            score += 2

    # Vulnerabilities directly raise priority.
    for v in vulns:
        sev = (v.get("severity") or "").lower()
        score += _SEVERITY_WEIGHTS.get(sev, 5)

    # Tech stack gives a small bump.
    score += min(len(tech), 10)

    if score >= 80:
        return score, "high"
    if score >= 50:
        return score, "medium"
    return score, "low"


# ---------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------


async def handle_analyze_surface(arguments: dict[str, Any]) -> list[TextContent]:
    subdomains = arguments.get("subdomains") or []
    live_urls = arguments.get("live_urls") or []
    tech_results = arguments.get("tech_results") or []
    vuln_findings = arguments.get("vuln_findings") or []

    # Index tech and vulns by URL (best-effort).
    tech_by_url: dict[str, list] = {}
    for t in tech_results:
        url = t.get("url", "")
        tech_by_url.setdefault(url, []).append(t)

    vuln_by_url: dict[str, list] = {}
    for v in vuln_findings:
        url = v.get("url", "")
        vuln_by_url.setdefault(url, []).append(v)

    surfaces: list[dict[str, Any]] = []

    # Build one entry per live URL (or per subdomain if no live URLs).
    if live_urls:
        for lu in live_urls:
            url = lu["url"]
            vulns = vuln_by_url.get(url, [])
            techs = tech_by_url.get(url, [])
            score, priority = _score_target(url, [lu], techs, vulns)
            surfaces.append({
                "target": url,
                "urls": [url],
                "ports": [],
                "services": [],
                "tech_stack": [f"{t.get('name', 'unknown')}" for t in techs],
                "vulnerabilities": [
                    {"type": v.get("type", "unknown"), "severity": v.get("severity", "info")}
                    for v in vulns
                ],
                "priority": priority,
            })
    elif subdomains:
        for sd in subdomains:
            domain = sd.get("domain", sd) if isinstance(sd, dict) else sd
            surfaces.append({
                "target": domain,
                "urls": [],
                "ports": [],
                "services": [],
                "tech_stack": [],
                "vulnerabilities": [],
                "priority": "low",
            })

    surfaces.sort(key=lambda s: ["high", "medium", "low"].index(s["priority"]))

    result = {
        "attack_surface": surfaces,
        "summary": {
            "total_targets": len(surfaces),
            "high_priority": sum(1 for s in surfaces if s["priority"] == "high"),
            "medium_priority": sum(1 for s in surfaces if s["priority"] == "medium"),
            "low_priority": sum(1 for s in surfaces if s["priority"] == "low"),
        },
    }
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


async def handle_generate_report(arguments: dict[str, Any]) -> list[TextContent]:
    findings = arguments["findings"]
    target = arguments["target"]
    fmt = arguments.get("format", "md")

    if fmt == "json":
        report = {
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
        }
        return [TextContent(type="text", text=json.dumps(report, indent=2, ensure_ascii=False))]

    # --- Markdown report ---
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# SRC Vulnerability Report: {target}",
        "",
        f"**Generated**: {now}",
        f"**Total findings**: {len(findings)}",
        "",
        "---",
        "",
    ]

    if not findings:
        lines.append("No findings to report.")
    else:
        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "info").upper()
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(sev, "⚪")
            lines.extend([
                f"## Finding {i}: {f.get('type', 'unknown')} {sev_emoji}",
                "",
                f"| Field    | Value |",
                f"|----------|-------|",
                f"| **Severity** | {sev} |",
                f"| **URL**      | {f.get('url', 'N/A')} |",
            ])

            if f.get("description"):
                lines.extend(["", f.get("description", "")])
            if f.get("evidence"):
                lines.extend(["", "**Evidence**:", "", "```", str(f["evidence"]), "```"])
            if f.get("remediation"):
                lines.extend(["", "**Remediation**:", "", f["remediation"]])
            lines.extend(["", "---", ""])

    report_text = "\n".join(lines)
    return [TextContent(type="text", text=report_text)]


# ---------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------


async def dispatch_report_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "analyze_surface":
        return await handle_analyze_surface(arguments)
    if name == "generate_report":
        return await handle_generate_report(arguments)

    raise ValueError(f"unknown report tool: {name!r}")
