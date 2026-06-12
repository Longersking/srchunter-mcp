# SRC Hunter MCP

An MCP (Model Context Protocol) server that equips AI coding agents with
offensive-security reconnaissance capabilities.  Designed for bug-bounty
hunters and security engineers who use **Claude Code**, **Cursor**, or
other MCP-compatible agents.

> ⚠️ **Early alpha** — the first tool (`subdomain_enum`) is live.
> Fingerprinting, vulnerability detection, and reporting tools are coming.

## Why

Bug-bounty (SRC) workflow is repetitive: enumerate subdomains, resolve
DNS, probe HTTP, fingerprint tech stacks, check for misconfigurations,
and document findings.  Each step requires a different CLI tool, and
stitching them together is manual.

SRC Hunter turns this workflow into a set of **Agent-callable tools**
connected via MCP.  Your AI agent becomes a junior pentester that you
direct with natural language.

## Architecture

```
Claude Code / Cursor  (MCP Host)
        │
        │  stdio (MCP Protocol)
        ▼
┌──────────────────────────┐
│   SRC Hunter MCP Server  │
│                          │
│  Phase 1: Recon ✓        │
│    subdomain_enum        │
│    resolve_targets [wip] │
│    port_scan [wip]       │
│    http_probe [wip]      │
│                          │
│  Phase 2: Fingerprint    │
│  Phase 3: Vuln Check     │
│  Phase 4: Reporting      │
└──────────────────────────┘
```

## Installation

```bash
# Clone
git clone <repo-url> && cd srchunter-mcp

# Create venv
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"
```

## Quick Start

### 1. Run tests

```bash
pytest -v
```

### 2. Add to Claude Code

```bash
claude mcp add srchunter -- python -m srchunter.server
```

Or via `.claude/mcp.json`:

```json
{
  "mcpServers": {
    "srchunter": {
      "command": "python",
      "args": ["-m", "srchunter.server"]
    }
  }
}
```

### 3. Use in Claude Code

```
> Enumerate subdomains of example.com using the srchunter tool
```

Claude Code will call `subdomain_enum("example.com")` and present the
results.

## Available Tools

### `subdomain_enum`

Query Certificate Transparency logs (crt.sh) for known subdomains.

| Parameter | Type   | Required | Description                              |
|-----------|--------|----------|------------------------------------------|
| `domain`  | string | Yes      | Target domain, e.g. `"example.com"`      |

Returns:
```json
{
  "query_domain": "example.com",
  "subdomains": [
    {"domain": "www.example.com", "source": "crtsh"},
    {"domain": "api.example.com", "source": "crtsh"}
  ],
  "count": 2,
  "elapsed": 1.23,
  "cached": false
}
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Run with coverage
pytest --cov=srchunter --cov-report=term-missing
```

## Project Status

See [PROGRESS.md](./PROGRESS.md) for the detailed roadmap and changelog.

## License

MIT
