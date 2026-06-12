"""Safe external-tool execution layer.

All external CLI invocations (subfinder, nuclei, whatweb, etc.) MUST
go through this module — never call subprocess directly from a tool.

Design goals:
    - No shell=True (injection prevention)
    - Hard timeout per invocation
    - Output size cap (prevent memory bloat)
    - Async-friendly (asyncio subprocess)
    - Centralised tool discovery (check if a binary is installed)
"""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------

# Maximum bytes to read from stdout / stderr before truncating.
MAX_OUTPUT_BYTES = 2 * 1024 * 1024  # 2 MiB

# Delimiter appended when output is truncated.
TRUNCATION_MARKER = b"\n[... output truncated ...]\n"


# ---------------------------------------------------------------
# Data types
# ---------------------------------------------------------------


@dataclass
class ToolResult:
    """Result of an external tool invocation."""

    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    elapsed: float  # wall-clock seconds
    timed_out: bool = False
    truncated: bool = False


# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------


def find_tool(name: str) -> str | None:
    """Return the absolute path to *name* if it's on PATH, else None.

    Use this to check whether an external dependency is installed
    before trying to run it.  Safe — does not execute anything.
    """
    return shutil.which(name)


def find_tools(*names: str) -> dict[str, str | None]:
    """Batch version of :func:`find_tool`."""
    return {name: find_tool(name) for name in names}


async def run_tool(
    *args: str,
    timeout: float = 60.0,
    env: dict[str, str] | None = None,
) -> ToolResult:
    """Run an external tool asynchronously and return its output.

    Parameters
    ----------
    *args:
        Command and arguments, e.g. ``run_tool("subfinder", "-d", domain)``.
        Each element is passed directly to exec — no shell interpolation.

    timeout:
        Hard wall-clock limit in seconds.  The subprocess receives
        SIGTERM after this, then SIGKILL after a 5 s grace period.

    env:
        Extra environment variables merged into ``os.environ``.
        Pass ``SRCHUNTER_DISABLED=1`` for tools that should refuse to
        run destructive operations.

    Returns
    -------
    ToolResult
        Fields: command, exit_code, stdout, stderr, elapsed, timed_out, truncated
    """
    t0 = asyncio.get_event_loop().time()

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=merged_env,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        timed_out = False
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.terminate()
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=5.0
                )
            except asyncio.TimeoutError:
                proc.kill()
                stdout_bytes, stderr_bytes = await proc.communicate()
        except ProcessLookupError:
            stdout_bytes, stderr_bytes = b"", b""
        except Exception:
            stdout_bytes, stderr_bytes = b"", b""

    elapsed = round(asyncio.get_event_loop().time() - t0, 2)

    # Truncate oversized output.
    truncated = False
    if stdout_bytes is None:
        stdout_bytes = b""
    if len(stdout_bytes) > MAX_OUTPUT_BYTES:
        stdout_bytes = stdout_bytes[:MAX_OUTPUT_BYTES] + TRUNCATION_MARKER
        truncated = True

    if stderr_bytes is None:
        stderr_bytes = b""

    exit_code = proc.returncode if proc.returncode is not None else -1

    return ToolResult(
        command=list(args),
        exit_code=exit_code,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        elapsed=elapsed,
        timed_out=timed_out,
        truncated=truncated,
    )
