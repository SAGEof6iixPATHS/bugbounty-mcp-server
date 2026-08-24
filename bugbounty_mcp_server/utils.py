"""Small, reusable runtime utilities."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

_T = TypeVar("_T")
_SENSITIVE_KEYS = re.compile(
    r"(authorization|cookie|credential|password|secret|token|api.?key)", re.I
)


def setup_logging(level: str = "INFO", log_file: str | Path | None = None) -> None:
    """Configure an idempotent stderr logger that cannot corrupt MCP stdio."""
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    managed_handlers = [
        handler for handler in root.handlers if getattr(handler, "_bugbounty_managed", False)
    ]
    for handler in managed_handlers:
        root.removeHandler(handler)
        handler.close()

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    console._bugbounty_managed = True  # type: ignore[attr-defined]
    root.addHandler(console)

    if log_file is not None:
        file_handler = logging.FileHandler(Path(log_file), encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler._bugbounty_managed = True  # type: ignore[attr-defined]
        root.addHandler(file_handler)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str | bytes) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def safe_filename(value: str, *, fallback: str = "result", max_length: int = 120) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (normalized or fallback)[:max_length]


def redact(value: Any) -> Any:
    """Recursively redact credential-like fields before logging."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEYS.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


class RateLimiter:
    """Concurrency-safe, monotonic fixed-interval rate limiter."""

    def __init__(self, calls_per_second: float):
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be positive")
        self._interval = 1.0 / calls_per_second
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._next_allowed - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next_allowed = max(now, self._next_allowed) + self._interval


def parse_ports(specification: str | None, defaults: Iterable[int], maximum: int) -> list[int]:
    """Parse comma-separated ports and inclusive ranges with a hard cap."""
    if specification is None or not specification.strip():
        ports = set(defaults)
    else:
        ports = set()
        for raw_part in specification.split(","):
            part = raw_part.strip()
            if not part:
                continue
            if "-" in part:
                bounds = part.split("-", 1)
                try:
                    start, end = int(bounds[0]), int(bounds[1])
                except ValueError as exc:
                    raise ValueError(f"invalid port range: {part!r}") from exc
                if start > end:
                    raise ValueError(f"port range starts after it ends: {part!r}")
                if end - start + 1 > maximum:
                    raise ValueError(f"port range exceeds the {maximum}-port limit")
                ports.update(range(start, end + 1))
            else:
                try:
                    ports.add(int(part))
                except ValueError as exc:
                    raise ValueError(f"invalid port: {part!r}") from exc
            if len(ports) > maximum:
                raise ValueError(f"scan exceeds the {maximum}-port limit")

    if not ports:
        raise ValueError("at least one port is required")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    if len(ports) > maximum:
        raise ValueError(f"scan exceeds the {maximum}-port limit")
    return sorted(ports)


async def run_command_async(
    command: list[str],
    *,
    timeout: float = 30,
    max_output_bytes: int = 5_000_000,
) -> dict[str, Any]:
    """Run an argv-only subprocess, kill its process group on timeout, and bound output."""
    if not command or not command[0]:
        raise ValueError("command cannot be empty")
    if timeout <= 0 or max_output_bytes <= 0:
        raise ValueError("timeout and max_output_bytes must be positive")

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = await process.communicate()

    stdout_truncated = len(stdout) > max_output_bytes
    stderr_truncated = len(stderr) > max_output_bytes
    stdout = stdout[:max_output_bytes]
    stderr = stderr[:max_output_bytes]
    return {
        "returncode": -1 if timed_out else process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "timed_out": timed_out,
        "success": not timed_out and process.returncode == 0,
    }


async def bounded_map(
    items: Iterable[_T],
    operation: Callable[[_T], Awaitable[Any]],
    *,
    concurrency: int,
) -> list[Any]:
    if concurrency < 1:
        raise ValueError("concurrency must be positive")
    semaphore = asyncio.Semaphore(concurrency)

    async def run(item: _T) -> Any:
        async with semaphore:
            return await operation(item)

    return await asyncio.gather(*(run(item) for item in items))


def atomic_write_json(path: Path, value: Any) -> None:
    """Write JSON via a sibling temporary file and atomic replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
