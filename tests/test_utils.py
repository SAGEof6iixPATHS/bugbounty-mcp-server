from __future__ import annotations

import asyncio
import json
import logging
import sys
import time

import pytest

from bugbounty_mcp_server.utils import (
    RateLimiter,
    atomic_write_json,
    bounded_map,
    parse_ports,
    redact,
    run_command_async,
    safe_filename,
    setup_logging,
)


def test_parse_ports_supports_ranges_deduplication_and_defaults() -> None:
    assert parse_ports(None, [443, 80, 443], 10) == [80, 443]
    assert parse_ports("80,443,8000-8002,443", [], 10) == [80, 443, 8000, 8001, 8002]


@pytest.mark.parametrize("value", ["0", "65536", "abc", "100-90", "1-100"])
def test_parse_ports_rejects_invalid_or_excessive_input(value: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(value, [], 10)


def test_redact_hides_nested_secret_fields() -> None:
    value = {
        "target": "example.com",
        "Authorization": "Bearer secret",
        "nested": [{"api_key": "secret", "safe": "visible"}],
    }

    assert redact(value) == {
        "target": "example.com",
        "Authorization": "[REDACTED]",
        "nested": [{"api_key": "[REDACTED]", "safe": "visible"}],
    }


@pytest.mark.asyncio
async def test_rate_limiter_serializes_concurrent_waiters() -> None:
    limiter = RateLimiter(100)
    started = time.monotonic()

    await asyncio.gather(limiter.wait(), limiter.wait(), limiter.wait())

    assert time.monotonic() - started >= 0.015


@pytest.mark.asyncio
async def test_command_runner_captures_output_and_bounds_it() -> None:
    result = await run_command_async(
        [sys.executable, "-c", "print('x' * 100)"],
        timeout=2,
        max_output_bytes=20,
    )

    assert result["success"]
    assert result["stdout"] == "x" * 20
    assert result["stdout_truncated"] is True


@pytest.mark.asyncio
async def test_command_runner_kills_timed_out_process_group() -> None:
    result = await run_command_async(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout=0.05,
    )

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["returncode"] == -1


def test_logging_is_idempotent_and_json_write_is_atomic(tmp_path) -> None:
    log_path = tmp_path / "server.log"
    setup_logging("DEBUG", log_path)
    setup_logging("INFO", log_path)
    managed = [
        handler
        for handler in logging.getLogger().handlers
        if getattr(handler, "_bugbounty_managed", False)
    ]
    assert len(managed) == 2

    destination = tmp_path / "nested" / "result.json"
    atomic_write_json(destination, {"ok": True})
    assert json.loads(destination.read_text()) == {"ok": True}
    assert list(destination.parent.glob("*.tmp")) == []


def test_safe_filename_normalizes_and_bounds_values() -> None:
    assert safe_filename(" ../../hello world?.json ") == "hello_world_.json"
    assert safe_filename("...", fallback="fallback") == "fallback"
    assert len(safe_filename("a" * 500)) == 120


@pytest.mark.asyncio
async def test_bounded_map_preserves_order_and_validates_concurrency() -> None:
    async def double(value: int) -> int:
        await asyncio.sleep(0)
        return value * 2

    assert await bounded_map([3, 1, 2], double, concurrency=2) == [6, 2, 4]
    with pytest.raises(ValueError, match="concurrency"):
        await bounded_map([], double, concurrency=0)


@pytest.mark.asyncio
async def test_command_runner_rejects_invalid_arguments() -> None:
    with pytest.raises(ValueError, match="empty"):
        await run_command_async([])
    with pytest.raises(ValueError, match="positive"):
        await run_command_async([sys.executable], timeout=0)
