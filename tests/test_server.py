from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from mcp import Client

from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.server import BugBountyMCPServer


@pytest.mark.asyncio
async def test_in_process_mcp_list_and_call_round_trip(tmp_path) -> None:
    config = BugBountyConfig(
        allowed_targets=["example.com"],
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
    )
    server = BugBountyMCPServer(config)
    await server.start()

    async with Client(server.server) as client:
        listed = await client.list_tools()
        result = await client.call_tool("scope_check", {"target": "example.com"})
        health = await client.call_tool("server_health", {})

    assert len(listed.tools) == 24
    assert result.is_error is False
    assert result.structured_content["allowed"] is True
    assert health.structured_content["status"] == "ok"
    assert health.structured_content["tools"] == 24


@pytest.mark.asyncio
async def test_mcp_errors_are_structured_and_flagged(tmp_path) -> None:
    config = BugBountyConfig(
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"}
    )
    server = BugBountyMCPServer(config)

    async with Client(server.server) as client:
        unknown = await client.call_tool("does_not_exist", {})
        invalid = await client.call_tool("scope_check", {"unexpected": True})

    assert unknown.is_error is True
    assert unknown.structured_content["error"]["code"] == "unknown_tool"
    assert invalid.is_error is True
    assert invalid.structured_content["error"]["code"] == "invalid_args"


def test_streamable_http_application_can_be_constructed(tmp_path) -> None:
    server = BugBountyMCPServer(
        BugBountyConfig(output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"})
    )

    application = server.server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        host="127.0.0.1",
    )

    assert application is not None


@pytest.mark.asyncio
async def test_timeout_internal_error_and_output_limit_are_safe(tmp_path) -> None:
    config = BugBountyConfig(
        tool_timeout=0.01,
        max_tool_output_chars=1000,
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
    )
    server = BugBountyMCPServer(config)

    async def slow(*_args, **_kwargs):
        await asyncio.sleep(1)
        return {}

    server.tools.call = slow
    async with Client(server.server) as client:
        timeout = await client.call_tool("server_health", {})
    assert timeout.structured_content["error"]["code"] == "timeout"

    server.tools.call = AsyncMock(side_effect=RuntimeError("secret detail"))
    async with Client(server.server) as client:
        internal = await client.call_tool("server_health", {})
    assert internal.structured_content["error"]["code"] == "internal_error"
    assert "secret detail" not in internal.content[0].text

    server.tools.call = AsyncMock(return_value={"large": "x" * 2000})
    async with Client(server.server) as client:
        limited = await client.call_tool("server_health", {})
    assert limited.structured_content["error"]["code"] == "output_limit"


@pytest.mark.asyncio
async def test_start_is_idempotent(tmp_path) -> None:
    server = BugBountyMCPServer(
        BugBountyConfig(output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"})
    )

    await server.start()
    await server.start()

    assert (tmp_path / "data").is_dir()
