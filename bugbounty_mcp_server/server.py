"""Model Context Protocol server wiring."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import uuid4

import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
)

from . import __version__
from .config import BugBountyConfig
from .tools import SecurityTools, ToolExecutionError
from .utils import setup_logging

logger = logging.getLogger(__name__)


class BugBountyMCPServer:
    """A scope-safe MCP server with exact schemas and structured results."""

    def __init__(self, config: BugBountyConfig | None = None):
        self.config = config or BugBountyConfig.load()
        self.tools = SecurityTools(self.config)
        self._started = False
        self.server: Server[Any] = Server(
            "bugbounty-mcp-server",
            version=__version__,
            instructions=(
                "Use these tools only for systems the user is authorized to test. "
                "Call scope_check before network activity, respect target boundaries, "
                "and record confirmed results as findings. Tool errors are structured "
                "so you can correct invalid arguments or scope configuration."
            ),
            on_list_tools=self._handle_list_tools,
            on_call_tool=self._handle_call_tool,
        )

    async def _handle_list_tools(
        self,
        _context: ServerRequestContext[Any],
        _params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return ListToolsResult(tools=self.tools.get_tools())

    async def _handle_call_tool(
        self,
        _context: ServerRequestContext[Any],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        logger.info("tool call started: %s", params.name)
        try:
            result = await asyncio.wait_for(
                self.tools.call(params.name, params.arguments),
                timeout=self.config.tool_timeout,
            )
        except ToolExecutionError as exc:
            logger.warning("tool call rejected: %s (%s)", params.name, exc.code)
            return self._error_result(exc.code, str(exc))
        except asyncio.TimeoutError:
            logger.warning("tool call timed out: %s", params.name)
            return self._error_result(
                "timeout",
                f"tool exceeded the {self.config.tool_timeout:g}-second timeout",
            )
        except asyncio.CancelledError:
            logger.info("tool call cancelled: %s", params.name)
            raise
        except Exception:
            incident_id = str(uuid4())
            logger.exception("unexpected tool failure: %s incident=%s", params.name, incident_id)
            return self._error_result(
                "internal_error",
                f"unexpected server error; incident id: {incident_id}",
            )

        logger.info("tool call completed: %s", params.name)
        text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        if len(text) > self.config.max_tool_output_chars:
            return self._error_result(
                "output_limit",
                "tool result exceeded the configured output limit; narrow the request",
            )
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=result,
            is_error=False,
        )

    @staticmethod
    def _error_result(code: str, message: str) -> CallToolResult:
        payload = {"error": {"code": code, "message": message}}
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
            structured_content=payload,
            is_error=True,
        )

    async def start(self) -> None:
        if self._started:
            return
        self.config.ensure_directories()
        self._started = True
        logger.info(
            "BugBounty MCP Server %s initialized with %d tools", __version__, len(self.tools.specs)
        )

    async def run_stdio(self) -> None:
        """Run one MCP connection over stdin/stdout."""
        setup_logging(self.config.log_level)
        await self.start()
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )

    async def run_streamable_http(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        path: str = "/mcp",
        stateless: bool = False,
        json_response: bool = False,
    ) -> None:
        """Run the MCP Streamable HTTP transport with the SDK's security defaults."""
        setup_logging(self.config.log_level)
        await self.start()
        application = self.server.streamable_http_app(
            streamable_http_path=path,
            stateless_http=stateless,
            json_response=json_response,
            host=host,
        )
        uvicorn_config = uvicorn.Config(
            application,
            host=host,
            port=port,
            log_level=self.config.log_level.lower(),
        )
        await uvicorn.Server(uvicorn_config).serve()
