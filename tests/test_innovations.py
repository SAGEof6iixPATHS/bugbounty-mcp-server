from __future__ import annotations

import json
import socket
from unittest.mock import AsyncMock

import dns.resolver
import pytest

import bugbounty_mcp_server.tools.core as core
from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.scope import parse_target
from bugbounty_mcp_server.tools import SecurityTools, ToolExecutionError


def _config(tmp_path) -> BugBountyConfig:
    return BugBountyConfig(
        allowed_targets=["example.com", "*.example.com"],
        requests_per_second=100,
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
    )


def _response(url: str, body: bytes, *, status: int = 200, content_type: str = "text/plain"):
    return core.HTTPResponse(
        requested_url=url,
        final_url=url,
        status=status,
        reason="OK",
        headers={"content-type": content_type},
        set_cookies=[],
        body=body,
        content_type=content_type,
        redirects=[],
        truncated=False,
        elapsed_ms=1.0,
    )


@pytest.mark.asyncio
async def test_batch_scope_metrics_and_assessment_summary(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    batch = await tools.call(
        "batch_scope_check",
        {"targets": ["example.com", "outside.test"]},
    )
    summary = await tools.call("assessment_summary", {})

    assert batch["allowed"] == 1
    assert batch["denied"] == 1
    assert summary["scope"]["configured"] is True
    assert summary["runtime"]["calls"] == 2
    assert summary["runtime"]["per_tool"]["batch_scope_check"] == 1


@pytest.mark.asyncio
async def test_email_security_analysis_normalizes_dns_posture(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))

    class Resolver:
        lifetime = 1.0

        def resolve(self, name: str, record_type: str):
            if record_type == "MX":
                return ["10 mail.example.com."]
            if name == "example.com":
                return ['"v=spf1 ~all"']
            if name.startswith("_dmarc"):
                return ['"v=DMARC1; p=none"']
            return []

    monkeypatch.setattr(core.dns.resolver, "Resolver", Resolver)
    result = await tools.email_security_analysis("example.com")

    issues = {finding["issue"] for finding in result["findings"]}
    assert "SPF uses a soft or neutral all mechanism" in issues
    assert "DMARC policy is monitoring-only (p=none)" in issues
    assert result["records"]["mx"]["values"] == ["10 mail.example.com"]


@pytest.mark.asyncio
async def test_security_txt_and_openapi_discovery_are_bounded_summaries(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )
    security_txt = (
        b"Contact: mailto:security@example.com\n"
        b"Expires: 2099-12-31T23:59:59Z\n"
        b"Policy: https://example.com/security\n"
    )
    tools._fetch = AsyncMock(
        return_value=_response(
            "https://example.com/.well-known/security.txt",
            security_txt,
        )
    )

    security_result = await tools.security_txt_analysis("https://example.com")

    assert security_result["present"] is True
    assert security_result["fields"]["contact"] == ["mailto:security@example.com"]
    assert security_result["content_sha256"]

    document = {
        "openapi": "3.1.0",
        "info": {"title": "Example API", "version": "1"},
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/health": {"get": {}},
        },
    }
    tools._fetch = AsyncMock(
        return_value=_response(
            "https://example.com/openapi.json",
            json.dumps(document).encode(),
            content_type="application/json",
        )
    )

    openapi_result = await tools.openapi_discovery(
        "https://example.com",
        paths=["/openapi.json"],
    )

    assert openapi_result["document_count"] == 1
    assert openapi_result["documents"][0]["path_count"] == 2
    assert openapi_result["documents"][0]["operation_count"] == 3
    assert "paths" not in openapi_result["documents"][0]


@pytest.mark.asyncio
async def test_openapi_yaml_aliases_are_rejected(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )
    body = b"openapi: 3.1.0\ninfo: &info {title: API, version: 1}\npaths: *info\n"
    tools._fetch = AsyncMock(
        return_value=_response(
            "https://example.com/openapi.yaml",
            body,
            content_type="application/yaml",
        )
    )

    result = await tools.openapi_discovery(
        "https://example.com",
        paths=["/openapi.yaml"],
    )

    assert result["documents"] == []


@pytest.mark.asyncio
async def test_absent_mail_controls_and_discovery_network_errors(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))

    class Resolver:
        lifetime = 1.0

        def resolve(self, _name: str, _record_type: str):
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(core.dns.resolver, "Resolver", Resolver)
    email = await tools.email_security_analysis("example.com")

    assert email["finding_count"] == 5
    assert all(record["error"] == "NoAnswer" for record in email["records"].values())

    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )
    tools._fetch = AsyncMock(
        side_effect=ToolExecutionError("connection refused", code="http_error")
    )
    security_txt = await tools.security_txt_analysis("https://example.com")
    openapi = await tools.openapi_discovery(
        "https://example.com",
        paths=["/openapi.json"],
    )

    assert security_txt["present"] is False
    assert all("error" in attempt for attempt in security_txt["attempts"])
    assert openapi["documents"] == []
    assert openapi["attempts"][0]["error"] == "connection refused"


@pytest.mark.asyncio
async def test_scope_resolver_returns_only_requested_address_family(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.resolve_network_safe = AsyncMock(
        return_value=(parse_target("example.com"), ("93.184.216.34", "2606:2800:220:1::"))
    )
    resolver = core._ScopeResolver(tools.scope)

    ipv4 = await resolver.resolve("example.com", 443, socket.AF_INET)
    ipv6 = await resolver.resolve("example.com", 443, socket.AF_INET6)

    assert [item["host"] for item in ipv4] == ["93.184.216.34"]
    assert [item["host"] for item in ipv6] == ["2606:2800:220:1::"]
    await resolver.close()

    with pytest.raises(OSError, match="no validated address"):
        await resolver.resolve("example.com", 443, socket.AF_UNIX)


def test_openapi_structure_limit_rejects_oversized_documents() -> None:
    with pytest.raises(ValueError, match="structure limit"):
        core._bounded_structure_size([1, 2, 3], maximum=2)


def test_html_inventory_has_independent_per_page_limits(tmp_path) -> None:
    config = _config(tmp_path)
    config.scanning.max_links_per_page = 1
    config.scanning.max_forms_per_page = 1
    tools = SecurityTools(config)
    response = _response(
        "https://example.com/",
        (
            b"<html><a href='/one'>one</a><a href='/two'>two</a>"
            b"<form action='/one'></form><form action='/two'></form></html>"
        ),
        content_type="text/html",
    )

    inspector = tools._inspect_html(response)

    assert inspector.links == ["/one"]
    assert inspector.forms == [{"action": "/one", "method": "GET"}]
    assert inspector.links_truncated is True
    assert inspector.forms_truncated is True
