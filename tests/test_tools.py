from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from jsonschema import Draft202012Validator

from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.scope import ScopeViolation
from bugbounty_mcp_server.tools import SecurityTools, ToolExecutionError


def _config(tmp_path, **overrides) -> BugBountyConfig:
    data = {
        "allowed_targets": ["127.0.0.1"],
        "allow_private_targets": True,
        "requests_per_second": 100,
        "output": {"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
        "scanning": {
            "connect_timeout": 0.2,
            "request_timeout": 2,
            "max_concurrency": 10,
            "max_pages_to_crawl": 10,
            "max_crawl_depth": 2,
        },
    }
    data.update(overrides)
    return BugBountyConfig.model_validate(data)


def _jwt_segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@asynccontextmanager
async def _http_server() -> AsyncIterator[int]:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
            lines = request.split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            status = "200 OK"
            extra_headers = [
                "Content-Type: text/html; charset=utf-8",
                "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options: nosniff",
                "Referrer-Policy: no-referrer",
                "Permissions-Policy: camera=()",
                "Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            ]
            body = (
                b"<html><title>Home</title><a href='/next'>Next</a>"
                b"<form action='/submit'></form></html>"
            )
            if path == "/redirect":
                status = "302 Found"
                extra_headers.append("Location: https://outside.test/path")
                body = b""
            elif path == "/local-redirect":
                status = "302 Found"
                extra_headers.append("Location: /next")
                body = b""
            elif path == "/missing":
                status = "404 Not Found"
                body = b"missing"
            elif path == "/admin":
                status = "403 Forbidden"
                body = b"forbidden"
            elif path == "/next":
                body = b"<html><title>Next</title><a href='/'>Home</a></html>"
            elif path == "/large":
                body = b"x" * 2000
            elif path == "/weak":
                extra_headers = [
                    "Content-Type: text/html",
                    "Server: test-server/1.0",
                    "X-Powered-By: test-framework",
                    "Set-Cookie: insecure=yes; Path=/",
                ]
            if "origin" in headers:
                allowed_origin = (
                    "*" if headers["origin"] == "https://wildcard.test" else headers["origin"]
                )
                extra_headers.append(f"Access-Control-Allow-Origin: {allowed_origin}")
                if headers["origin"] != "https://reflect.test":
                    extra_headers.append("Access-Control-Allow-Credentials: true")
                extra_headers.append("Vary: Origin")
            response_head = (
                f"HTTP/1.1 {status}\r\n"
                + "\r\n".join(extra_headers)
                + f"\r\nContent-Length: {0 if method == 'HEAD' else len(body)}"
                + "\r\nConnection: close\r\n\r\n"
            )
            writer.write(response_head.encode("latin-1"))
            if method != "HEAD":
                writer.write(body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


def test_registry_has_unique_honest_schema_surface(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    definitions = tools.get_tools()
    names = [definition.name for definition in definitions]

    assert len(names) == 53
    assert len(names) == len(set(names))
    assert "anti_forensics_techniques" not in names
    assert "server_health" in names
    assert all(
        definition.input_schema.get("additionalProperties") is False for definition in definitions
    )
    assert all(definition.output_schema.get("required") for definition in definitions)
    for definition in definitions:
        Draft202012Validator.check_schema(definition.input_schema)
        Draft202012Validator.check_schema(definition.output_schema)


@pytest.mark.asyncio
async def test_dispatch_validates_arguments_and_scope(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    with pytest.raises(ToolExecutionError, match="unknown tool"):
        await tools.call("missing", {})
    with pytest.raises(ToolExecutionError, match="required property"):
        await tools.call("scope_check", {})
    with pytest.raises(ToolExecutionError, match="Additional properties"):
        await tools.call("scope_check", {"target": "127.0.0.1", "extra": True})
    with pytest.raises(ToolExecutionError, match="not a 'uuid'"):
        await tools.call("update_finding", {"finding_id": "not-a-uuid", "status": "open"})

    result = await tools.call("scope_check", {"target": "127.0.0.1"})
    assert result["allowed"] is True


@pytest.mark.asyncio
async def test_jwt_analysis_is_local_and_flags_unsigned_tokens(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    token = f"{_jwt_segment({'alg': 'none', 'typ': 'JWT'})}.{_jwt_segment({'sub': '123'})}."

    result = await tools.jwt_security_test(token)

    assert result["header"]["alg"] == "none"
    assert result["signature_present"] is False
    assert {finding["severity"] for finding in result["findings"]} >= {"critical", "low"}


@pytest.mark.asyncio
async def test_tcp_scan_detects_a_local_listener(tmp_path) -> None:
    async def handler(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await writer.wait_closed()

    listener = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = listener.sockets[0].getsockname()[1]
    tools = SecurityTools(_config(tmp_path))
    async with listener:
        result = await tools.port_scan("127.0.0.1", str(port))

    assert result["open_count"] == 1
    assert result["open_ports"][0]["port"] == port


@pytest.mark.asyncio
async def test_http_audits_crawl_and_directory_discovery(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    async with _http_server() as port:
        base = f"http://127.0.0.1:{port}/"
        probe = await tools.http_probe(base)
        headers = await tools.headers_analysis(base)
        cookies = await tools.cookie_security_analysis(base)
        cors = await tools.cors_scan(base)
        crawl = await tools.web_crawler(base, max_pages=5, max_depth=1)
        directories = await tools.web_directory_scan(base, paths=["admin", "missing"])

    assert probe["status"] == 200
    assert probe["title"] == "Home"
    assert probe["content_sha256"]
    assert "set-cookie" not in probe["headers"]
    assert probe["redacted_header_names"] == ["set-cookie"]
    assert probe["set_cookie_count"] == 1
    assert headers["score"] >= 70
    assert cookies["cookies"][0]["issues"] == []
    assert cors["findings"][0]["severity"] == "high"
    assert crawl["page_count"] == 2
    assert crawl["forms"][0]["action"].endswith("/submit")
    assert [finding["status"] for finding in directories["results"]] == [403]


@pytest.mark.asyncio
async def test_redirect_cannot_escape_scope(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    async with _http_server() as port:
        with pytest.raises(ScopeViolation, match="ALLOWED_TARGETS"):
            await tools.http_probe(f"http://127.0.0.1:{port}/redirect")


@pytest.mark.asyncio
async def test_local_redirect_body_limit_and_weak_controls(tmp_path) -> None:
    config = _config(tmp_path)
    config.scanning.max_response_bytes = 1024
    tools = SecurityTools(config)
    async with _http_server() as port:
        base = f"http://127.0.0.1:{port}"
        redirected = await tools.http_probe(f"{base}/local-redirect")
        large = await tools.http_probe(f"{base}/large")
        weak_headers = await tools.headers_analysis(f"{base}/weak")
        weak_cookies = await tools.cookie_security_analysis(f"{base}/weak")
        cors = await tools.cors_scan(
            f"{base}/",
            origins=["https://wildcard.test", "https://reflect.test"],
        )

    assert redirected["final_url"].endswith("/next")
    assert len(redirected["redirects"]) == 1
    assert large["body_truncated"] is True
    assert large["content_length_read"] == 1024
    assert weak_headers["score"] < 50
    assert weak_headers["information_disclosure"]["server"] == "test-server/1.0"
    assert set(weak_cookies["cookies"][0]["issues"]) == {
        "missing Secure",
        "missing HttpOnly",
        "missing SameSite",
    }

    with pytest.raises(ValueError, match="absolute HTTP"):
        await tools.cors_scan(f"{base}/", origins=["https://example.com/path"])
    assert {finding["severity"] for finding in cors["findings"]} == {"medium"}


@pytest.mark.asyncio
async def test_nuclei_is_fail_closed_until_operator_enables_it(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    with pytest.raises(ToolExecutionError, match="Nuclei is disabled"):
        await tools.nuclei_scan("127.0.0.1")


@pytest.mark.asyncio
async def test_finding_tools_round_trip(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    created = await tools.create_finding(
        title="Missing header",
        severity="low",
        target="http://127.0.0.1",
        description="A defense-in-depth header is absent.",
    )
    listed = await tools.list_findings(status="open")
    updated = await tools.update_finding(created["finding"]["id"], status="resolved")
    report = await tools.generate_vulnerability_report(report_format="json")

    assert listed["count"] == 1
    assert updated["finding"]["status"] == "resolved"
    assert report["total_findings"] == 1
