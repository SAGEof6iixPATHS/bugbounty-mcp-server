from __future__ import annotations

import json
from unittest.mock import AsyncMock

import dns.resolver
import pytest

import bugbounty_mcp_server.tools.core as core
from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.scope import ScopeViolation, parse_target
from bugbounty_mcp_server.tools import SecurityTools, ToolExecutionError


def _config(tmp_path) -> BugBountyConfig:
    return BugBountyConfig(
        allowed_targets=["example.com", "*.example.com"],
        requests_per_second=100,
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
    )


@pytest.mark.asyncio
async def test_dns_enumeration_collects_values_and_expected_errors(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))

    class Resolver:
        lifetime = 1.0

        def resolve(self, _host: str, record_type: str):
            if record_type == "TXT":
                raise dns.resolver.NoAnswer
            return ["192.0.2.1", "192.0.2.2"]

    monkeypatch.setattr(core.dns.resolver, "Resolver", Resolver)

    result = await tools.dns_enumeration("example.com", ["A", "TXT"])

    assert result["records"]["A"]["values"] == ["192.0.2.1", "192.0.2.2"]
    assert result["records"]["TXT"]["values"] == []
    assert result["records"]["TXT"]["error"] == "NoAnswer"


@pytest.mark.asyncio
async def test_dns_and_subdomain_tools_require_domains(tmp_path) -> None:
    config = _config(tmp_path)
    config.allowed_targets.append("203.0.113.10")
    tools = SecurityTools(config)
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("203.0.113.10"))

    with pytest.raises(ValueError, match="domain name"):
        await tools.dns_enumeration("203.0.113.10")
    with pytest.raises(ValueError, match="domain name"):
        await tools.subdomain_enumeration("203.0.113.10")


@pytest.mark.asyncio
async def test_subdomain_enumeration_parses_ct_and_active_dns(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))

    async def authorize(value: str, **_kwargs):
        return parse_target(value)

    async def resolve(value: str, **_kwargs):
        parsed = parse_target(value)
        addresses = ("203.0.113.20",) if parsed.host.startswith("www.") else ()
        if not addresses:
            raise ScopeViolation("not found")
        return parsed, addresses

    tools.scope.require_network_safe = authorize
    tools.scope.resolve_network_safe = resolve

    payload = json.dumps(
        [
            {"name_value": "api.example.com\n*.dev.example.com"},
            {"name_value": "outside.test\ninvalid name.example.com"},
        ]
    ).encode()

    class Content:
        async def read(self, _limit: int) -> bytes:
            return payload

    class Response:
        status = 200
        content = Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(core.aiohttp, "ClientSession", Session)
    result = await tools.subdomain_enumeration(
        "example.com",
        active=True,
        candidates=["www", "missing"],
    )

    assert result["subdomains"] == [
        "api.example.com",
        "dev.example.com",
        "www.example.com",
    ]
    assert result["resolved"]["www.example.com"] == ["203.0.113.20"]


@pytest.mark.asyncio
async def test_subdomain_enumeration_reports_ct_http_failure(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))

    class Response:
        status = 503

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(core.aiohttp, "ClientSession", Session)

    result = await tools.subdomain_enumeration("example.com")

    assert result["subdomains"] == []
    assert "HTTP 503" in result["errors"][0]


@pytest.mark.asyncio
async def test_nuclei_success_failure_and_health(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    config.tools.enable_nuclei = True
    tools = SecurityTools(config)
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))
    monkeypatch.setattr(core.shutil, "which", lambda _path: "/usr/local/bin/nuclei")
    success = {
        "success": True,
        "stdout": (
            json.dumps(
                {
                    "template-id": "headers",
                    "info": {"name": "Header issue", "severity": "low"},
                    "matched-at": "https://example.com",
                    "type": "http",
                }
            )
            + "\nnot-json\n"
        ),
        "stderr": "",
        "returncode": 0,
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }
    command_runner = AsyncMock(return_value=success)
    monkeypatch.setattr(core, "run_command_async", command_runner)

    result = await tools.nuclei_scan("example.com", severity=["low"], tags=["headers"])
    health = await tools.server_health()

    assert result["finding_count"] == 1
    assert result["by_severity"] == {"low": 1}
    assert health["nuclei"] == {"enabled": True, "available": True}
    command = command_runner.await_args.args[0]
    assert "-restrict-local-network-access" in command
    assert "-no-interactsh" in command
    assert "-disable-redirects" in command
    assert command[command.index("-rate-limit") + 1] == "100"

    failure = {**success, "success": False, "stdout": "", "stderr": "bad templates"}
    monkeypatch.setattr(core, "run_command_async", AsyncMock(return_value=failure))
    with pytest.raises(ToolExecutionError, match="bad templates"):
        await tools.nuclei_scan("example.com")


@pytest.mark.asyncio
async def test_nuclei_reports_missing_binary(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    config.tools.enable_nuclei = True
    tools = SecurityTools(config)
    tools.scope.require_network_safe = AsyncMock(return_value=parse_target("example.com"))
    monkeypatch.setattr(core.shutil, "which", lambda _path: None)

    with pytest.raises(ToolExecutionError, match="not found"):
        await tools.nuclei_scan("example.com")


@pytest.mark.asyncio
async def test_configured_directory_wordlist_and_invalid_jwts(tmp_path) -> None:
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("# comment\nadmin\n\nstatus\n", encoding="utf-8")
    config = _config(tmp_path)
    config.scanning.directory_wordlist = wordlist
    tools = SecurityTools(config)
    tools._fetch = AsyncMock(side_effect=ToolExecutionError("offline", code="http_error"))

    result = await tools.web_directory_scan("https://example.com")

    assert result["requests"] == 2
    assert result["results"] == []
    with pytest.raises(ValueError, match="exactly three"):
        await tools.jwt_security_test("two.parts")
    with pytest.raises(ValueError, match="base64url JSON"):
        await tools.jwt_security_test("not-json.payload.signature")


@pytest.mark.asyncio
async def test_hmac_jwt_claim_advice(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    def encode(value: dict) -> str:
        import base64

        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    token = f"{encode({'alg': 'HS256', 'kid': 'key-1'})}.{encode({'exp': 1})}.signature"
    result = await tools.jwt_security_test(token)

    issues = [finding["issue"] for finding in result["findings"]]
    assert any("HMAC" in issue for issue in issues)
    assert any("expired" in issue for issue in issues)
    assert any("kid" in issue for issue in issues)
