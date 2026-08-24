from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

import bugbounty_mcp_server.tools.core as core
from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.scope import parse_target
from bugbounty_mcp_server.tools import SecurityTools, ToolExecutionError
from bugbounty_mcp_server.tools.analyzers import (
    analyze_cloud_references,
    analyze_csp,
    analyze_openapi_document,
    analyze_secret_patterns,
    analyze_url_parameters,
    calculate_cvss_v31,
    extract_javascript_endpoints,
    generate_domain_variants,
    load_structured_document,
    parse_robots,
)


def _config(tmp_path, *, external: list[str] | None = None) -> BugBountyConfig:
    return BugBountyConfig(
        allowed_targets=["example.com", "*.example.com"],
        requests_per_second=100,
        tools={"enabled_external_tools": external or []},
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
    )


def _response(
    url: str,
    body: bytes = b"",
    *,
    status: int = 200,
    content_type: str = "text/plain",
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
) -> core.HTTPResponse:
    response_headers = {"content-type": content_type, **(headers or {})}
    return core.HTTPResponse(
        requested_url=url,
        final_url=url,
        status=status,
        reason="OK",
        headers=response_headers,
        set_cookies=cookies or [],
        body=body,
        content_type=content_type,
        redirects=[],
        truncated=False,
        elapsed_ms=1.0,
    )


def test_pure_analyzers_cover_local_security_workflows() -> None:
    variants = generate_domain_variants("example.com", maximum=20)
    assert len(variants) == 20
    assert all(item["domain"].endswith(".com") for item in variants)

    parameters = analyze_url_parameters(
        "https://example.com/view?id=42&redirect=https%3A%2F%2Fevil.test&token=sensitive"
    )
    assert parameters["parameter_count"] == 3
    assert parameters["category_counts"]["redirect"] == 1
    assert "sensitive" not in json.dumps(parameters)

    secrets = analyze_secret_patterns("key=AKIAABCDEFGHIJKLMNOP\n-----BEGIN PRIVATE KEY-----")
    assert secrets["match_count"] == 2
    assert secrets["values_redacted"] is True
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(secrets)

    clouds = analyze_cloud_references(
        "https://bucket.s3.us-east-1.amazonaws.com/a.txt "
        "https://acct.blob.core.windows.net/container/file"
    )
    assert clouds["reference_count"] == 2
    assert set(clouds["by_provider"]) == {"aws_s3", "azure_blob_storage"}

    endpoints = extract_javascript_endpoints(
        "fetch('/api/v1/users'); const ws='wss://example.com/ws'"
    )
    assert endpoints["endpoint_count"] == 2


def test_cvss_and_openapi_local_analysis() -> None:
    cvss = calculate_cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss["base_score"] == 9.8
    assert cvss["rating"] == "critical"

    with pytest.raises(ValueError, match="missing metrics"):
        calculate_cvss_v31("AV:N/AC:L")

    document = load_structured_document(
        """
openapi: 3.1.0
paths:
  /public:
    get:
      operationId: public
  /legacy:
    trace:
      deprecated: true
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
""",
        "yaml",
    )
    result = analyze_openapi_document(document)
    assert result["operation_count"] == 2
    assert result["deprecated_operations"] == [{"path": "/legacy", "method": "TRACE"}]
    assert any("TRACE" in finding["issue"] for finding in result["findings"])

    with pytest.raises(ValueError, match="aliases"):
        load_structured_document("root: &root [1]\ncopy: *root\n", "yaml")


def test_csp_and_robots_parsers() -> None:
    csp = analyze_csp("default-src 'self'; script-src * 'unsafe-eval'; report-uri /csp")
    issues = {finding["issue"] for finding in csp["findings"]}
    assert "script-src allows unsafe-eval" in issues
    assert "report-uri is deprecated; prefer report-to" in issues

    robots = parse_robots(
        "User-agent: *\nDisallow: /admin\nAllow: /admin/help\n"
        "Sitemap: https://example.com/sitemap.xml\n"
    )
    assert robots["group_count"] == 1
    assert robots["rule_count"] == 2
    assert robots["sitemaps"] == ["https://example.com/sitemap.xml"]


@pytest.mark.asyncio
async def test_local_tools_are_typed_and_never_open_the_network(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    variation = await tools.call(
        "domain_variation_generator", {"domain": "example.com", "maximum": 10}
    )
    parameters = await tools.call("url_parameter_analysis", {"url": "https://example.com/?id=1"})
    secret_result = await tools.call("secret_pattern_analysis", {"content": "AKIAABCDEFGHIJKLMNOP"})
    cvss = await tools.call(
        "cvss_v31_calculator",
        {"vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )

    assert variation["count"] == 10
    assert parameters["parameter_count"] == 1
    assert secret_result["match_count"] == 1
    assert cvss["base_score"] == 9.8


@pytest.mark.asyncio
async def test_dnssec_wildcard_and_dangling_dns_tools(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))

    async def dns_values(name: str, record_type: str):
        if record_type == "DNSKEY":
            return ["257 3 13 public-key"], None
        if record_type == "DS":
            return ["12345 13 2 digest"], None
        if record_type == "RRSIG":
            return ["A 13 2 signature"], None
        if record_type == "CNAME":
            return ["missing.provider.test"], None
        return [], "NXDOMAIN"

    tools._dns_values = AsyncMock(side_effect=dns_values)
    dnssec = await tools.call("dnssec_posture_analysis", {"domain": "example.com"})
    dangling = await tools.call("dangling_dns_analysis", {"domain": "example.com"})

    assert dnssec["signed"] is True
    assert dangling["dangling"] is True

    async def wildcard_values(_name: str, record_type: str):
        return (["93.184.216.34"], None) if record_type == "A" else ([], "NoAnswer")

    tools._dns_values = AsyncMock(side_effect=wildcard_values)
    wildcard = await tools.call(
        "wildcard_dns_analysis", {"domain": "example.com", "probe_count": 3}
    )
    assert wildcard["wildcard_detected"] is True
    assert wildcard["consistent_answer_count"] == 3


@pytest.mark.asyncio
async def test_web_policy_metadata_and_fingerprint_tools(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )

    async def fetch(url: str, **_kwargs):
        if url.endswith("robots.txt"):
            return _response(url, b"User-agent: *\nDisallow: /private\n")
        if url.endswith("sitemap.xml"):
            body = (
                b"<urlset><url><loc>https://example.com/a</loc></url>"
                b"<url><loc>https://outside.test/b</loc></url></urlset>"
            )
            return _response(url, body, content_type="application/xml")
        body = (
            b"<html><meta name='generator' content='WordPress 7'>"
            b"<script src='/wp-content/app.js'></script></html>"
        )
        return _response(
            url,
            body,
            content_type="text/html",
            headers={
                "content-security-policy": "default-src 'self'; object-src 'none'",
                "server": "nginx",
                "cache-control": "private, no-store",
            },
            cookies=["csrftoken=x; Secure; HttpOnly"],
        )

    tools._fetch = AsyncMock(side_effect=fetch)
    csp = await tools.call("csp_analysis", {"url": "https://example.com"})
    robots = await tools.call("robots_txt_analysis", {"url": "https://example.com"})
    sitemap = await tools.call("sitemap_analysis", {"url": "https://example.com"})
    technology = await tools.call("technology_fingerprint", {"url": "https://example.com"})
    cache = await tools.call("cache_policy_analysis", {"url": "https://example.com/profile"})

    assert csp["present"] is True
    assert robots["rule_count"] == 1
    assert sitemap["url_count"] == 1
    assert sitemap["external_or_unauthorized_count"] == 1
    assert "WordPress" in technology["technologies"]
    assert cache["cacheable"] is False


@pytest.mark.asyncio
async def test_javascript_source_map_and_sri_tools(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    page = _response(
        "https://example.com/",
        (
            b"<script src='/app.js'></script>"
            b"<script src='https://cdn.test/lib.js'></script>"
            b"<link rel='stylesheet' href='https://cdn.test/app.css' integrity='sha384-abc'>"
        ),
        content_type="text/html",
    )
    script = _response(
        "https://example.com/app.js",
        b"fetch('/api/users'); //# sourceMappingURL=app.js.map",
        content_type="application/javascript",
    )
    source_map = _response(
        "https://example.com/app.js.map",
        headers={"content-length": "200"},
    )

    async def fetch(url: str, **_kwargs):
        if url.endswith("app.js.map"):
            return source_map
        if url.endswith("app.js"):
            return script
        return page

    tools._fetch = AsyncMock(side_effect=fetch)
    endpoints = await tools.call(
        "javascript_endpoint_discovery",
        {"url": "https://example.com/", "max_scripts": 5},
    )
    maps = await tools.call(
        "source_map_discovery", {"url": "https://example.com/", "max_scripts": 5}
    )
    sri = await tools.call("sri_analysis", {"url": "https://example.com/"})

    assert endpoints["endpoint_count"] == 2
    assert {item["url"] for item in endpoints["endpoints"]} == {
        "https://example.com/api/users",
        "https://example.com/app.js",
    }
    assert maps["available_count"] == 1
    assert sri["external_resource_count"] == 2
    assert sri["coverage_percent"] == 50.0


@pytest.mark.asyncio
async def test_oidc_graphql_sensitive_files_methods_and_favicon(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )

    async def fetch(url: str, *, method: str = "GET", **_kwargs):
        if "openid-configuration" in url:
            body = json.dumps(
                {
                    "issuer": "https://example.com",
                    "authorization_endpoint": "https://example.com/oauth/authorize",
                    "token_endpoint": "https://example.com/oauth/token",
                    "code_challenge_methods_supported": ["S256"],
                }
            ).encode()
            return _response(url, body, content_type="application/json")
        if "oauth-authorization-server" in url:
            return _response(url, status=404)
        if "query=" in url:
            return _response(
                url, b'{"data":{"__typename":"Query"}}', content_type="application/json"
            )
        if method == "OPTIONS":
            return _response(url, headers={"allow": "GET, HEAD, PUT, OPTIONS"})
        if url.endswith("favicon.ico"):
            return _response(url, b"icon", content_type="image/x-icon")
        if any(path in url for path in ("/.env", "/.git/HEAD")):
            return _response(url, status=200, headers={"content-length": "20"})
        return _response(url, b"<html></html>", content_type="text/html", status=404)

    tools._fetch = AsyncMock(side_effect=fetch)
    oidc = await tools.call("oauth_oidc_discovery", {"url": "https://example.com"})
    graphql = await tools.call(
        "graphql_endpoint_discovery",
        {"url": "https://example.com", "paths": ["/graphql"]},
    )
    exposures = await tools.call(
        "sensitive_file_exposure_scan",
        {"url": "https://example.com", "paths": ["/.env", "/.git/HEAD"]},
    )
    methods = await tools.call("http_method_analysis", {"url": "https://example.com"})
    favicon = await tools.call("favicon_fingerprint", {"url": "https://example.com"})

    assert oidc["documents"][0]["s256_pkce_supported"] is True
    assert graphql["endpoint_count"] == 1
    assert exposures["finding_count"] == 2
    assert methods["potentially_dangerous_methods"] == ["PUT"]
    assert favicon["found"] is True
    assert favicon["sha256"]


@pytest.mark.asyncio
async def test_batch_and_metadata_discovery_handle_partial_errors(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.http_probe = AsyncMock(
        side_effect=[
            {
                "requested_url": "https://example.com",
                "final_url": "https://example.com",
                "status": 200,
            },
            ToolExecutionError("refused", code="http_error"),
        ]
    )
    batch = await tools.call(
        "batch_http_probe",
        {"urls": ["https://example.com", "https://api.example.com"]},
    )
    assert batch["count"] == 1
    assert batch["error_count"] == 1

    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )

    async def fetch(url: str, **_kwargs):
        return _response(url, status=200 if url.endswith("manifest.json") else 404)

    tools._fetch = AsyncMock(side_effect=fetch)
    metadata = await tools.call(
        "web_metadata_discovery",
        {"url": "https://example.com", "paths": ["/manifest.json", "/missing"]},
    )
    assert metadata["found_count"] == 1


@pytest.mark.asyncio
async def test_passive_external_adapters_are_opt_in_and_scope_filtered(
    tmp_path, monkeypatch
) -> None:
    disabled = SecurityTools(_config(tmp_path))
    with pytest.raises(ToolExecutionError, match="disabled"):
        await disabled.subfinder_discovery("example.com")

    tools = SecurityTools(_config(tmp_path, external=["subfinder", "amass", "assetfinder", "gau"]))
    monkeypatch.setattr(core.shutil, "which", lambda value: f"/usr/local/bin/{value}")
    command_result = {
        "returncode": 0,
        "stdout": "api.example.com\noutside.test\nhttps://example.com/api?id=1\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "timed_out": False,
        "success": True,
    }
    runner = AsyncMock(return_value=command_result)
    monkeypatch.setattr(core, "run_command_async", runner)

    subfinder = await tools.call("subfinder_discovery", {"domain": "example.com"})
    amass = await tools.call("amass_passive_discovery", {"domain": "example.com"})
    assetfinder = await tools.call("assetfinder_discovery", {"domain": "example.com"})
    gau = await tools.call("gau_url_discovery", {"domain": "example.com"})
    health = await tools.call("server_health", {})

    assert subfinder["subdomains"] == ["api.example.com"]
    assert amass["subdomains"] == ["api.example.com"]
    assert assetfinder["subdomains"] == ["api.example.com"]
    assert gau["urls"] == ["https://example.com/api?id=1"]
    assert health["external_tools"]["subfinder"] == {"enabled": True, "available": True}
    assert runner.await_count == 4


def test_registry_contains_every_expanded_tool_with_output_schema(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    definitions = {definition.name: definition for definition in tools.get_tools()}
    expected = {
        "domain_variation_generator",
        "url_parameter_analysis",
        "secret_pattern_analysis",
        "cloud_asset_reference_analysis",
        "cvss_v31_calculator",
        "openapi_security_analysis",
        "dnssec_posture_analysis",
        "wildcard_dns_analysis",
        "dangling_dns_analysis",
        "batch_http_probe",
        "csp_analysis",
        "robots_txt_analysis",
        "sitemap_analysis",
        "technology_fingerprint",
        "web_metadata_discovery",
        "javascript_endpoint_discovery",
        "source_map_discovery",
        "oauth_oidc_discovery",
        "graphql_endpoint_discovery",
        "sensitive_file_exposure_scan",
        "cache_policy_analysis",
        "sri_analysis",
        "favicon_fingerprint",
        "http_method_analysis",
        "tls_configuration_analysis",
        "subfinder_discovery",
        "amass_passive_discovery",
        "assetfinder_discovery",
        "gau_url_discovery",
    }
    assert len(definitions) == 53
    assert expected <= definitions.keys()
    assert all(definitions[name].output_schema for name in expected)


def test_analyzer_rejection_and_alternate_scoring_paths() -> None:
    with pytest.raises(ValueError, match="dotted domain"):
        generate_domain_variants("localhost", maximum=10)
    with pytest.raises(ValueError, match="absolute HTTP"):
        analyze_url_parameters("ftp://example.com/file")
    with pytest.raises(ValueError, match="more than 200"):
        analyze_url_parameters(
            "https://example.com/?" + "&".join(f"p{index}=x" for index in range(201))
        )
    with pytest.raises(ValueError, match="not valid json"):
        load_structured_document("{", "json")
    with pytest.raises(ValueError, match="OpenAPI document root"):
        analyze_openapi_document([])
    with pytest.raises(ValueError, match="does not contain"):
        analyze_openapi_document({"openapi": "3.1.0"})

    zero = calculate_cvss_v31("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")
    changed = calculate_cvss_v31("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert zero["base_score"] == 0.0
    assert zero["rating"] == "none"
    assert changed["base_score"] == 10.0

    empty_csp = analyze_csp("")
    assert any(item["issue"] == "default-src is missing" for item in empty_csp["findings"])
    assert parse_robots("Disallow: /private\ninvalid\n")["malformed_lines"] == 2


@pytest.mark.asyncio
async def test_absent_web_controls_and_safe_no_signal_paths(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )
    missing = _response("https://example.com/", status=404)
    tools._fetch = AsyncMock(return_value=missing)

    csp = await tools.call("csp_analysis", {"url": "https://example.com"})
    robots = await tools.call("robots_txt_analysis", {"url": "https://example.com"})
    assert csp["present"] is False
    assert robots["present"] is False

    with pytest.raises(ValueError, match="relative"):
        await tools.sitemap_analysis("https://example.com", "https://outside.test/map.xml")

    tools._fetch = AsyncMock(
        return_value=_response(
            "https://example.com/account",
            b"<script src='/local.js'></script>",
            content_type="text/html",
            headers={"cache-control": "public", "allow": "GET, HEAD"},
            cookies=["session=x"],
        )
    )
    cache = await tools.call("cache_policy_analysis", {"url": "https://example.com/account"})
    sri = await tools.call("sri_analysis", {"url": "https://example.com/account"})
    methods = await tools.call("http_method_analysis", {"url": "https://example.com/account"})
    assert cache["finding_count"] == 2
    assert sri["coverage_percent"] == 100.0
    assert methods["potentially_dangerous_methods"] == []


@pytest.mark.asyncio
async def test_discovery_tools_bound_errors_and_invalid_documents(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.require_network_safe = AsyncMock(
        return_value=parse_target("https://example.com", require_url=True)
    )
    tools._fetch = AsyncMock(side_effect=ToolExecutionError("network failure", code="http_error"))
    metadata = await tools.web_metadata_discovery(
        "https://example.com", paths=["/.well-known/webfinger"]
    )
    oidc = await tools.oauth_oidc_discovery("https://example.com")
    graphql = await tools.graphql_endpoint_discovery("https://example.com", paths=["/graphql"])
    exposures = await tools.sensitive_file_exposure_scan("https://example.com", paths=["/.env"])
    assert metadata["results"][0]["error"] == "network failure"
    assert oidc["document_count"] == 0
    assert graphql["endpoint_count"] == 0
    assert exposures["finding_count"] == 0

    page = _response(
        "https://example.com/",
        b"<link rel='icon' href='https://outside.test/icon.png'>",
        content_type="text/html",
    )

    async def favicon_fetch(url: str, **_kwargs):
        if url == "https://example.com/":
            return page
        raise ToolExecutionError("not found", code="http_error")

    tools._fetch = AsyncMock(side_effect=favicon_fetch)
    favicon = await tools.favicon_fingerprint("https://example.com/")
    assert favicon["found"] is False
    assert favicon["attempts"][0]["skipped"] == "outside authorized scope"


@pytest.mark.asyncio
async def test_unsigned_dns_and_no_wildcard_paths(tmp_path) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools._dns_values = AsyncMock(return_value=([], "NoAnswer"))
    dnssec = await tools.dnssec_posture_analysis("example.com")
    wildcard = await tools.wildcard_dns_analysis("example.com", probe_count=2)
    dangling = await tools.dangling_dns_analysis("example.com")
    assert dnssec["signed"] is False
    assert dnssec["finding_count"] == 1
    assert wildcard["wildcard_detected"] is False
    assert dangling["dangling"] is False


@pytest.mark.asyncio
async def test_tls_protocol_matrix_uses_pinned_address(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path))
    tools.scope.resolve_network_safe = AsyncMock(
        return_value=(parse_target("example.com"), ("93.184.216.34",))
    )

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeTLS(FakeSocket):
        def version(self):
            return "TLS"

        def cipher(self):
            return ("TEST-CIPHER", "TLS", 256)

    class FakeContext:
        check_hostname = False
        verify_mode = 0
        minimum_version = None
        maximum_version = None

        def wrap_socket(self, _socket, *, server_hostname: str):
            assert server_hostname == "example.com"
            return FakeTLS()

    monkeypatch.setattr(core.ssl, "SSLContext", lambda _protocol: FakeContext())
    monkeypatch.setattr(core.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())

    result = await tools.call("tls_configuration_analysis", {"target": "example.com", "port": 443})
    assert result["supported_protocols"] == ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert result["finding_count"] == 1


@pytest.mark.asyncio
async def test_external_adapter_missing_binary_and_failed_process(tmp_path, monkeypatch) -> None:
    tools = SecurityTools(_config(tmp_path, external=["subfinder"]))
    monkeypatch.setattr(core.shutil, "which", lambda _value: None)
    with pytest.raises(ToolExecutionError, match="not found"):
        await tools.subfinder_discovery("example.com")

    monkeypatch.setattr(core.shutil, "which", lambda _value: "/bin/subfinder")
    monkeypatch.setattr(
        core,
        "run_command_async",
        AsyncMock(
            return_value={
                "returncode": 1,
                "stdout": "",
                "stderr": "provider error",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "success": False,
            }
        ),
    )
    with pytest.raises(ToolExecutionError, match="provider error"):
        await tools.subfinder_discovery("example.com")
