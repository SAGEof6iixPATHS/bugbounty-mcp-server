from __future__ import annotations

import json

import pytest
from mcp import Client
from mcp.types import PromptReference

from bugbounty_mcp_server.config import BugBountyConfig
from bugbounty_mcp_server.server import BugBountyMCPServer, _HTTPGuardMiddleware


def _config(tmp_path, **overrides) -> BugBountyConfig:
    return BugBountyConfig(
        allowed_targets=["example.com", "*.example.com"],
        output={"data_dir": tmp_path / "data", "output_dir": tmp_path / "output"},
        **overrides,
    )


@pytest.mark.asyncio
async def test_mcp_resources_prompts_templates_and_completions(tmp_path) -> None:
    server = BugBountyMCPServer(_config(tmp_path))
    finding = await server.tools.create_finding(
        title="Missing authorization",
        severity="high",
        target="https://example.com/api/users/1",
        description="A second user's record is returned.",
        cwe="CWE-639",
        confidence="confirmed",
    )
    finding_id = finding["finding"]["id"]
    evidence = await server.tools.add_finding_evidence(
        finding_id,
        "redacted-response",
        '{"user_id": 2}',
        "application/json",
    )

    async with Client(server.server) as client:
        resources = await client.list_resources()
        templates = await client.list_resource_templates()
        guide = await client.read_resource("bugbounty://guides/scope-safety")
        tool_catalog = await client.read_resource("bugbounty://reference/tools")
        config_schema = await client.read_resource("bugbounty://reference/config-schema")
        assessment = await client.read_resource("bugbounty://state/assessment")
        finding_list = await client.read_resource("bugbounty://state/findings")
        finding_resource = await client.read_resource(f"bugbounty://findings/{finding_id}")
        evidence_resource = await client.read_resource(evidence["evidence"]["resource_uri"])
        prompts = await client.list_prompts()
        prompt = await client.get_prompt("finding-triage", {"finding_id": finding_id})
        completion = await client.complete(
            PromptReference(type="ref/prompt", name="finding-triage"),
            {"name": "finding_id", "value": finding_id[:8]},
        )

    uris = {str(resource.uri) for resource in resources.resources}
    assert "bugbounty://reference/tools" in uris
    assert f"bugbounty://findings/{finding_id}" in uris
    assert len(templates.resource_templates) == 2
    assert "validated DNS answer" in guide.contents[0].text
    assert len(json.loads(tool_catalog.contents[0].text)) == 24
    assert json.loads(config_schema.contents[0].text)["title"] == "BugBountyConfig"
    assert json.loads(assessment.contents[0].text)["scope"]["configured"] is True
    assert json.loads(finding_list.contents[0].text)["count"] == 1
    assert json.loads(finding_resource.contents[0].text)["cwe"] == "CWE-639"
    assert evidence_resource.contents[0].text == '{"user_id": 2}'
    assert len(prompts.prompts) == 5
    assert "untrusted assessment data" in prompt.messages[0].content.text
    assert completion.completion.values == [finding_id]


@pytest.mark.asyncio
async def test_all_workflow_prompts_and_completion_sources(tmp_path) -> None:
    server = BugBountyMCPServer(_config(tmp_path))
    finding = await server.tools.create_finding(
        title="Test finding",
        severity="low",
        target="example.com",
        description="A bounded test record.",
    )
    finding_id = finding["finding"]["id"]

    assessment = await server.catalog.get_prompt(
        "assessment-plan",
        {"target": "example.com", "program_rules": "No automated exploitation."},
    )
    passive = await server.catalog.get_prompt("passive-recon", {"target": "example.com"})
    disclosure = await server.catalog.get_prompt(
        "disclosure-draft",
        {"finding_id": finding_id, "audience": "engineering team"},
    )
    remediation = await server.catalog.get_prompt(
        "remediation-validation",
        {"finding_id": finding_id},
    )
    target_completion = await server.catalog.complete(
        type(
            "Params",
            (),
            {"argument": type("Argument", (), {"name": "target", "value": "ex"})()},
        )()
    )
    audience_completion = await server.catalog.complete(
        type(
            "Params",
            (),
            {"argument": type("Argument", (), {"name": "audience", "value": "eng"})()},
        )()
    )

    assert "<program-rules>" in assessment.messages[0].content.text
    assert "email-security" in passive.messages[0].content.text
    assert "engineering team" in disclosure.messages[0].content.text
    assert "success/failure criteria" in remediation.messages[0].content.text
    assert target_completion.completion.values == ["example.com"]
    assert audience_completion.completion.values == ["engineering team"]

    with pytest.raises(ValueError, match="target is required"):
        await server.catalog.get_prompt("assessment-plan", {})
    with pytest.raises(ValueError, match="finding_id is required"):
        await server.catalog.get_prompt("finding-triage", {})
    with pytest.raises(ValueError, match="unknown prompt"):
        await server.catalog.get_prompt("unknown", {"finding_id": finding_id})
    with pytest.raises(ValueError, match="resource not found"):
        await server.catalog.read("bugbounty://missing/resource")


@pytest.mark.asyncio
async def test_http_guard_rejects_bad_token_and_adds_headers() -> None:
    called = False

    async def application(_scope, _receive, send) -> None:
        nonlocal called
        called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    messages = []

    async def send(message) -> None:
        messages.append(message)

    middleware = _HTTPGuardMiddleware(application, "a" * 24)
    await middleware({"type": "http", "headers": []}, receive, send)
    assert called is False
    assert messages[0]["status"] == 401
    assert (b"www-authenticate", b"Bearer") in messages[0]["headers"]

    messages.clear()
    await middleware(
        {"type": "http", "headers": [(b"authorization", b"Bearer " + b"a" * 24)]},
        receive,
        send,
    )
    assert called is True
    assert messages[0]["status"] == 200
    assert (b"x-content-type-options", b"nosniff") in messages[0]["headers"]
