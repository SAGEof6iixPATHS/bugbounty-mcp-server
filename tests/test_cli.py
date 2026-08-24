from __future__ import annotations

import json

from click.testing import CliRunner

from bugbounty_mcp_server.cli import cli
from bugbounty_mcp_server.server import BugBountyMCPServer


def test_help_validation_and_tool_listing() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        help_result = runner.invoke(cli, ["--help"])
        validation = runner.invoke(cli, ["validate-config", "--json"])
        listing = runner.invoke(cli, ["list-tools", "--json"])

    assert help_result.exit_code == 0
    assert "Scope-safe MCP tools" in help_result.output
    assert validation.exit_code == 0
    assert json.loads(validation.output)["scope_ready"] is False
    definitions = json.loads(listing.output)
    assert len(definitions) == 53
    assert {item["name"] for item in definitions} >= {"scope_check", "port_scan"}


def test_export_config_refuses_to_overwrite() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        first = runner.invoke(
            cli,
            ["export-config", "--format", "yaml", "--output", "config.yaml"],
        )
        second = runner.invoke(
            cli,
            ["export-config", "--format", "yaml", "--output", "config.yaml"],
        )

    assert first.exit_code == 0
    assert second.exit_code != 0
    assert "refusing to overwrite" in second.output


def test_remote_http_bind_requires_explicit_acknowledgement() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            ["serve", "--transport", "streamable-http", "--host", "0.0.0.0"],
        )

    assert result.exit_code != 0
    assert "refusing a non-loopback HTTP bind" in result.output


def test_invalid_configuration_is_a_clean_cli_error() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("bad.yaml", "w", encoding="utf-8") as handle:
            handle.write("safe_mode: maybe\n")
        result = runner.invoke(cli, ["--config", "bad.yaml", "validate-config"])

    assert result.exit_code != 0
    assert "configuration error" in result.output


def test_human_readable_validation_and_listing() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        validation = runner.invoke(cli, ["validate-config"])
        listing = runner.invoke(cli, ["list-tools"])

    assert validation.exit_code == 0
    assert "Network tools are fail-closed" in validation.output
    assert "Nuclei:" in validation.output
    assert listing.exit_code == 0
    assert "53 available tools" in listing.output


def test_resource_and_prompt_catalog_commands() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        resources = runner.invoke(cli, ["list-resources", "--json"])
        prompts = runner.invoke(cli, ["list-prompts", "--json"])

    assert resources.exit_code == 0
    assert {item["uri"] for item in json.loads(resources.output)} >= {
        "bugbounty://guides/getting-started",
        "bugbounty://reference/tools",
    }
    assert prompts.exit_code == 0
    assert {item["name"] for item in json.loads(prompts.output)} >= {
        "assessment-plan",
        "finding-triage",
    }


def test_acknowledged_remote_http_bind_runs_with_warning(monkeypatch) -> None:
    calls = []

    async def fake_run(self, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(BugBountyMCPServer, "run_streamable_http", fake_run)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            [
                "serve",
                "--transport",
                "streamable-http",
                "--host",
                "0.0.0.0",
                "--port",
                "9000",
                "--allow-remote",
            ],
        )

    assert result.exit_code == 0
    assert "WARNING" in result.output
    assert calls == [
        {
            "host": "0.0.0.0",
            "port": 9000,
            "path": "/mcp",
            "stateless": False,
            "json_response": False,
        }
    ]


def test_http_path_must_be_absolute(monkeypatch) -> None:
    async def fake_run(self, **kwargs):
        raise AssertionError("must not run")

    monkeypatch.setattr(BugBountyMCPServer, "run_streamable_http", fake_run)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli,
            ["serve", "--transport", "streamable-http", "--path", "relative"],
        )

    assert result.exit_code != 0
    assert "--path must start with /" in result.output
