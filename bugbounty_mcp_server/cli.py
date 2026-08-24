"""Command-line entry point for serving and validating the MCP server."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shutil
from pathlib import Path
from typing import Any

import click
import yaml
from pydantic import ValidationError

from . import __version__
from .config import BugBountyConfig
from .server import BugBountyMCPServer


def _load_config(path: str | None) -> BugBountyConfig:
    try:
        return BugBountyConfig.load(path)
    except (OSError, ValueError, ValidationError) as exc:
        raise click.ClickException(f"configuration error: {exc}") from exc


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="JSON or YAML configuration file. Environment variables override file values.",
)
@click.option("--verbose", "is_verbose", is_flag=True, help="Enable debug logging.")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None, is_verbose: bool) -> None:
    """Scope-safe MCP tools for authorized bug bounty work."""
    config = _load_config(str(config_path) if config_path else None)
    if is_verbose:
        config.log_level = "DEBUG"
    ctx.obj = config


@cli.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "streamable-http"], case_sensitive=False),
    default="stdio",
    show_default=True,
)
@click.option("--host", default="127.0.0.1", show_default=True, help="HTTP bind address.")
@click.option("--port", type=click.IntRange(1, 65535), default=8000, show_default=True)
@click.option("--path", "http_path", default="/mcp", show_default=True)
@click.option("--stateless", is_flag=True, help="Use stateless Streamable HTTP sessions.")
@click.option(
    "--json-response", is_flag=True, help="Use JSON instead of SSE responses where possible."
)
@click.option(
    "--allow-remote",
    is_flag=True,
    help="Acknowledge that the HTTP listener will bind beyond loopback.",
)
@click.pass_obj
def serve(
    config: BugBountyConfig,
    transport: str,
    host: str,
    port: int,
    http_path: str,
    stateless: bool,
    json_response: bool,
    allow_remote: bool,
) -> None:
    """Start the MCP server. Stdio is the secure default."""
    server = BugBountyMCPServer(config)
    try:
        if transport == "stdio":
            # Never write startup text to stdout: stdout is the MCP protocol stream.
            asyncio.run(server.run_stdio())
            return

        if not http_path.startswith("/"):
            raise click.ClickException("--path must start with /")
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host.lower() == "localhost"
        if not is_loopback and not allow_remote:
            raise click.ClickException(
                "refusing a non-loopback HTTP bind without --allow-remote; "
                "remote exposure requires explicit operator acknowledgement"
            )
        if not is_loopback:
            if config.http.bearer_token is None:
                click.echo(
                    "WARNING: exposing an unauthenticated security-testing server; "
                    "set HTTP_BEARER_TOKEN or place it behind authenticated TLS.",
                    err=True,
                )
            else:
                click.echo(
                    "WARNING: bearer authentication is enabled, but TLS is still required "
                    "outside a trusted local network.",
                    err=True,
                )
        asyncio.run(
            server.run_streamable_http(
                host=host,
                port=port,
                path=http_path,
                stateless=stateless,
                json_response=json_response,
            )
        )
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("server stopped")
    except click.ClickException:
        raise
    except Exception as exc:
        if config.log_level == "DEBUG":
            logging.exception("server failed")
        raise click.ClickException(f"server failed: {exc}") from exc


def _configuration_status(config: BugBountyConfig) -> dict[str, Any]:
    scope_ready = not config.safe_mode or bool(config.allowed_targets)
    data_parent = config.output.data_dir.expanduser().resolve().parent
    output_parent = config.output.output_dir.expanduser().resolve().parent
    return {
        "valid": True,
        "scope_ready": scope_ready,
        "safe_mode": config.safe_mode,
        "allowed_target_count": len(config.allowed_targets),
        "blocked_target_count": len(config.blocked_targets),
        "private_targets_enabled": config.allow_private_targets,
        "http_bearer_auth_enabled": config.http.bearer_token is not None,
        "storage": {
            "data_parent_exists": data_parent.exists(),
            "output_parent_exists": output_parent.exists(),
        },
        "optional_tools": {
            "nuclei_enabled": config.tools.enable_nuclei,
            "nuclei_available": shutil.which(config.tools.nuclei_path) is not None,
            "external": {
                name: {
                    "enabled": name in config.tools.enabled_external_tools,
                    "available": shutil.which(str(getattr(config.tools, f"{name}_path")))
                    is not None,
                }
                for name in ("amass", "assetfinder", "gau", "subfinder")
            },
        },
    }


@cli.command("validate-config")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_obj
def validate_config(config: BugBountyConfig, as_json: bool) -> None:
    """Validate configuration and report readiness without exposing secrets."""
    status = _configuration_status(config)
    if as_json:
        click.echo(json.dumps(status, indent=2))
        return
    click.echo("Configuration is valid.")
    click.echo(f"Safe mode: {'enabled' if config.safe_mode else 'disabled'}")
    click.echo(f"Allowed targets: {len(config.allowed_targets)}")
    click.echo(
        "HTTP bearer authentication: "
        + ("enabled" if status["http_bearer_auth_enabled"] else "disabled")
    )
    if not status["scope_ready"]:
        click.echo("Network tools are fail-closed until ALLOWED_TARGETS is configured.")
    nuclei = status["optional_tools"]
    click.echo(
        "Nuclei: "
        + ("enabled" if nuclei["nuclei_enabled"] else "disabled")
        + ", "
        + ("binary found" if nuclei["nuclei_available"] else "binary not found")
    )
    external = nuclei["external"]
    click.echo(
        "Passive CLI adapters enabled: "
        + (", ".join(name for name, state in external.items() if state["enabled"]) or "none")
    )


@cli.command("list-tools")
@click.option("--json", "as_json", is_flag=True, help="Emit MCP tool definitions as JSON.")
@click.pass_obj
def list_tools(config: BugBountyConfig, as_json: bool) -> None:
    """List the exact tool surface exposed to MCP clients."""
    definitions = BugBountyMCPServer(config).tools.get_tools()
    if as_json:
        click.echo(
            json.dumps(
                [
                    definition.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for definition in definitions
                ],
                indent=2,
            )
        )
        return
    click.echo(f"{len(definitions)} available tools:")
    for definition in definitions:
        click.echo(f"  {definition.name:<34} {definition.description}")


@cli.command("list-resources")
@click.option("--json", "as_json", is_flag=True, help="Emit MCP resources as JSON.")
@click.pass_obj
def list_resources(config: BugBountyConfig, as_json: bool) -> None:
    """List static and current dynamic MCP resources."""
    catalog = BugBountyMCPServer(config).catalog
    resources = asyncio.run(catalog.list_resources())
    if as_json:
        click.echo(
            json.dumps(
                [
                    resource.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for resource in resources
                ],
                indent=2,
            )
        )
        return
    click.echo(f"{len(resources)} available resources:")
    for resource in resources:
        click.echo(f"  {resource.uri!s:<46} {resource.title or resource.name}")


@cli.command("list-prompts")
@click.option("--json", "as_json", is_flag=True, help="Emit MCP prompts as JSON.")
@click.pass_obj
def list_prompts(config: BugBountyConfig, as_json: bool) -> None:
    """List reusable MCP workflow prompts."""
    prompts = BugBountyMCPServer(config).catalog.list_prompts()
    if as_json:
        click.echo(
            json.dumps(
                [
                    prompt.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for prompt in prompts
                ],
                indent=2,
            )
        )
        return
    click.echo(f"{len(prompts)} available prompts:")
    for prompt in prompts:
        click.echo(f"  {prompt.name:<28} {prompt.description or ''}")


@cli.command("export-config")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    show_default=True,
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New destination file; existing files are not overwritten.",
)
def export_config(output_format: str, output: Path) -> None:
    """Write a default configuration template."""
    config = BugBountyConfig()
    data = config.model_dump(mode="json")
    try:
        with output.open("x", encoding="utf-8") as handle:
            if output_format == "json":
                json.dump(data, handle, indent=2)
                handle.write("\n")
            else:
                yaml.safe_dump(data, handle, sort_keys=False)
    except FileExistsError as exc:
        raise click.ClickException(f"refusing to overwrite existing file: {output}") from exc
    except OSError as exc:
        raise click.ClickException(f"could not write {output}: {exc}") from exc
    click.echo(str(output))


def main() -> None:
    cli(prog_name="bugbounty-mcp")


if __name__ == "__main__":
    main()
