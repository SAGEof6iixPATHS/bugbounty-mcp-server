# BugBounty MCP Server

A production-oriented Model Context Protocol server for authorized bug bounty reconnaissance,
bounded security checks, and finding management.

Version 2 replaces the previous 92-tool prototype with 18 tools that are implemented, schema
validated, scope checked, output bounded, and covered by protocol-level tests. It uses the current
[MCP Python SDK](https://py.sdk.modelcontextprotocol.io/) v2 API and supports stdio and Streamable
HTTP transports.

> Use this server only on systems you own or have explicit permission to test. The server enforces
> configured scope, but authorization remains the operator's responsibility.

## What is included

| Area | Tools |
| --- | --- |
| Safety | `scope_check`, `server_health` |
| Reconnaissance | `dns_enumeration`, `subdomain_enumeration` |
| HTTP/TLS | `http_probe`, `headers_analysis`, `cors_scan`, `cookie_security_analysis`, `ssl_scan` |
| Bounded scanning | `port_scan`, `web_crawler`, `web_directory_scan`, optional `nuclei_scan` |
| Offline analysis | `jwt_security_test` |
| Findings and reports | `create_finding`, `list_findings`, `update_finding`, `generate_vulnerability_report` |

The server deliberately does not expose simulated scanners, credential dumping, persistence,
anti-forensics, social-engineering templates, or payload generators. A smaller honest tool surface
is safer and more useful to an MCP client than a large catalog of placeholders.

## Requirements

- Python 3.10 or newer; Python 3.11+ is recommended.
- An MCP-compatible client.
- Nuclei is optional and disabled unless explicitly enabled.

## Install

```bash
git clone https://github.com/gokulapap/bugbounty-mcp-server.git
cd bugbounty-mcp-server
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp env.example .env
```

Set at least one authorized target before using a network tool:

```dotenv
SAFE_MODE=true
ALLOWED_TARGETS=example.com,*.example.com
```

Safe mode is fail-closed. If `ALLOWED_TARGETS` is empty, network tools reject every target.

Validate the installation:

```bash
bugbounty-mcp validate-config
bugbounty-mcp list-tools
```

For development:

```bash
python -m pip install -e '.[dev]'
ruff check .
mypy bugbounty_mcp_server
pytest --cov=bugbounty_mcp_server
```

## MCP client configuration

Use the virtual environment's absolute executable path. A generic MCP client configuration looks
like this:

```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "/absolute/path/bugbounty-mcp-server/.venv/bin/bugbounty-mcp",
      "args": ["serve"],
      "env": {
        "SAFE_MODE": "true",
        "ALLOWED_TARGETS": "example.com,*.example.com"
      }
    }
  }
}
```

The default transport is stdio. Nothing except MCP protocol messages is written to stdout; logs go
to stderr.

## Target scope

Scope entries are comma-separated and matched after canonicalization:

```dotenv
# The apex only
ALLOWED_TARGETS=example.com

# Subdomains only; does not include the apex
ALLOWED_TARGETS=*.example.com

# Both apex and subdomains
ALLOWED_TARGETS=example.com,*.example.com

# An internal lab requires both the CIDR and explicit private-target opt-in
ALLOWED_TARGETS=10.20.0.0/16
ALLOW_PRIVATE_TARGETS=true

# Block rules win over allow rules
BLOCKED_TARGETS=admin.example.com
```

Safety behavior:

- Exact domains do not match lookalikes or subdomains.
- `*.example.com` matches child labels but not `example.com` itself.
- CIDR rules match IP targets.
- Block rules take precedence.
- Credentials embedded in URLs and non-HTTP URL schemes are rejected.
- Redirect destinations are re-authorized before they are followed.
- Public domain names resolving to private, loopback, link-local, reserved, or multicast addresses
  are rejected unless private targets are explicitly enabled.
- Port count, concurrency, body size, redirect count, crawl depth, pages, paths, runtime, and MCP
  output all have server-side limits.

## Configuration

Configuration priority is: defaults, optional JSON/YAML file, then environment variables.

```bash
bugbounty-mcp --config config.yaml serve
bugbounty-mcp export-config --format yaml --output config.yaml
```

Important settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SAFE_MODE` | `true` | Require allow-list matching |
| `ALLOWED_TARGETS` | empty | Authorized exact domains, wildcards, IPs, or CIDRs |
| `BLOCKED_TARGETS` | empty | Explicitly denied targets |
| `ALLOW_PRIVATE_TARGETS` | `false` | Permit non-public IP space for a controlled lab |
| `REQUESTS_PER_SECOND` | `5` | Shared outbound pacing |
| `DEFAULT_TIMEOUT` | `15` | HTTP operation timeout in seconds |
| `CONNECT_TIMEOUT` | `2` | TCP connect timeout in seconds |
| `TOOL_TIMEOUT` | `300` | Whole MCP tool-call timeout |
| `MAX_CONCURRENT_SCANS` | `30` | Concurrency cap |
| `MAX_PORTS_PER_SCAN` | `1024` | TCP port cap per call |
| `MAX_CRAWL_DEPTH` | `2` | Crawler depth cap |
| `MAX_PAGES_TO_CRAWL` | `30` | Crawler page cap |
| `DATA_DIR` | `data` | Finding store directory |
| `OUTPUT_DIR` | `output` | Report directory |
| `ENABLE_NUCLEI` | `false` | Enable the optional Nuclei adapter |
| `NUCLEI_PATH` | `nuclei` | Nuclei executable name or path |

See [env.example](env.example) for the full environment template.

## Tool behavior

All tools have closed JSON Schemas (`additionalProperties: false`). Invalid input, unknown tools,
scope violations, disabled dependencies, timeouts, output limits, and internal incidents return
MCP `CallToolResult` objects with `isError: true` and a structured error:

```json
{
  "error": {
    "code": "target_not_allowed",
    "message": "target is outside ALLOWED_TARGETS"
  }
}
```

Successful tools return both human-readable JSON text and `structuredContent`.

### Nuclei

Nuclei execution must be enabled by the operator:

```dotenv
ENABLE_NUCLEI=true
NUCLEI_PATH=nuclei
```

The adapter passes an argv list without a shell, validates severities and tags, restricts the target
to scope, enforces a timeout and output bound, and returns a normalized finding subset. You are
still responsible for reviewing installed templates and their request behavior.

### Findings and reports

Findings are stored atomically in `DATA_DIR/findings.json`. Reports are generated in JSON, Markdown,
or escaped standalone HTML under `OUTPUT_DIR`. Report filenames are generated by the server; tool
callers cannot choose arbitrary filesystem destinations.

## Streamable HTTP

Local HTTP mode:

```bash
bugbounty-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
```

The CLI refuses a non-loopback bind unless `--allow-remote` is present. That flag is only an explicit
acknowledgement: this project does not provide user authentication. For remote use, place the server
behind authenticated TLS, network policy, and request logging that does not record secrets.

## Docker

The image intentionally contains the Python server only. It does not download unpinned offensive
tools during the build.

```bash
docker compose up --build
```

Compose binds the Streamable HTTP endpoint to host loopback at `http://127.0.0.1:3001/mcp` and mounts
`data/` and `output/`. Configure `ALLOWED_TARGETS` in your local `.env` first.

For stdio from a container:

```bash
docker run --rm -i \
  -e SAFE_MODE=true \
  -e ALLOWED_TARGETS=example.com,*.example.com \
  bugbounty-mcp:2.0.0 serve
```

## Design notes

- MCP SDK v2 low-level handlers preserve exact schemas and structured error/result control.
- Capabilities are derived from registered handlers instead of being manually over-advertised.
- Configuration construction has no directory or logging side effects; server startup owns them.
- Secrets are never included in health output or tool-call logs.
- Subprocesses use argv execution, a closed stdin, bounded captured output, and process-group cleanup
  on timeout.
- The local finding store is suitable for a single server process. Use an external transactional
  store if multiple replicas must write concurrently.

See [SECURITY.md](SECURITY.md) for the threat model and [USAGE.md](USAGE.md) for example workflows.

## License

MIT. See [LICENSE](LICENSE).
