# BugBounty MCP Server

A production-oriented Model Context Protocol server for authorized bug bounty reconnaissance,
bounded security checks, and finding management.

Version 2.1 replaces the previous 92-tool prototype with 24 tools that are implemented, schema
validated, scope checked, output bounded, and covered by protocol-level tests. It uses the current
[MCP Python SDK](https://py.sdk.modelcontextprotocol.io/) v2 API and supports stdio and Streamable
HTTP transports.

> Use this server only on systems you own or have explicit permission to test. The server enforces
> configured scope, but authorization remains the operator's responsibility.

## What is included

| Area | Tools |
| --- | --- |
| Safety | `scope_check`, `batch_scope_check`, `server_health`, `assessment_summary` |
| Reconnaissance | `dns_enumeration`, `email_security_analysis`, `subdomain_enumeration` |
| HTTP/TLS | `http_probe`, `headers_analysis`, `cors_scan`, `cookie_security_analysis`, `security_txt_analysis`, `openapi_discovery`, `ssl_scan` |
| Bounded scanning | `port_scan`, `web_crawler`, `web_directory_scan`, optional `nuclei_scan` |
| Offline analysis | `jwt_security_test` |
| Findings and reports | `create_finding`, `add_finding_evidence`, `list_findings`, `update_finding`, `generate_vulnerability_report` |

The server also exposes MCP-native knowledge and state:

- Five bundled guidance resources plus live tool-schema, configuration-schema, assessment-state,
  finding, and integrity-checked evidence resources.
- Resource templates for findings and evidence.
- Five reusable prompts for planning, passive reconnaissance, triage, disclosure, and remediation
  validation.
- Argument completion for configured targets, finding IDs, and report audiences.

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
bugbounty-mcp list-resources
bugbounty-mcp list-prompts
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
| `MAX_LINKS_PER_PAGE` | `1000` | Per-page crawler link inventory cap |
| `MAX_FORMS_PER_PAGE` | `200` | Per-page crawler form inventory cap |
| `MAX_EVIDENCE_BYTES` | `500000` | Per-artifact evidence limit |
| `DATA_DIR` | `data` | Finding store directory |
| `OUTPUT_DIR` | `output` | Report directory |
| `HTTP_BEARER_TOKEN` | empty | Optional Streamable HTTP bearer token, minimum 24 characters |
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

Findings are stored atomically in `DATA_DIR/findings.json`. Structured fields include confidence,
impact, reproduction steps, CWE, CVSS score, tags, and source-tool attribution. Evidence artifacts
are private, size-bounded, content-addressed with SHA-256, and checked for tampering when read.
Reports are generated in JSON, Markdown, escaped standalone HTML, or SARIF 2.1.0 under `OUTPUT_DIR`.
Report filenames are generated by the server; tool callers cannot choose arbitrary destinations.

## Streamable HTTP

Local HTTP mode:

```bash
bugbounty-mcp serve --transport streamable-http --host 127.0.0.1 --port 8000
```

The CLI refuses a non-loopback bind unless `--allow-remote` is present. Set a random token of at
least 24 characters to require constant-time bearer authentication:

```dotenv
HTTP_BEARER_TOKEN=replace-with-a-long-random-secret
```

Send it as `Authorization: Bearer <token>`. Bearer tokens do not provide encryption, so remote use
still requires TLS, network policy, and request logging that does not record credentials. For
multi-user or internet-facing deployments, prefer an OAuth-capable authenticating reverse proxy.

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
  bugbounty-mcp:2.1.0 serve
```

## Design notes

- MCP SDK v2 low-level handlers preserve exact schemas and structured error/result control.
- Capabilities are derived from registered handlers instead of being manually over-advertised.
- Configuration construction has no directory or logging side effects; server startup owns them.
- Secrets are never included in health output or tool-call logs.
- Subprocesses use argv execution, a closed stdin, bounded captured output, and process-group cleanup
  on timeout.
- Validated DNS answers are pinned into HTTP, TCP, and TLS connections to prevent rebinding between
  authorization and connection establishment.
- The local finding store is suitable for a single server process. Use an external transactional
  store if multiple replicas must write concurrently.

Further resources:

- [Usage workflows](USAGE.md)
- [Security and threat model](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Operations guide](docs/OPERATIONS.md)
- [MCP feature catalog](docs/MCP_FEATURES.md)
- [Safe YAML configuration](examples/config.safe.yaml)
- [Generic MCP client configuration](examples/mcp-client.json)
- [Contributing guide](CONTRIBUTING.md)

## License

MIT. See [LICENSE](LICENSE).
