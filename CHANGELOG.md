# Changelog

All notable changes are documented here.

## 2.0.0 - 2026-08-24

### Added

- MCP Python SDK v2 low-level server with stdio and Streamable HTTP transports.
- Exact JSON Schema validation and structured success/error results.
- Fail-closed target authorization with exact domains, wildcard labels, IPs, CIDRs, redirect checks,
  private-address controls, and DNS resolution checks.
- Eighteen implemented tools for reconnaissance, bounded scanning, offline JWT analysis, findings,
  reports, and server health.
- Atomic finding persistence and escaped JSON, Markdown, and HTML reports.
- Bounded subprocess execution and optional, disabled-by-default Nuclei integration.
- Unit, behavioral, CLI, local-network, and in-process MCP integration tests with 80% coverage gate.
- Minimal non-root Docker image and loopback-only Compose publishing.

### Changed

- Python requirement is now 3.10+.
- Stdio logging is isolated to stderr.
- Configuration is validated, side-effect free until startup, and supports YAML/JSON plus environment
  overrides.
- Documentation and scripts now describe only behavior the server implements.

### Removed

- Unimplemented, simulated, and high-risk placeholder tools from the public MCP surface.
- Prototype dependencies that were unused by runtime code.
- Automatic system-package and unpinned offensive-tool installation.
- Tracked local `.env` file; rotate any real secret that may have existed in repository history.
