# Operations guide

## Production checklist

- Keep `SAFE_MODE=true` and encode the exact program scope and exclusions.
- Start with conservative request, concurrency, crawl, path, port, response, and evidence limits.
- Use stdio for a single local client. For HTTP, configure `HTTP_BEARER_TOKEN`, terminate TLS, and
  retain the explicit `--allow-remote` acknowledgement.
- Apply outbound firewall policy that permits only authorized program ranges plus required DNS and
  certificate-transparency services.
- Run the container as its built-in UID/GID 10001 with a read-only root filesystem.
- Back up `DATA_DIR`; treat both data and reports as sensitive assessment material.
- Keep Nuclei disabled unless its binary and template set are reviewed and pinned.
- Keep passive CLI adapters disabled unless their binaries, data sources, credentials, upstream
  terms, and the bounty program's passive-enumeration rules are reviewed.

## Health and readiness

`bugbounty-mcp validate-config --json` validates static readiness without revealing secrets.
The `server_health` tool reports version, scope readiness, optional dependency status, storage paths,
and in-process execution metrics. `assessment_summary` adds severity/status counts and assessed
targets.

Health reports Subfinder, Amass, Assetfinder, and gau availability separately from enablement. A
binary being present does not enable its MCP adapter.

The container health check validates that configuration can be loaded. Compose also checks that the
HTTP listener accepts TCP connections; successful TCP connection is not an authenticated MCP probe.

## Backups and recovery

Stop the single writer before taking a consistent filesystem snapshot. Back up `findings.json` and
the `evidence/` tree together. Reports can be regenerated. After recovery, read evidence resources
to verify stored SHA-256 digests. If the store JSON is corrupt, preserve it for investigation instead
of replacing it silently.

## Upgrade procedure

1. Read `CHANGELOG.md` and back up `DATA_DIR`.
2. Build the wheel and run `twine check`, or build the container locally.
3. Run `validate-config`, list the exposed tools/resources/prompts, and execute the test suite.
4. Roll out to loopback or a staging network first.
5. Confirm client initialization, a scope check, resource read, and finding/report round trip.

## Observability and privacy

Logs contain tool names and generated incident IDs, not raw arguments. In-memory metrics reset on
restart and intentionally contain no target names. Proxy logs must redact `Authorization` headers.
MCP client transcripts may contain target metadata or finding text and should follow the program's
data-retention rules.
