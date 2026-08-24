# Security policy and threat model

## Supported version

Security fixes are provided for the latest release on `main`. Version 1 was a prototype and is not
supported.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose users. Use GitHub's private security
advisory workflow for this repository. Include the affected version, impact, reproduction steps, and
any suggested mitigation. Do not include real credentials, customer data, or targets you are not
authorized to test.

## Authorization model

The operator is responsible for obtaining permission from the asset owner. The server adds technical
guardrails but cannot determine whether a person is legally authorized.

Safe mode defaults to enabled and fails closed:

- An empty `ALLOWED_TARGETS` permits no network operations.
- Exact domains, wildcard subdomains, IPs, and CIDR ranges use canonical matching.
- Block rules take precedence over allow rules.
- Private and other non-public addresses require `ALLOW_PRIVATE_TARGETS=true`.
- URLs containing credentials and non-HTTP schemes are rejected.
- Redirect destinations are rechecked before use.
- Public hostnames that resolve to non-public addresses are rejected by default.
- The validated numeric DNS answers are used for the actual HTTP, TCP, and TLS connection.

Disabling safe mode is intended only for a separately isolated, explicitly authorized lab.

## Trust boundaries

### MCP client and model

Tool input is untrusted. Every registered tool has a closed JSON Schema, bounded collection/string
sizes, and a server-side execution timeout. Unknown fields and unknown tools are rejected. Tool-call
logs contain the tool name, not raw arguments that may contain evidence or tokens.

### Network targets

Network content, redirects, certificates, DNS records, headers, passive-provider output, and Nuclei
output are untrusted.
Response bodies are bounded and not returned by `http_probe`. HTML is parsed for inventory only and
is never rendered by the server. Report HTML escapes finding content.

HTTP uses a validating connector that hands the checked numeric answers directly to the transport.
TCP and TLS tools likewise connect to the checked numeric answer while retaining the authorized
hostname for HTTP routing and TLS SNI. Egress network policy remains recommended as independent
defense in depth.

### Local filesystem

MCP callers cannot choose report or finding-store paths. The configured `DATA_DIR`, `OUTPUT_DIR`, and
optional operator-configured directory wordlist are trusted configuration. JSON finding updates use a
sibling temporary file and atomic replacement. Finding and evidence files are owner-readable only;
evidence is size bounded and verified against its stored SHA-256 digest when read.

The store is designed for one server process. Multiple writers on a shared directory need an external
transactional datastore.

### External tools

Nuclei is disabled by default. When enabled:

- The target must pass scope checks.
- Severity and tag values are schema constrained.
- The process runs from an argv list without a shell.
- Stdin is closed.
- Runtime and captured output are bounded.
- The process group is killed on timeout.
- Redirects, update checks, interaction services, dangerous template tags, and stdin are disabled.
- Rate, concurrency, response-size, and local-network restrictions are passed explicitly.

Installed templates remain part of the trust boundary. Review and pin them according to your program's
rules and traffic limits.

Subfinder, passive Amass, Assetfinder, and gau are also disabled by default. Enabling one authorizes
the server to invoke the configured binary and disclose the queried domain to its data sources. The
server passes argv without a shell, bounds runtime/output, rejects non-domain noise, and rechecks
every returned subdomain or URL against scope. External tool configuration, provider credentials,
provider behavior, binary provenance, and upstream terms remain operator trust boundaries.

The local `secret_pattern_analysis` tool returns only type, location, length, and a shortened
SHA-256 fingerprint. It never returns matched credential values. Supplied content can still reach
the MCP client/server process boundary, so callers should minimize sensitive input and use a local
stdio deployment for incident-response material.

## Transport security

Stdio is the recommended local transport. The server reserves stdout exclusively for MCP protocol
messages and sends logs to stderr.

Streamable HTTP binds to loopback by default. The CLI refuses non-loopback binding without an explicit
`--allow-remote` acknowledgement. `HTTP_BEARER_TOKEN` enables constant-time pre-shared bearer
authentication and defensive no-store/content-sniffing response headers. A bearer token is a
single-principal deployment control, not a multi-user authorization system. For remote deployment,
require all of the following:

- Authenticated TLS termination.
- Network allow-listing or a private network.
- Per-user authorization and audit logging at the proxy.
- Request and concurrency limits.
- Egress policy appropriate to the authorized targets.
- A non-root, read-only runtime with only `DATA_DIR` and `OUTPUT_DIR` writable.

Do not expose the HTTP endpoint directly to the public internet.

## Secrets

- Keep `.env` untracked and readable only by the operator.
- Prefer injecting environment variables from a secret manager in deployed environments.
- Never place secrets in MCP client configuration committed to source control.
- Health and validation output reports only counts, booleans, paths, and dependency availability.
- If a secret was ever committed, removing the file in a later commit is insufficient: rotate the
  secret and follow the hosting provider's history-rewrite procedure if required.

## Operational controls

- Start with a low `REQUESTS_PER_SECOND` and narrow scope.
- Keep `MAX_PORTS_PER_SCAN`, crawl limits, and directory request limits small.
- Use program-approved user agents where required.
- Manually verify tool signals before creating or submitting a finding.
- Back up the finding store and restrict its filesystem permissions; evidence may be sensitive.
- Review MCP client transcripts because tool results can contain target metadata.

## Non-goals

This project is not a full penetration-testing framework, exploitation platform, credential manager,
multi-tenant service, browser sandbox, or vulnerability oracle. It intentionally does not provide
credential dumping, persistence, anti-forensics, evasion, social engineering, reverse shells, or
destructive payload generation.
