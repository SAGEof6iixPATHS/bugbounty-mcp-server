# Tool catalog

Version 2.2 exposes 53 real MCP tools. `bugbounty-mcp list-tools --json` is the canonical,
machine-readable catalog and includes every input schema, output schema, title, description, and MCP
annotation.

## Safety classes

| Class | Behavior |
| --- | --- |
| Local | Does not open the network or run a subprocess |
| Passive DNS/provider | Queries DNS, certificate transparency, or an explicitly enabled passive provider |
| Bounded HTTP | Sends only the documented GET, HEAD, or OPTIONS requests with redirect, response, rate, and scope limits |
| Bounded network | Uses scope-pinned addresses for TCP or TLS connections |
| Local write | Writes only to server-managed finding, evidence, or report storage |
| Optional subprocess | Disabled by default; uses argv-only execution with runtime and output limits |

## Scope and local analysis

| Tool | Class | Purpose |
| --- | --- | --- |
| `scope_check` | Local | Explain one canonical scope decision |
| `batch_scope_check` | Local | Evaluate up to 100 targets |
| `domain_variation_generator` | Local | Generate typo-oriented domain candidates without resolving them |
| `url_parameter_analysis` | Local | Classify query parameters while hashing their values |
| `secret_pattern_analysis` | Local | Detect common credential formats without returning secret values |
| `cloud_asset_reference_analysis` | Local | Extract S3, GCS, Azure Blob, and Firebase references |
| `cvss_v31_calculator` | Local | Validate and score CVSS v3.1 base vectors |
| `jwt_security_test` | Local | Decode JWT metadata without claiming signature verification |
| `openapi_security_analysis` | Local | Analyze supplied JSON or alias-free YAML API descriptions |

Example local pipeline:

```json
{"url":"https://example.com/view?id=42&redirect_uri=https%3A%2F%2Fexample.com"}
```

Pass the result to `url_parameter_analysis`; parameter values are represented by lengths and
SHA-256 hashes, not echoed.

## DNS, email, and asset discovery

| Tool | Class | Purpose |
| --- | --- | --- |
| `dns_enumeration` | Passive DNS | Query selected A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA records |
| `dnssec_posture_analysis` | Passive DNS | Inspect DNSKEY, DS, and RRSIG publication |
| `wildcard_dns_analysis` | Passive DNS | Compare two to five random authorized labels |
| `dangling_dns_analysis` | Passive DNS | Identify unresolved CNAME targets requiring manual takeover verification |
| `email_security_analysis` | Passive DNS | Correlate MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting |
| `subdomain_enumeration` | Passive provider / optional DNS | Query certificate transparency and optionally resolve supplied prefixes |

DNSSEC output intentionally distinguishes record publication from full chain-of-trust validation.
Dangling CNAMEs and wildcard answers are indicators, never automatic vulnerability claims.

## HTTP inventory and discovery

| Tool | Class | Purpose |
| --- | --- | --- |
| `http_probe` | Bounded HTTP | Return response metadata, selected headers, and a body hash |
| `batch_http_probe` | Bounded HTTP | Probe up to 20 authorized URLs with partial-error reporting |
| `robots_txt_analysis` | Bounded HTTP | Parse RFC 9309 groups, rules, and sitemap references |
| `sitemap_analysis` | Bounded HTTP | Inventory up to 1,000 authorized sitemap URLs |
| `web_metadata_discovery` | Bounded HTTP | Check conventional `.well-known` and web metadata paths |
| `javascript_endpoint_discovery` | Bounded HTTP | Extract literal same-scope URL and path references |
| `source_map_discovery` | Bounded HTTP | Check `sourceMappingURL` and conventional map candidates without returning map bodies |
| `favicon_fingerprint` | Bounded HTTP | Return stable favicon hashes and metadata, never image bytes |
| `web_crawler` | Bounded HTTP | Crawl bounded same-host HTML pages and inventory links/forms |
| `web_directory_scan` | Bounded HTTP | HEAD-probe bounded caller or operator-controlled paths |

The crawler, JavaScript inventory, sitemap parser, and archive adapters discard external or
unauthorized results. Discovery output is not authorization to test newly found assets.

## Browser, API, and platform posture

| Tool | Class | Purpose |
| --- | --- | --- |
| `headers_analysis` | Bounded HTTP | Score important browser security and disclosure headers |
| `csp_analysis` | Bounded HTTP | Parse CSP and flag unsafe, missing, duplicate, or deprecated directives |
| `cors_scan` | Bounded HTTP | Compare unauthenticated responses for up to five origins |
| `cookie_security_analysis` | Bounded HTTP | Inspect response cookie attributes without replaying credentials |
| `cache_policy_analysis` | Bounded HTTP | Assess caching directives, validators, Vary, and CDN signals |
| `sri_analysis` | Bounded HTTP | Measure integrity coverage for external scripts/stylesheets |
| `technology_fingerprint` | Bounded HTTP | Correlate headers, cookie names, scripts, generators, and body markers |
| `security_txt_analysis` | Bounded HTTP | Validate RFC 9116 Contact and Expires metadata |
| `openapi_discovery` | Bounded HTTP | Discover and summarize same-origin OpenAPI/Swagger documents |
| `oauth_oidc_discovery` | Bounded HTTP | Summarize discovery endpoints, grants, response types, and PKCE metadata |
| `graphql_endpoint_discovery` | Bounded HTTP | Send read-only `__typename` or optional introspection GET probes |
| `sensitive_file_exposure_scan` | Bounded HTTP | HEAD-check a curated set of sensitive paths without reading bodies |
| `http_method_analysis` | Bounded HTTP | Send OPTIONS and assess advertised methods without invoking them |

`sensitive_file_exposure_scan` and `http_method_analysis` report candidates only. Generic error
pages, WAF responses, and broad OPTIONS handlers can create false positives.

## Network and TLS

| Tool | Class | Purpose |
| --- | --- | --- |
| `ssl_scan` | Bounded network | Inspect certificate identity, validity, trust, protocol, and cipher |
| `tls_configuration_analysis` | Bounded network | Test TLS 1.0 through TLS 1.3 individually |
| `port_scan` | Bounded network | Perform a capped TCP connect scan |

These tools connect to the exact IP addresses returned by authorization-time DNS validation while
retaining the original hostname for TLS SNI.

## Optional bug-bounty integrations

| Tool | Class | Purpose |
| --- | --- | --- |
| `nuclei_scan` | Optional subprocess | Run a hardened, rate-limited Nuclei invocation |
| `subfinder_discovery` | Optional subprocess | Run passive Subfinder and scope-filter results |
| `amass_passive_discovery` | Optional subprocess | Run `amass enum -passive` and scope-filter results |
| `assetfinder_discovery` | Optional subprocess | Run Assetfinder and scope-filter results |
| `gau_url_discovery` | Optional subprocess | Query configured gau archive providers and scope-filter URLs |

Install these binaries separately. They are not downloaded into the Python environment or Docker
image. Enable a reviewed subset:

```dotenv
ENABLE_NUCLEI=false
ENABLED_EXTERNAL_TOOLS=subfinder,gau
SUBFINDER_PATH=/opt/security-tools/subfinder
GAU_PATH=/opt/security-tools/gau
```

Passive provider tools disclose the queried domain to their configured data sources. Confirm that
this is allowed by the program rules before enabling them.

## Findings and runtime state

| Tool | Class | Purpose |
| --- | --- | --- |
| `create_finding` | Local write | Store a structured, auditable finding |
| `add_finding_evidence` | Local write | Store a private evidence artifact with a SHA-256 integrity record |
| `list_findings` | Local | Filter stored findings |
| `update_finding` | Local write | Change workflow status and append audit history |
| `generate_vulnerability_report` | Local write | Export JSON, Markdown, escaped HTML, or SARIF 2.1.0 |
| `assessment_summary` | Local | Summarize scope, findings, and runtime metrics |
| `server_health` | Local | Report safe readiness and optional binary availability |

## Tool result interpretation

- A successful tool result means execution succeeded, not that a vulnerability is confirmed.
- `confidence: heuristic`, candidate paths, dangling aliases, and response fingerprints require
  manual validation.
- Output schemas validate server behavior but do not make untrusted remote content safe to execute.
- Findings should contain minimal, redacted evidence and reproducible authorization context.
