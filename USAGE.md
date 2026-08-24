# Usage guide

This guide assumes the server is installed and `ALLOWED_TARGETS` contains the exact assets you are
authorized to test. Use `scope_check` before any network operation.

## Recommended assessment flow

1. Confirm scope with `scope_check`.
2. Gather passive data with `dns_enumeration` and `subdomain_enumeration`.
3. Confirm exposed services with a bounded `port_scan`.
4. Use `http_probe`, `ssl_scan`, `headers_analysis`, `cookie_security_analysis`, and `cors_scan`.
5. Inventory same-host pages and paths with `web_crawler` and `web_directory_scan`.
6. If the operator enabled it, use narrowly filtered `nuclei_scan` calls.
7. Manually confirm suspected issues before calling `create_finding`.
8. Track resolution and export a report.

## Example tool inputs

### Scope

```json
{"target": "https://api.example.com/v1/health"}
```

### DNS records

```json
{
  "domain": "example.com",
  "record_types": ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
}
```

### Certificate-transparency subdomains

Passive only:

```json
{"domain": "example.com"}
```

Certificate transparency plus a bounded active candidate list:

```json
{
  "domain": "example.com",
  "active": true,
  "candidates": ["api", "admin", "staging"]
}
```

The apex and candidate subdomains must each match `ALLOWED_TARGETS` for active resolution. A typical
configuration includes both `example.com` and `*.example.com`.

### HTTP metadata

```json
{
  "url": "https://example.com/",
  "method": "GET",
  "follow_redirects": true
}
```

The body is not returned. The result includes status, final URL, redirect chain, selected headers,
title, coarse technology hints, bytes read, truncation status, elapsed time, and a SHA-256 body hash.

### TLS certificate

```json
{"target": "example.com", "port": 443}
```

### TCP connect scan

```json
{"target": "example.com", "ports": "80,443,8000-8010"}
```

If `ports` is omitted, the configured small default list is used. Ranges are inclusive, deduplicated,
and rejected when they exceed `MAX_PORTS_PER_SCAN`.

### Security headers

```json
{"url": "https://example.com/account"}
```

The score is a prioritization aid, not proof of vulnerability. Applicability varies by endpoint and
application architecture.

### CORS

```json
{
  "url": "https://api.example.com/profile",
  "origins": ["https://example.invalid", "null"]
}
```

The tool sends unauthenticated GET requests. A reflected origin is a signal to investigate; impact
depends on credential behavior and whether sensitive responses are readable cross-origin.

### Cookies

```json
{"url": "https://example.com/login"}
```

The tool examines cookies created by the unauthenticated response. It does not accept or replay user
credentials.

### Crawl

```json
{
  "url": "https://example.com/",
  "max_pages": 20,
  "max_depth": 2
}
```

Only same-host HTTP(S) links are queued. Every redirect is checked against scope.

### Directory discovery

```json
{
  "url": "https://example.com/",
  "paths": ["robots.txt", ".well-known/security.txt", "api", "admin"]
}
```

When `paths` is omitted, the operator-configured wordlist is used; otherwise a short built-in list is
used. The caller cannot supply an arbitrary filesystem path.

### JWT analysis

```json
{"jwt_token": "eyJ...header.eyJ...payload.signature"}
```

The JWT is decoded locally. Its signature is not verified because no trust key or issuer policy is
provided. Treat results as metadata review only.

### Nuclei

```json
{
  "target": "https://example.com/",
  "severity": ["critical", "high"],
  "tags": ["cve", "misconfig"]
}
```

This call fails with `tool_disabled` unless `ENABLE_NUCLEI=true`, and with `dependency_missing` if the
configured binary is unavailable.

## Findings workflow

Create a confirmed finding:

```json
{
  "title": "Session cookie missing SameSite",
  "severity": "low",
  "target": "https://example.com/login",
  "description": "The unauthenticated login response creates a session cookie without SameSite.",
  "evidence": "Set-Cookie: session=...; Secure; HttpOnly",
  "remediation": "Set SameSite=Lax or Strict where compatible.",
  "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie"]
}
```

List open high-severity findings:

```json
{"severity": "high", "status": "open"}
```

Update a finding:

```json
{
  "finding_id": "2a0a253a-39bd-4f1c-8ed5-bf747727f0f0",
  "status": "resolved",
  "note": "Retested in production on 2026-08-24."
}
```

Generate a report:

```json
{"report_format": "html", "target": "https://example.com/login"}
```

Supported statuses are `open`, `triaged`, `accepted`, `resolved`, and `false_positive`. Supported
severities are `critical`, `high`, `medium`, `low`, and `info`.

## CLI operations

```bash
bugbounty-mcp --help
bugbounty-mcp validate-config
bugbounty-mcp validate-config --json
bugbounty-mcp list-tools
bugbounty-mcp list-tools --json
bugbounty-mcp export-config --format yaml --output config.yaml
bugbounty-mcp serve
```

`export-config` refuses to overwrite an existing file.

## Error handling

Expected failures are returned to the MCP client with `isError: true`. Common error codes:

| Code | Meaning |
| --- | --- |
| `unknown_tool` | The requested name is not registered |
| `invalid_args` | Arguments failed the exact JSON Schema |
| `target_not_allowed` | Target or redirect is invalid, blocked, private, or outside scope |
| `tool_disabled` | Optional integration is disabled |
| `dependency_missing` | External executable is unavailable |
| `external_tool_failed` | External process failed without usable findings |
| `http_error` / `tls_error` | Bounded network operation failed |
| `timeout` | Whole tool execution exceeded `TOOL_TIMEOUT` |
| `output_limit` | Result was too large to safely return |
| `internal_error` | Unexpected server failure; logs contain a correlation ID |

Do not treat a tool's lack of findings as proof that a target is secure. These tools provide bounded
evidence gathering; human validation and program-specific methodology are still required.
