# Architecture

## Runtime flow

```text
MCP client
  ├─ stdio ───────────────────────────────┐
  └─ Streamable HTTP → bearer guard ─────┤
                                          ▼
                                MCP SDK v2 low-level server
                                  ├─ tools (24)
                                  ├─ resources + templates
                                  ├─ prompts + completion
                                  └─ structured errors/results
                                          │
                  ┌───────────────────────┼────────────────────────┐
                  ▼                       ▼                        ▼
          scope + DNS pinning      finding/evidence store     bounded adapters
                  │                  atomic private files       HTTP/TCP/TLS/Nuclei
                  ▼
         authorized destination
```

## Components

- `config.py` merges defaults, YAML/JSON, and environment variables into closed Pydantic models.
- `scope.py` canonicalizes domains, IDNs, IPs, URLs, ports, wildcards, and CIDRs. Block rules win.
  DNS answers are validated and returned to callers so the connection uses the checked address.
- `tools/core.py` contains the bounded, auditable tool registry. Each tool has closed input and
  documented output JSON Schemas.
- `findings.py` owns atomic finding updates, structured metadata, private evidence, SHA-256
  verification, and JSON/Markdown/HTML/SARIF exports.
- `catalog.py` projects guidance and runtime state through MCP resources, templates, prompts, and
  completions without exposing arbitrary filesystem paths.
- `server.py` maps exceptions to structured MCP errors and provides stdio plus guarded Streamable
  HTTP transports.

## Invariants

1. Safe mode with no allow-list permits no target.
2. Every network operation has target, rate, concurrency, response-size, and time bounds.
3. Redirects are re-authorized and validated DNS answers are pinned into connections.
4. MCP callers cannot select executable paths, report paths, evidence paths, or wordlist paths.
5. Stdio writes protocol messages only to stdout; diagnostics use stderr.
6. Secrets are represented by `SecretStr` and omitted from health, resource, and validation data.
7. Evidence bodies are not included in resource listings or SARIF reports.

## Scaling boundary

The local store is deliberately single-process. Run one writer per data directory. A multi-replica
deployment should replace `FindingStore` with a transactional database/object store and use an
external identity-aware proxy. Tool execution is stateless apart from runtime metrics and the local
finding store.
