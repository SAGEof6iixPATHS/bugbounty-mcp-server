# Contributing

Contributions should preserve the server's honest, bounded, authorization-first design.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy bugbounty_mcp_server
pytest --cov=bugbounty_mcp_server
python -m build
twine check dist/*
```

## Adding a tool

Add only behavior that can be implemented and tested. Every tool needs a closed input schema, useful
output schema, hard limits, correct MCP annotations, scope checks before network work, structured
expected errors, tests for success/failure/bounds, and documentation. Do not add exploit payloads,
credential theft, persistence, evasion, destructive testing, or placeholder output.

## Security-sensitive changes

Threat-model redirects, DNS, subprocesses, filesystem paths, credentials, response sizes, parser
complexity, and prompt injection. Prefer passive checks. Never make a new external integration active
by default. Report security issues through the private process described in `SECURITY.md`.
