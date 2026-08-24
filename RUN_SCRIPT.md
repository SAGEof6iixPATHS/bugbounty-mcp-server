# Helper scripts

The scripts are intentionally thin wrappers. They do not parse `.env` with shell expansion, install
system security tools, use `sudo`, or print banners into the MCP stdio stream.

## Install

```bash
./install.sh
```

This creates `.venv` and installs the project. Pass `--dev` to install development dependencies:

```bash
./install.sh --dev
```

## Run

```bash
./run.sh validate-config
./run.sh list-tools
./run.sh list-resources
./run.sh list-prompts
./run.sh serve
```

`run.sh` chooses `.venv/bin/bugbounty-mcp`, then `venv/bin/bugbounty-mcp`, then an executable already
on `PATH`. It uses `exec`, so signals and stdin/stdout reach the server directly.

Environment variables are loaded by the Python configuration layer via `python-dotenv`; the wrapper
does not source or evaluate `.env`.

## Docker

```bash
./docker.sh build
./docker.sh up
./docker.sh logs
./docker.sh down
```

These commands are convenience aliases for `docker build` and `docker compose`. See the main README
for the security boundary of Streamable HTTP deployments.
