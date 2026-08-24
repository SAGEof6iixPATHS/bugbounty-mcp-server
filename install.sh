#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

python_command="${PYTHON:-python3}"
if ! command -v "$python_command" >/dev/null 2>&1; then
    echo "Python was not found: $python_command" >&2
    exit 1
fi

if ! "$python_command" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
    echo "Python 3.10 or newer is required." >&2
    exit 1
fi

if [[ ! -x .venv/bin/python ]]; then
    "$python_command" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
if [[ "${1:-}" == "--dev" ]]; then
    .venv/bin/python -m pip install -e '.[dev]'
else
    .venv/bin/python -m pip install -e .
fi

if [[ ! -e .env ]]; then
    cp env.example .env
    chmod 600 .env
fi

.venv/bin/bugbounty-mcp validate-config
