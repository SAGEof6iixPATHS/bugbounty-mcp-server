#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ -x .venv/bin/bugbounty-mcp ]]; then
    executable=.venv/bin/bugbounty-mcp
elif [[ -x venv/bin/bugbounty-mcp ]]; then
    executable=venv/bin/bugbounty-mcp
elif command -v bugbounty-mcp >/dev/null 2>&1; then
    executable="$(command -v bugbounty-mcp)"
else
    echo "bugbounty-mcp is not installed; run ./install.sh first." >&2
    exit 1
fi

exec "$executable" "$@"
