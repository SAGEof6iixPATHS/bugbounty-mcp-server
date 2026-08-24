#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

case "${1:-help}" in
    build)
        exec docker build --tag bugbounty-mcp:2.1.0 .
        ;;
    up)
        exec docker compose up --build --detach
        ;;
    down)
        exec docker compose down
        ;;
    logs)
        exec docker compose logs --follow bugbounty-mcp
        ;;
    config)
        exec docker compose config
        ;;
    help|-h|--help)
        echo "Usage: ./docker.sh {build|up|down|logs|config}" >&2
        ;;
    *)
        echo "Unknown command: $1" >&2
        exit 2
        ;;
esac
