#!/usr/bin/env bash
# Stops the demo and deletes the group: shares, state, audit log and .env.
set -euo pipefail
cd "$(dirname "$0")"
docker compose down 2>/dev/null || true
rm -rf signer-1 signer-2 signer-3 coordinator .env
