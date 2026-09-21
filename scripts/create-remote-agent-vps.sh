#!/usr/bin/env bash
set -euo pipefail

# Run on fauna-buzz. Default: plan (no secrets written, no compose apply).
# mint writes 0600 secret files. serve --apply starts the Tailscale-local API.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${FAUNA_AI_LAB:-/opt/fauna-ai-lab}

exec docker run --rm \
  --network host \
  --mount "type=bind,src=$SCRIPT_DIR/create-remote-agent.mjs,dst=/app/create-remote-agent.mjs,readonly" \
  --mount "type=bind,src=$ROOT/secrets,dst=/opt/fauna-ai-lab/secrets" \
  --mount "type=bind,src=$ROOT,dst=/opt/fauna-ai-lab" \
  -e AGENT_SECRETS_DIR=/opt/fauna-ai-lab/secrets \
  -e COMPOSE_DIR=/opt/fauna-ai-lab \
  -e OWNER_NSEC_FILE="${OWNER_NSEC_FILE:-}" \
  -e SUPERADMIN_PUBKEY="${SUPERADMIN_PUBKEY:-}" \
  -e AGENT_NAME="${AGENT_NAME:-}" \
  -e AGENT_SLUG="${AGENT_SLUG:-}" \
  -e AGENT_CHANNEL_ID="${AGENT_CHANNEL_ID:-}" \
  -e AGENT_CHANNEL_NAME="${AGENT_CHANNEL_NAME:-}" \
  -e BIND="${BIND:-127.0.0.1}" \
  -e PORT="${PORT:-8787}" \
  node:22-alpine \
  sh -c 'cd /app && npm install --silent --no-save --ignore-scripts nostr-tools@2.23.12 @noble/curves@2.0.1 && node create-remote-agent.mjs "$@"' \
  -- "$@"
