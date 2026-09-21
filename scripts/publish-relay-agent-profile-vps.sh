#!/usr/bin/env bash
set -euo pipefail

# Run this on fauna-buzz as root. It never copies the agent key off the VPS.
# Default is a dry-run; pass --publish only after reviewing the output.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KEY_FILE=${AGENT_PRIVATE_KEY_FILE:-/opt/fauna-ai-lab/secrets/agent-private-key}
AUTH_TAG_FILE=${AGENT_AUTH_TAG_FILE:-/opt/fauna-ai-lab/secrets/agent-auth-tag}

[[ -r "$KEY_FILE" ]] || { echo "missing key file: $KEY_FILE" >&2; exit 1; }
[[ -r "$AUTH_TAG_FILE" ]] || { echo "missing auth-tag file: $AUTH_TAG_FILE" >&2; exit 1; }

exec docker run --rm \
  --mount "type=bind,src=$SCRIPT_DIR/publish-relay-agent-profile.mjs,dst=/app/publish-relay-agent-profile.mjs,readonly" \
  --mount "type=bind,src=$KEY_FILE,dst=/run/secrets/agent-private-key,readonly" \
  --mount "type=bind,src=$AUTH_TAG_FILE,dst=/run/secrets/agent-auth-tag,readonly" \
  -e AGENT_PRIVATE_KEY_FILE=/run/secrets/agent-private-key \
  -e AGENT_AUTH_TAG_FILE=/run/secrets/agent-auth-tag \
  node:22-alpine \
  sh -c 'cd /app && npm install --silent --no-save --ignore-scripts nostr-tools && node publish-relay-agent-profile.mjs "$@"' \
  -- "$@"
