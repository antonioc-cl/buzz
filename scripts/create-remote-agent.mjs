#!/usr/bin/env node
/**
 * Mint a VPS-only Buzz agent. nsec is written to a 0600 file and never logged.
 * Default is dry-run. Live compose apply requires --apply on the VPS.
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createHash, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  nip19,
  verifyEvent,
} from "nostr-tools";

const RESERVED_SLUGS = new Set(["agent", "relay", "postgres", "redis", "minio"]);

export function parseSlug(value) {
  const slug = String(value ?? "").trim();
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(slug)) {
    throw new Error("slug must be lowercase alphanumeric + hyphen");
  }
  if (RESERVED_SLUGS.has(slug)) throw new Error(`slug '${slug}' is reserved`);
  return slug;
}

export function slugFromName(name) {
  return parseSlug(
    String(name ?? "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32),
  );
}

export function mintAgentIdentity() {
  const secret = generateSecretKey();
  return { pubkey: getPublicKey(secret), nsec: nip19.nsecEncode(secret) };
}

export function redactSecrets(value) {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, entry] of Object.entries(value)) {
      if (/nsec|secret|private[_-]?key/i.test(key)) continue;
      out[key] = redactSecrets(entry);
    }
    return out;
  }
  if (typeof value === "string" && value.startsWith("nsec1")) return "[redacted]";
  return value;
}

function secretBytes(raw) {
  if (raw instanceof Uint8Array) return raw;
  const value = String(raw).trim();
  if (value.startsWith("nsec1")) {
    const decoded = nip19.decode(value);
    if (decoded.type !== "nsec") throw new Error("not an nsec");
    return decoded.data;
  }
  if (/^[0-9a-f]{64}$/i.test(value)) {
    return Uint8Array.from(value.match(/../g).map((byte) => Number.parseInt(byte, 16)));
  }
  throw new Error("owner key must be nsec or 64-char hex");
}

export function computeAuthTag(ownerSecret, agentPubkey, conditions = "") {
  const owner = secretBytes(ownerSecret);
  const ownerPubkey = getPublicKey(owner);
  if (ownerPubkey === agentPubkey) throw new Error("self-attestation rejected");
  const preimage = `nostr:agent-auth:${agentPubkey}:${conditions}`;
  const digest = createHash("sha256").update(preimage).digest();
  const sig = Buffer.from(schnorr.sign(digest, owner)).toString("hex");
  return JSON.stringify(["auth", ownerPubkey, conditions, sig]);
}

export function writeAgentSecrets({ secretsDir, slug, nsec, authTagJson }) {
  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(secretsDir, `${slug}-private-key`);
  const tagFile = path.join(secretsDir, `${slug}-auth-tag`);
  if (fs.existsSync(keyFile) || fs.existsSync(tagFile)) {
    throw new Error(`secrets for '${slug}' already exist`);
  }
  fs.writeFileSync(keyFile, `${nsec}\n`, { mode: 0o600 });
  fs.writeFileSync(tagFile, `${authTagJson}\n`, { mode: 0o600 });
  const pubkey = getPublicKey(secretBytes(nsec));
  return { slug, pubkey, keyFile, tagFile };
}

export function buildProfile({
  name,
  channelId,
  channelName,
  respondTo = "anyone",
}) {
  return {
    name,
    display_name: name,
    agent_type: "acp",
    channels: [channelName],
    channel_ids: [channelId],
    capabilities: ["acp"],
    status: "online",
    respond_to: respondTo,
    respond_to_allowlist: [],
    channel_add_policy: "owner_only",
  };
}

export function buildComposeOverlay({ slug, channel }) {
  const service = `agent-${slug}`;
  const key = `${slug}_private_key`;
  const tag = `${slug}_auth_tag`;
  return `services:
  ${service}:
    image: ghcr.io/block/buzz-sprig@sha256:d40784ef395025c28a1003af71d46444409e480534fa4a3ddfcc4778053224e6
    depends_on:
      relay: {condition: service_healthy}
    entrypoint: ["/bin/bash", "-ec"]
    command:
      - |
        export BUZZ_PRIVATE_KEY="$$(cat /run/secrets/${key})"
        export BUZZ_AUTH_TAG="$$(cat /run/secrets/${tag})"
        export OPENROUTER_API_KEY="$$(cat /run/secrets/openrouter_api_key)"
        exec /usr/local/bin/sprig-entrypoint
    environment:
      HOME: /home/agent
      BUZZ_RELAY_URL: wss://chat.faunaprod.cl
      BUZZ_ACP_AGENT_COMMAND: /usr/local/bin/buzz-agent
      BUZZ_ACP_AGENT_ARGS: ""
      BUZZ_ACP_MCP_COMMAND: /usr/local/bin/buzz-dev-mcp
      BUZZ_ACP_RESPOND_TO: anyone
      BUZZ_ACP_CHANNELS: ${channel}
      BUZZ_ACP_SESSION_POLICY: thread
      BUZZ_ACP_AGENTS: "1"
      BUZZ_AGENT_PROVIDER: openrouter
      BUZZ_AGENT_MODEL: openai/gpt-5.6-luna
      OPENROUTER_MODEL: openai/gpt-5.6-luna
      BUZZ_AGENT_SYSTEM_PROMPT_FILE: /config/system-prompt.txt
    secrets: [${key}, ${tag}, openrouter_api_key]
    configs:
      - source: system_prompt
        target: /config/system-prompt.txt
    volumes:
      - ${service}-work:/workspace
    working_dir: /workspace
    restart: "no"
secrets:
  ${key}: {file: ./secrets/${slug}-private-key}
  ${tag}: {file: ./secrets/${slug}-auth-tag}
volumes:
  ${service}-work: {}
`;
}

export function authorizeRemoteAgentRequest({
  event,
  superadminPubkey,
  url,
  method,
  body,
}) {
  if (!event || event.kind !== 27235) return false;
  if (!verifyEvent(event)) return false;
  if (event.pubkey !== superadminPubkey) return false;
  const tags = Object.fromEntries(
    event.tags.filter((tag) => tag.length >= 2).map((tag) => [tag[0], tag[1]]),
  );
  if (tags.u !== url || tags.method !== method) return false;
  const digest = createHash("sha256").update(body ?? "").digest("hex");
  return tags.payload === digest;
}

export function authorizeBearerToken(header, expected) {
  if (!header?.startsWith("Bearer ") || !expected) return false;
  const got = Buffer.from(header.slice(7));
  const want = Buffer.from(expected);
  if (got.length !== want.length) return false;
  return timingSafeEqual(got, want);
}

export function channelAllowed(input, allowed) {
  if (!allowed) return true;
  return input.channelId === allowed || input.channelName === allowed;
}

function fail(message) {
  console.error(`create-remote-agent: ${message}`);
  process.exit(1);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function nostrAuthEvent(header) {
  if (!header?.startsWith("Nostr ")) return null;
  try {
    return JSON.parse(Buffer.from(header.slice(6), "base64").toString("utf8"));
  } catch {
    return null;
  }
}

async function handleCreate(req, res, { superadminPubkey, apply }) {
  const url = `http://${req.headers.host}${req.url}`;
  const body = await readJson(req);
  const event = nostrAuthEvent(req.headers.authorization);
  const bearerOk = authorizeBearerToken(
    req.headers.authorization,
    process.env.SERVICE_TOKEN,
  );
  const nipOk = authorizeRemoteAgentRequest({
    event,
    superadminPubkey,
    url,
    method: "POST",
    body,
  });
  if (!bearerOk && !nipOk) {
    res.writeHead(403, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "forbidden" }));
    return;
  }
  let input;
  try {
    input = JSON.parse(body);
    if (!input.name?.trim()) throw new Error("name required");
    input.slug = parseSlug(input.slug || slugFromName(input.name));
    if (!channelAllowed(input, process.env.ALLOWED_CHANNEL)) {
      throw new Error("channel not allowed");
    }
  } catch (error) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: error.message }));
    return;
  }
  if (!apply) {
    res.writeHead(202, { "content-type": "application/json" });
    res.end(JSON.stringify({ dry_run: true, slug: input.slug, name: input.name.trim() }));
    return;
  }
  const ownerFile = process.env.OWNER_NSEC_FILE;
  if (!ownerFile || !fs.existsSync(ownerFile)) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "OWNER_NSEC_FILE missing" }));
    return;
  }
  const minted = mintAgentIdentity();
  const authTagJson = computeAuthTag(
    fs.readFileSync(ownerFile, "utf8"),
    minted.pubkey,
  );
  const secretsDir = process.env.AGENT_SECRETS_DIR ?? "/opt/fauna-ai-lab/secrets";
  const written = writeAgentSecrets({
    secretsDir,
    slug: input.slug,
    nsec: minted.nsec,
    authTagJson,
  });
  const overlay = buildComposeOverlay({
    slug: input.slug,
    channel: input.channelName ?? process.env.PILOT_CHANNEL ?? "fauna-ai-pilot",
  });
  const overlayPath = path.join(
    process.env.COMPOSE_DIR ?? "/opt/fauna-ai-lab",
    `compose.d/${input.slug}.yml`,
  );
  fs.mkdirSync(path.dirname(overlayPath), { recursive: true });
  fs.writeFileSync(overlayPath, overlay, { mode: 0o600 });
  res.writeHead(201, { "content-type": "application/json" });
  res.end(
    JSON.stringify({
      pubkey: written.pubkey,
      slug: input.slug,
      name: input.name.trim(),
      apply: true,
      overlayPath,
    }),
  );
}

function serve() {
  if (!process.env.SERVICE_TOKEN && process.env.SERVICE_TOKEN_FILE) {
    process.env.SERVICE_TOKEN = fs
      .readFileSync(process.env.SERVICE_TOKEN_FILE, "utf8")
      .trim();
  }
  const superadminPubkey = process.env.SUPERADMIN_PUBKEY;
  if (!/^[0-9a-f]{64}$/.test(superadminPubkey ?? "")) {
    fail("SUPERADMIN_PUBKEY must be 64-char hex");
  }
  const apply = process.argv.includes("--apply");
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.BIND ?? "127.0.0.1";
  http
    .createServer((req, res) => {
      if (req.method === "GET" && req.url === "/health") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === "POST" && req.url === "/v1/remote-agents") {
        handleCreate(req, res, { superadminPubkey, apply }).catch(() => {
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "internal" }));
        });
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    })
    .listen(port, host, () => {
      console.log(JSON.stringify({ listening: `${host}:${port}`, apply }));
    });
}

function main() {
  const command = process.argv[2];
  if (command === "serve") return serve();
  if (command !== "plan" && command !== "mint") {
    fail("usage: create-remote-agent.mjs plan|mint|serve [--apply]");
  }
  const name = process.env.AGENT_NAME ?? "New Fauna Agent";
  const slug = parseSlug(process.env.AGENT_SLUG ?? "new-agent");
  const minted = mintAgentIdentity();
  const profile = buildProfile({
    name,
    pubkey: minted.pubkey,
    channelId: process.env.AGENT_CHANNEL_ID ?? "944336c0-0ece-46fb-af4f-e6697fcce477",
    channelName: process.env.AGENT_CHANNEL_NAME ?? "fauna-ai-pilot",
  });
  const overlay = buildComposeOverlay({
    slug,
    channel: process.env.AGENT_CHANNEL_NAME ?? "fauna-ai-pilot",
  });
  if (command === "mint") {
    const ownerFile = process.env.OWNER_NSEC_FILE;
    if (!ownerFile) fail("OWNER_NSEC_FILE required for mint");
    const written = writeAgentSecrets({
      secretsDir: process.env.AGENT_SECRETS_DIR ?? "./secrets",
      slug,
      nsec: minted.nsec,
      authTagJson: computeAuthTag(fs.readFileSync(ownerFile, "utf8"), minted.pubkey),
    });
    console.log(JSON.stringify({ minted: true, ...redactSecrets(written), profile }, null, 2));
    return;
  }
  console.log(JSON.stringify({ dry_run: true, slug, name, profile, overlay }, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
