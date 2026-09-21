#!/usr/bin/env node
/**
 * Publish the VPS agent's kind:10100 discovery profile.
 *
 * Run on the VPS only. The private key is read from AGENT_PRIVATE_KEY_FILE and
 * is never printed or sent anywhere except the local signing process.
 *
 * Default: dry-run. Add --publish to submit the replaceable profile event.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import { finalizeEvent, getPublicKey, nip19 } from "nostr-tools";

const AGENT_PUBKEY = "699f6dda532ea4353b79950be1b0e72a0cb7a41098ff3115044c63aaace0c92e";
const RELAY_HTTP_URL = (process.env.RELAY_HTTP_URL ?? "https://chat.faunaprod.cl").replace(/\/$/, "");
const CHANNEL_ID = process.env.AGENT_CHANNEL_ID ?? "944336c0-0ece-46fb-af4f-e6697fcce477";
const CHANNEL_NAME = process.env.AGENT_CHANNEL_NAME ?? "fauna-ai-pilot";
const AGENT_NAME = process.env.AGENT_NAME ?? "Fauna Creative Ops";
const KEY_FILE = process.env.AGENT_PRIVATE_KEY_FILE ?? "/run/secrets/agent-private-key";
const AUTH_TAG_FILE = process.env.AGENT_AUTH_TAG_FILE ?? "/run/secrets/agent-auth-tag";

function fail(message) {
  console.error(`publish-relay-agent-profile: ${message}`);
  process.exit(1);
}

function secretBytes(raw) {
  const value = raw.trim();
  if (value.startsWith("nsec1")) {
    const decoded = nip19.decode(value);
    if (decoded.type !== "nsec") fail("key file does not contain an nsec");
    return decoded.data;
  }
  if (/^[0-9a-f]{64}$/i.test(value)) {
    return Uint8Array.from(value.match(/../g).map((byte) => Number.parseInt(byte, 16)));
  }
  fail("key file must contain an nsec or 64-character hex key");
}

function authTag() {
  if (!fs.existsSync(AUTH_TAG_FILE)) return null;
  const value = JSON.parse(fs.readFileSync(AUTH_TAG_FILE, "utf8"));
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== "auth") {
    fail("auth tag file is not a valid NIP-OA tag");
  }
  return value;
}

const secret = secretBytes(fs.readFileSync(KEY_FILE, "utf8"));
const pubkey = getPublicKey(secret);
if (pubkey !== AGENT_PUBKEY) fail(`key belongs to ${pubkey}, expected the Fauna agent`);

const profile = {
  name: AGENT_NAME,
  display_name: AGENT_NAME,
  agent_type: "acp",
  channels: [CHANNEL_NAME],
  channel_ids: [CHANNEL_ID],
  capabilities: ["acp"],
  status: "online",
  respond_to: "anyone",
  respond_to_allowlist: [],
  // Required by the relay's kind:10100 side-effect handler. This controls who
  // may add the agent to channels; it does not widen message response scope.
  channel_add_policy: "owner_only",
};

const tags = [];
const oa = authTag();
if (oa) tags.push(["auth", oa[1], oa[2], oa[3]]);
const event = finalizeEvent(
  {
    kind: 10100,
    content: JSON.stringify(profile),
    tags,
    created_at: Math.floor(Date.now() / 1000),
  },
  secret,
);

if (!process.argv.includes("--publish")) {
  console.log(JSON.stringify({
    dry_run: true,
    relay: RELAY_HTTP_URL,
    pubkey,
    kind: event.kind,
    profile,
    has_auth_tag: Boolean(oa),
  }, null, 2));
  process.exit(0);
}

const body = JSON.stringify(event);
const url = `${RELAY_HTTP_URL}/events`;
const nip98 = finalizeEvent({
  kind: 27235,
  content: "",
  created_at: Math.floor(Date.now() / 1000),
  tags: [
    ["u", url],
    ["method", "POST"],
    ["nonce", crypto.randomUUID()],
    ["payload", crypto.createHash("sha256").update(body).digest("hex")],
  ],
}, secret);

const response = await fetch(url, {
  method: "POST",
  headers: {
    Authorization: `Nostr ${Buffer.from(JSON.stringify(nip98)).toString("base64")}`,
    "Content-Type": "application/json",
  },
  body,
});
const responseText = await response.text();
if (!response.ok) fail(`relay rejected profile (${response.status}): ${responseText}`);
console.log(JSON.stringify({ published: true, relay: RELAY_HTTP_URL, pubkey, response: responseText }));
