import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools";
import {
  authorizeBearerToken,
  authorizeRemoteAgentRequest,
  buildComposeOverlay,
  buildProfile,
  channelAllowed,
  computeAuthTag,
  mintAgentIdentity,
  parseSlug,
  redactSecrets,
  writeAgentSecrets,
} from "./create-remote-agent.mjs";

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "remote-agent-"));
}

test("parseSlug: accepts stable slugs and rejects collisions/junk", () => {
  assert.equal(parseSlug("reviewer"), "reviewer");
  assert.throws(() => parseSlug("agent"), /reserved/);
  assert.throws(() => parseSlug("Fauna"), /slug/);
  assert.throws(() => parseSlug("../etc"), /slug/);
});

test("mintAgentIdentity: unique pubkeys; nsec never appears in redacted output", () => {
  const a = mintAgentIdentity();
  const b = mintAgentIdentity();
  assert.equal(a.pubkey.length, 64);
  assert.notEqual(a.pubkey, b.pubkey);
  assert.match(a.nsec, /^nsec1/);
  const redacted = JSON.stringify(redactSecrets(a));
  assert.equal(redacted.includes(a.nsec), false);
  assert.equal(redacted.includes("nsec1"), false);
});

test("computeAuthTag: owner-attested tag verifies and rejects self-attestation", () => {
  const owner = generateSecretKey();
  const agent = mintAgentIdentity();
  const tag = JSON.parse(computeAuthTag(owner, agent.pubkey));
  assert.equal(tag[0], "auth");
  assert.equal(tag[1], getPublicKey(owner));
  assert.equal(tag[2], "");
  assert.equal(tag[3].length, 128);

  assert.throws(
    () => computeAuthTag(owner, getPublicKey(owner)),
    /self-attestation/,
  );
});

test("writeAgentSecrets: writes 0600 files and never returns nsec", () => {
  const dir = tmpDir();
  const minted = mintAgentIdentity();
  const owner = generateSecretKey();
  const result = writeAgentSecrets({
    secretsDir: dir,
    slug: "reviewer",
    nsec: minted.nsec,
    authTagJson: computeAuthTag(owner, minted.pubkey),
  });
  assert.equal(result.pubkey, minted.pubkey);
  assert.equal("nsec" in result, false);
  const keyFile = path.join(dir, "reviewer-private-key");
  const mode = fs.statSync(keyFile).mode & 0o777;
  assert.equal(mode, 0o600);
  assert.equal(fs.readFileSync(keyFile, "utf8").includes("nsec1"), true);
});

test("buildComposeOverlay: new service, unique secrets, shared openrouter key", () => {
  const yaml = buildComposeOverlay({
    slug: "reviewer",
    channel: "fauna-ai-pilot",
  });
  assert.match(yaml, /agent-reviewer:/);
  assert.match(yaml, /reviewer_private_key/);
  assert.doesNotMatch(yaml, /nsec1/);
  assert.match(yaml, /openrouter_api_key/);
  assert.doesNotMatch(yaml, /\bagent:\s*$/m);
});

test("buildProfile: owner_only channel add, unique name/pubkey", () => {
  const profile = buildProfile({
    name: "Code Reviewer",
    pubkey: "ab".repeat(32),
    channelId: "944336c0-0ece-46fb-af4f-e6697fcce477",
    channelName: "fauna-ai-pilot",
  });
  assert.equal(profile.channel_add_policy, "owner_only");
  assert.equal(profile.respond_to, "anyone");
  assert.deepEqual(profile.channel_ids.length, 1);
});

test("authorizeBearerToken: exact token only", () => {
  assert.equal(authorizeBearerToken("Bearer secret-token", "secret-token"), true);
  assert.equal(authorizeBearerToken("Bearer other-token", "secret-token"), false);
  assert.equal(authorizeBearerToken("Nostr abc", "secret-token"), false);
});

test("channelAllowed: pins fauna-ai-pilot", () => {
  assert.equal(channelAllowed({ channelName: "fauna-ai-pilot" }, "fauna-ai-pilot"), true);
  assert.equal(channelAllowed({ channelName: "general" }, "fauna-ai-pilot"), false);
});

test("authorizeRemoteAgentRequest: superadmin only", () => {
  const admin = generateSecretKey();
  const other = generateSecretKey();
  const url = "http://127.0.0.1:8787/v1/remote-agents";
  const body = '{"name":"Code Reviewer","slug":"reviewer"}';
  const payload = createHash("sha256").update(body).digest("hex");
  const event = {
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    content: "",
    tags: [
      ["u", url],
      ["method", "POST"],
      ["payload", payload],
    ],
  };
  const signed = finalizeEvent(event, admin);
  assert.equal(
    authorizeRemoteAgentRequest({
      event: signed,
      superadminPubkey: getPublicKey(admin),
      url,
      method: "POST",
      body,
    }),
    true,
  );
  assert.equal(
    authorizeRemoteAgentRequest({
      event: finalizeEvent({ ...event, created_at: event.created_at + 1 }, other),
      superadminPubkey: getPublicKey(admin),
      url,
      method: "POST",
      body,
    }),
    false,
  );
});
