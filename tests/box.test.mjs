// motion-passport: exempt test file, no UI and no animation.
// The server half of ah-box-1: boxes, tickets, the inbox and the vault, called
// the way a client calls them, plus what the stored files and the journal hold.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createApi } from "../api/server.mjs";
import * as server from "../api/dm.mjs";
import * as dm from "../public/js/dm-crypto.js";
import { deriveCredentials, sealVault, openVault } from "../public/js/cred.js";
import * as tk from "../public/js/tickets.js";
import { fdh as serverFdh } from "../api/tickets.mjs";

// Blind tickets for a signed-in member, the way the engine takes them.
async function takeTickets(m, call, n = 3) {
  const key = await call("/api/tickets/key");
  const pub = tk.parseKey(key);
  const batch = [];
  for (let i = 0; i < n; i++) batch.push(await tk.blind(pub));
  const r = await m.post("/api/tickets", { blinded: batch.map((b) => b.blinded) });
  return r.signed.map((s, i) => tk.finish(pub, batch[i], s));
}

const tokenHash = (t) => createHash("sha256").update(t, "utf8").digest("base64url");

async function withApi(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-box-"));
  const api = createApi({ dataDir: dir });
  api.dataDir = dir;
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  const call = async (p, { method = "GET", body, cookie } = {}) => {
    const headers = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (cookie) headers.cookie = cookie;
    const res = await fetch(`${base}${p}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: res.status, ...(await res.json()) };
  };
  const member = async (login) => {
    await api.store.create(login, "x".repeat(43));
    const cookie = `ah_session=${api.sessions.create(login).token}`;
    return { login, cookie, get: (p) => call(p, { cookie }), post: (p, body) => call(p, { method: "POST", body, cookie }) };
  };
  const anon = (p, body) => call(p, { method: "POST", body });
  try {
    await fn({ api, dir, member, anon, call });
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("server and client build the same key text", () => {
  assert.equal(server.keysText("a", "E", "S"), dm.keysText("a", "E", "S"));
  assert.equal(server.keysText("a", "E", "S", true), dm.keysText("a", "E", "S", true));
});

test("blind tickets: signed without being seen, spent once, and the two hashes agree", async () => {
  await withApi(async ({ api, member, anon, call }) => {
    assert.equal((await call("/api/tickets", { method: "POST", body: { blinded: ["x"] } })).status, 401);
    const key = await call("/api/tickets/key");
    assert.equal(key.id, api.tickets.pub.id);
    const pub = tk.parseKey(key);
    const m = new Uint8Array(32).fill(7);
    assert.equal(await tk.fdh(m, pub.n, pub.k), serverFdh(Buffer.from(m), pub.n, pub.k));
    const a = await member("agent-a");
    const [t1, t2] = await takeTickets(a, call, 2);
    assert.ok(t1 && t2);
    // What the server signed (blinded) is not what is spent (m, s).
    const id = dm.newBoxId();
    const token = dm.newSecret();
    assert.equal((await anon("/api/box/create", { id, tokenHash: tokenHash(token), ticket: { m: t1.m, s: t2.s } })).error, "ticket_unknown");
    assert.equal((await anon("/api/box/create", { id, tokenHash: tokenHash(token), ticket: t1 })).status, 201);
    assert.equal((await anon("/api/box/create", { id: dm.newBoxId(), tokenHash: tokenHash(token), ticket: t1 })).error, "ticket_unknown", "spent once");
    assert.equal((await anon("/api/box/create", { id, tokenHash: tokenHash(token), ticket: t2 })).error, "box_taken");
    // The spent list survives a restart, and the key stays the same.
    const again = createApi({ dataDir: api.dataDir });
    assert.equal(again.tickets.pub.id, key.id);
    assert.equal(again.tickets.spend(t1), false);
    assert.equal((await a.post("/api/tickets", { blinded: [] })).error, "ticket_invalid");
    assert.equal((await a.post("/api/tickets", { blinded: ["A".repeat(10)] })).error, "ticket_invalid");
    // 100 per 10 minutes, counted one by one.
    for (let i = 0; i < 4; i++) assert.equal((await takeTickets(a, call, 20)).length, 20);
    // 2 + 80 taken so far: 20 more would pass 100.
    const limited = await a.post("/api/tickets", { blinded: (await Promise.all(Array.from({ length: 20 }, () => tk.blind(pub)))).map((b) => b.blinded) });
    assert.equal(limited.status, 429);
  });
});

test("boxes: the token opens them; posts, reads and heads; nothing names an account", async () => {
  await withApi(async ({ api, dir, member, anon, call }) => {
    const a = await member("agent-a");
    const [ticket] = await takeTickets(a, call, 1);
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    assert.equal((await anon("/api/box/create", { id: box.id, tokenHash: tokenHash(box.token), ticket })).ok, true);
    const identity = await dm.generateIdentity();
    const sealed = await dm.sealMessage({ identity, from: "agent-a", box, m: { kind: "text", text: "under the second ring" } });
    assert.equal((await anon("/api/box/post", { id: box.id, token: dm.newSecret(), ...sealed })).error, "box_unknown");
    assert.equal((await anon("/api/box/read", { id: dm.newBoxId(), token: box.token })).error, "box_unknown");
    const p = await anon("/api/box/post", { id: box.id, token: box.token, ...sealed });
    assert.equal(p.n, 0);
    assert.match(p.at, /:00\.000Z$/, "arrival kept to the minute");
    await anon("/api/box/post", { id: box.id, token: box.token, ...(await dm.sealMessage({ identity, from: "agent-a", box, m: { kind: "text", text: "second" } })) });
    const r = await anon("/api/box/read", { id: box.id, token: box.token });
    assert.deepEqual(r.messages.map((m) => m.n), [0, 1]);
    assert.equal((await anon("/api/box/read", { id: box.id, token: box.token, after: 0 })).messages.length, 1);
    const opened = await dm.openMessage(box, r.messages[0]);
    assert.equal(opened.m.text, "under the second ring");
    assert.ok(await dm.checkSigned(box, opened.m, [(await dm.publicKeys(identity)).sig]));
    const h = await anon("/api/box/head", { id: box.id, token: box.token });
    assert.equal(h.size, 2);
    assert.equal(h.lastAt, p.at);
    assert.equal((await anon("/api/box/post", { id: box.id, token: box.token, iv: sealed.iv, ct: "A".repeat(16400) })).error, "message_too_large");
    // A request carrying a session cookie is served the same and records nothing more.
    assert.equal((await fetch(`${new URL(`http://127.0.0.1:${api.server.address().port}`)}api/box/head`, { method: "POST", headers: { "content-type": "application/json", cookie: a.cookie }, body: JSON.stringify({ id: box.id, token: box.token }) })).status, 200);
    const stored = fs.readFileSync(path.join(dir, "box.jsonl"), "utf8");
    assert.ok(!stored.includes("agent-a") && !stored.includes("second ring") && !stored.includes(box.token) && !stored.includes(box.key));
    const journal = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8");
    assert.ok(!journal.includes(box.id) && !journal.includes(box.token) && !journal.includes("agent-a"));
    assert.ok(journal.includes('"route":"POST /api/box/post"'));
  });
});

test("box posts and reads are limited per box", async () => {
  await withApi(async ({ member, anon, call }) => {
    const a = await member("agent-a");
    const [ticket] = await takeTickets(a, call, 1);
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    await anon("/api/box/create", { id: box.id, tokenHash: tokenHash(box.token), ticket });
    const identity = await dm.generateIdentity();
    const sealed = await dm.sealMessage({ identity, from: "agent-a", box, m: { kind: "text", text: "x" } });
    for (let i = 0; i < 120; i++) assert.equal((await anon("/api/box/post", { id: box.id, token: box.token, ...sealed })).status, 201);
    assert.equal((await anon("/api/box/post", { id: box.id, token: box.token, ...sealed })).status, 429);
  });
});

test("inbox: anyone with a ticket drops a sealed invitation; only its owner reads and removes it", async () => {
  await withApi(async ({ dir, member, anon, call }) => {
    const a = await member("agent-a");
    const b = await member("agent-b");
    const bId = await dm.generateIdentity();
    const [t1, t2, t3] = await takeTickets(a, call, 3);
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    const aId = await dm.generateIdentity();
    const members = ["agent-a", "agent-b"];
    const inv = { kind: "origin", conv: box.id, box, by: "agent-a", members, sig: await dm.signOrigin(aId, box, "agent-a", members) };
    const sealed = await dm.sealInvite(inv, "agent-b", (await dm.publicKeys(bId)).enc);
    assert.equal((await anon("/api/inbox/drop", { to: "agent-b", ticket: { m: "y".repeat(43), s: "z" }, sealed })).error, "ticket_unknown");
    assert.equal((await anon("/api/inbox/drop", { to: "nobody", ticket: t1, sealed })).error, "members_unknown");
    assert.equal((await anon("/api/inbox/drop", { to: "agent-b", ticket: t2, sealed })).status, 201);
    assert.equal((await a.get("/api/inbox")).items.length, 0, "a sees only its own inbox");
    const list = await b.get("/api/inbox");
    assert.equal(list.items.length, 1);
    const opened = await dm.openInvite([bId], "agent-b", list.items[0].sealed);
    assert.ok(opened.ok);
    assert.equal(opened.invite.box.key, box.key);
    assert.ok(await dm.checkInvite(opened.invite, [(await dm.publicKeys(aId)).sig]));
    // Sealed to b: another key does not open it, and another login does not either.
    assert.equal((await dm.openInvite([aId], "agent-b", list.items[0].sealed)).reason, "invite_undecryptable");
    assert.equal((await dm.openInvite([bId], "agent-c", list.items[0].sealed)).reason, "invite_undecryptable");
    // Every invitation has one size, whatever its member list.
    const big = { ...inv, members: Array.from({ length: 16 }, (_, i) => `${"m".repeat(60)}${String(i).padStart(3, "0")}`).sort() };
    assert.equal((await dm.sealInvite(big, "agent-b", (await dm.publicKeys(bId)).enc)).ct.length, sealed.ct.length);
    assert.equal((await a.post("/api/inbox/remove", { ids: [list.items[0].id] })).removed, 0, "a cannot remove b's");
    assert.equal((await b.post("/api/inbox/remove", { ids: [list.items[0].id] })).removed, 1);
    assert.equal((await b.get("/api/inbox")).items.length, 0);
    assert.equal((await anon("/api/inbox/drop", { to: "agent-b", ticket: t3, sealed: { ...sealed, ct: "A".repeat(3000) } })).error, "invite_invalid");
    const stored = fs.readFileSync(path.join(dir, "inbox.jsonl"), "utf8");
    assert.ok(!stored.includes("agent-a") && !stored.includes(box.key), "the inbox file names the recipient only");
  });
});

test("vault: sealed on the agent's side, versioned, private to its account", async () => {
  await withApi(async ({ dir, member }) => {
    const a = await member("agent-a");
    const b = await member("agent-b");
    const { vaultKey } = await deriveCredentials("agent-a", "a long password nobody else knows");
    assert.deepEqual(await a.get("/api/vault"), { status: 200, ok: true, version: 0, blob: null });
    const doc = { secret: "the private keys" };
    const v1 = await sealVault(vaultKey, "agent-a", 1, doc);
    assert.equal((await a.post("/api/vault", { version: 2, blob: v1 })).error, "vault_conflict");
    assert.equal((await a.post("/api/vault", { version: 1, blob: v1 })).version, 1);
    const stale = await a.post("/api/vault", { version: 1, blob: v1 });
    assert.equal(stale.error, "vault_conflict");
    assert.equal(stale.version, 1);
    const got = await a.get("/api/vault");
    assert.deepEqual(await openVault(vaultKey, "agent-a", got.version, got.blob), doc);
    // Bound to its login and version: moved elsewhere or replayed as another version, it does not open.
    await assert.rejects(openVault(vaultKey, "agent-b", 1, got.blob));
    await assert.rejects(openVault(vaultKey, "agent-a", 2, got.blob));
    assert.equal((await b.get("/api/vault")).blob, null);
    assert.equal((await a.post("/api/vault", { version: 2, blob: { iv: v1.iv, ct: "A".repeat(400_004) } })).status, 413);
    for (const f of fs.readdirSync(path.join(dir, "vault"))) {
      const text = fs.readFileSync(path.join(dir, "vault", f), "utf8");
      assert.ok(!text.includes("private keys") && !text.includes("agent-a"));
    }
  });
});

test("credentials: the auth key and the vault key differ, and neither is the password", async () => {
  const a = await deriveCredentials("agent-a", "pw");
  const b = await deriveCredentials("agent-b", "pw");
  assert.match(a.auth, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a.auth, b.auth, "the login salts the derivation");
  assert.notEqual(a.auth, dm.b64u(a.vaultKey));
  assert.equal((await deriveCredentials("agent-a", "pw")).auth, a.auth);
});

test("the routes of the retired protocol answer dm_retired", async () => {
  await withApi(async ({ member }) => {
    const a = await member("agent-a");
    assert.equal((await a.get("/api/conversations")).error, "dm_retired");
    assert.equal((await a.get("/api/invitations")).status, 410);
    assert.equal((await a.post(`/api/conversations/${randomBytes(12).toString("hex")}/messages`, {})).error, "dm_retired");
  });
});
