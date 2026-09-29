// motion-passport: exempt test file, no UI and no animation.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { applyRemovals, readRemovedPosts, rewriteJsonl } from "../api/removals.mjs";
import { createApi } from "../api/server.mjs";
import { CEILINGS } from "../api/rules.mjs";

const OWNER = "keeper";
const A = `${"a".repeat(24)}-000000`;
const B = `${"b".repeat(24)}-000000`;
const hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const lines = (f) => fs.readFileSync(f, "utf8").split("\n").filter(Boolean);
const jsonl = (f, recs, tail = "") => fs.writeFileSync(f, recs.map((r) => JSON.stringify(r)).join("\n") + "\n" + tail);
const id = (n) => String(n).padStart(24, "0");

function seed() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-removals-"));
  jsonl(path.join(dir, "accounts.jsonl"), [
    { login: OWNER, hash: "scrypt$old", owner: true },
    { login: A, hash: "scrypt$a", cred: "ah-cred-1" },
    { login: OWNER, hash: "scrypt$newer", owner: true },
    { login: B, hash: "scrypt$b", cred: "ah-cred-1" },
  ]);
  fs.mkdirSync(path.join(dir, "vault"));
  fs.writeFileSync(path.join(dir, "vault", `${hex(OWNER)}.json`), "{}");
  fs.writeFileSync(path.join(dir, "vault", `${hex(OWNER)}.json.7.tmp`), "{}");
  fs.writeFileSync(path.join(dir, "vault", `${hex(A)}.json`), "{}");
  jsonl(path.join(dir, "inbox.jsonl"), [
    { t: "drop", id: "1".repeat(24), to: OWNER, at: "2026-09-29T10:00:00.000Z", sealed: {} },
    { t: "drop", id: "2".repeat(24), to: A, at: "2026-09-29T10:00:00.000Z", sealed: {} },
    { t: "remove", to: OWNER, ids: ["1".repeat(24)] },
  ]);
  const t0 = "2026-09-29T10:00:00.000Z";
  jsonl(
    path.join(dir, "forum.jsonl"),
    [
      { id: id(1), thread: "f".repeat(24), author: OWNER, text: "first by the owner", at: t0 },
      { id: id(2), thread: "f".repeat(24), author: A, text: "reply by a", at: t0 },
      { type: "ban", thread: "f".repeat(24), login: A, by: OWNER, at: t0 },
      { id: id(3), thread: "e".repeat(24), author: A, text: "a thread by a", at: t0 },
      { id: id(4), thread: "e".repeat(24), author: B, text: "text to remove", at: t0 },
      { type: "ban", thread: "e".repeat(24), login: B, by: A, at: t0 },
    ],
    '{"id":"torn',
  );
  jsonl(path.join(dir, "keys.jsonl"), [{ login: OWNER, enc: "x", sig: "y" }]);
  jsonl(path.join(dir, "dm.jsonl"), [
    { t: "conv", id: "c1", members: [A, OWNER] },
    { t: "msg", conv: "c1", from: A, ct: "..." },
    { t: "conv", id: "c2", members: [A, B] },
  ]);
  return dir;
}

test("an owner-marked account is deleted everywhere but the key log", () => {
  const dir = seed();
  try {
    const keysBefore = fs.readFileSync(path.join(dir, "keys.jsonl"));
    const c = applyRemovals(dir, { posts: [id(4)], now: () => Date.parse("2026-09-29T17:00:00Z") });
    assert.deepEqual(c, { accounts: 1, accountLines: 2, vaults: 1, inbox: 2, forumMessages: 1, forumBans: 1, retired: 1, posts: 1 });

    assert.deepEqual(lines(path.join(dir, "accounts.jsonl")).map((l) => JSON.parse(l).login), [A, B]);
    assert.deepEqual(fs.readdirSync(path.join(dir, "vault")), [`${hex(A)}.json`]);
    assert.deepEqual(lines(path.join(dir, "inbox.jsonl")).map((l) => JSON.parse(l).to), [A]);
    assert.deepEqual(lines(path.join(dir, "dm.jsonl")).map((l) => JSON.parse(l).id ?? JSON.parse(l).t), ["msg", "c2"]);
    assert.ok(fs.readFileSync(path.join(dir, "keys.jsonl")).equals(keysBefore), "the key log is not touched");

    const forum = lines(path.join(dir, "forum.jsonl"));
    assert.equal(forum.length, 6, "one ban dropped, the torn line kept");
    assert.deepEqual(JSON.parse(forum[0]), { id: id(1), thread: "f".repeat(24), at: "2026-09-29T10:00:00.000Z", removed: true });
    assert.deepEqual(JSON.parse(forum[3]), { id: id(4), thread: "e".repeat(24), author: B, at: "2026-09-29T10:00:00.000Z", removed: true });
    assert.equal(forum[5], '{"id":"torn');
    const all = fs.readFileSync(path.join(dir, "forum.jsonl"), "utf8") + fs.readFileSync(path.join(dir, "accounts.jsonl"), "utf8") + fs.readFileSync(path.join(dir, "inbox.jsonl"), "utf8");
    assert.ok(!all.includes(OWNER), "the login is gone from the live files");
    assert.ok(!all.includes("text to remove") && !all.includes("first by the owner"), "removed text is gone from the live file");

    const journal = lines(path.join(dir, "removals-journal.jsonl"));
    assert.equal(journal.length, 1);
    assert.ok(!journal[0].includes(OWNER) && !journal[0].includes(id(4)), "the journal carries counts only");

    // Idempotent: a second start changes nothing and journals nothing.
    const again = applyRemovals(dir, { posts: [id(4)] });
    assert.ok(Object.values(again).every((n) => n === 0));
    assert.equal(lines(path.join(dir, "removals-journal.jsonl")).length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the API serves removal markers: no text, no author for a deleted account, owner null", async () => {
  const dir = seed();
  applyRemovals(dir, { posts: [id(4)] });
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  const cookie = `ah_session=${api.sessions.create(A).token}`;
  const get = async (p) => (await fetch(`${base}${p}`, { headers: { cookie } })).json();
  try {
    assert.equal(api.store.has(OWNER), false);
    const f = await get(`/api/threads/${"f".repeat(24)}`);
    assert.equal(f.owner, null);
    assert.deepEqual(f.banned, [], "the deleted account's bans are gone");
    assert.deepEqual(f.messages[0], { id: id(1), author: null, text: null, at: "2026-09-29T10:00:00.000Z", removed: true });
    assert.deepEqual(f.messages[1], { id: id(2), author: A, text: "reply by a", at: "2026-09-29T10:00:00.000Z" });
    const e = await get(`/api/threads/${"e".repeat(24)}`);
    assert.deepEqual(e.messages[1], { id: id(4), author: B, text: null, at: "2026-09-29T10:00:00.000Z", removed: true });
    assert.deepEqual(e.banned, [B], "other bans stay");
    const list = await get("/api/threads");
    assert.equal(list.threads.find((t) => t.id === "f".repeat(24)).first.removed, true);
    // Nobody owns a thread whose first author was deleted: no ban there.
    const ban = await fetch(`${base}/api/threads/${"f".repeat(24)}/bans`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ login: B }) });
    assert.equal((await ban.json()).error, "not_thread_owner");
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("removed-posts.json in the source is a valid list of message ids", () => {
  const ids = readRemovedPosts();
  assert.ok(Array.isArray(ids));
  for (const x of ids) assert.match(x, /^[0-9a-f]{24}$/);
  const bad = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ah-rp-")), "r.json");
  fs.writeFileSync(bad, JSON.stringify({ removed: [{ id: "nope" }] }));
  assert.throws(() => readRemovedPosts(bad));
});

test("rewriteJsonl leaves an untouched file as it was", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-rw-"));
  const f = path.join(dir, "x.jsonl");
  fs.writeFileSync(f, '{"a":1}\n{"a":2}\n');
  const before = fs.statSync(f).ino;
  assert.equal(rewriteJsonl(f, () => undefined), 0);
  assert.equal(fs.statSync(f).ino, before, "not rewritten");
  assert.equal(rewriteJsonl(path.join(dir, "missing.jsonl"), () => null), 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("storage ceilings: accounts_full and vault_full answer 507", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-ceil-"));
  const keep = { ...CEILINGS };
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  try {
    CEILINGS.accounts = 1;
    assert.equal((await api.store.create(A, "x".repeat(43))).ok, true);
    assert.equal((await api.store.create(B, "x".repeat(43))).reason, "accounts_full");

    const cookie = `ah_session=${api.sessions.create(A).token}`;
    const put = (version, ct) => fetch(`${base}/api/vault`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ version, blob: { iv: "AAAAAAAAAAAAAAAA", ct } }) });
    assert.equal((await put(1, "A".repeat(400))).status, 200);
    CEILINGS.vaultBytes = api.vaults.bytes + 10;
    const full = await put(2, "A".repeat(800));
    assert.equal(full.status, 507);
    assert.equal((await full.json()).error, "vault_full");
    assert.equal((await put(2, "A".repeat(100))).status, 200, "a write that shrinks the vault still lands");
  } finally {
    Object.assign(CEILINGS, keep);
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
