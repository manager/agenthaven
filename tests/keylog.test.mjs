// motion-passport: exempt test file, no UI and no animation.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createApi } from "../api/server.mjs";
import * as server from "../api/dm.mjs";
import * as dm from "../public/js/dm-crypto.js";
import { KeyLog, KLOG, leafText, parseHead } from "../public/js/key-log.js";
import { createClient } from "../client/ah-client.mjs";
import { ENGINE } from "../public/js/dm-engine.js";
// Agents here register moments apart: the record is read again at once.
ENGINE.witnessRetryMs = 0;

// RFC 6962 tree hash written out the plain recursive way, as an outside check
// on both implementations.
const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
function mth(leaves) {
  if (!leaves.length) return sha();
  if (leaves.length === 1) return sha(Buffer.from([0]), Buffer.from(leafText(leaves[0]), "utf8"));
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return sha(Buffer.from([1]), mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}


// What the witness outside agent haven would publish right now: the key log
// head as the server's own key book computes it. Tests that freeze or forge
// the record build their own.
const liveWitness = (api) => async () => {
  const entries = [];
  let p = api.keys.page(0);
  for (;;) {
    entries.push(...p.entries);
    if (entries.length >= p.size || !p.entries.length) break;
    p = api.keys.page(entries.length);
  }
  return { v: "ah-witness-1", head: `${p.size}:${p.root}`, keylog: { size: p.size, root: p.root, entries } };
};
let W = null;
async function withApi(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-klog-"));
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  W = liveWitness(api);
  const member = async (login) => {
    await api.store.create(login, "x".repeat(8));
    const cookie = `ah_session=${api.sessions.create(login).token}`;
    const get = async (p) => {
      const res = await fetch(`${base}${p}`, { headers: { cookie } });
      return { status: res.status, ...(await res.json()) };
    };
    const post = async (p, body) => {
      const res = await fetch(`${base}${p}`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify(body) });
      return { status: res.status, ...(await res.json()) };
    };
    return { login, cookie, get, post, fetchPage: (from) => get(`/api/keylog?from=${from}`) };
  };
  try {
    await fn({ api, base, dir, member });
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A hostile server writes a set into its log without its own checks.
function hostileAppend(api, set) {
  const rec = { ...set, at: new Date().toISOString() };
  api.keys.log.append([rec]);
  api.keys.index(rec);
}

// A published key set as the key book stores it.
async function keySet(login, identity, previous, opts) {
  return { login, ...(await dm.keysPublication(login, identity, previous, opts)), at: new Date().toISOString() };
}

test("server and client compute the same tree hash, and it is RFC 6962's", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-klog-"));
  try {
    const book = new server.KeyBook(dir);
    const ids = [];
    for (let i = 0; i < 5; i++) ids.push(await dm.generateIdentity());
    // 19 sets: first sets, replacements and a reset, so every leaf shape occurs.
    for (let i = 0; i < 19; i++) {
      const who = `agent-${i % 5}`;
      const had = book.history(who).length;
      const next = await dm.generateIdentity();
      const reset = i === 12;
      const body = await dm.keysPublication(who, next, had && !reset ? ids[i % 5] : null, { reset });
      assert.ok(book.publish(who, body).ok, `set ${i}`);
      ids[i % 5] = next;
    }
    const page = book.page(0);
    assert.equal(page.size, 19);
    const log = new KeyLog();
    assert.deepEqual(await log.sync(async (from) => book.page(from)), { ok: true, added: 19 });
    for (let n = 0; n <= 19; n++) {
      const expected = mth(page.entries.slice(0, n)).toString("base64url");
      assert.equal(book.rootAt(n), expected, `server root at ${n}`);
      assert.equal(await log.rootAt(n), expected, `client root at ${n}`);
    }
    assert.equal(server.leafText(page.entries[12]), leafText(page.entries[12]));
    assert.match(server.leafText(page.entries[12]), /\nreset\n/);
    assert.equal(server.KLOG.version, KLOG.version);
    assert.equal(server.KLOG.pageMax, KLOG.pageMax);
    // The book reloaded from its file gives the same log.
    assert.equal(new server.KeyBook(dir).rootAt(19), book.rootAt(19));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("GET /api/keylog pages the log, needs a session and refuses a bad from", async () => {
  await withApi(async ({ base, member }) => {
    const a = await member("agent-a");
    const b = await member("agent-b");
    const ia = await dm.generateIdentity();
    const ib = await dm.generateIdentity();
    assert.equal((await a.post("/api/keys", await dm.keysPublication("agent-a", ia))).status, 201);
    assert.equal((await b.post("/api/keys", await dm.keysPublication("agent-b", ib))).status, 201);
    const all = await a.get("/api/keylog");
    assert.equal(all.size, 2);
    assert.deepEqual(all.entries.map((e) => e.login), ["agent-a", "agent-b"]);
    const tail = await a.get("/api/keylog?from=1");
    assert.equal(tail.from, 1);
    assert.deepEqual(tail.entries.map((e) => e.login), ["agent-b"]);
    assert.equal(tail.root, all.root);
    assert.equal((await a.get("/api/keylog?from=2")).entries.length, 0);
    for (const bad of ["3", "-1", "01", "x", "1.5"]) assert.equal((await a.get(`/api/keylog?from=${bad}`)).error, "keylog_range", bad);
    assert.equal((await fetch(`${base}/api/keylog`)).status, 401);
    assert.equal((await a.post("/api/keylog", {})).status, 405);
  });
});

test("a client catches a rewritten, shortened or invalid log and keeps what it had", async () => {
  await withApi(async ({ member }) => {
    const a = await member("agent-a");
    const ia = await dm.generateIdentity();
    await a.post("/api/keys", await dm.keysPublication("agent-a", ia));
    const log = new KeyLog();
    assert.ok((await log.sync(a.fetchPage)).ok);
    const good = await log.head();

    // Same size, another root: the server rewrote an entry.
    const rewritten = async (from) => ({ ...(await a.fetchPage(from)), root: "A".repeat(43) });
    assert.equal((await log.sync(rewritten)).reason, "keylog_fork");
    assert.equal(await log.head(), good);

    // A page that does not start where the client stands, and a log shorter than the one it holds.
    assert.equal((await log.sync(async () => ({ ok: true, size: 5, root: "x", from: 0, entries: [] }))).reason, "keylog_invalid");
    assert.equal((await log.sync(async (from) => ({ ok: true, size: 0, root: "x", from, entries: [] }))).reason, "keylog_fork");

    // A new set whose proof does not verify, and a replacement without a chain.
    const other = await dm.generateIdentity();
    const forged = { ...(await keySet("agent-b", other)), proof: (await keySet("agent-b", ia)).proof };
    // Correct roots, so only the proof or chain check can refuse these pages.
    const withEntry = (e) => async (from) => {
      const root = mth([...log.entries, e]).toString("base64url");
      return { ok: true, size: from + 1, root, from, entries: [e], pageRoot: root };
    };
    // The same page with a valid set is taken, so the refusals below come from the checks.
    const probe = new KeyLog(JSON.parse(JSON.stringify(log.toJSON())));
    const fine = await keySet("agent-z", other);
    const fineRoot = mth([...log.entries, fine]).toString("base64url");
    assert.ok((await probe.sync(async (from) => ({ ok: true, size: from + 1, root: fineRoot, from, entries: [fine], pageRoot: fineRoot }))).ok);
    assert.equal((await log.sync(withEntry(forged))).reason, "keylog_invalid");
    assert.equal((await log.sync(withEntry(await keySet("agent-a", other)))).reason, "keylog_invalid");
    // A page that makes no progress.
    assert.equal((await log.sync(async (from) => ({ ok: true, size: from + 1, root: "x", from, entries: [] }))).reason, "keylog_invalid");
    assert.equal(log.size, 1);
    assert.equal(await log.head(), good);

    // After all that the honest log still syncs, and a saved copy restores.
    await a.post("/api/keys", await dm.keysPublication("agent-a", other, ia));
    assert.deepEqual(await log.sync(a.fetchPage), { ok: true, added: 1 });
    const restored = new KeyLog(JSON.parse(JSON.stringify(log.toJSON())));
    assert.equal(await restored.head(), await log.head());
    assert.deepEqual(await restored.sync(a.fetchPage), { ok: true, added: 0 });
  });
});

test("keys published in a member's name show as foreign to that member", async () => {
  await withApi(async ({ api, member }) => {
    const b = await member("agent-b");
    const mine = await dm.generateIdentity();
    await b.post("/api/keys", await dm.keysPublication("agent-b", mine));
    const log = new KeyLog();
    await log.sync(b.fetchPage);
    const own = [(await dm.publicKeys(mine)).sig];
    assert.equal(log.foreign("agent-b", own), null);
    // A hostile server publishes a new chain for agent-b with its own keys.
    const attacker = await dm.generateIdentity();
    assert.ok(api.keys.publish("agent-b", await dm.keysPublication("agent-b", attacker, null, { reset: true })).ok);
    assert.ok((await log.sync(b.fetchPage)).ok);
    const f = log.foreign("agent-b", own);
    assert.equal(f.sig, (await dm.publicKeys(attacker)).sig);
    // Chaining the real key back on top would repeat a signed set: the server
    // refuses it, and a hostile server that writes it anyway breaks the log for
    // every client.
    assert.equal(api.keys.publish("agent-b", await dm.keysPublication("agent-b", mine, attacker)).reason, "keys_repeat");
    hostileAppend(api, { login: "agent-b", ...(await dm.keysPublication("agent-b", mine, attacker)) });
    assert.equal((await log.sync(b.fetchPage)).reason, "keylog_invalid");
    assert.equal(log.foreign("agent-b", own).sig, f.sig);
  });
});

test("a head from a member on another log is keylog_fork; a head ahead is keylog_behind", async () => {
  const ia = await dm.generateIdentity();
  const ib = await dm.generateIdentity();
  const real = [await keySet("agent-a", ia), await keySet("agent-b", ib)];
  const forgedB = await keySet("agent-b", await dm.generateIdentity());
  const pageOf = (entries) => {
    const root = mth(entries).toString("base64url");
    return async (from) => ({ ok: true, size: entries.length, root, from, entries: entries.slice(from), pageRoot: root });
  };
  const seenByA = new KeyLog();
  const seenByB = new KeyLog();
  assert.ok((await seenByA.sync(pageOf([real[0], forgedB]))).ok);
  assert.ok((await seenByB.sync(pageOf(real))).ok);
  // A, fed the forged key for B, writes to B; B reads A's head.
  const box = { id: "0".repeat(32), token: dm.newSecret(), key: dm.newSecret() };
  const stored = await dm.sealMessage({ identity: ia, from: "agent-a", box, m: { kind: "text", text: "hello", head: await seenByA.head() } });
  const opened = await dm.openMessage(box, stored);
  assert.ok(opened.ok);
  assert.ok(await dm.checkSigned(box, opened.m, [real[0].sig]));
  assert.equal(opened.m.head, await seenByA.head());
  assert.deepEqual(await seenByB.checkHead(opened.m.head), { ok: false, reason: "keylog_fork" });
  assert.deepEqual(await seenByA.checkHead(await seenByA.head()), { ok: true });
  // An older head of the same log matches; one beyond it cannot be checked yet.
  assert.deepEqual(await seenByB.checkHead(`1:${await seenByB.rootAt(1)}`), { ok: true });
  assert.equal((await seenByB.checkHead(`3:${"A".repeat(43)}`)).reason, "keylog_behind");
  assert.equal((await seenByB.checkHead("2:short")).reason, "keylog_head");
  assert.deepEqual(parseHead(`0:${"A".repeat(43)}`), { size: 0, root: "A".repeat(43) });
  await assert.rejects(dm.sealMessage({ identity: ia, from: "agent-a", box, m: { kind: "text", text: "x", head: "nope" } }));
});

test("the head and the login ride inside the padding: bucket sizes are unchanged", async () => {
  const id = await dm.generateIdentity();
  const box = { id: "0".repeat(32), token: dm.newSecret(), key: dm.newSecret() };
  const lens = new Set();
  for (const from of ["a", "x".repeat(63)]) {
    for (const head of [undefined, `0:${"A".repeat(43)}`, `${"9".repeat(15)}:${"A".repeat(43)}`]) {
      for (const text of ["a", "a".repeat(700)]) {
        lens.add((await dm.sealMessage({ identity: id, from, box, m: { kind: "text", text, head } })).ct.length);
      }
    }
  }
  assert.equal(lens.size, 1, "every message in the first bucket has one ct length");
  // A leave and a move pad to the same first bucket as a short text.
  lens.add((await dm.sealMessage({ identity: id, from: "a", box, m: { kind: "leave", removed: "b", members: ["a"] } })).ct.length);
  lens.add((await dm.sealMessage({ identity: id, from: "a", box, m: { kind: "move", next: "1".repeat(32), members: ["a"] } })).ct.length);
  assert.equal(lens.size, 1);
  let longest = "a".repeat(11900);
  while (!dm.fitsText(longest)) longest = longest.slice(1);
  const e = await dm.sealMessage({ identity: id, from: "x".repeat(63), box, m: { kind: "text", text: longest, head: `${"9".repeat(15)}:${"A".repeat(43)}` } });
  assert.ok(e.ct.length <= dm.DM.ctMax);
  assert.equal(e.ct.length, dm.ctLength(longest));
  assert.equal(dm.ctLength(longest + "a"), -1);
});

// ---- The engine (page and reference client) against a server ----

async function agent(base) {
  const c = createClient({ base, witness: W });
  const cred = await c.register();
  await c.login(cred.login, cred.password);
  return { c, ...cred };
}

test("engine: keys published in an agent's name raise keylog_foreign_key for it", async () => {
  await withApi(async ({ api, base }) => {
    const a = await agent(base);
    assert.equal(a.c.engine.warning, "");
    const attacker = await dm.generateIdentity();
    assert.ok(api.keys.publish(a.login, await dm.keysPublication(a.login, attacker, null, { reset: true })).ok);
    const r = await a.c.log();
    assert.equal(r.warning, "keylog_foreign_key");
    assert.equal(r.foreign[0].sig, (await dm.publicKeys(attacker)).sig);
    // A reset answers it: new keys, and the forged set counts as seen.
    await a.c.resetKeys();
    assert.equal(a.c.engine.warning, "");
  });
});

test("engine: a first publication the server logs chained from a key it made is caught", async () => {
  await withApi(async ({ api, base }) => {
    // The server slips a set of its own in before the agent's first one.
    const c = createClient({ base, witness: W });
    const { login, password } = await c.register();
    const planted = await dm.generateIdentity();
    assert.ok(api.keys.publish(login, await dm.keysPublication(login, planted)).ok);
    // The agent's first open publishes its own keys as a reset over what it
    // found, and counts the planted set as seen; a set planted after is foreign.
    await c.login(login, password);
    assert.equal(c.engine.warning, "");
    const later = await dm.generateIdentity();
    assert.ok(api.keys.publish(login, await dm.keysPublication(login, later, null, { reset: true })).ok);
    assert.equal((await c.log()).warning, "keylog_foreign_key");
  });
});

test("engine: the key log head kept in the vault catches a rewritten log on the next visit", async () => {
  await withApi(async ({ api, base }) => {
    const a = await agent(base);
    const b = await agent(base);
    await a.c.verifyPeer(b.login);
    // The server swaps b's set for another in its log.
    const forged = await dm.generateIdentity();
    const i = api.keys.all.findIndex((r) => r.login === b.login);
    const swapped = { login: b.login, ...(await dm.keysPublication(b.login, forged)), at: api.keys.all[i].at };
    api.keys.all[i] = swapped;
    api.keys.byLogin.set(b.login, [swapped]);
    api.keys.leaves[i] = server.leafHash(swapped);
    api.keys.nodes.clear();
    // A new process for a: only login and password. The vault remembers the head.
    const again = createClient({ base, witness: W });
    await assert.rejects(again.login(a.login, a.password), /keylog_fork/);
  });
});

test("engine: a pinned key that the log later resets is key_changed until trusted", async () => {
  await withApi(async ({ api, base }) => {
    const a = await agent(base);
    const b = await agent(base);
    const first = await a.c.verifyPeer(b.login);
    // A forged reset for b (the server, or b's password in other hands).
    const forged = await dm.generateIdentity();
    assert.ok(api.keys.publish(b.login, await dm.keysPublication(b.login, forged, null, { reset: true })).ok);
    await a.c.log();
    await assert.rejects(a.c.start([b.login]), /key_changed/);
    // After checking outside agent haven, trust re-pins the keys with exactly that fingerprint.
    await assert.rejects(a.c.trust(b.login, first.fingerprint), /fingerprint_mismatch/);
    await assert.rejects(a.c.trust(b.login), /fingerprint_mismatch/);
    const t = await a.c.trust(b.login, (await a.c.verifyPeer(b.login)).fingerprint);
    assert.notEqual(t.fingerprint, first.fingerprint);
    assert.equal((await a.c.verifyPeer(b.login)).fingerprint, t.fingerprint);
  });
});

// Swaps a's first set in the server's log for another and returns a function
// that puts the real one back.
async function swapFirstSet(api, login) {
  const i = api.keys.all.findIndex((r) => r.login === login);
  const real = api.keys.all[i];
  const forged = await dm.generateIdentity();
  const swapped = { login, ...(await dm.keysPublication(login, forged)), at: real.at };
  const put = (rec) => {
    api.keys.all[i] = rec;
    api.keys.byLogin.set(login, api.keys.all.filter((r) => r.login === login));
    api.keys.leaves[i] = server.leafHash(rec);
    api.keys.nodes.clear();
  };
  put(swapped);
  return () => put(real);
}

test("engine: an open client sends nothing while the log does not extend the one it checked", async () => {
  await withApi(async ({ api, base }) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "before");
    const restore = await swapFirstSet(api, b.login);
    const box = a.c.engine.vault.convs[conv.id].boxes[0];
    const count = async () => (await fetch(`${base}/api/box/head`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: box.id, token: box.token }) }).then((r) => r.json())).size;
    const before = await count();
    await assert.rejects(a.c.send(conv.id, "during"), /keylog_fork/);
    await assert.rejects(a.c.start([b.login]), /keylog_fork/);
    await assert.rejects(a.c.leave(conv.id, c.login), /keylog_fork/);
    assert.equal(await count(), before, "nothing reached the box");
    // The server shows the log a checked again: sending resumes.
    restore();
    await a.c.send(conv.id, "after");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["before", "after"]);
  });
});

test("engine: keys in the agent's own name stop its sending until it answers them", async () => {
  await withApi(async ({ api, base }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const attacker = await dm.generateIdentity();
    assert.ok(api.keys.publish(a.login, await dm.keysPublication(a.login, attacker, null, { reset: true })).ok);
    await assert.rejects(a.c.send(conv.id, "to whom?"), /keylog_foreign_key/);
    await assert.rejects(a.c.start([b.login]), /keylog_foreign_key/);
    await a.c.resetKeys();
    await a.c.send(conv.id, "answered");
  });
});

test("engine: keys another client of the same account published are not foreign", async () => {
  await withApi(async ({ base }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const second = createClient({ base, witness: W });
    await second.login(a.login, a.password);
    await second.resetKeys();
    // The first client reads the vault again before calling the new keys foreign.
    await a.c.send(conv.id, "from the first client");
  });
});

test("engine: a fork found while reading, after the send's own check, still stops the send", async () => {
  await withApi(async ({ api, base, member }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const box = a.c.engine.vault.convs[conv.id].boxes[0];
    // Between a's check and a's read of the box: the log grows, b writes with
    // a head a has not seen (so a's read syncs again), and the log a checked
    // is rewritten.
    const real = globalThis.fetch;
    let armed = true;
    globalThis.fetch = async (url, init) => {
      if (armed && String(url).endsWith("/api/box/read")) {
        armed = false;
        const extra = await dm.generateIdentity();
        await api.store.create("zz-extra", "x".repeat(8));
        assert.ok(api.keys.publish("zz-extra", await dm.keysPublication("zz-extra", extra)).ok);
        await b.c.send(conv.id, "head ahead");
        await swapFirstSet(api, b.login);
      }
      return real(url, init);
    };
    try {
      await assert.rejects(a.c.send(conv.id, "after the fork"), /keylog_fork/);
    } finally {
      globalThis.fetch = real;
    }
    const all = await fetch(`${base}/api/box/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: box.id, token: box.token }) }).then((r) => r.json());
    const texts = [];
    for (const m of all.messages) {
      const o = await dm.openMessage(box, m);
      if (o.ok) texts.push(o.m.text);
    }
    assert.deepEqual(texts, ["head ahead"]);
  });
});
