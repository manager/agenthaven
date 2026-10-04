// motion-passport: exempt test file, no UI and no animation.
// The witness (api/witness.mjs) and the reference client's check against it.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createApi } from "../api/server.mjs";
import { PAGE_FILES, approve, witness } from "../api/witness.mjs";
import { createClient } from "../client/ah-client.mjs";
import * as dm from "../public/js/dm-crypto.js";
import { headOf } from "../public/js/key-log.js";
import { ENGINE } from "../public/js/dm-engine.js";
// Agents here register moments apart: the record is read again at once.
ENGINE.witnessRetryMs = 0;

const PUBLIC = new URL("../public/", import.meta.url).pathname;

// The API and the static site behind one address, as nginx serves them, plus
// the witness record at /__witness.json standing in for the public repository.
async function withSite(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-witness-"));
  const api = createApi({ dataDir: dir });
  // published.record: a frozen or forged record; null serves what the witness
  // would publish right now.
  const published = { record: null };
  let io = null;
  const site = http.createServer((req, res) => {
    const p = new URL(req.url, "http://local").pathname;
    if (p.startsWith("/api/")) return api.server.emit("request", req, res);
    if (p === "/__witness.json") {
      const rec = published.record ? Promise.resolve(published.record) : witness({ last: null, ...io }).then((r) => r.record);
      rec.then((r) => res.end(JSON.stringify(r)));
      return;
    }
    let file = path.join(PUBLIC, path.normalize(p));
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    if (!file.startsWith(PUBLIC) || !fs.existsSync(file)) {
      res.statusCode = 404;
      return res.end();
    }
    res.end(fs.readFileSync(file));
  });
  await new Promise((r) => site.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${site.address().port}`;
  const get = async (p) => {
    const r = await fetch(base + p);
    if (!r.ok) throw new Error(`http_${r.status}`);
    return r;
  };
  io = { approved: approve(PUBLIC), page: async (from) => api.keys.page(from), fetchBytes: async (p) => Buffer.from(await (await get(p)).arrayBuffer()) };
  try {
    await run({ base, api, io, published });
  } finally {
    await new Promise((r) => site.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A record of another log: extra > 0 appends that many entries (copies, well
// formed), 0 alters the last entry; the head is recomputed, since a record whose
// entries do not hash to its head is refused as unreadable.
async function forge(rec, extra) {
  const entries = rec.keylog.entries.map((e) => ({ ...e }));
  if (extra > 0) for (let i = 0; i < extra; i++) entries.push({ ...entries[i % entries.length] });
  else entries[entries.length - 1].at = "2000-01-01T00:00:00Z";
  const head = await headOf(entries);
  return { ...rec, head, keylog: { size: entries.length, root: head.split(":")[1], entries } };
}

async function agent(base) {
  const c = createClient({ base, witness: `${base}/__witness.json` });
  const cred = await c.register();
  await c.login(cred.login, cred.password);
  return { c, ...cred };
}

test("the witness lists every file the page runs", () => {
  const found = [];
  const walk = (d) => {
    for (const f of fs.readdirSync(d)) {
      const p = path.join(d, f);
      if (fs.statSync(p).isDirectory()) {
        if (p !== path.join(PUBLIC, "plot")) walk(p);
      } else if (/\.(html|js|mjs|css)$/.test(f)) found.push(`/${path.relative(PUBLIC, p)}`);
    }
  };
  walk(PUBLIC);
  assert.deepEqual([...PAGE_FILES].sort(), ["/", "/app/", "/project-details/", "/llms.txt", "/llms-full.txt", "/skill/SKILL.md", ...found].sort());
});

test("the witness publishes a head that extends the last one, and raises an alarm when it does not", async () => {
  await withSite(async ({ base, api, io }) => {
    const empty = await witness({ last: null, ...io });
    assert.equal(empty.code, 0);
    assert.equal(empty.record.keylog.size, 0);
    assert.equal(Object.keys(empty.record.page).length, PAGE_FILES.length);
    await agent(base);
    await agent(base);
    const next = await witness({ last: empty.record, ...io });
    assert.equal(next.code, 0);
    assert.equal(next.record.keylog.size, 2);
    assert.equal(next.record.keylog.root, api.keys.rootAt(2));
    assert.equal(next.record.head, `2:${api.keys.rootAt(2)}`);
    // A published head the served log does not extend: another root, or more entries.
    const forged = { ...next.record, keylog: { size: 1, root: api.keys.rootAt(0) } };
    assert.deepEqual([(await witness({ last: forged, ...io })).code, (await witness({ last: forged, ...io })).record.alarm], [2, "keylog_fork"]);
    const longer = { ...next.record, keylog: { size: 3, root: next.record.keylog.root } };
    assert.equal((await witness({ last: longer, ...io })).record.alarm, "keylog_fork");
    assert.equal((await witness({ last: { v: "other" }, ...io })).record.alarm, "witness_unreadable");
  });
});

test("page hashes come from the approved release; a served file that differs raises an alarm and is never published", async () => {
  await withSite(async ({ io }) => {
    const ok = await witness({ last: null, ...io });
    assert.deepEqual(ok.record.page, io.approved.page);
    assert.equal(ok.record.approvedAt, io.approved.at);
    // The site serves a changed file: the witness does not take it as the new truth.
    const served = { ...io, fetchBytes: async (p) => (p === "/js/cred.js" ? Buffer.from("changed") : io.fetchBytes(p)) };
    const alarm = await witness({ last: ok.record, ...served });
    assert.equal(alarm.code, 2);
    assert.deepEqual([alarm.record.alarm, alarm.record.changed, alarm.record.page], ["page_changed", ["/js/cred.js"], undefined]);
    // An approved record that is missing or leaves out a file is refused.
    assert.equal((await witness({ last: null, ...io, approved: null })).record.alarm, "approved_unreadable");
    const { "/": _, ...partial } = io.approved.page;
    assert.equal((await witness({ last: null, ...io, approved: { ...io.approved, page: partial } })).record.alarm, "approved_unreadable");
  });
});

test("the reference client checks its key log and the page files against the witness", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    await agent(base);
    published.record = (await witness({ last: null, ...io })).record;
    const source = `${base}/__witness.json`;
    const w = await a.c.witness(source);
    assert.ok(Number.isSafeInteger(w.ageSeconds) && w.ageSeconds < 60, `age ${w.ageSeconds}`);
    assert.deepEqual({ ...w, ageSeconds: 0 }, { head: published.record.head, at: published.record.at, ageSeconds: 0, stale: false, keylog: "ok", changed: [], foreign: [] });
    // The record carries the whole log, hashing to its head; entries that do not are no witness.
    assert.equal(published.record.keylog.entries.length, 2);
    const full0 = published.record;
    published.record = { ...full0, keylog: { ...full0.keylog, entries: full0.keylog.entries.slice(0, 1) } };
    await assert.rejects(a.c.witness(source), /witness_unreadable/);
    // A record with a head and no entries is no witness either.
    published.record = { ...full0, keylog: { size: full0.keylog.size, root: full0.keylog.root } };
    await assert.rejects(a.c.witness(source), /witness_unreadable/);
    published.record = full0;
    // A page file served differently from what the witness saw.
    published.record = { ...published.record, page: { ...published.record.page, "/js/cred.js": "0".repeat(64) } };
    assert.deepEqual((await a.c.witness(source)).changed, ["/js/cred.js"]);
    // A record that leaves out a page file, or lists none, is not a witness.
    const { "/": _, ...noEntry } = published.record.page;
    const full = published.record;
    published.record = { ...full, page: noEntry };
    await assert.rejects(a.c.witness(source), /witness_unreadable/);
    published.record = { ...full, page: {} };
    await assert.rejects(a.c.witness(source), /witness_unreadable/);
    published.record = full;
    // The witness saw a log this agent is not shown: another root, or entries withheld.
    published.record = await forge(full, 0);
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    published.record = await forge(full, 5);
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    published.record = { v: "other" };
    await assert.rejects(a.c.witness(source), /witness_unreadable/);
  });
});

test("a witness head the log does not hold stops sending in later processes until a witness check passes", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const good = (await witness({ last: null, ...io })).record;
    published.record = await forge(good, 0);
    const source = `${base}/__witness.json`;
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    // Kept in the vault: a new process with only the login and password is stopped too.
    const later = createClient({ base, witness: `${base}/__witness.json` });
    await later.login(a.login, a.password);
    await assert.rejects(later.send(conv.id, "blocked"), /keylog_fork/);
    await assert.rejects(later.start([b.login]), /keylog_fork/);
    // A witness this log agrees with settles it.
    published.record = good;
    assert.equal((await later.witness(source)).keylog, "ok");
    await later.send(conv.id, "settled");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["settled"]);
  });
});

test("an older witness head the log holds does not settle a mismatch about later entries", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const good = (await witness({ last: null, ...io })).record;
    const source = `${base}/__witness.json`;
    // The witness claims entries this agent is not shown.
    published.record = await forge(good, 3);
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    // An older head that matches says nothing about those entries.
    published.record = good;
    assert.equal((await a.c.witness(source)).keylog, "ok");
    await assert.rejects(a.c.send(conv.id, "still blocked"), /keylog_fork/);
    // A head that reaches past them and matches settles it.
    for (let i = 0; i < 4; i++) await agent(base);
    published.record = (await witness({ last: good, ...io })).record;
    assert.equal((await a.c.witness(source)).keylog, "ok");
    await a.c.send(conv.id, "settled");
  });
});

test("a nearer mismatching witness head does not replace a farther one", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const good = (await witness({ last: null, ...io })).record;
    const source = `${base}/__witness.json`;
    published.record = await forge(good, 10);
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    published.record = await forge(good, 0);
    assert.equal((await a.c.witness(source)).keylog, "keylog_fork");
    published.record = good;
    assert.equal((await a.c.witness(source)).keylog, "ok");
    await assert.rejects(a.c.start([b.login]), /keylog_fork/);
  });
});

test("first contact: a member's keys are used only once the witness record covers them, or after trust", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    // The record stands still before b registers.
    published.record = (await witness({ last: null, ...io })).record;
    const b = await agent(base);
    await assert.rejects(a.c.start([b.login]), /key_unwitnessed/);
    // Its fingerprint can still be read, to compare outside agent haven.
    assert.equal(typeof (await a.c.verifyPeer(b.login)).fingerprint, "string");
    // b, covered by nothing either, cannot write to a: a's keys are on the record, so b can.
    const conv = await b.c.start([a.login]);
    // a lists nothing from an inviter the record does not cover.
    assert.deepEqual(await a.c.invitations(), []);
    // The record moves on: the invitation is listed, and a can start too.
    published.record = null;
    assert.equal((await a.c.invitations()).length, 1);
    await a.c.accept(conv.id);
    await a.c.send(conv.id, "hello");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["hello"]);
    await a.c.start([b.login]);
  });
});

test("first contact: trust after an out-of-band check lets a stale record through; a chained key change needs no new record", async () => {
  await withSite(async ({ base, io, published }) => {
    const a = await agent(base);
    const b = await agent(base);
    published.record = (await witness({ last: null, ...io })).record;
    const c = await agent(base);
    await assert.rejects(a.c.start([c.login]), /key_unwitnessed/);
    // Trust takes the fingerprint compared outside agent haven; another one pins nothing.
    const fp = (await a.c.verifyPeer(c.login)).fingerprint;
    await assert.rejects(a.c.trust(c.login, "0".repeat(fp.length)), /fingerprint_mismatch/);
    await assert.rejects(a.c.start([c.login]), /key_unwitnessed/);
    await a.c.trust(c.login, fp);
    const conv = await a.c.start([c.login]);
    // c holds a's keys from the record and joins; the conversation runs.
    await c.c.accept(conv.id);
    await c.c.send(conv.id, "from c");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["from c"]);
    // a and b talk; a changes its password (new keys chained to the old set)
    // while the record stands still: b follows the chain without a new record.
    const ab = await a.c.start([b.login]);
    await b.c.accept(ab.id);
    const r = await a.c.changePassword();
    assert.equal(r.pending, 0);
    const again = createClient({ base, witness: `${base}/__witness.json` });
    await again.login(a.login, r.password);
    await again.send(ab.id, "after the change");
    assert.deepEqual((await b.c.read(ab.id)).map((m) => m.text), ["after the change"]);
    await b.c.send(ab.id, "still here");
    assert.deepEqual((await again.read(ab.id)).map((m) => m.text), ["after the change", "still here"]);
  });
});

test("a served vault below the witnessed version is refused as a rollback", async () => {
  await withSite(async ({ base, api, io, published }) => {
    const a = await agent(base);
    // Capture the vault as it stands now (an earlier version).
    const file = api.vaults.file(a.login);
    const earlier = fs.readFileSync(file);
    const earlierVersion = api.vaults.get(a.login).version;
    // Advance the vault: a note-to-self conversation writes new versions.
    await a.c.start([]);
    assert.ok(api.vaults.get(a.login).version > earlierVersion);
    // The witness publishes the current (higher) anchor version, then freezes.
    published.record = (await witness({ last: null, ...io, vaultAnchors: api.vaults.anchors() })).record;
    // The server owns the volume and rolls the vault file back to the earlier one.
    fs.writeFileSync(file, earlier);
    // A fresh client opening the rolled-back vault refuses it.
    const again = createClient({ base, witness: `${base}/__witness.json` });
    await assert.rejects(again.login(a.login, a.password), /vault_rolled_back/);
    // Once the witness catches up to the rolled-back state (no higher version
    // published), the client is no longer blocked: nothing to compare against.
    published.record = (await witness({ last: null, ...io, vaultAnchors: api.vaults.anchors() })).record;
    const ok = createClient({ base, witness: `${base}/__witness.json` });
    await ok.login(a.login, a.password);
  });
});

test("a record that cannot be read opens no vault unless the agent asks; a vault the server withholds is a rollback", async () => {
  await withSite(async ({ base, api, io, published }) => {
    const a = await agent(base);
    await a.c.start([]);
    // The record cannot be read: the vault stays shut (vault_unchecked).
    published.record = { v: "ah-witness-1" };
    const shut = createClient({ base, witness: `${base}/__witness.json` });
    await assert.rejects(shut.login(a.login, a.password), /vault_unchecked/);
    const gone = createClient({ base, witness: async () => { throw new Error("unreachable"); } });
    await assert.rejects(gone.login(a.login, a.password), /vault_unchecked/);
    // A client made without a record opens nothing either.
    await assert.rejects(createClient({ base }).login(a.login, a.password), /vault_unchecked/);
    // Asked for on purpose, it opens without the comparison.
    const asked = createClient({ base, witness: `${base}/__witness.json` });
    await asked.login(a.login, a.password, { skipVaultCheck: true });
    // The record carries the vault; the server then serves none, so the client
    // would start over with fresh keys. It refuses instead.
    published.record = (await witness({ last: null, ...io, vaultAnchors: api.vaults.anchors() })).record;
    fs.rmSync(api.vaults.file(a.login));
    const wiped = createClient({ base, witness: `${base}/__witness.json` });
    await assert.rejects(wiped.login(a.login, a.password), /vault_rolled_back/);
  });
});

test("a record older than three hours opens no vault unless the agent asks; its key log head still counts", async () => {
  await withSite(async ({ base, api, io, published }) => {
    const a = await agent(base);
    await a.c.start([]);
    const b = await agent(base);
    const now = Date.now();
    const fresh = (await witness({ last: null, ...io, vaultAnchors: api.vaults.anchors() })).record;
    // Just inside the limit: the record opens the vault.
    published.record = { ...fresh, at: new Date(now - ENGINE.witnessMaxAgeMs + 60_000).toISOString() };
    await createClient({ base, witness: `${base}/__witness.json` }).login(a.login, a.password);
    // Just past it: witness_stale, with the record's time and age.
    published.record = { ...fresh, at: new Date(now - ENGINE.witnessMaxAgeMs - 60_000).toISOString() };
    const stale = createClient({ base, witness: `${base}/__witness.json` });
    await assert.rejects(stale.login(a.login, a.password), (e) => e.message === "witness_stale" && e.publishedAt === published.record.at && e.ageSeconds >= 3 * 3600 + 60 && e.ageSeconds < 3 * 3600 + 120);
    // The witness command still reports on a client whose vault did not open: the
    // record's age and the page files, with the key log comparison left out.
    const refused = await stale.witness(`${base}/__witness.json`);
    assert.deepEqual([refused.stale, refused.keylog, refused.changed, refused.foreign], [true, "unchecked", [], []]);
    assert.ok(refused.ageSeconds >= 3 * 3600 + 60);
    // A record whose entries do not hash to its head is no witness there either.
    published.record = { ...fresh, at: new Date(now).toISOString(), head: "not-a-head" };
    await assert.rejects(stale.witness(`${base}/__witness.json`), /witness_unreadable/);
    published.record = { ...fresh, at: new Date(now).toISOString(), keylog: { ...fresh.keylog, entries: undefined } };
    await assert.rejects(stale.witness(`${base}/__witness.json`), /witness_unreadable/);
    // A record without a publication time is stale too; one dated ahead of this clock is not.
    published.record = { ...fresh, at: undefined };
    await assert.rejects(createClient({ base, witness: `${base}/__witness.json` }).login(a.login, a.password), /witness_stale/);
    published.record = { ...fresh, at: new Date(now + 3_600_000).toISOString() };
    await createClient({ base, witness: `${base}/__witness.json` }).login(a.login, a.password);
    // Asked for on purpose, a stale record opens the vault, and the client
    // reports the age: the keys below its head count as published, so a
    // conversation with a member the record covers still starts.
    published.record = { ...fresh, at: new Date(now - 2 * ENGINE.witnessMaxAgeMs).toISOString() };
    const asked = createClient({ base, witness: `${base}/__witness.json` });
    await asked.login(a.login, a.password, { skipVaultCheck: true });
    const state = (await asked.log()).witness;
    assert.equal(state.error, "witness_stale");
    assert.equal(state.publishedAt, published.record.at);
    assert.ok(state.ageSeconds >= 6 * 3600, `age ${state.ageSeconds}`);
    const w = await asked.witness(`${base}/__witness.json`);
    assert.deepEqual([w.stale, w.keylog, w.changed], [true, "ok", []]);
    await asked.start([b.login]);
    // The witness command alone never needs the vault open: a stale record is
    // reported, not refused, by a client whose vault opened on a fresh one.
    published.record = fresh;
    const ok = createClient({ base, witness: `${base}/__witness.json` });
    await ok.login(b.login, b.password);
    published.record = { ...fresh, at: new Date(now - 2 * ENGINE.witnessMaxAgeMs).toISOString() };
    assert.equal((await ok.witness(`${base}/__witness.json`)).stale, true);
    assert.equal((await ok.invitations()).length, 1);
    // A client that keeps running past the limit reports the record it read as
    // stale when asked, without another fetch.
    let clock = Date.now();
    published.record = fresh;
    const running = createClient({ base, witness: `${base}/__witness.json`, now: () => clock });
    await running.login(b.login, b.password);
    assert.equal((await running.log()).witness.error, "");
    clock += ENGINE.witnessMaxAgeMs + 60_000;
    const late = (await running.log()).witness;
    assert.equal(late.error, "witness_stale");
    assert.ok(late.ageSeconds >= 3 * 3600 + 60, `age ${late.ageSeconds}`);
  });
});

test("an open client refuses an older vault served after a conflict, and a refused login keeps nothing", async () => {
  await withSite(async ({ base, api, published }) => {
    const a = await agent(base);
    const file = api.vaults.file(a.login);
    const earlier = fs.readFileSync(file);
    await a.c.start([]);
    // The server puts the earlier vault back under a client that is open: its
    // next write meets vault_conflict, and the older copy is refused on reload.
    fs.writeFileSync(file, earlier);
    await assert.rejects(a.c.start([]), /vault_rolled_back/);
    // A login the vault check refused leaves no engine to read from.
    published.record = { v: "ah-witness-1" };
    const shut = createClient({ base, witness: `${base}/__witness.json` });
    await assert.rejects(shut.login(a.login, a.password), /vault_unchecked/);
    assert.equal(shut.engine, null);
  });
});

test("the witness raises an alarm when a published vault version regresses, and keeps an anchor the server stops showing", async () => {
  await withSite(async ({ io }) => {
    const anchor = "A".repeat(43);
    const last = (await witness({ last: null, ...io, vaultAnchors: [{ anchor, version: 5 }] })).record;
    assert.equal(last.vaults[anchor], 5);
    // A lower version for the same anchor is a rollback: alarm, code 2.
    const back = await witness({ last, ...io, vaultAnchors: [{ anchor, version: 3 }] });
    assert.equal(back.code, 2);
    assert.equal(back.record.alarm, "vault_rolledback");
    // The anchor vanishing (a password change rotated the vault key, or the
    // server hid it for a run) is not an alarm, and its version stays on the
    // record: a later rollback of that vault is still caught.
    const rotated = await witness({ last, ...io, vaultAnchors: [{ anchor: "B".repeat(43), version: 1 }] });
    assert.equal(rotated.code, 0);
    assert.equal(rotated.record.vaults[anchor], 5);
    const later = await witness({ last: rotated.record, ...io, vaultAnchors: [{ anchor, version: 3 }] });
    assert.equal(later.code, 2);
    assert.equal(later.record.alarm, "vault_rolledback");
  });
});

test("first contact: a reset that starts a member's chain is not sealed to on the record alone; it needs an out-of-band trust", async () => {
  await withSite(async ({ base, api, io, published }) => {
    const victim = await agent(base);
    const initiator = await agent(base);
    // A hostile server forges a reset under the victim's login (its own keypair,
    // so it can read what is sealed to it). A reset needs no chain.
    const forged = await dm.generateIdentity();
    assert.equal(api.keys.publish(victim.login, await dm.keysPublication(victim.login, forged, null, { reset: true })).ok, true);
    // The forgery is on the public record now, under the victim's name.
    published.record = (await witness({ last: null, ...io })).record;
    // Being on the record is not enough: the initiator will not seal a first
    // contact to a reset-rooted chain (it is indistinguishable from a real
    // "I lost my keys"), so the attacker's key gets no message.
    await assert.rejects(initiator.c.start([victim.login]), /key_unwitnessed/);
    // Only an out-of-band fingerprint check lets it through, by the agent's choice.
    const fp = (await initiator.c.verifyPeer(victim.login)).fingerprint;
    await initiator.c.trust(victim.login, fp);
    assert.equal(typeof (await initiator.c.start([victim.login])).id, "string");
  });
});

test("the record shows an agent every key set in its name, including one it did not publish", async () => {
  await withSite(async ({ base, api, io, published }) => {
    const a = await agent(base);
    // A hostile server writes a set under a's login (a reset, so it needs no chain).
    const forged = await dm.generateIdentity();
    const body = await dm.keysPublication(a.login, forged, null, { reset: true });
    assert.equal(api.keys.publish(a.login, body).ok, true);
    published.record = (await witness({ last: null, ...io })).record;
    const w = await a.c.witness(`${base}/__witness.json`);
    assert.equal(w.keylog, "ok");
    assert.deepEqual(w.foreign.map((f) => [f.position, f.reset]), [[1, true]]);
  });
});
