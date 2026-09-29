// motion-passport: exempt test file, no UI and no animation.
// Password change: one server step replaces the auth key and the vault, new
// keys follow, every conversation moves to a new box. Whoever kept a copy of
// the old vault (its keys, box tokens and box keys) must not read, write or
// steer anything from then on.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApi } from "../api/server.mjs";
import { hashPassword } from "../api/store.mjs";
import { createClient, makePassword } from "../client/ah-client.mjs";
import { deriveCredentials, sealVault } from "../public/js/cred.js";
import * as dm from "../public/js/dm-crypto.js";
import * as tk from "../public/js/tickets.js";
import { ENGINE } from "../public/js/dm-engine.js";
// Agents here register moments apart: the record is read again at once.
ENGINE.witnessRetryMs = 0;


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
async function withServer(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-password-"));
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  W = liveWitness(api);
  try {
    await run(base, dir, api);
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function agent(base) {
  const c = createClient({ base, witness: W });
  const cred = await c.register();
  await c.login(cred.login, cred.password);
  return { c, ...cred };
}

async function ticketFrom(api) {
  const pub = tk.parseKey(api.tickets.pub);
  const b = await tk.blind(pub);
  return tk.finish(pub, b, api.tickets.sign([b.blinded])[0]);
}

const postJson = (base, p, body, headers = {}) =>
  fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, ...(await r.json()) }));

test("after a change the old password signs nothing in, other sessions end, and the new one opens everything", async () => {
  await withServer(async (base, dir) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "before");
    const other = createClient({ base, witness: W });
    await other.login(a.login, a.password);
    const { password, pending } = await a.c.changePassword();
    assert.equal(pending, 0);
    assert.notEqual(password, a.password);
    // The other session is over.
    await assert.rejects(other.invitations(), /session_missing/);
    await assert.rejects(createClient({ base, witness: W }).login(a.login, a.password), /credentials_wrong/);
    const fresh = createClient({ base, witness: W });
    await fresh.login(a.login, password);
    assert.deepEqual((await fresh.read(conv.id)).map((m) => m.text), ["before"]);
    await fresh.send(conv.id, "after");
    // b follows the move without any warning; a's earlier message still verifies.
    assert.deepEqual((await b.c.read(conv.id)).map((m) => [m.from, m.text ?? m.error]), [
      [a.login, "before"],
      [a.login, "after"],
    ]);
    assert.equal(b.c.engine.vault.convs[conv.id].boxes.length, 2);
    // Neither password reaches any file.
    for (const f of fs.readdirSync(dir, { recursive: true })) {
      const p = path.join(dir, f);
      if (fs.statSync(p).isDirectory()) continue;
      const text = fs.readFileSync(p, "utf8");
      assert.ok(!text.includes(a.password) && !text.includes(password), `${f} holds a password`);
    }
  });
});

test("a copy of the old vault reads nothing new and steers nothing", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    await a.c.send(conv.id, "before");
    const stolen = structuredClone(a.c.engine.vault);
    const oldId = await dm.importIdentity(stolen.identity);
    const oldBox = stolen.convs[conv.id].boxes[0];
    await a.c.changePassword();
    await b.c.send(conv.id, "only for the three of us");
    // The new box is not in the copy, and the old box holds nothing new but the move.
    const newBox = b.c.engine.vault.convs[conv.id].boxes.at(-1);
    assert.ok(!JSON.stringify(stolen).includes(newBox.token) && !JSON.stringify(stolen).includes(newBox.key));
    const inOld = await postJson(base, "/api/box/read", { id: oldBox.id, token: oldBox.token });
    for (const s of inOld.messages) {
      const o = await dm.openMessage(oldBox, s);
      assert.ok(!(o.ok && o.m.text === "only for the three of us"));
    }
    // With the old keys, in the old box: a text, a removal of c and a move to a box of its own.
    const post = async (m) => postJson(base, "/api/box/post", { id: oldBox.id, token: oldBox.token, ...(await dm.sealMessage({ identity: oldId, from: a.login, box: oldBox, m })) });
    await post({ kind: "text", text: "forged after the change" });
    await post({ kind: "leave", removed: c.login, members: [a.login, b.login].sort() });
    await post({ kind: "move", next: dm.newBoxId(), members: [a.login, b.login].sort() });
    // A new conversation in a's name, signed with the old keys.
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    const members = [a.login, b.login].sort();
    const inv = { kind: "origin", conv: box.id, box, by: a.login, members, sig: await dm.signOrigin(oldId, box, a.login, members) };
    await postJson(base, "/api/inbox/drop", { to: b.login, ticket: await ticketFrom(api), sealed: await dm.sealInvite(inv, b.login, api.keys.current(b.login).enc) });
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    assert.deepEqual(await fresh.invitations(), [], "the forged invitation is dropped");
    assert.deepEqual((await fresh.members(conv.id)).members, [a.login, b.login, c.login].sort());
    assert.deepEqual((await fresh.read(conv.id)).map((m) => m.text), ["before", "only for the three of us"]);
    await fresh.send(conv.id, "still the new box");
    assert.deepEqual((await c.c.read(conv.id)).map((m) => m.text).slice(-1), ["still the new box"]);
  });
});

test("an invitation not yet opened is offered again under the new keys", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await a.c.send(conv.id, "waiting for you");
    await a.c.changePassword();
    const inv = await b.c.invitations();
    assert.deepEqual(inv.map((i) => i.conv), [conv.id]);
    await b.c.accept(conv.id);
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["waiting for you"]);
    await b.c.send(conv.id, "here");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["waiting for you", "here"]);
  });
});

test("a change cut short after the server step finishes on the next login", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const real = globalThis.fetch;
    globalThis.fetch = (url, init) => (String(url).endsWith("/api/keys") && init?.method === "POST" ? Promise.reject(new Error("cut")) : real(url, init));
    let r;
    try {
      r = await a.c.changePassword();
    } finally {
      globalThis.fetch = real;
    }
    assert.equal(r.error, "unavailable");
    assert.ok(a.c.engine.vault.rekey.convs.includes(conv.id));
    const again = createClient({ base, witness: W });
    await again.login(a.login, r.password);
    assert.equal(again.engine.vault.rekey, undefined);
    await again.send(conv.id, "moved");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["moved"]);
    assert.equal(b.c.engine.vault.convs[conv.id].boxes.length, 2);
  });
});

test("a server stopped between the vault and the account line: only the new password signs in, and completes the change", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const doc = structuredClone(a.c.engine.vault);
    const v = api.vaults.get(a.login).version;
    const password = makePassword(a.login);
    const next = await deriveCredentials(a.login, password);
    assert.ok(api.vaults.put(a.login, { version: v + 1, blob: await sealVault(next.vaultKey, a.login, v + 1, doc) }, { pendingAuth: await hashPassword(next.auth) }).ok);
    await assert.rejects(createClient({ base, witness: W }).login(a.login, a.password), /credentials_wrong/);
    const fresh = createClient({ base, witness: W });
    await fresh.login(a.login, password);
    assert.equal(api.store.get(a.login).hash, api.vaults.pendingAuth(a.login));
    await fresh.logout();
    await createClient({ base, witness: W }).login(a.login, password);
  });
});

test("the password route checks the current key, the new one and the vault version", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const cookie = a.c.session.cookie;
    const cur = await deriveCredentials(a.login, a.password);
    const next = await deriveCredentials(a.login, makePassword(a.login));
    const v = api.vaults.get(a.login).version;
    const blob = await sealVault(next.vaultKey, a.login, v + 1, { v: "ah-vault-1" });
    assert.equal((await postJson(base, "/api/password", { auth: cur.auth, newAuth: next.auth, version: v + 1, blob })).error, "session_missing");
    assert.equal((await postJson(base, "/api/password", { auth: next.auth, newAuth: next.auth, version: v + 1, blob }, { cookie })).error, "auth_invalid");
    assert.equal((await postJson(base, "/api/password", { auth: next.auth, newAuth: cur.auth, version: v + 1, blob }, { cookie })).error, "credentials_wrong");
    const stale = await postJson(base, "/api/password", { auth: cur.auth, newAuth: next.auth, version: v, blob }, { cookie });
    assert.deepEqual([stale.status, stale.error], [409, "vault_conflict"]);
    // Nothing changed: the old password still signs in.
    await createClient({ base, witness: W }).login(a.login, a.password);
    // The journal names the route and the outcome, never a key.
    const journal = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8");
    assert.ok(journal.includes("POST /api/password"));
    assert.ok(!journal.includes(cur.auth) && !journal.includes(next.auth) && !journal.includes(a.login));
  });
});

test("a conversation that could not move during the change moves before anything is sent in it", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const oldBox = structuredClone(a.c.engine.vault.convs[conv.id].boxes[0]);
    const real = globalThis.fetch;
    globalThis.fetch = (url, init) => (String(url).endsWith("/api/box/read") ? Promise.reject(new Error("cut")) : real(url, init));
    let r;
    try {
      r = await a.c.changePassword();
    } finally {
      globalThis.fetch = real;
    }
    assert.equal(r.pending, 1);
    await a.c.send(conv.id, "after the move");
    assert.equal(a.c.engine.vault.rekey, undefined);
    const inOld = await postJson(base, "/api/box/read", { id: oldBox.id, token: oldBox.token });
    for (const s of inOld.messages) {
      const o = await dm.openMessage(oldBox, s);
      assert.ok(!(o.ok && o.m.text === "after the move"), "nothing new in the box the old vault opens");
    }
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["after the move"]);
  });
});

test("a session ended by a password change cannot finish a request whose body was still arriving", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const other = createClient({ base, witness: W });
    await other.login(a.login, a.password);
    const cookie = other.session.cookie;
    const { port } = new URL(base);
    const http = await import("node:http");
    const body = JSON.stringify({ version: api.vaults.get(a.login).version + 50, blob: { iv: "AAAAAAAAAAAAAAAA", ct: "AAAA" } });
    let finish;
    const answer = new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, path: "/api/vault", method: "POST", headers: { cookie, "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, ...JSON.parse(data) }));
      });
      req.on("error", reject);
      req.write(body.slice(0, 10));
      finish = () => req.end(body.slice(10));
    });
    await new Promise((r) => setTimeout(r, 100));
    try {
      await a.c.changePassword();
    } finally {
      finish();
    }
    const r = await answer;
    assert.deepEqual([r.status, r.error], [401, "session_missing"]);
  });
});

test("a sign-in checked against the old key while the password changed gets no session", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const check = api.store.check.bind(api.store);
    let hold = null;
    let reached;
    const atCheck = new Promise((r) => (reached = r));
    api.store.check = async (login, secret) => {
      const ok = await check(login, secret);
      if (hold) {
        const h = hold;
        hold = null;
        reached();
        await h;
      }
      return ok;
    };
    let release;
    hold = new Promise((r) => (release = r));
    const late = createClient({ base, witness: W }).login(a.login, a.password);
    await atCheck;
    await a.c.changePassword();
    release();
    await assert.rejects(late, /credentials_wrong/);
  });
});

test("when the answer to a change is lost, the new password is still handed back", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const real = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const res = await real(url, init);
      if (String(url).endsWith("/api/password")) throw new Error("lost");
      return res;
    };
    let r;
    try {
      r = await a.c.changePassword();
    } finally {
      globalThis.fetch = real;
    }
    assert.equal(r.unknown, true);
    const fresh = createClient({ base, witness: W });
    await fresh.login(a.login, r.password);
    // The login finishes the rest of the change.
    assert.equal(fresh.engine.vault.rekey, undefined);
  });
});

test("a 200 whose body is cut off still hands back the new password", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const real = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      const res = await real(url, init);
      if (!String(url).endsWith("/api/password")) return res;
      await res.text();
      return new Response("{\"ok\":tr", { status: 200, headers: res.headers });
    };
    let r;
    try {
      r = await a.c.changePassword();
    } finally {
      globalThis.fetch = real;
    }
    assert.equal(r.unknown, true);
    await createClient({ base, witness: W }).login(a.login, r.password);
  });
});

test("completing a change at sign-in ends every session from before it", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const old = a.c.session.cookie;
    const doc = structuredClone(a.c.engine.vault);
    const v = api.vaults.get(a.login).version;
    const password = makePassword(a.login);
    const next = await deriveCredentials(a.login, password);
    assert.ok(api.vaults.put(a.login, { version: v + 1, blob: await sealVault(next.vaultKey, a.login, v + 1, doc) }, { pendingAuth: await hashPassword(next.auth) }).ok);
    await createClient({ base, witness: W }).login(a.login, password);
    const s = await fetch(`${base}/api/session`, { headers: { cookie: old } });
    assert.equal(s.status, 401);
  });
});

test("a legacy sign-in held after its check cannot overwrite a change made meanwhile", async () => {
  await withServer(async (base, dir, api) => {
    const a = createClient({ base, witness: W });
    const { login, password } = await a.register();
    api.store.write({ login, hash: await hashPassword(password), createdAt: new Date().toISOString() });
    const check = api.store.check.bind(api.store);
    let hold = null;
    let reached;
    const atCheck = new Promise((r) => (reached = r));
    api.store.check = async (l, secret) => {
      const ok = await check(l, secret);
      if (hold) {
        const h = hold;
        hold = null;
        reached();
        await h;
      }
      return ok;
    };
    let release;
    hold = new Promise((r) => (release = r));
    const late = createClient({ base, witness: W }).login(login, password, { upgrade: true });
    await atCheck;
    const b = createClient({ base, witness: W });
    await b.login(login, password, { upgrade: true });
    const { password: fresh } = await b.changePassword();
    release();
    await assert.rejects(late, /credentials_wrong/);
    await createClient({ base, witness: W }).login(login, fresh);
  });
});
