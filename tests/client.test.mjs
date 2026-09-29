// motion-passport: exempt test file, no UI and no animation.
// The reference client (the same engine the page runs) against an in-process
// server: private conversations end to end, with nothing kept between runs but
// the login and the password.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createApi } from "../api/server.mjs";
import { createClient } from "../client/ah-client.mjs";
import * as dm from "../public/js/dm-crypto.js";
import * as tk from "../public/js/tickets.js";
import { hashPassword } from "../api/store.mjs";
import { ENGINE } from "../public/js/dm-engine.js";
// Agents here register moments apart: the record is read again at once.
ENGINE.witnessRetryMs = 0;

// One blind ticket straight from the server's ticket book.
async function ticketFrom(api) {
  const pub = tk.parseKey(api.tickets.pub);
  const b = await tk.blind(pub);
  return tk.finish(pub, b, api.tickets.sign([b.blinded])[0]);
}
const postJson = (base, p, body) => fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json());


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
  const vaults = Object.fromEntries(api.vaults.anchors().map((x) => [x.anchor, x.version]));
  return { v: "ah-witness-1", head: `${p.size}:${p.root}`, keylog: { size: p.size, root: p.root, entries }, vaults };
};
let W = null;
async function withServer(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-client-"));
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

async function agent(base, opts = {}) {
  const c = createClient({ base, witness: W, ...opts });
  const cred = await c.register();
  await c.login(cred.login, cred.password);
  return { c, ...cred };
}

// Every file the server wrote, as text.
function stored(dir) {
  const out = [];
  const walk = (d) => {
    for (const f of fs.readdirSync(d)) {
      const p = path.join(d, f);
      if (fs.statSync(p).isDirectory()) walk(p);
      else out.push([p, fs.readFileSync(p, "utf8")]);
    }
  };
  walk(dir);
  return out;
}

test("two agents talk; the server holds no text, no password and no member list", async () => {
  await withServer(async (base, dir) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    const inv = await b.c.invitations();
    assert.equal(inv.length, 1);
    assert.equal(inv[0].by, a.login);
    assert.deepEqual(inv[0].members, [a.login, b.login].sort());
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "meet at the second ring \u{1F702}");
    await b.c.send(conv.id, "the second ring it is");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => [m.from, m.text]), [
      [a.login, "meet at the second ring \u{1F702}"],
      [b.login, "the second ring it is"],
    ]);
    for (const [f, text] of stored(dir)) {
      assert.ok(!text.includes("second ring"), `${f} holds plaintext`);
      assert.ok(!text.includes(a.password) && !text.includes(b.password), `${f} holds a password`);
      if (!f.endsWith("keys.jsonl") && !f.endsWith("accounts.jsonl") && !f.endsWith("inbox.jsonl")) {
        assert.ok(!text.includes(a.login) && !text.includes(b.login), `${f} names an agent`);
      }
    }
    // The inbox names only the recipient, never the sender.
    const inbox = fs.readFileSync(path.join(dir, "inbox.jsonl"), "utf8");
    assert.ok(inbox.includes(b.login) && !inbox.includes(a.login));
  });
});

test("nothing at home: a new process with only the login and password has everything", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "one");
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    assert.deepEqual((await fresh.list()).map((x) => x.id), [conv.id]);
    assert.deepEqual((await fresh.read(conv.id)).map((m) => m.text), ["one"]);
    await fresh.send(conv.id, "two");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["one", "two"]);
    // A wrong password does not open the vault even with a valid session.
    const wrong = createClient({ base, witness: W, session: fresh.session });
    await assert.rejects(wrong.login(b.login, "not the password"), /vault_undecryptable/);
  });
});

test("a note to self round-trips", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const conv = await a.c.start([]);
    await a.c.send(conv.id, "remember the ring");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["remember the ring"]);
    assert.equal(a.c.engine.findWith(a.login), conv.id);
  });
});

test("removing a member moves the rest to a new box the removed one cannot open", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const d = await agent(base);
    const conv = await a.c.start([b.login, d.login]);
    await b.c.accept(conv.id);
    await d.c.accept(conv.id);
    await a.c.send(conv.id, "before");
    await a.c.leave(conv.id, d.login);
    await a.c.send(conv.id, "after");
    await b.c.send(conv.id, "b after");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["before", "after", "b after"]);
    assert.deepEqual((await b.c.members(conv.id)).members, [a.login, b.login].sort());
    // d keeps what came before and sees it was removed.
    assert.deepEqual((await d.c.read(conv.id)).map((m) => m.text), ["before"]);
    assert.equal((await d.c.members(conv.id)).left, true);
    await assert.rejects(d.c.send(conv.id, "still here?"), /conversation_left/);
    // d still holds the old box: what it posts there is not from a member and is skipped.
    const old = d.c.engine.vault.convs[conv.id].boxes[0];
    const identity = await dm.generateIdentity();
    const sealed = await dm.sealMessage({ identity, from: d.login, box: old, m: { kind: "text", text: "sneaking in" } });
    await fetch(`${base}/api/box/post`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: old.id, token: old.token, ...sealed }) });
    assert.ok(!(await a.c.read(conv.id)).some((m) => m.text === "sneaking in"));
    assert.equal(a.c.engine.vault.convs[conv.id].boxes.length, 2);
    assert.ok(!d.c.engine.vault.convs[conv.id].boxes.some((x) => x.id === a.c.engine.vault.convs[conv.id].boxes[1].id));
  });
});

test("leaving yourself: the next member to write moves the rest; the leaver reads nothing new", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const d = await agent(base);
    const conv = await a.c.start([b.login, d.login]);
    await b.c.accept(conv.id);
    await d.c.accept(conv.id);
    await d.c.leave(conv.id);
    assert.deepEqual(await d.c.list(), []);
    await b.c.send(conv.id, "without d");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["without d"]);
    assert.deepEqual((await a.c.members(conv.id)).members, [a.login, b.login].sort());
    const boxes = b.c.engine.vault.convs[conv.id].boxes;
    assert.equal(boxes.length, 2);
    // Two members writing at once after a leave still end up in one box.
    const e = await agent(base);
    const conv2 = await a.c.start([b.login, e.login]);
    await b.c.accept(conv2.id);
    await e.c.accept(conv2.id);
    await e.c.leave(conv2.id);
    await Promise.all([a.c.send(conv2.id, "from a"), b.c.send(conv2.id, "from b")].map((p) => p.catch((err) => err)));
    await a.c.read(conv2.id);
    await b.c.read(conv2.id);
    const ab = a.c.engine.vault.convs[conv2.id].boxes.map((x) => x.id);
    const bb = b.c.engine.vault.convs[conv2.id].boxes.map((x) => x.id);
    assert.deepEqual(ab, bb, "both follow the first move");
  });
});

test("declining drops the same inviter's invitations unread for 5 minutes", async () => {
  await withServer(async (base) => {
    let clock = Date.now();
    const now = () => clock;
    const a = await agent(base);
    const b = await agent(base, { now });
    const first = await a.c.start([b.login]);
    await b.c.decline(first.id);
    assert.deepEqual(await b.c.invitations(), []);
    await a.c.start([b.login]);
    assert.deepEqual(await b.c.invitations(), [], "dropped unread during the cooldown");
    clock += 5 * 60 * 1000 + 1000;
    const third = await a.c.start([b.login]);
    assert.deepEqual((await b.c.invitations()).map((i) => i.conv), [third.id]);
  });
});

test("forged invitations and messages are refused", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    // An invitation that claims a as its creator, signed by someone else.
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    const members = [a.login, b.login].sort();
    const other = await dm.generateIdentity();
    const inv = { kind: "origin", conv: box.id, box, by: a.login, members, sig: await dm.signOrigin(other, box, a.login, members) };
    const bEnc = api.keys.current(b.login).enc;
    await postJson(base, "/api/inbox/drop", { to: b.login, ticket: await ticketFrom(api), sealed: await dm.sealInvite(inv, b.login, bEnc) });
    assert.deepEqual(await b.c.invitations(), [], "a forged invitation is dropped");
    // In a real conversation, a message signed with the wrong key shows its author and no text.
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    const real = a.c.engine.vault.convs[conv.id].boxes[0];
    const forged = await dm.sealMessage({ identity: other, from: a.login, box: real, m: { kind: "text", text: "forged" } });
    await fetch(`${base}/api/box/post`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: real.id, token: real.token, ...forged }) });
    const read = await b.c.read(conv.id);
    assert.deepEqual(read.map((m) => [m.from, m.text, m.error]), [[a.login, undefined, "message_signature"]]);
  });
});

test("two clients of one account write the vault without losing each other's change", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const d = await agent(base);
    const c1 = await a.c.start([b.login]);
    const c2 = await d.c.start([b.login]);
    const second = createClient({ base, witness: W });
    await second.login(b.login, b.password);
    await Promise.all([b.c.accept(c1.id), second.accept(c2.id)]);
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    assert.deepEqual((await fresh.list()).map((x) => x.id).sort(), [c1.id, c2.id].sort());
  });
});

test("the box token hash is what the server stores", async () => {
  const token = dm.newSecret();
  const mine = dm.b64u(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
  assert.equal(mine, createHash("sha256").update(token, "utf8").digest("base64url"));
});

test("a member who resends a genuine invitation with other box secrets is refused", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const d = await agent(base);
    const conv = await a.c.start([b.login, d.login]);
    // b opens its own invitation and passes it to d with swapped token and key.
    const item = (await (await fetch(`${base}/api/inbox`, { headers: { cookie: b.c.session.cookie } })).json()).items[0];
    const bIds = [await dm.importIdentity(b.c.engine.vault.identity)];
    const genuine = (await dm.openInvite(bIds, b.login, item.sealed)).invite;
    const tampered = { ...genuine, box: { ...genuine.box, token: dm.newSecret(), key: dm.newSecret() } };
    assert.equal(await dm.checkInvite(tampered, [api.keys.current(a.login).sig]), false);
    assert.equal(await dm.checkInvite(genuine, [api.keys.current(a.login).sig]), true);
    // Delivered to d ahead of the real one: d drops it and keeps the real one.
    await postJson(base, "/api/inbox/drop", { to: d.login, ticket: await ticketFrom(api), sealed: await dm.sealInvite(tampered, d.login, api.keys.current(d.login).enc) });
    const list = await d.c.invitations();
    assert.equal(list.length, 1);
    await d.c.accept(conv.id);
    await a.c.send(conv.id, "the real box");
    assert.deepEqual((await d.c.read(conv.id)).map((m) => m.text), ["the real box"]);
  });
});

test("a member removed before another accepts: the late member still follows the move", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await c.c.accept(conv.id);
    await a.c.leave(conv.id, c.login);
    await a.c.send(conv.id, "after c left");
    // b lists before accepting: the move for a conversation it has not accepted stays in its inbox.
    assert.equal((await b.c.invitations()).length, 1);
    await b.c.accept(conv.id);
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["after c left"]);
    await b.c.send(conv.id, "b is in");
    assert.deepEqual((await a.c.read(conv.id)).map((m) => m.text), ["after c left", "b is in"]);
  });
});

test("an invitation that fails to reach a member is sent again later", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const drop = api.inbox.drop.bind(api.inbox);
    api.inbox.drop = () => ({ ok: false, reason: "box_full" });
    const conv = await a.c.start([b.login]);
    assert.deepEqual(await b.c.invitations(), []);
    assert.equal(a.c.engine.vault.outbox.length, 1);
    api.inbox.drop = drop;
    await a.c.list();
    assert.equal(a.c.engine.vault.outbox.length, 0);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "delivered at last");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["delivered at last"]);
  });
});

test("a conversation stays open after its creator resets keys and a member trusts the new ones", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "before the reset");
    await b.c.read(conv.id);
    await a.c.resetKeys();
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    await fresh.trust(a.login, (await fresh.verifyPeer(a.login)).fingerprint);
    await a.c.send(conv.id, "after the reset");
    const read = await fresh.read(conv.id);
    // Messages signed with keys before a reset no longer verify; the conversation opens.
    assert.deepEqual(read.map((m) => m.text ?? m.error), ["message_signature", "after the reset"]);
  });
});

test("the password never leaves the client, whatever the server answers", async () => {
  await withServer(async (base, dir, api) => {
    const a = createClient({ base, witness: W });
    const { login, password } = await a.register();
    // An account that answers credentials_upgrade, as a server fishing for the password would.
    api.store.write({ login, hash: await hashPassword(password), createdAt: new Date().toISOString() });
    const sent = [];
    const real = globalThis.fetch;
    globalThis.fetch = (url, init) => {
      if (init?.body) sent.push(String(init.body));
      return real(url, init);
    };
    try {
      await assert.rejects(a.login(login, password), /credentials_upgrade/);
    } finally {
      globalThis.fetch = real;
    }
    assert.ok(sent.length > 0 && sent.every((b) => !b.includes(password)));
    // Sent only on purpose.
    await a.login(login, password, { upgrade: true });
    assert.ok(a.engine);
    await a.logout();
    assert.equal(a.engine, null);
  });
});

test("a forged key reset for a member does not undo a removal: nobody writes into the old box again", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    await a.c.leave(conv.id, c.login);
    await b.c.send(conv.id, "after c");
    // The server publishes a reset for a with keys it made.
    const forged = await dm.generateIdentity();
    assert.ok(api.keys.publish(a.login, await dm.keysPublication(a.login, forged, null, { reset: true })).ok);
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    await fresh.trust(a.login, (await fresh.verifyPeer(a.login)).fingerprint);
    // b's vault remembers the leave and the move it verified: still two members, still the new box.
    assert.deepEqual((await fresh.members(conv.id)).members, [a.login, b.login].sort());
    await fresh.send(conv.id, "still private");
    const old = c.c.engine.vault.convs[conv.id].boxes[0];
    const inOld = await fetch(`${base}/api/box/read`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: old.id, token: old.token }) }).then((r) => r.json());
    for (const s of inOld.messages) {
      const o = await dm.openMessage(old, s);
      assert.ok(!(o.ok && o.m.text === "still private"), "nothing new lands where c can read it");
    }
  });
});

test("move invitations are saved before the move is posted and delivered on a later visit", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    const drop = api.inbox.drop.bind(api.inbox);
    api.inbox.drop = () => ({ ok: false, reason: "box_full" });
    await a.c.leave(conv.id, c.login);
    api.inbox.drop = drop;
    assert.equal(a.c.engine.vault.outbox.length, 1);
    // A new process for a, with only the password, delivers what waited.
    const again = createClient({ base, witness: W });
    await again.login(a.login, a.password);
    assert.equal(again.engine.vault.outbox.length, 0);
    await again.send(conv.id, "moved");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["moved"]);
  });
});

test("a stale second session of a member does not throw away a move the first one needs", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    const second = createClient({ base, witness: W });
    await second.login(b.login, b.password);
    await second.invitations();
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    await a.c.leave(conv.id, c.login);
    // The second session still has the vault from before b accepted.
    await second.invitations();
    await a.c.send(conv.id, "for b");
    assert.deepEqual((await b.c.read(conv.id)).map((m) => m.text), ["for b"]);
  });
});

test("the ticket key id is computed by the client, not taken from the server", async () => {
  await withServer(async (base, dir, api) => {
    const real = api.tickets.pub;
    api.tickets.pub = { ...real, id: "made-up" };
    const a = await agent(base);
    assert.equal(a.c.engine.vault.ticketKey, await tk.keyId(real));
    // Another exponent on the same modulus would mark one account's tickets: refused.
    api.tickets.pub = { ...real, e: "AQAD" };
    const b = createClient({ base, witness: W });
    const cred = await b.register();
    await b.login(cred.login, cred.password);
    await assert.rejects(b.start([]), /ticket_invalid/);
  });
});

test("a remembered leave cannot be reused with other contents, nor left out by the server", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    await a.c.leave(conv.id, c.login);
    await b.c.send(conv.id, "b follows");
    const oldBox = b.c.engine.vault.convs[conv.id].boxes[0];
    // c, removed but holding the old key, re-seals a's signed leave as "a removed b".
    const stored = api.boxes.byId.get(oldBox.id).messages;
    const leaveAt = [];
    for (const rec of stored) {
      const o = await dm.openMessage(oldBox, rec);
      if (o.ok && o.m.kind === "leave") leaveAt.push([rec, o.m]);
    }
    const [[rec, leave]] = leaveAt;
    const altered = { ...leave, removed: b.login, members: [a.login, c.login].sort() };
    const body = new TextEncoder().encode(JSON.stringify(altered));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey("raw", dm.unb64u(oldBox.key), { name: "AES-GCM" }, false, ["encrypt"]);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(`ah-box-1\n${oldBox.id}`) }, key, body));
    // The server serves the altered one in the original's place.
    rec.iv = dm.b64u(iv);
    rec.ct = dm.b64u(ct);
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    const r = await fresh.engine.refresh(conv.id);
    assert.equal(r.ok, false);
    assert.equal(r.error, "conversation_changed");
    await assert.rejects(fresh.send(conv.id, "must not go anywhere"), /conversation_changed/);
  });
});

test("news: invitations, then only what others sent since the last call, across processes", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    const first = await b.c.news();
    assert.deepEqual(first.invitations.map((i) => i.conv), [conv.id]);
    assert.equal(first.conversations.length, 0);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "one");
    await a.c.send(conv.id, "two");
    const n1 = await b.c.news();
    assert.equal(n1.invitations.length, 0);
    assert.deepEqual(n1.conversations.map((c) => [c.id, c.messages.map((m) => m.text)]), [[conv.id, ["one", "two"]]]);
    assert.equal((await b.c.news()).conversations.length, 0);
    await b.c.send(conv.id, "own words are not news");
    assert.equal((await b.c.news()).conversations.length, 0);
    await a.c.send(conv.id, "three");
    // A new process with only the login and password picks up where the last left off.
    const again = createClient({ base, witness: W });
    await again.login(b.login, b.password);
    assert.deepEqual((await again.news()).conversations.map((c) => c.messages.map((m) => m.text)), [["three"]]);
    assert.equal((await again.news()).conversations.length, 0);
  });
});

test("news follows a conversation into its next box after a removal", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    await a.c.send(conv.id, "before");
    assert.deepEqual((await b.c.news()).conversations.map((x) => x.messages.map((m) => m.text)), [["before"]]);
    await a.c.leave(conv.id, c.login);
    await a.c.send(conv.id, "after");
    const n = await b.c.news();
    assert.deepEqual(n.conversations.map((x) => [x.members.length, x.messages.map((m) => m.text)]), [[2, ["after"]]]);
  });
});

test("news keeps reading a conversation whose move invitation arrives late", async () => {
  await withServer(async (base, dir, api) => {
    const a = await agent(base);
    const b = await agent(base);
    const c = await agent(base);
    const conv = await a.c.start([b.login, c.login]);
    await b.c.accept(conv.id);
    await c.c.accept(conv.id);
    const drop = api.inbox.drop.bind(api.inbox);
    api.inbox.drop = () => ({ ok: false, reason: "box_full" });
    await a.c.leave(conv.id, c.login);
    // b sees the leave and the move, but the invitation to the new box has not come.
    assert.equal((await b.c.news()).conversations.length, 0);
    assert.equal((await b.c.news()).conversations.length, 0);
    api.inbox.drop = drop;
    await a.c.send(conv.id, "in the new box");
    assert.deepEqual((await b.c.news()).conversations.map((x) => x.messages.map((m) => m.text)), [["in the new box"]]);
  });
});

test("news never moves a saved position back when two clients of one account ask", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const conv = await a.c.start([b.login]);
    await b.c.accept(conv.id);
    await a.c.send(conv.id, "one");
    const slow = createClient({ base, witness: W });
    await slow.login(b.login, b.password);
    // Hold slow's first vault write until b has saved a later position.
    const realFetch = globalThis.fetch;
    let release;
    const held = new Promise((r) => (release = r));
    let blocked = null;
    const reached = new Promise((r) => (blocked = r));
    globalThis.fetch = async (url, init = {}) => {
      if (blocked && String(url).endsWith("/api/vault") && init.method === "POST" && init.headers?.cookie === slow.session.cookie) {
        const b0 = blocked;
        blocked = null;
        b0();
        await held;
      }
      return realFetch(url, init);
    };
    try {
      const pending = slow.news();
      await reached;
      await a.c.send(conv.id, "two");
      assert.deepEqual((await b.c.news()).conversations.map((x) => x.messages.map((m) => m.text)), [["one", "two"]]);
      release();
      assert.deepEqual((await pending).conversations.map((x) => x.messages.map((m) => m.text)), [["one"]]);
    } finally {
      globalThis.fetch = realFetch;
    }
    const fresh = createClient({ base, witness: W });
    await fresh.login(b.login, b.password);
    assert.equal((await fresh.news()).conversations.length, 0);
  });
});

test("the reference client reads and writes the forum", async () => {
  await withServer(async (base) => {
    const a = await agent(base);
    const b = await agent(base);
    const { id } = await a.c.post(["hello from a"]);
    await b.c.reply(id, ["hello back"]);
    const list = await b.c.threads();
    assert.equal(list.threads[0].id, id);
    const t = await a.c.thread(id);
    assert.deepEqual(t.messages.map((m) => [m.author, m.text]), [[a.login, "hello from a"], [b.login, "hello back"]]);
    await assert.rejects(a.c.post(["x".repeat(281)]), /message_too_long/);
  });
});
