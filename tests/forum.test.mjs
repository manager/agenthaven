// motion-passport: exempt test file, no UI and no animation.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createApi } from "../api/server.mjs";
import { checkMessages, Forum, FORUM } from "../api/forum.mjs";

async function withApi(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-forum-"));
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  const as = (login) => {
    if (!api.store.has(login)) api.store.byLogin.set(login, { login });
    const cookie = `ah_session=${api.sessions.create(login).token}`;
    return {
      cookie,
      get: (p) => fetch(`${base}${p}`, { headers: { cookie } }),
      post: (p, body) =>
        fetch(`${base}${p}`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify(body) }),
    };
  };
  try {
    await fn({ base, as, dir });
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("message rules: 1-280 code points, 1-8 per request, no control characters", () => {
  assert.equal(checkMessages(["hi"]).ok, true);
  assert.equal(checkMessages("hi").reason, "messages_missing");
  assert.equal(checkMessages([]).reason, "messages_missing");
  assert.equal(checkMessages(Array(9).fill("x")).reason, "messages_too_many");
  assert.equal(checkMessages(Array(8).fill("x")).ok, true);
  assert.equal(checkMessages([7]).reason, "message_not_string");
  assert.equal(checkMessages([" \n\t "]).reason, "message_empty");
  assert.equal(checkMessages(["a".repeat(280)]).ok, true);
  assert.equal(checkMessages(["a".repeat(281)]).reason, "message_too_long");
  // Code points, not UTF-16 units: 280 emoji fit.
  assert.equal(checkMessages(["🜂".repeat(280)]).ok, true);
  assert.equal(checkMessages(["line one\nline two\ttab"]).ok, true);
  assert.equal(checkMessages(["bell\u0007"]).reason, "message_charset");
  assert.equal(checkMessages(["\u200b\u200b"]).reason, "message_empty");
  assert.equal(checkMessages(["a\u202eb"]).reason, "message_charset");
  assert.equal(checkMessages(["a\r\nb"]).texts[0], "a\nb");
  assert.equal(checkMessages(["a\rb"]).reason, "message_charset");
  assert.equal(checkMessages([Array(12).fill("x").join("\n")]).ok, true);
  assert.equal(checkMessages([Array(13).fill("x").join("\n")]).reason, "message_lines");
  assert.equal(checkMessages(["e\u0301"]).ok, true);
  assert.equal(checkMessages(["x" + "\u0301".repeat(4)]).reason, "message_marks");
  // Blank-looking characters alone, and marks with no base, show nothing.
  for (const cp of [0x3164, 0x2800, 0xffa0, 0x034f, 0xfe0f]) {
    assert.equal(checkMessages([String.fromCodePoint(cp, cp)]).reason, "message_empty", cp.toString(16));
  }
  // A format character between marks does not reset the run.
  assert.equal(checkMessages(["x" + "\u0301\u0301\u200d\u0301\u0301"]).reason, "message_marks");
  // Emoji joined with ZWJ still pass.
  assert.equal(checkMessages(["\u{1F469}\u200d\u{1F4BB}"]).ok, true);
});

test("thread list paging never skips threads with equal times", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-forum-"));
  try {
    const f = new Forum(dir);
    const ids = [];
    for (let i = 0; i < 7; i++) ids.push(f.open("a", ["x"], 1000).thread.id);
    ids.push(f.open("a", ["newer"], 2000).thread.id);
    const seen = [];
    let cursor;
    for (let guard = 0; guard < 10; guard++) {
      const page = f.list({ cursor, limit: 2 });
      seen.push(...page.threads.map((t) => t.id));
      if (!page.more) break;
      cursor = page.next;
    }
    assert.equal(seen.length, 8);
    assert.deepEqual([...seen].sort(), [...ids].sort());
    assert.equal(seen[0], ids[7], "newest first");
    assert.equal(f.list({ cursor: "junk" }).reason, "cursor_unknown");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a torn line from a crash never swallows the next message", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-forum-"));
  try {
    const f = new Forum(dir);
    const t = f.open("a", ["kept"]).thread;
    fs.appendFileSync(path.join(dir, "forum.jsonl"), '{"id":"torn","thread":"');
    const g = new Forum(dir);
    assert.equal(g.add(t.id, "b", ["after the crash"]).ok, true);
    const h = new Forum(dir);
    assert.deepEqual(h.read(t.id).messages.map((m) => m.text), ["kept", "after the crash"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the page mirrors the server's message rules", () => {
  const src = fs.readFileSync(new URL("../public/js/app.js", import.meta.url), "utf8");
  const num = (name) => Number(new RegExp(`const ${name} = (\\d+);`).exec(src)[1]);
  assert.equal(num("MAX_CHARS"), FORUM.messageMax);
  assert.equal(num("MAX_BATCH"), FORUM.batchMax);
  assert.equal(num("MAX_IN_A_ROW"), FORUM.inARowMax);
  assert.equal(num("MAX_LINES"), FORUM.linesMax);
  assert.equal(num("MAX_MARKS"), FORUM.marksInARowMax);
  const fsrc = fs.readFileSync(new URL("../api/forum.mjs", import.meta.url), "utf8");
  for (const name of ["BAD_CHARS", "INVISIBLE"]) {
    const re = (text) => new RegExp(`const ${name} = (\\/.+\\/u?);`).exec(text)[1];
    assert.equal(re(src), re(fsrc), name);
  }
});

test("forum needs a session", async () => {
  await withApi(async ({ base }) => {
    for (const [method, p] of [["GET", "/api/threads"], ["POST", "/api/threads"], ["GET", `/api/threads/${"a".repeat(24)}`]]) {
      const res = await fetch(`${base}${p}`, { method });
      assert.equal(res.status, 401, `${method} ${p}`);
      assert.equal((await res.json()).error, "session_missing");
    }
  });
});

test("open a thread, reply, read in order, list by latest activity", async () => {
  await withApi(async ({ as }) => {
    const a = as("agent-a");
    const b = as("agent-b");
    let res = await a.post("/api/threads", { messages: ["first", "second"] });
    assert.equal(res.status, 201);
    const t1 = await res.json();
    assert.equal(t1.messages.length, 2);
    assert.deepEqual(t1.messages.map((m) => m.author), ["agent-a", "agent-a"]);

    res = await b.post("/api/threads", { messages: ["another topic"] });
    const t2 = await res.json();

    res = await b.post(`/api/threads/${t1.id}/messages`, { messages: ["reply"] });
    assert.equal(res.status, 201);

    const read = await (await a.get(`/api/threads/${t1.id}`)).json();
    assert.deepEqual(read.messages.map((m) => m.text), ["first", "second", "reply"]);
    assert.equal(read.more, false);

    // Paging with the after cursor.
    const page = await (await a.get(`/api/threads/${t1.id}?after=${read.messages[0].id}&limit=1`)).json();
    assert.deepEqual(page.messages.map((m) => m.text), ["second"]);
    assert.equal(page.more, true);

    const list = await (await a.get("/api/threads")).json();
    assert.deepEqual(list.threads.map((t) => t.id).sort(), [t1.id, t2.id].sort());
    const one = list.threads.find((t) => t.id === t1.id);
    assert.equal(one.first.text, "first");
    assert.equal(one.count, 3);

    assert.equal((await a.get(`/api/threads/${"0".repeat(24)}`)).status, 404);
  });
});

test("at most 8 messages in a row per author in a thread", async () => {
  await withApi(async ({ as }) => {
    const a = as("agent-a");
    const b = as("agent-b");
    const t = await (await a.post("/api/threads", { messages: Array(6).fill("x") })).json();
    let res = await a.post(`/api/threads/${t.id}/messages`, { messages: ["7", "8", "9"] });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "thread_in_a_row");
    res = await a.post(`/api/threads/${t.id}/messages`, { messages: ["7", "8"] });
    assert.equal(res.status, 201);
    res = await a.post(`/api/threads/${t.id}/messages`, { messages: ["9"] });
    assert.equal(res.status, 409);
    // Another author speaks; the count starts again.
    assert.equal((await b.post(`/api/threads/${t.id}/messages`, { messages: ["hello"] })).status, 201);
    assert.equal((await a.post(`/api/threads/${t.id}/messages`, { messages: Array(8).fill("y") })).status, 201);
  });
});

test("forum survives a restart and the journal holds no message text", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-forum-"));
  try {
    const f = new Forum(dir);
    const t = f.open("agent-a", ["secret-looking text"]).thread;
    f.add(t.id, "agent-b", ["answer"]);
    const again = new Forum(dir);
    assert.deepEqual(again.read(t.id).messages.map((m) => m.text), ["secret-looking text", "answer"]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  await withApi(async ({ as, dir: apiDir }) => {
    const a = as("agent-a");
    const t = await (await a.post("/api/threads", { messages: ["do not journal me"] })).json();
    await a.get(`/api/threads/${t.id}`);
    const journal = fs.readFileSync(path.join(apiDir, "api-journal.jsonl"), "utf8");
    assert.ok(!journal.includes("do not journal me"));
    assert.ok(!journal.includes(t.id), "thread ids stay out of the journal");
    assert.ok(journal.includes("GET /api/threads/:id"));
    // Near-miss paths under /api/threads/ are masked too.
    await a.get(`/api/threads/${t.id}/`);
    await a.get(`/api/threads/${t.id.toUpperCase()}`);
    const again = fs.readFileSync(path.join(apiDir, "api-journal.jsonl"), "utf8");
    assert.ok(!again.toLowerCase().includes(t.id), "no thread id in any journal line");
  });
});

test("forum writes are limited per account, counted in messages", async () => {
  await withApi(async ({ as }) => {
    const a = as("agent-a");
    const statuses = [];
    // 10 posts of 8 messages use the 80-message budget; the 11th is refused.
    for (let i = 0; i < 11; i++) statuses.push((await a.post("/api/threads", { messages: Array(8).fill("x") })).status);
    assert.equal(statuses.filter((s) => s === 201).length, 10);
    assert.equal(statuses.at(-1), 429);
    // Another account is not affected.
    assert.equal((await as("agent-b").post("/api/threads", { messages: ["x"] })).status, 201);
  });
});

test("published forum limits match the code", async () => {
  const { rulesDocument } = await import("../api/rules.mjs");
  const f = rulesDocument().forum;
  assert.ok(f.message.includes(String(FORUM.messageMax)));
  assert.ok(f.inARow.includes(String(FORUM.inARowMax)));
  assert.ok(f.open.includes(`1-${FORUM.batchMax}`));
});

test("the thread owner can ban another account from posting in that thread, and lift it", async () => {
  await withApi(async ({ base, as, dir }) => {
    const owner = as("agent-a");
    const b = as("agent-b");
    const c = as("agent-c");
    const del = (who, p) => fetch(`${base}${p}`, { method: "DELETE", headers: { cookie: who.cookie } });
    const t = await (await owner.post("/api/threads", { messages: ["my thread"] })).json();
    assert.equal((await b.post(`/api/threads/${t.id}/messages`, { messages: ["hello"] })).status, 201);

    // Only the owner may ban; nobody bans themselves or an unknown account.
    let res = await b.post(`/api/threads/${t.id}/bans`, { login: "agent-c" });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "not_thread_owner");
    assert.equal((await (await owner.post(`/api/threads/${t.id}/bans`, { login: "agent-a" })).json()).error, "ban_self");
    assert.equal((await (await owner.post(`/api/threads/${t.id}/bans`, { login: "nobody-at-all" })).json()).error, "ban_unknown");
    assert.equal((await (await owner.post(`/api/threads/${t.id}/bans`, { login: 7 })).json()).error, "ban_invalid");

    res = await owner.post(`/api/threads/${t.id}/bans`, { login: "agent-b" });
    assert.equal(res.status, 201);
    assert.deepEqual((await res.json()).banned, ["agent-b"]);
    // Banning twice changes nothing.
    assert.equal((await owner.post(`/api/threads/${t.id}/bans`, { login: "agent-b" })).status, 200);

    // B can no longer post there, but can still read, and B's earlier message stays.
    res = await b.post(`/api/threads/${t.id}/messages`, { messages: ["again"] });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "thread_banned");
    const read = await (await b.get(`/api/threads/${t.id}`)).json();
    assert.equal(read.owner, "agent-a");
    assert.deepEqual(read.banned, ["agent-b"]);
    assert.deepEqual(read.messages.map((m) => m.text), ["my thread", "hello"]);

    // The ban is for that thread only.
    const other = await (await c.post("/api/threads", { messages: ["elsewhere"] })).json();
    assert.equal((await b.post(`/api/threads/${other.id}/messages`, { messages: ["fine here"] })).status, 201);
    // Others still post.
    assert.equal((await c.post(`/api/threads/${t.id}/messages`, { messages: ["still open"] })).status, 201);

    // Only the owner lifts it.
    assert.equal((await del(c, `/api/threads/${t.id}/bans/agent-b`)).status, 403);
    res = await del(owner, `/api/threads/${t.id}/bans/agent-b`);
    assert.equal(res.status, 201);
    assert.deepEqual((await res.json()).banned, []);
    assert.equal((await b.post(`/api/threads/${t.id}/messages`, { messages: ["back"] })).status, 201);

    // Bans survive a restart, and no login reaches the journal.
    await owner.post(`/api/threads/${t.id}/bans`, { login: "agent-c" });
    const again = new Forum(dir);
    assert.deepEqual([...again.threads.get(t.id).bans], ["agent-c"]);
    const journal = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8");
    assert.ok(!journal.includes("agent-b") && !journal.includes("agent-c"), "login in journal");
    assert.ok(journal.includes("DELETE /api/threads/:id/bans/:login"));
    // A doubled slash makes the path unparsable as a route: it is journaled as :unknown.
    await fetch(`${base}//api/threads/${t.id}/bans/agent-c`, { method: "DELETE", headers: { cookie: owner.cookie } });
    const after = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8");
    assert.ok(!after.includes(t.id) && !after.includes("agent-c"), "id or login in journal");
  });
});
