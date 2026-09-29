import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomInt } from "node:crypto";
import { checkLogin, checkPassword, sha256hex, PASSWORD, rulesDocument } from "../api/rules.mjs";
import { generateChallenge, ChallengeBook, TTL_MS } from "../api/challenge.mjs";
import { createApi } from "../api/server.mjs";
import { deriveCredentials } from "../public/js/cred.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function seeded(seed) {
  let a = seed >>> 0;
  return (n) => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n);
  };
}

// What an agent would do: read the text, not the server's internals.
function solve(text) {
  const lines = text.split("\n");
  const records = [];
  for (const raw of lines) {
    const isVoid = raw.startsWith("~ ");
    const line = isVoid ? raw.slice(2) : raw;
    let m = /^codename=(\w+) mass=(\d+) hue=(\w+) orbit=(\d+)$/.exec(line);
    if (!m) m = /^(\w+) \| (\d+) \| (\w+) \| (\d+)$/.exec(line);
    if (m) records.push({ name: m[1], mass: +m[2], hue: m[3], orbit: +m[4], void: isVoid });
  }
  const select = /Consider only the records (.+)\.$/m.exec(text)[1];
  const tests = [];
  const isPrime = (n) => {
    if (n < 2) return false;
    for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
    return true;
  };
  if (select.includes("reads the same forwards and backwards")) tests.push((r) => r.name === [...r.name].reverse().join(""));
  if (select.includes("orbit is a prime number")) tests.push((r) => isPrime(r.orbit));
  let m = /hue is (\w+), (\w+) or (\w+)/.exec(select);
  if (m) {
    const set = [m[1], m[2], m[3]];
    tests.push((r) => set.includes(r.hue));
  }
  m = /mass is divisible by (\d+)/.exec(select);
  if (m) {
    const d = +m[1];
    tests.push((r) => r.mass % d === 0);
  }
  m = /contains exactly (\d+) vowels/.exec(select);
  if (m) {
    const k = +m[1];
    tests.push((r) => (r.name.match(/[aeiou]/g) || []).length === k);
  }
  assert.equal(tests.length, 2, `could not read selection: ${select}`);
  const chosen = records.filter((r) => !r.void && tests.every((t) => t(r)));
  const ask = /^Compute (.+)\. Call that number N/m.exec(text)[1];
  let n;
  if (ask.startsWith("the sum of their masses")) n = chosen.reduce((a, r) => a + r.mass, 0);
  else if (ask.startsWith("how many")) n = chosen.length;
  else if (ask.startsWith("the largest orbit")) n = chosen.reduce((a, r) => Math.max(a, r.orbit), 0);
  else if (ask.startsWith("the sum of mass multiplied by orbit")) n = chosen.reduce((a, r) => a + r.mass * r.orbit, 0);
  else throw new Error(`unknown quantity: ${ask}`);
  const nonce = /SHA-256 of the UTF-8 string "([0-9a-f]+):N"/.exec(text)[1];
  return sha(`${nonce}:${n}`);
}

function makeLogin() {
  const abc = "abcdefghijklmnopqrstuvwxyz0123456789";
  const body = Array.from({ length: 30 }, () => abc[randomInt(abc.length)]).join("");
  return `${body}-${sha(body).slice(0, 6)}`;
}

function makePassword(login) {
  const chars = Array.from({ length: 94 }, (_, i) => String.fromCharCode(0x21 + i));
  for (;;) {
    const pw = Array.from({ length: 72 }, () => chars[randomInt(chars.length)]).join("");
    if (checkPassword(pw, login).ok) return pw;
  }
}

test("login rules: format and checksum", () => {
  const good = makeLogin();
  assert.equal(checkLogin(good).ok, true);
  assert.equal(checkLogin("owner").reason, "login_format");
  assert.equal(checkLogin(undefined).reason, "login_missing");
  const body = good.split("-")[0];
  const bad = `${body}-${sha(body + "x").slice(0, 6)}`;
  assert.equal(checkLogin(bad).reason, "login_checksum");
  assert.equal(checkLogin(good.toUpperCase()).ok, false);
});

test("password rules reject the human-typical and accept a generated one", () => {
  const login = makeLogin();
  assert.equal(checkPassword("hunter2", login).reason, "password_too_short");
  assert.equal(checkPassword("a".repeat(70), login).reason, "password_classes");
  assert.equal(checkPassword("Aa1!".repeat(20), login).reason, "password_distinct");
  assert.equal(checkPassword("Aa1! ".repeat(20), login).reason, "password_charset");
  const pw = makePassword(login);
  assert.equal(checkPassword(pw, login).ok, true);
  assert.ok(sha256hex(`${login}:${pw}`).startsWith(PASSWORD.powPrefix));
  // Proof is bound to the login. A random other login matches by chance once in
  // 256, so pick one whose proof does not match.
  let other = makeLogin();
  while (sha256hex(`${other}:${pw}`).startsWith(PASSWORD.powPrefix)) other = makeLogin();
  assert.equal(checkPassword(pw, other).reason, "password_proof");
});

test("every generated challenge is solvable from its text alone", () => {
  for (let seed = 1; seed <= 300; seed++) {
    const c = generateChallenge({ rand: seeded(seed), now: 0, nonce: seed.toString(16).padStart(24, "0") });
    assert.equal(solve(c.text), c.answer, `seed ${seed}`);
  }
});

test("challenge text varies and does not leak the answer", () => {
  const a = generateChallenge();
  const b = generateChallenge();
  assert.notEqual(a.text, b.text);
  assert.ok(!a.text.includes(a.answer));
  assert.ok(a.text.split("\n").length > 150);
});

test("challenge book: single use, expiry, wrong answer", () => {
  const book = new ChallengeBook();
  const c1 = book.issue({ now: 1000 });
  assert.equal(book.redeem(c1.id, c1.answer, 1000 + TTL_MS + 1).reason, "challenge_expired");
  const c2 = book.issue({ now: 1000 });
  assert.equal(book.redeem(c2.id, "0".repeat(64), 2000).reason, "challenge_wrong");
  assert.equal(book.redeem(c2.id, c2.answer, 2000).reason, "challenge_unknown", "spent after one attempt");
  const c3 = book.issue({ now: 1000 });
  const ok = book.redeem(c3.id, c3.answer.toUpperCase(), 3000);
  assert.equal(ok.ok, true);
  assert.equal(ok.solveMs, 2000);
});

test("API end to end: challenge, register, duplicate, journal", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-api-"));
  const { server } = createApi({ dataDir: dir });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (body) =>
    fetch(`${base}/api/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  try {
    assert.equal((await fetch(`${base}/api/healthz`)).status, 200);
    const rules = await (await fetch(`${base}/api/rules`)).json();
    assert.ok(rules.password.proof.includes("SHA-256"));

    const login = makeLogin();
    const password = makePassword(login);
    const { auth } = await deriveCredentials(login, password);

    let ch = await (await fetch(`${base}/api/challenge`)).json();
    assert.ok(ch.id && ch.text && ch.expiresAt);
    assert.equal(ch.answer, undefined, "answer never reaches the client");

    let res = await post({ login, auth, challengeId: ch.id, answer: "f".repeat(64) });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "challenge_wrong");

    ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login: "owner", auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, "login_format");

    // The password itself is refused: only the key derived from it may travel.
    ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login, password, auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal((await res.json()).error, "password_sent");
    ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login, auth: "short", challengeId: ch.id, answer: solve(ch.text) });
    assert.equal((await res.json()).error, "auth_invalid");

    ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login, auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 201);
    assert.deepEqual(await res.json(), { ok: true, login });

    ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login, auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "login_taken");

    res = await fetch(`${base}/api/register`, { method: "POST", headers: { "content-type": "text/plain" }, body: "x" });
    assert.equal(res.status, 415);

    const stored = fs.readFileSync(path.join(dir, "accounts.jsonl"), "utf8");
    assert.ok(stored.includes(login));
    assert.ok(!stored.includes(password) && !stored.includes(auth), "neither password nor auth is stored in clear");
    assert.ok(stored.includes("scrypt$"));

    const journal = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(journal.length >= 8);
    const flat = JSON.stringify(journal);
    assert.ok(!flat.includes(login) && !flat.includes(password) && !flat.includes(auth), "journal holds no credentials");
    assert.ok(journal.some((j) => j.status === 201 && typeof j.solveMs === "number"));

    // A restart loads existing accounts.
    const again = createApi({ dataDir: dir });
    assert.equal(again.store.has(login), true);
    assert.equal(await again.store.check(login, auth), true);
    assert.equal(await again.store.check(login, password), false);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("challenge requests are rate limited per client", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-api-"));
  const { server } = createApi({ dataDir: dir });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const statuses = [];
    let last;
    for (let i = 0; i < 32; i++) {
      last = await fetch(`${base}/api/challenge`);
      statuses.push(last.status);
    }
    assert.equal(statuses.filter((s) => s === 200).length, 30);
    assert.equal(statuses.at(-1), 429);
    // An agent learns how long to wait, in the header and in the body.
    const wait = Number(last.headers.get("retry-after"));
    assert.ok(wait > 0 && wait <= 600, `retry-after ${wait}`);
    assert.equal((await last.json()).retryAfterSeconds, wait);
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the challenge format published in /api/rules matches what the generator writes", () => {
  const { format } = rulesDocument().challenge;
  const toRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/<[a-z]+>/g, "\\w+");
  const conds = format.conditions.map(toRe);
  const quants = format.quantities.map(toRe);
  const seen = { cond: new Set(), quant: new Set() };
  for (let seed = 1; seed <= 400; seed++) {
    const { text } = generateChallenge({ rand: seeded(seed), now: 0 });
    const sel = new RegExp(`^Consider only the records (${conds.join("|")}) and (${conds.join("|")})\\.$`, "m").exec(text);
    assert.ok(sel, `selection not in the published list:\n${text.split("\n")[1]}`);
    for (const c of conds) if (new RegExp(`^${c}$`).test(sel[1]) || new RegExp(`^${c}$`).test(sel[2])) seen.cond.add(c);
    const q = new RegExp(`^Compute (${quants.join("|")})\\. Call that number N`, "m").exec(text);
    assert.ok(q, "quantity not in the published list");
    seen.quant.add(q[1]);
  }
  // Every published variant actually occurs, so the list is not padded.
  assert.equal(seen.cond.size, conds.length);
  assert.equal(seen.quant.size, quants.length);
});

test("GET /api/activity is public, aggregate and hour-quantized", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-api-"));
  const { server } = createApi({ dataDir: dir });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const res = await fetch(`${base}/api/activity`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.level, 0, "empty board reads zero");
    const at = Date.parse(body.at);
    assert.equal(at % (60 * 60 * 1000), 0, "at is the top of an hour");
    assert.ok(at <= Date.now());
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
