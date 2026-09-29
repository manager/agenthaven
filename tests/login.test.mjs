import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomInt } from "node:crypto";
import { checkPassword, rulesDocument, LEGACY_UPGRADE_UNTIL } from "../api/rules.mjs";
import { createApi } from "../api/server.mjs";
import { deriveCredentials } from "../public/js/cred.js";
import { hashPassword } from "../api/store.mjs";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// Solves the challenge from its text, as an agent would (same approach as api.test.mjs).
function solve(text) {
  const records = [];
  for (const raw of text.split("\n")) {
    const isVoid = raw.startsWith("~ ");
    const line = isVoid ? raw.slice(2) : raw;
    const m = /^codename=(\w+) mass=(\d+) hue=(\w+) orbit=(\d+)$/.exec(line) || /^(\w+) \| (\d+) \| (\w+) \| (\d+)$/.exec(line);
    if (m) records.push({ name: m[1], mass: +m[2], hue: m[3], orbit: +m[4], void: isVoid });
  }
  const select = /Consider only the records (.+)\.$/m.exec(text)[1];
  const isPrime = (n) => { if (n < 2) return false; for (let d = 2; d * d <= n; d++) if (n % d === 0) return false; return true; };
  const tests = [];
  if (select.includes("reads the same forwards and backwards")) tests.push((r) => r.name === [...r.name].reverse().join(""));
  if (select.includes("orbit is a prime number")) tests.push((r) => isPrime(r.orbit));
  let m = /hue is (\w+), (\w+) or (\w+)/.exec(select);
  if (m) { const set = [m[1], m[2], m[3]]; tests.push((r) => set.includes(r.hue)); }
  m = /mass is divisible by (\d+)/.exec(select);
  if (m) { const d = +m[1]; tests.push((r) => r.mass % d === 0); }
  m = /contains exactly (\d+) vowels/.exec(select);
  if (m) { const k = +m[1]; tests.push((r) => (r.name.match(/[aeiou]/g) || []).length === k); }
  const chosen = records.filter((r) => !r.void && tests.every((t) => t(r)));
  const ask = /^Compute (.+)\. Call that number N/m.exec(text)[1];
  let n;
  if (ask.startsWith("the sum of their masses")) n = chosen.reduce((a, r) => a + r.mass, 0);
  else if (ask.startsWith("how many")) n = chosen.length;
  else if (ask.startsWith("the largest orbit")) n = chosen.reduce((a, r) => Math.max(a, r.orbit), 0);
  else n = chosen.reduce((a, r) => a + r.mass * r.orbit, 0);
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

test("register, then log in, read the session, log out", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-login-"));
  const { server } = createApi({ dataDir: dir });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const challenge = async () => (await fetch(`${base}/api/challenge`)).json();
  const post = (route, body, headers = {}) =>
    fetch(`${base}${route}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  try {
    const login = makeLogin();
    const password = makePassword(login);
    const { auth } = await deriveCredentials(login, password);
    const wrong = (await deriveCredentials(login, makePassword(login))).auth;

    let ch = await challenge();
    assert.equal((await post("/api/register", { login, auth, challengeId: ch.id, answer: solve(ch.text) })).status, 201);

    // Wrong password and unknown login give the same code.
    ch = await challenge();
    let res = await post("/api/login", { login, auth: wrong, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "credentials_wrong");
    assert.equal(res.headers.get("set-cookie"), null);

    ch = await challenge();
    const stranger = makeLogin();
    res = await post("/api/login", { login: stranger, auth: wrong, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "credentials_wrong");

    // Login needs a solved challenge too.
    ch = await challenge();
    res = await post("/api/login", { login, auth, challengeId: ch.id, answer: "0".repeat(64) });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "challenge_wrong");

    ch = await challenge();
    res = await post("/api/login", { login, auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.login, login);
    const cookie = res.headers.get("set-cookie");
    assert.match(cookie, /^ah_session=[A-Za-z0-9_-]{43}; HttpOnly; Secure; SameSite=Strict; Path=\/api; Max-Age=86400$/);
    const token = cookie.split(";")[0];

    res = await fetch(`${base}/api/session`, { headers: { cookie: token } });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).login, login);

    assert.equal((await fetch(`${base}/api/session`)).status, 401);
    assert.equal((await fetch(`${base}/api/session`, { headers: { cookie: "ah_session=forged" } })).status, 401);

    res = await post("/api/logout", {}, { cookie: token });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("set-cookie"), /Max-Age=0/);
    assert.equal((await fetch(`${base}/api/session`, { headers: { cookie: token } })).status, 401);

    const journal = fs.readFileSync(path.join(dir, "api-journal.jsonl"), "utf8");
    assert.ok(!journal.includes(login) && !journal.includes(password) && !journal.includes(auth) && !journal.includes(token.split("=")[1]));
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("rules document keeps login rules and describes sign-in", () => {
  const d = rulesDocument();
  assert.equal(typeof d.login, "object");
  assert.ok(d.login.checksum);
  assert.match(d.signIn, /POST \/api\/login/);
  assert.ok(d.codes.credentials_wrong && d.codes.session_missing);
});

test("an account from before ah-cred-1 moves to its auth key on one sign-in with the password", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-upgrade-"));
  const api = createApi({ dataDir: dir });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  const signIn = async (body) => {
    const ch = await (await fetch(`${base}/api/challenge`)).json();
    const res = await fetch(`${base}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, challengeId: ch.id, answer: solve(ch.text) }) });
    return { status: res.status, ...(await res.json()) };
  };
  try {
    const login = makeLogin();
    const password = makePassword(login);
    const { auth } = await deriveCredentials(login, password);
    // A line as the store wrote it before ah-cred-1: a hash of the password.
    api.store.write({ login, hash: await hashPassword(password), createdAt: new Date().toISOString() });
    assert.equal((await signIn({ login, auth })).error, "credentials_upgrade");
    assert.equal((await signIn({ login, auth, password: password + "x" })).error, "credentials_wrong");
    assert.equal((await signIn({ login, auth, password })).ok, true);
    // From now on auth alone; the password no longer signs in.
    assert.equal((await signIn({ login, auth })).ok, true);
    assert.equal((await signIn({ login, auth: (await deriveCredentials(login, "other")).auth, password })).error, "credentials_wrong");
    const again = createApi({ dataDir: dir });
    assert.equal(again.store.legacy(login), false);
    assert.equal(await again.store.check(login, auth), true);
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the move from a password-keyed account closes at LEGACY_UPGRADE_UNTIL", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-expired-"));
  const api = createApi({ dataDir: dir, now: () => Date.parse(LEGACY_UPGRADE_UNTIL) });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  try {
    const login = makeLogin();
    const password = makePassword(login);
    const { auth } = await deriveCredentials(login, password);
    api.store.write({ login, hash: await hashPassword(password), createdAt: new Date().toISOString() });
    const ch = await (await fetch(`${base}/api/challenge`)).json();
    const res = await fetch(`${base}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ login, auth, password, challengeId: ch.id, answer: solve(ch.text) }) });
    assert.equal(res.status, 410);
    assert.equal((await res.json()).error, "credentials_expired");
    assert.equal(api.store.legacy(login), true);
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the owner account from the Access-gated days signs nothing in", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-owner-"));
  // A different password than the real one, which never appears in the repo.
  const { auth } = await deriveCredentials("owner", "test-owner-password");
  fs.writeFileSync(path.join(dir, "accounts.jsonl"), JSON.stringify({ login: "owner", hash: await hashPassword(auth), cred: "ah-cred-1", createdAt: "2026-09-24T09:00:00.000Z", owner: true }) + "\n");
  const { server } = createApi({ dataDir: dir });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (body) => fetch(`${base}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  try {
    // No challenge-free path is left.
    let res = await post({ login: "owner", auth });
    assert.equal(res.status, 403);
    // The right key with a solved challenge answers like a wrong one.
    const ch = await (await fetch(`${base}/api/challenge`)).json();
    res = await post({ login: "owner", auth, challengeId: ch.id, answer: solve(ch.text) });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "credentials_wrong");
    assert.equal(res.headers.get("set-cookie"), null);
    // Without the owner mark, a login outside the format is refused all the same.
    fs.writeFileSync(path.join(dir, "accounts.jsonl"), JSON.stringify({ login: "owner", hash: await hashPassword(auth), cred: "ah-cred-1", createdAt: "2026-09-24T09:00:00.000Z" }) + "\n");
    const again = createApi({ dataDir: dir });
    await new Promise((r) => again.server.listen(0, "127.0.0.1", r));
    try {
      const b2 = `http://127.0.0.1:${again.server.address().port}`;
      const c2 = await (await fetch(`${b2}/api/challenge`)).json();
      const r2 = await fetch(`${b2}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ login: "owner", auth, challengeId: c2.id, answer: solve(c2.text) }) });
      assert.equal((await r2.json()).error, "credentials_wrong");
    } finally {
      again.server.close();
    }
  } finally {
    server.close();
  }
});
