import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { activityReading, nextMidnight, VaultDays, WINDOW_MS, QUANTUM_MS, DAY_MS, FULL_AT } from "../api/activity-signal.mjs";
import { createApi } from "../api/server.mjs";

const HOUR = 60 * 60 * 1000;
// A time in the middle of an hour, so quantization is observable.
const NOW = 1_800_000_000_000 + 37 * 60 * 1000;
const HOUR_TOP = Math.floor(NOW / QUANTUM_MS) * QUANTUM_MS;
const post = (who, t) => ({ who, t });

test("one agent lights one percent however much it writes; FULL_AT agents light the ring", () => {
  const at = HOUR_TOP - 5 * 60 * 1000; // inside the window and past hour
  assert.equal(activityReading({ posts: [post("a", at)] }, NOW).level, 1 / FULL_AT);
  const oneAgent = Array.from({ length: 500 }, () => post("a", at));
  assert.equal(activityReading({ posts: oneAgent }, NOW).level, 1 / FULL_AT, "one agent posting 500 times is still one agent");
  const many = Array.from({ length: FULL_AT }, (_, i) => post(`a${i}`, at));
  assert.equal(activityReading({ posts: many }, NOW).level, 1);
  const over = Array.from({ length: FULL_AT + 50 }, (_, i) => post(`a${i}`, at));
  assert.equal(activityReading({ posts: over }, NOW).level, 1);
});

test("the reading is quantized to the top of the hour", () => {
  const r = activityReading({}, NOW);
  assert.equal(r.at, HOUR_TOP);
  assert.equal(r.at % QUANTUM_MS, 0);
  assert.ok(r.at <= NOW);
});

test("posts older than the window do not count", () => {
  const old = HOUR_TOP - WINDOW_MS - 1000;
  const edge = HOUR_TOP - WINDOW_MS + 1000;
  assert.equal(activityReading({ posts: [post("a", old)] }, NOW).level, 0);
  assert.equal(activityReading({ posts: [post("a", edge)] }, NOW).level, 1 / FULL_AT);
});

test("posts in the running hour are not counted yet (intended delay)", () => {
  const justNow = NOW - 60 * 1000; // after HOUR_TOP
  assert.ok(justNow > HOUR_TOP);
  assert.equal(activityReading({ posts: [post("a", justNow)] }, NOW).level, 0);
});

test("nothing reads level zero; malformed entries are ignored", () => {
  assert.equal(activityReading({}, NOW).level, 0);
  const good = HOUR_TOP - HOUR;
  const bad = [post("a", NaN), post("b", Infinity), post("c", null), post("d", "x"), { t: good }, null];
  assert.equal(activityReading({ posts: [...bad, post("e", good)] }, NOW).level, 1 / FULL_AT);
});

test("a vault write counts only from the next UTC midnight, and leaves at a midnight", () => {
  const dayStart = Math.floor(NOW / DAY_MS) * DAY_MS;
  const earlyToday = dayStart + 60 * 1000;
  // Written today: not visible at any hour of today.
  for (let h = 1; h < 24; h++) assert.equal(activityReading({ vaultWrites: [post("v", earlyToday)] }, dayStart + h * HOUR + 1).level, 0);
  // Visible from the first reading after midnight.
  assert.equal(activityReading({ vaultWrites: [post("v", earlyToday)] }, dayStart + DAY_MS + 1).level, 1 / FULL_AT);
  // Visible for 72 hours from that midnight, then gone, again at a midnight.
  const counted = nextMidnight(earlyToday);
  assert.equal(activityReading({ vaultWrites: [post("v", earlyToday)] }, counted + WINDOW_MS - 1).level, 1 / FULL_AT);
  assert.equal(activityReading({ vaultWrites: [post("v", earlyToday)] }, counted + WINDOW_MS + HOUR).level, 0);
  assert.equal((counted + WINDOW_MS) % DAY_MS, 0, "it leaves at a midnight");
});

test("forum posts and vault writes of one agent count once", () => {
  const yesterday = HOUR_TOP - DAY_MS;
  const r = activityReading({ posts: [post("a", HOUR_TOP - HOUR)], vaultWrites: [post("a", yesterday), post("b", yesterday)] }, NOW);
  assert.equal(r.level, 2 / FULL_AT);
});

test("VaultDays keeps one entry per account and day, and drops days past the window", () => {
  const d = new VaultDays([{ who: "a", t: NOW - 3 * DAY_MS }]);
  d.note("a", NOW);
  d.note("a", NOW + 1000);
  d.note("b", NOW - 10 * DAY_MS);
  const w = d.writes(NOW);
  assert.equal(w.filter((x) => x.who === "a").length, 2);
  assert.equal(w.filter((x) => x.who === "b").length, 0);
  assert.ok(w.every((x) => x.t % DAY_MS === 0), "only the day is kept");
  // A second write on a later day keeps the earlier day counted: the count
  // never drops at the hour of a write.
  const before = activityReading({ vaultWrites: d.writes(NOW) }, NOW + DAY_MS).level;
  d.note("a", NOW + DAY_MS);
  assert.equal(activityReading({ vaultWrites: d.writes(NOW + DAY_MS) }, NOW + DAY_MS).level, before);
});

test("GET /api/activity counts agents from forum posts and vault writes", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-activity-"));
  let clock = NOW;
  const api = createApi({ dataDir: dir, now: () => clock });
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${api.server.address().port}`;
  const as = (login) => {
    api.store.byLogin.set(login, { login });
    const cookie = `ah_session=${api.sessions.create(login, clock).token}`;
    return (p, body) => fetch(`${base}${p}`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify(body) });
  };
  const level = async () => (await (await fetch(`${base}/api/activity`)).json()).level;
  try {
    const a = as("a".repeat(24) + "-000000");
    const b = as("b".repeat(24) + "-000000");
    assert.equal((await a("/api/threads", { messages: ["one", "two", "three"] })).status, 201);
    const blob = { iv: "AAAAAAAAAAAAAAAA", ct: "AAAA" };
    assert.equal((await b("/api/vault", { version: 1, blob })).status, 200);
    assert.equal(await level(), 0, "the running hour is not counted");
    clock = NOW + HOUR;
    assert.equal(await level(), 1 / FULL_AT, "the forum author counts once from the next hour; the vault write waits for midnight");
    clock = nextMidnight(NOW) + 1;
    assert.equal(await level(), 2 / FULL_AT);
    // The same reading within the hour: computed once.
    clock += 30 * 60 * 1000;
    assert.equal(await level(), 2 / FULL_AT);
  } finally {
    await new Promise((r) => api.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
