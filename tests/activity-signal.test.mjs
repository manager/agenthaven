import test from "node:test";
import assert from "node:assert/strict";
import { activityReading, WINDOW_MS, QUANTUM_MS, FULL_AT } from "../api/activity-signal.mjs";

const HOUR = 60 * 60 * 1000;
// A time in the middle of an hour, so quantization is observable.
const NOW = 1_800_000_000_000 + 37 * 60 * 1000;
const HOUR_TOP = Math.floor(NOW / QUANTUM_MS) * QUANTUM_MS;

test("one message lights one percent, full board caps at FULL_AT", () => {
  const at = HOUR_TOP - 5 * 60 * 1000; // inside the window and past hour
  assert.equal(activityReading([at], NOW).level, 1 / FULL_AT);
  const many = Array.from({ length: FULL_AT }, () => at);
  assert.equal(activityReading(many, NOW).level, 1);
  const over = Array.from({ length: FULL_AT + 50 }, () => at);
  assert.equal(activityReading(over, NOW).level, 1);
});

test("the reading is quantized to the top of the hour", () => {
  const r = activityReading([], NOW);
  assert.equal(r.at, HOUR_TOP);
  assert.equal(r.at % QUANTUM_MS, 0);
  assert.ok(r.at <= NOW);
});

test("posts older than the window do not count", () => {
  const old = HOUR_TOP - WINDOW_MS - 1000;
  const edge = HOUR_TOP - WINDOW_MS + 1000;
  assert.equal(activityReading([old], NOW).level, 0);
  assert.equal(activityReading([edge], NOW).level, 1 / FULL_AT);
});

test("posts in the running hour are not counted yet (intended delay)", () => {
  const justNow = NOW - 60 * 1000; // after HOUR_TOP
  assert.ok(justNow > HOUR_TOP);
  assert.equal(activityReading([justNow], NOW).level, 0);
});

test("no posts reads level zero", () => {
  assert.equal(activityReading([], NOW).level, 0);
});

test("non-finite timestamps are ignored", () => {
  const good = HOUR_TOP - HOUR;
  assert.equal(activityReading([NaN, Infinity, null, "x", good], NOW).level, 1 / FULL_AT);
});
