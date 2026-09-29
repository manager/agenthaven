import test from "node:test";
import assert from "node:assert/strict";
import {
  BASELINE,
  CEILING,
  levelToBrightness,
  toState,
  brightnessFor,
  fixtureFromSearch,
} from "../public/js/activity.js";

const NOW = 1_800_000_000_000;

test("brightness is bounded and monotonic in the level", () => {
  let prev = -Infinity;
  for (let i = 0; i <= 1000; i++) {
    const b = levelToBrightness(i / 1000);
    assert.ok(b >= BASELINE && b <= CEILING, `out of range at ${i}`);
    assert.ok(b >= prev, `not monotonic at ${i}`);
    prev = b;
  }
  assert.equal(levelToBrightness(0), BASELINE);
  assert.ok(Math.abs(levelToBrightness(1) - CEILING) < 1e-12);
  assert.ok(levelToBrightness(0.5) > levelToBrightness(0.25));
});

test("out-of-range levels are clamped by the mapping", () => {
  assert.equal(levelToBrightness(-5), BASELINE);
  assert.ok(Math.abs(levelToBrightness(9) - CEILING) < 1e-12);
});

test("missing, invalid and stale readings stay unknown and render baseline", () => {
  const bad = [
    null,
    undefined,
    42,
    {},
    { level: "0.5", at: NOW },
    { level: NaN, at: NOW },
    { level: -0.1, at: NOW },
    { level: 1.1, at: NOW },
    { level: 0.5 },
    { level: 0.5, at: NOW - 16 * 60 * 1000 },
    { level: 0.5, at: NOW + 1000 },
  ];
  for (const r of bad) {
    const s = toState(r, NOW);
    assert.equal(s.kind, "unknown", JSON.stringify(r));
    assert.equal(brightnessFor(s), BASELINE);
  }
});

test("measured zero is distinct from unknown but shows baseline light", () => {
  const zero = toState({ level: 0, at: NOW - 1000 }, NOW);
  assert.equal(zero.kind, "measured");
  assert.equal(zero.level, 0);
  assert.equal(brightnessFor(zero), BASELINE);
  assert.notEqual(zero.kind, toState(null, NOW).kind);
});

test("a fresh measured reading raises brightness", () => {
  const s = toState({ level: 0.6, at: NOW - 1000 }, NOW);
  assert.equal(s.kind, "measured");
  assert.ok(brightnessFor(s) > BASELINE);
});

test("URL fixture is tagged fixture, never measured", () => {
  assert.equal(fixtureFromSearch(""), null);
  assert.equal(fixtureFromSearch("?other=1"), null);
  const f = fixtureFromSearch("?fixture=0.8");
  assert.equal(f.kind, "fixture");
  assert.equal(f.level, 0.8);
  assert.ok(brightnessFor(f) > BASELINE);
  assert.equal(fixtureFromSearch("?fixture=abc").kind, "unknown");
  assert.equal(fixtureFromSearch("?fixture=2").kind, "unknown");
  // A reading cannot promote itself to measured by claiming fixture.
  assert.equal(toState({ kind: "fixture", level: 0.3, at: NOW }, NOW).kind, "fixture");
});
