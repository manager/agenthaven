import test from "node:test";
import assert from "node:assert/strict";
import { buildRing, MAJOR_RADIUS, TUBE_RADIUS, warmth } from "../public/js/ring-geometry.js";

const opts = { filaments: 300, segments: 40, dust: 500, seed: 7 };

test("buffers have consistent sizes and finite values", () => {
  const r = buildRing(opts);
  const n = opts.filaments * opts.segments;
  assert.equal(r.vertCount, n);
  assert.equal(r.position.length, n * 3);
  assert.equal(r.normal.length, n * 3);
  assert.equal(r.along.length, n);
  assert.equal(r.amber.length, n);
  assert.equal(r.warm.length, n);
  assert.equal(r.index.length, opts.filaments * (opts.segments - 1) * 2);
  for (const arr of [r.position, r.normal, r.along, r.amber, r.warm, r.dust.position]) {
    for (const v of arr) assert.ok(Number.isFinite(v));
  }
  for (const i of r.index) assert.ok(i < n);
});

test("index pairs never bridge two filaments", () => {
  const r = buildRing(opts);
  for (let k = 0; k < r.index.length; k += 2) {
    const a = r.index[k];
    const b = r.index[k + 1];
    assert.equal(b, a + 1);
    assert.equal(Math.floor(a / opts.segments), Math.floor(b / opts.segments));
  }
});

test("every point lies inside the torus volume and the centre stays open", () => {
  const r = buildRing(opts);
  const maxTube = TUBE_RADIUS * 1.2;
  for (let i = 0; i < r.vertCount; i++) {
    const x = r.position[i * 3];
    const y = r.position[i * 3 + 1];
    const z = r.position[i * 3 + 2];
    const planar = Math.hypot(x, z);
    const tube = Math.hypot(planar - MAJOR_RADIUS, y);
    assert.ok(tube <= maxTube, `point ${i} outside tube: ${tube}`);
    assert.ok(planar >= MAJOR_RADIUS - maxTube, `point ${i} in the hole`);
    assert.ok(Math.hypot(x, y, z) <= r.boundingRadius + 1e-6);
  }
});

test("amber and warmth stay in [0, 1]; some but not all strands carry amber", () => {
  const r = buildRing(opts);
  let lit = 0;
  for (const a of r.amber) {
    assert.ok(a >= 0 && a <= 1);
    if (a > 0.1) lit++;
  }
  assert.ok(lit > 0 && lit < r.vertCount * 0.5);
  for (let u = 0; u < 7; u += 0.37) for (let v = 0; v < 7; v += 0.41) {
    const w = warmth(u, v);
    assert.ok(w >= 0 && w <= 1);
  }
});

test("the same seed gives the same ring", () => {
  const a = buildRing(opts);
  const b = buildRing(opts);
  assert.deepEqual(a.position, b.position);
});
