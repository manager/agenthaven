// Procedural filament torus. Pure data, no Three.js, so it can be tested in Node.
// The ring lies in the XZ plane with its axis on Y. Every filament is a strand
// that winds helically around the tube for part of the ring's circumference.

export const MAJOR_RADIUS = 1.0;
export const TUBE_RADIUS = 0.36;

// Deterministic PRNG so the ring looks the same on every load.
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Low-frequency field over the torus surface in [0, 1]. Where it is high,
// rising activity spreads amber first, so light grows in regions rather than
// on single strands.
export function warmth(u, v) {
  const s =
    Math.sin(u * 2 + 0.7) * 0.5 +
    Math.sin(u * 3 - v * 1.0 + 1.9) * 0.3 +
    Math.cos(v * 2 + u + 0.4) * 0.2;
  return (s + 1) / 2;
}

export function buildRing({ filaments = 1800, segments = 120, dust = 6000, seed = 7 } = {}) {
  const rnd = mulberry32(seed);
  const vertCount = filaments * segments;

  const position = new Float32Array(vertCount * 3);
  const normal = new Float32Array(vertCount * 3);
  const along = new Float32Array(vertCount); // 0..1 along the filament
  const amber = new Float32Array(vertCount); // amber lit at baseline, 0..1
  const warm = new Float32Array(vertCount); // spread potential, 0..1
  const flicker = new Float32Array(vertCount); // per-filament phase
  const index = new Uint32Array(filaments * (segments - 1) * 2);

  let vi = 0;
  let ii = 0;
  const TAU = Math.PI * 2;

  for (let f = 0; f < filaments; f++) {
    const u0 = rnd() * TAU;
    const arc = 0.9 + rnd() * 2.4;
    const v0 = rnd() * TAU;
    // Most strands wind the same way; a few cross against the grain.
    const twist = (rnd() < 0.86 ? 1 : -1) * (1.4 + rnd() * 1.8);
    // Denser toward the outer skin of the tube, some strands inside the volume.
    const depth = 0.7 + 0.36 * Math.pow(rnd(), 0.55);
    const wobA = 0.04 + rnd() * 0.08;
    const wobF = 2 + rnd() * 5;
    const wobP = rnd() * TAU;
    const phase = rnd() * TAU;

    const hasAmber = rnd() < 0.24;
    const amberAt = rnd();
    const amberWidth = 0.05 + rnd() * 0.18;
    const amberPeak = 0.35 + rnd() * 0.65;

    const base = vi;
    for (let s = 0; s < segments; s++) {
      const t = s / (segments - 1);
      const u = u0 + arc * t;
      const v = v0 + twist * arc * t + Math.sin(t * wobF + wobP) * wobA * 3;
      const rho = TUBE_RADIUS * depth * (1 + Math.sin(t * wobF * 1.7 + wobP) * wobA);

      const cu = Math.cos(u);
      const su = Math.sin(u);
      const cv = Math.cos(v);
      const sv = Math.sin(v);

      // Tube-centre direction in the ring plane, then out along the tube.
      const nx = cu * cv;
      const ny = sv;
      const nz = su * cv;

      position[vi * 3] = MAJOR_RADIUS * cu + rho * nx;
      position[vi * 3 + 1] = rho * ny;
      position[vi * 3 + 2] = MAJOR_RADIUS * su + rho * nz;
      normal[vi * 3] = nx;
      normal[vi * 3 + 1] = ny;
      normal[vi * 3 + 2] = nz;

      along[vi] = t;
      const d = (t - amberAt) / amberWidth;
      amber[vi] = hasAmber ? amberPeak * Math.exp(-d * d) : 0;
      warm[vi] = warmth(u, v);
      flicker[vi] = phase;
      vi++;
    }
    for (let s = 0; s < segments - 1; s++) {
      index[ii++] = base + s;
      index[ii++] = base + s + 1;
    }
  }

  // Dust: fine specks sitting on the strands, as in the reference.
  const dustPosition = new Float32Array(dust * 3);
  const dustAmber = new Float32Array(dust);
  const dustPhase = new Float32Array(dust);
  const dustNormal = new Float32Array(dust * 3);
  for (let p = 0; p < dust; p++) {
    const src = Math.floor(rnd() * vertCount);
    for (let k = 0; k < 3; k++) {
      dustPosition[p * 3 + k] = position[src * 3 + k] + (rnd() - 0.5) * 0.004;
      dustNormal[p * 3 + k] = normal[src * 3 + k];
    }
    dustAmber[p] = amber[src] > 0.2 ? 1 : 0;
    dustPhase[p] = rnd() * TAU;
  }

  return {
    vertCount,
    position,
    normal,
    along,
    amber,
    warm,
    flicker,
    index,
    dust: { count: dust, position: dustPosition, normal: dustNormal, amber: dustAmber, phase: dustPhase },
    // Deepest strand: depth 1.06 x wobble 1.12 of the tube radius.
    boundingRadius: MAJOR_RADIUS + TUBE_RADIUS * 1.19,
  };
}
