// Aggregate activity adapter for the ring.
// The scene only ever sees a brightness value. No feed is connected yet, so
// production stays at baseline; see "Ring activity contract" in CLAUDE.md.

export const BASELINE = 0.32;
export const CEILING = 1.0;
// Curve steepness: level 1 reaches ~95% of the range, detail stays readable.
const K = 3.0;
export const DEFAULT_MAX_AGE_MS = 15 * 60 * 1000;

// Map an aggregate level in [0, 1] to brightness in [BASELINE, CEILING].
// Bounded and monotonic: more activity never produces less light.
export function levelToBrightness(level) {
  const x = Math.min(1, Math.max(0, level));
  const span = (1 - Math.exp(-K * x)) / (1 - Math.exp(-K));
  return BASELINE + (CEILING - BASELINE) * span;
}

// Normalise a raw reading into an internal state.
//   { kind: "unknown" }                    missing, invalid or stale
//   { kind: "measured", level, at }        an approved aggregate reading
//   { kind: "fixture", level }             development only, never reported
export function toState(reading, now = Date.now(), maxAgeMs = DEFAULT_MAX_AGE_MS) {
  if (!reading || typeof reading !== "object") return { kind: "unknown" };
  const { level } = reading;
  if (typeof level !== "number" || !Number.isFinite(level) || level < 0 || level > 1) {
    return { kind: "unknown" };
  }
  if (reading.kind === "fixture") return { kind: "fixture", level };
  const at = reading.at;
  if (typeof at !== "number" || !Number.isFinite(at) || at > now || now - at > maxAgeMs) {
    return { kind: "unknown" };
  }
  return { kind: "measured", level, at };
}

export function brightnessFor(state) {
  if (!state || state.kind === "unknown") return BASELINE;
  return levelToBrightness(state.level);
}

// Development fixture from the page URL: ?fixture=0.6
export function fixtureFromSearch(search) {
  const raw = new URLSearchParams(search).get("fixture");
  if (raw === null || raw.trim() === "") return null;
  const level = Number(raw);
  return toState({ kind: "fixture", level });
}
