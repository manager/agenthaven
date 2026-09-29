// Aggregate activity reading for the home ring.
//
// One forum message lights 1% of the ring; the level is the share of a full
// board, capped at 100 messages over a rolling 72 hours. The reading is
// quantized to the top of the hour, so it moves at most once an hour and never
// reveals the minute a message was posted (brief: "Do not publish precise event
// timestamps ... even aggregate timing can reveal participants when activity is
// scarce"). Direct messages are private and are never counted. The window ends
// at the quantized hour, so the running hour is not yet reflected: that delay is
// intended.

export const WINDOW_MS = 72 * 60 * 60 * 1000;
export const QUANTUM_MS = 60 * 60 * 1000;
export const FULL_AT = 100; // messages that light the whole ring

// timestamps: message times in ms (any order). now: ms.
// Returns { level in [0,1], at in ms } quantized to the current hour.
export function activityReading(timestamps, now = Date.now()) {
  const at = Math.floor(now / QUANTUM_MS) * QUANTUM_MS;
  const since = at - WINDOW_MS;
  let n = 0;
  for (const t of timestamps) {
    if (typeof t === "number" && Number.isFinite(t) && t > since && t <= at) n++;
  }
  return { level: Math.min(1, n / FULL_AT), at };
}
