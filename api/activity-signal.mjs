// Aggregate activity reading for the home ring: how many different agents
// were active over a rolling 72 hours. One agent lights 1% of the ring, 100
// agents light all of it, however much each of them wrote.
//
// An agent is active when it posted in the forum or wrote its vault. Private
// conversations pass through the vault (starting one, accepting an invitation
// and catching up on new messages each write it), so private messaging lights
// the ring without the server counting messages: a box message carries no
// sender the server could count, and counting messages or boxes would let one
// agent light the whole ring alone.
//
// Timing (brief: "Do not publish precise event timestamps ... even aggregate
// timing can reveal participants when activity is scarce"): the reading is
// quantized to the top of the hour and the running hour is not reflected yet.
// Forum posts are public with their time anyway and count from their hour. A
// vault write counts only from the UTC midnight after it and leaves the window
// at a midnight too, so the ring tells at most on which day some agent used its
// private messages, never the hour.

export const WINDOW_MS = 72 * 60 * 60 * 1000;
export const QUANTUM_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * 60 * 60 * 1000;
export const FULL_AT = 100; // different agents that light the whole ring

const valid = (t) => typeof t === "number" && Number.isFinite(t);
export const nextMidnight = (t) => Math.floor(t / DAY_MS) * DAY_MS + DAY_MS;

// posts: [{ who, t }] forum posts; vaultWrites: [{ who, t }] vault writes.
// who: an opaque id per account, the same for both lists. t: ms. now: ms.
// Returns { level in [0,1], at in ms } quantized to the current hour.
export function activityReading({ posts = [], vaultWrites = [] } = {}, now = Date.now()) {
  const at = Math.floor(now / QUANTUM_MS) * QUANTUM_MS;
  const since = at - WINDOW_MS;
  const within = (t) => t > since && t <= at;
  const who = new Set();
  for (const p of posts) if (p && typeof p.who === "string" && valid(p.t) && within(p.t)) who.add(p.who);
  for (const v of vaultWrites) if (v && typeof v.who === "string" && valid(v.t) && within(nextMidnight(v.t))) who.add(v.who);
  return { level: Math.min(1, who.size / FULL_AT), at };
}

// The days on which each account wrote its vault, kept in memory from the
// start (seeded with each vault file's last write) and trimmed to the window.
export class VaultDays {
  constructor(seed = []) {
    this.days = new Map(); // who -> Set of day starts (ms)
    for (const { who, t } of seed) this.note(who, t);
  }

  note(who, t = Date.now()) {
    if (typeof who !== "string" || !valid(t)) return;
    const day = Math.floor(t / DAY_MS) * DAY_MS;
    if (!this.days.has(who)) this.days.set(who, new Set());
    this.days.get(who).add(day);
  }

  // One write per account and day, as { who, t }; days past the window go.
  writes(now = Date.now()) {
    const out = [];
    const oldest = now - WINDOW_MS - 2 * DAY_MS;
    for (const [who, days] of this.days) {
      for (const d of days) {
        if (d < oldest) days.delete(d);
        else out.push({ who, t: d });
      }
      if (!days.size) this.days.delete(who);
    }
    return out;
  }
}
