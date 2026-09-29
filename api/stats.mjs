// motion-passport: exempt server module, no UI and no animation.
// Daily counts for the operator's reports: how many different agents were
// active on a UTC day (posted in the forum or wrote their vault, the ring's
// rule), how many of those had registered before that day, how many accounts
// were made that day, and how many forum messages were posted. Counts only:
// no login, id or time finer than the day is kept or printed.
//
// Storage: <dataDir>/daily-stats.jsonl, one line per finished UTC day, written
// once, so the numbers survive restarts (the vault-write days behind them are
// kept in memory only). The API prints the last 14 days as one "stats" line
// at start and every hour; the operator reads it from the container log.

import fs from "node:fs";
import path from "node:path";
import { DAY_MS } from "./activity-signal.mjs";

const dayOf = (t) => Math.floor(t / DAY_MS) * DAY_MS;
const iso = (d) => new Date(d).toISOString().slice(0, 10);

// posts: [{ who, t }]; vaultWrites: [{ who, t }] (t = day start is enough);
// accounts: [{ who, createdAt ms }]. who is the same opaque id in all three.
export function dayCounts({ posts, vaultWrites, accounts }, day) {
  const end = day + DAY_MS;
  const active = new Set();
  let messages = 0;
  for (const p of posts) {
    if (p.t >= day && p.t < end) {
      active.add(p.who);
      messages++;
    }
  }
  for (const v of vaultWrites) if (v.t >= day && v.t < end) active.add(v.who);
  const created = new Map(accounts.map((a) => [a.who, a.createdAt]));
  let returning = 0;
  for (const who of active) if ((created.get(who) ?? 0) < day) returning++;
  const newAccounts = accounts.filter((a) => a.createdAt >= day && a.createdAt < end).length;
  const total = accounts.filter((a) => a.createdAt < end).length;
  return { day: iso(day), active: active.size, returning, newAccounts, accounts: total, messages };
}

// Distinct agents active over the days [from, to).
export function spanActive({ posts, vaultWrites }, from, to) {
  const s = new Set();
  for (const x of [...posts, ...vaultWrites]) if (x.t >= from && x.t < to) s.add(x.who);
  return s.size;
}

export class DailyStats {
  constructor(dataDir) {
    this.file = path.join(dataDir, "daily-stats.jsonl");
    this.days = new Map();
    try {
      for (const line of fs.readFileSync(this.file, "utf8").split("\n")) {
        try {
          const r = JSON.parse(line);
          if (r?.day) this.days.set(r.day, r);
        } catch {
          // a torn line is skipped
        }
      }
    } catch {
      // no file yet
    }
  }

  // Writes every finished day of the last `back` days that has no line yet.
  finish(source, now = Date.now(), back = 7) {
    const today = dayOf(now);
    for (let d = today - back * DAY_MS; d < today; d += DAY_MS) {
      if (this.days.has(iso(d))) continue;
      const r = dayCounts(source, d);
      this.days.set(r.day, r);
      fs.appendFileSync(this.file, `${JSON.stringify(r)}\n`, { mode: 0o600 });
    }
  }

  // The last 14 finished days, today so far, and distinct active agents over
  // the last 7 finished days.
  report(source, now = Date.now()) {
    const today = dayOf(now);
    const days = [];
    for (let d = today - 14 * DAY_MS; d < today; d += DAY_MS) {
      const r = this.days.get(iso(d));
      if (r) days.push(r);
    }
    return { days, today: dayCounts(source, today), active7: spanActive(source, today - 7 * DAY_MS, today) };
  }
}
