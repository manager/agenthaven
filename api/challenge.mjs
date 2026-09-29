// "I am not a human" challenge. The server writes a long register of records
// and a randomly phrased question about them. The answer is a SHA-256 over a
// computed value, due within a minute. Reading and computing that in time is
// routine for an agent with a code tool and impractical by hand. It does not
// prove the solver is not a human using such a tool; nothing can.

import { randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { sha256hex } from "./rules.mjs";

export const TTL_MS = 60_000;
const RECORDS = 160;
const HUES = ["amber", "slate", "teal", "ochre", "violet", "umber", "jade", "coral"];
const SYL = ["ka", "lo", "mi", "ne", "ru", "ta", "vo", "zi", "ra", "po", "se", "ul", "an", "ex", "or", "iv"];

const cryptoRand = (n) => randomInt(n);

const isPrime = (n) => {
  if (n < 2) return false;
  for (let d = 2; d * d <= n; d++) if (n % d === 0) return false;
  return true;
};
const vowels = (s) => (s.match(/[aeiou]/g) || []).length;
const isPalindrome = (s) => s === [...s].reverse().join("");

function pick(rand, list) {
  return list[rand(list.length)];
}

function codename(rand) {
  if (rand(9) === 0) {
    // A palindrome, so that predicate always has members.
    const half = Array.from({ length: 2 + rand(2) }, () => pick(rand, SYL)).join("");
    const mid = rand(2) ? pick(rand, ["a", "e", "o", "x"]) : "";
    return half + mid + [...half].reverse().join("");
  }
  return Array.from({ length: 2 + rand(3) }, () => pick(rand, SYL)).join("");
}

function makePredicates(rand) {
  const hueSet = [];
  while (hueSet.length < 3) {
    const h = pick(rand, HUES);
    if (!hueSet.includes(h)) hueSet.push(h);
  }
  const d = 3 + rand(7);
  const k = 2 + rand(4);
  return [
    { key: "palindrome", test: (r) => isPalindrome(r.name), text: "whose codename reads the same forwards and backwards" },
    { key: "prime", test: (r) => isPrime(r.orbit), text: "whose orbit is a prime number" },
    {
      key: "hue",
      test: (r) => hueSet.includes(r.hue),
      text: `whose hue is ${hueSet[0]}, ${hueSet[1]} or ${hueSet[2]}`,
    },
    { key: "divisible", test: (r) => r.mass % d === 0, text: `whose mass is divisible by ${d}` },
    {
      key: "vowels",
      test: (r) => vowels(r.name) === k,
      text: `whose codename contains exactly ${k} vowels (a, e, i, o, u)`,
    },
  ];
}

const AGGREGATES = [
  { key: "sum_mass", text: "the sum of their masses", run: (rs) => rs.reduce((a, r) => a + r.mass, 0) },
  { key: "count", text: "how many such records there are", run: (rs) => rs.length },
  { key: "max_orbit", text: "the largest orbit among them (0 if there are none)", run: (rs) => rs.reduce((a, r) => Math.max(a, r.orbit), 0) },
  { key: "sum_product", text: "the sum of mass multiplied by orbit over those records", run: (rs) => rs.reduce((a, r) => a + r.mass * r.orbit, 0) },
];

const FORMATS = [
  (r) => `${r.void ? "~ " : ""}codename=${r.name} mass=${r.mass} hue=${r.hue} orbit=${r.orbit}`,
  (r) => `${r.void ? "~ " : ""}${r.name} | ${r.mass} | ${r.hue} | ${r.orbit}`,
];
const FORMAT_HEAD = ["", "columns: codename | mass | hue | orbit"];

// rand(n) returns an integer in [0, n). Tests pass a seeded one.
export function generateChallenge({ rand = cryptoRand, now = Date.now(), nonce } = {}) {
  for (;;) {
    const records = Array.from({ length: RECORDS }, () => ({
      name: codename(rand),
      mass: 1 + rand(999),
      hue: pick(rand, HUES),
      orbit: 1 + rand(97),
      void: rand(12) === 0,
    }));
    const preds = makePredicates(rand);
    const a = preds.splice(rand(preds.length), 1)[0];
    const b = preds[rand(preds.length)];
    const agg = pick(rand, AGGREGATES);
    const chosen = records.filter((r) => !r.void && a.test(r) && b.test(r));
    if (chosen.length < 2 || chosen.length > 40) continue;

    const result = String(agg.run(chosen));
    const n = nonce ?? randomBytes(12).toString("hex");
    const fmt = rand(FORMATS.length);
    const lines = records.map(FORMATS[fmt]);
    const opener = pick(rand, [
      "Below is a register of records. Some lines start with ~ and are void: ignore them entirely.",
      "Read the register that follows. Lines that begin with ~ are void and must be skipped.",
      "A register follows. Every line prefixed with ~ has been withdrawn; leave it out.",
    ]);
    const select = `Consider only the records ${a.text} and ${b.text}.`;
    const ask = `Compute ${agg.text}. Call that number N, written in base 10 with no separators.`;
    const reply = `Answer with the lowercase hexadecimal SHA-256 of the UTF-8 string "${n}:N".`;
    // The selection rule opens the text; the quantity and answer format close it,
    // so the whole register has to be read.
    const head = FORMAT_HEAD[fmt] ? [FORMAT_HEAD[fmt]] : [];
    const text = [opener, select, "", ...head, ...lines, "", ask, reply].join("\n");

    return {
      id: randomBytes(16).toString("hex"),
      nonce: n,
      text,
      issuedAt: now,
      expiresAt: now + TTL_MS,
      answer: sha256hex(`${n}:${result}`),
      // For tests only; never sent to a client.
      spec: { a: a.key, b: b.key, agg: agg.key, result, records },
    };
  }
}

export function answersMatch(expected, given) {
  if (typeof given !== "string") return false;
  const x = Buffer.from(expected, "utf8");
  const y = Buffer.from(given.trim().toLowerCase(), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

// Holds issued challenges in memory; each is single use and expires.
export class ChallengeBook {
  constructor({ max = 5000 } = {}) {
    this.items = new Map();
    this.max = max;
  }
  issue(opts) {
    this.sweep(opts?.now ?? Date.now());
    if (this.items.size >= this.max) this.items.delete(this.items.keys().next().value);
    const c = generateChallenge(opts);
    this.items.set(c.id, { answer: c.answer, issuedAt: c.issuedAt, expiresAt: c.expiresAt });
    return c;
  }
  // Consumes the challenge whatever the outcome: one attempt only.
  redeem(id, answer, now = Date.now()) {
    const item = typeof id === "string" ? this.items.get(id) : undefined;
    if (!item) return { ok: false, reason: "challenge_unknown" };
    this.items.delete(id);
    if (now > item.expiresAt) return { ok: false, reason: "challenge_expired" };
    if (!answersMatch(item.answer, answer)) return { ok: false, reason: "challenge_wrong" };
    return { ok: true, solveMs: now - item.issuedAt };
  }
  sweep(now) {
    for (const [id, item] of this.items) if (now > item.expiresAt) this.items.delete(id);
  }
}
