// motion-passport: exempt server module, no UI and no animation.
// Published keys and the key log.
// Each account publishes an X25519 and an Ed25519 public key, signed by
// itself; members take each other's keys from the key log (ah-klog-1,
// public/js/key-log.js), which the server cannot rewrite without clients
// noticing. The conversations themselves live in api/box.mjs (ah-box-1).
//
// Storage (AppendLog, append only):
//   <dataDir>/keys.jsonl  published key sets, one line per set
// dm.jsonl, the conversations of the retired ah-dm protocol, stays in the
// data volume untouched and is no longer read.

import fs from "node:fs";
import path from "node:path";
import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, verify as edVerify } from "node:crypto";
import { AppendLog } from "./jsonl.mjs";

export const DMS = {
  keysVersion: "ah-keys-1",
};

const B64U = /^[A-Za-z0-9_-]+$/;
const KEY_LEN = 43; // 32 bytes
const SIG_LEN = 86; // 64 bytes

// Must match public/js/dm-crypto.js (tests/dm.test.mjs checks both).
export const keysText = (login, enc, sig, reset = false) => `${DMS.keysVersion}\n${login}\n${enc}\n${sig}${reset ? "\nreset" : ""}`;
// Key log ah-klog-1, specified in public/js/key-log.js: every accepted key set
// in order, under an RFC 6962 tree hash that clients recompute themselves.
export const KLOG = { version: "ah-klog-1", pageMax: 500 };
export const leafText = (e) => [KLOG.version, e.login, e.enc, e.sig, e.proof, e.prev || "", e.reset ? "reset" : "", e.at].join("\n");
const sha = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
export const leafHash = (e) => sha(Buffer.from([0]), Buffer.from(leafText(e), "utf8"));

function edCheck(sigPublic, signature, text) {
  try {
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: sigPublic }, format: "jwk" });
    return edVerify(null, Buffer.from(text, "utf8"), key, Buffer.from(signature, "base64url"));
  } catch {
    return false;
  }
}

// A small-order Ed25519 key lets anyone forge its signatures: refuse every
// encoding whose y is one of the 8 small-order points' (0, 1, p-1, Y8, p-Y8)
// or is not canonical (>= p). Same list as public/js/dm-crypto.js.
const P = (1n << 255n) - 19n;
const Y8 = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n;
const SMALL_Y = new Set([0n, 1n, P - 1n, Y8, P - Y8]);
export function weakSigKey(sig) {
  const bytes = Buffer.from(String(sig), "base64url");
  if (bytes.length !== 32) return true;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  return y >= P || SMALL_Y.has(y);
}

// A low-order X25519 key gives an all-zero shared secret, which WebCrypto
// refuses, so nobody could send to its owner's conversations; refuse it.
export function weakEncKey(enc) {
  try {
    const pub = createPublicKey({ key: { kty: "OKP", crv: "X25519", x: enc }, format: "jwk" });
    const secret = diffieHellman({ privateKey: generateKeyPairSync("x25519").privateKey, publicKey: pub });
    return secret.every((b) => b === 0);
  } catch {
    return true;
  }
}

// Canonical base64url only, so one value never has two spellings.
const canonical = (v) => Buffer.from(v, "base64url").toString("base64url") === v;
const isB64u = (v, len) => typeof v === "string" && v.length === len && B64U.test(v) && canonical(v);

export class KeyBook {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.byLogin = new Map(); // login -> [sets], oldest first
    this.all = []; // every set in publication order: the key log
    this.leaves = [];
    this.nodes = new Map(); // "lo:hi" -> hash of a complete subtree
    this.log = new AppendLog(path.join(dataDir, "keys.jsonl"), (r) => this.index(r));
  }

  index(r) {
    if (!r || typeof r.login !== "string") return;
    if (!this.byLogin.has(r.login)) this.byLogin.set(r.login, []);
    this.byLogin.get(r.login).push(r);
    this.all.push(r);
    this.leaves.push(leafHash(r));
  }

  hashRange(lo, hi) {
    if (hi - lo === 1) return this.leaves[lo];
    const full = ((hi - lo) & (hi - lo - 1)) === 0;
    const key = `${lo}:${hi}`;
    if (full && this.nodes.has(key)) return this.nodes.get(key);
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    const h = sha(Buffer.from([1]), this.hashRange(lo, lo + k), this.hashRange(lo + k, hi));
    if (full) this.nodes.set(key, h);
    return h;
  }

  // Sets that repeat an earlier one (same login, keys and reset flag); clients refuse a log with any.
  repeats() {
    const seen = new Set();
    let n = 0;
    for (const r of this.all) {
      const k = `${r.login}\n${r.enc}\n${r.sig}\n${r.reset === true}`;
      if (seen.has(k)) n++;
      seen.add(k);
    }
    return n;
  }

  // The tree hash of the first n sets, base64url.
  rootAt(n) {
    return (n === 0 ? sha() : this.hashRange(0, n)).toString("base64url");
  }

  // GET /api/keylog?from=<n>: up to pageMax sets from index n, with the head
  // of the whole log as it stands.
  page(from) {
    const size = this.all.length;
    if (!Number.isSafeInteger(from) || from < 0 || from > size) return { ok: false, reason: "keylog_range" };
    const entries = this.all.slice(from, from + KLOG.pageMax).map((r) => ({ login: r.login, ...publicSet(r) }));
    // pageRoot: the root up to this page's last entry, so a client keeps each page it checked.
    return { ok: true, size, root: this.rootAt(size), from, entries, pageRoot: this.rootAt(from + entries.length) };
  }

  history(login) {
    return this.byLogin.get(login) || [];
  }

  current(login) {
    const h = this.history(login);
    return h.length ? h[h.length - 1] : null;
  }

  // body: { enc, sig, proof, prev } as made by keysPublication().
  // reset: the owner lost the previous keys and starts a new chain (prev null).
  publish(login, body, now = Date.now()) {
    const { enc, sig, proof, prev } = body || {};
    const reset = body?.reset === true;
    if (body?.reset !== undefined && typeof body.reset !== "boolean") return { ok: false, reason: "keys_invalid" };
    if (!isB64u(enc, KEY_LEN) || !isB64u(sig, KEY_LEN) || !isB64u(proof, SIG_LEN)) return { ok: false, reason: "keys_invalid" };
    if (prev != null && !isB64u(prev, SIG_LEN)) return { ok: false, reason: "keys_invalid" };
    const text = keysText(login, enc, sig, reset);
    if (!edCheck(sig, proof, text)) return { ok: false, reason: "keys_proof" };
    if (weakSigKey(sig) || weakEncKey(enc)) return { ok: false, reason: "keys_weak" };
    const cur = this.current(login);
    // The same keys again are a no-op, unless flagged reset: that starts a new
    // chain on the same keys, how an owner answers sets published in its name.
    if (cur && cur.enc === enc && cur.sig === sig && !reset) return { ok: true, unchanged: true, set: cur };
    // The same keys with the same reset flag go in the log once per login, so
    // a signed set cannot be replayed later (clients refuse a repeat too).
    if (this.history(login).some((h) => h.enc === enc && h.sig === sig && (h.reset === true) === reset)) return { ok: false, reason: "keys_repeat" };
    // A replacement must be signed by the set it replaces; a first set must not claim one.
    const chained = cur && !reset ? Boolean(prev && edCheck(cur.sig, prev, text)) : prev == null;
    if (!chained) return { ok: false, reason: "keys_chain" };
    const rec = { login, enc, sig, proof, prev: prev ?? null, at: new Date(now).toISOString() };
    // Stored as signed: the flag is part of the proof's text.
    if (reset) rec.reset = true;
    this.log.append([rec]);
    this.index(rec);
    return { ok: true, set: rec };
  }
}

export function publicSet(r) {
  const out = { enc: r.enc, sig: r.sig, proof: r.proof, prev: r.prev, at: r.at };
  if (r.reset) out.reset = true;
  return out;
}

