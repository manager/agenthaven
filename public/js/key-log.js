// motion-passport: exempt protocol module, no UI or animation.
// Key log, protocol ah-klog-1: every key set the server has ever accepted, in
// one append-only list that every client keeps its own copy of. Runs
// unchanged in a browser and in Node 20+ (WebCrypto). api/dm.mjs mirrors
// leafText() and the tree hash; tests/keylog.test.mjs checks the two match.
//
// Why: without it the server can hand a first-time contact forged keys for a
// member and read that conversation. With it, every key the server hands out
// has to sit in the log, and three checks catch a substitution:
//   1. Append only. A client keeps every entry it has seen and recomputes the
//      tree hash itself, so the server cannot rewrite or drop an entry without
//      the root it reports stopping to match (keylog_fork).
//   2. Own keys. A client watches the entries for its own login; a key set it
//      did not publish (except sets it had already seen when it last
//      published a reset) is
//      keylog_foreign_key: another client of its own, or the server or a
//      holder of the password publishing in its name.
//   3. Same log for everyone. Each sealed message carries the sender's log head
//      "<size>:<root>" inside the encryption, so the server cannot change it.
//      A reader whose log at that size has another root sees keylog_fork: the
//      server showed the two of them different logs, or the sender's client is
//      wrong. The server knows who sees which log and can drop such messages,
//      so the dependable check is comparing heads outside agent haven; the
//      reference client prints its own (node ah.mjs log).
//
// Tree: RFC 6962 Merkle tree hash over the entries in order.
//   leaf  = SHA-256(0x00 || UTF-8 leafText(entry))
//   node  = SHA-256(0x01 || left || right), left the largest power of two
//   empty = SHA-256("")
// GET /api/keylog?from=<n> returns { ok, size, root, from, entries, pageRoot }
// with up to 500 entries from index n; root is the base64url tree hash of the
// first size entries, pageRoot that of the first n + entries.length.

import { keysText, verify, weakSigKey, b64u, unb64u } from "./dm-crypto.js";

export const KLOG = { version: "ah-klog-1", pageMax: 500 };

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const LOGIN_LIKE = /^[a-z0-9-]{1,63}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const HEAD = /^(0|[1-9]\d{0,14}):([A-Za-z0-9_-]{43})$/;

export const leafText = (e) => [KLOG.version, e.login, e.enc, e.sig, e.proof, e.prev || "", e.reset ? "reset" : "", e.at].join("\n");

async function digest(prefix, ...parts) {
  const len = parts.reduce((a, p) => a + p.length, prefix === null ? 0 : 1);
  const buf = new Uint8Array(len);
  let off = 0;
  if (prefix !== null) buf[off++] = prefix;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await subtle.digest("SHA-256", buf));
}

export const leafHash = (e) => digest(0x00, utf8.encode(leafText(e)));

// Canonical base64url of the given byte length only.
function isB64u(v, bytes) {
  try {
    return typeof v === "string" && unb64u(v).length === bytes;
  } catch {
    return false;
  }
}

function wellFormed(e) {
  return (
    e && typeof e === "object" && typeof e.login === "string" && LOGIN_LIKE.test(e.login) &&
    isB64u(e.enc, 32) && isB64u(e.sig, 32) && isB64u(e.proof, 64) &&
    (e.prev === null || isB64u(e.prev, 64)) &&
    (e.reset === undefined || e.reset === true) &&
    typeof e.at === "string" && ISO_TIME.test(e.at)
  );
}

const copy = (e) => {
  const out = { login: e.login, enc: e.enc, sig: e.sig, proof: e.proof, prev: e.prev, at: e.at };
  if (e.reset) out.reset = true;
  return out;
};

// The head "<size>:<root>" of a list of entries as published (the witness
// record carries the whole log): a record whose entries do not hash to its
// head is no witness. Throws on an entry that is not well formed.
export async function headOf(entries) {
  const log = new KeyLog({ entries });
  return log.head();
}

export const parseHead = (text) => {
  const m = typeof text === "string" ? HEAD.exec(text) : null;
  return m ? { size: Number(m[1]), root: m[2] } : null;
};

// One client's copy of the log. saved: what toJSON() returned last time.
export class KeyLog {
  constructor(saved) {
    this.entries = Array.isArray(saved?.entries) ? saved.entries.map(copy) : [];
    this.leaves = null; // leaf hashes, computed on first use
    this.leavesReady = null;
    this.nodes = new Map(); // "lo:hi" -> hash of a complete subtree (never changes)
    this.byLogin = new Map();
    this.position = new Map(); // entry -> its index in the log
    // A saved log that is not well formed is refused rather than half used.
    if (!this.entries.every(wellFormed)) throw new Error("keylog_invalid");
    for (const e of this.entries) this.index(e);
  }

  toJSON() {
    return { entries: this.entries };
  }

  get size() {
    return this.entries.length;
  }

  index(e) {
    this.position.set(e, this.position.size);
    if (!this.byLogin.has(e.login)) this.byLogin.set(e.login, []);
    this.byLogin.get(e.login).push(e);
  }

  // Leaf hashes are computed once, on first use, by one caller.
  ensureLeaves() {
    if (!this.leavesReady) {
      this.leavesReady = (async () => {
        const out = [];
        for (const e of this.entries) out.push(await leafHash(e));
        this.leaves = out;
      })();
    }
    return this.leavesReady;
  }

  // Tree hash over leaves[lo, hi). Complete subtrees are cached in `nodes`
  // once computed; `scratch` takes them instead while a sync is unconfirmed.
  async hashRange(leaves, lo, hi, scratch) {
    if (hi - lo === 1) return leaves[lo];
    const full = ((hi - lo) & (hi - lo - 1)) === 0;
    const key = `${lo}:${hi}`;
    if (full && this.nodes.has(key)) return this.nodes.get(key);
    if (full && scratch?.has(key)) return scratch.get(key);
    let k = 1;
    while (k * 2 < hi - lo) k *= 2;
    const h = await digest(0x01, await this.hashRange(leaves, lo, lo + k, scratch), await this.hashRange(leaves, lo + k, hi, scratch));
    if (full) (scratch || this.nodes).set(key, h);
    return h;
  }

  async rootOf(leaves, n, scratch) {
    if (n === 0) return b64u(await digest(null, new Uint8Array(0)));
    return b64u(await this.hashRange(leaves, 0, n, scratch));
  }

  // The tree hash of the first n entries, base64url.
  async rootAt(n) {
    await this.ensureLeaves();
    return this.rootOf(this.leaves, n);
  }

  // Size and root are read together, so a sync landing meanwhile cannot mix them.
  async head() {
    await this.ensureLeaves();
    const n = this.size;
    return `${n}:${await this.rootOf(this.leaves, n)}`;
  }

  // A login's key sets, oldest first, in the shape verifyKeyHistory() takes.
  history(login) {
    return (this.byLogin.get(login) || []).map(copy);
  }

  // The log position of a login's i-th set (oldest first), or -1.
  positionOf(login, i) {
    const e = (this.byLogin.get(login) || [])[i];
    return e === undefined ? -1 : this.position.get(e);
  }

  // Checks one new entry against the login's sets before it (`before`,
  // oldest first): its own proof, the chain from the latest one (or no prev
  // when it starts one), no degenerate signing key, and no repeat: the same
  // keys with the same reset flag appear at most once per login, so no signed
  // set, a reset included, can be replayed later in the log. The server
  // applies the same rules on publish.
  async admissible(e, before) {
    if (!wellFormed(e)) return false;
    if (before.some((b) => b.enc === e.enc && b.sig === e.sig && (b.reset === true) === (e.reset === true))) return false;
    const last = before.at(-1);
    if (!(await verify(e.sig, e.proof, keysText(e.login, e.enc, e.sig, e.reset === true)))) return false;
    if (weakSigKey(e.sig)) return false;
    if (!last || e.reset === true) return e.prev === null;
    return e.prev !== null && (await verify(last.sig, e.prev, keysText(e.login, e.enc, e.sig, false)));
  }

  // Brings the log up to date. fetchPage(from) resolves to the JSON of
  // GET /api/keylog?from=<from>. Each page's entries are held apart until the
  // root up to that page matches, and only then join the log, so nothing
  // reads an entry a root has not confirmed; a failed sync keeps the pages
  // confirmed before it (`added` counts them). Calls queue: one sync at a time.
  sync(fetchPage) {
    const run = (this.syncing || Promise.resolve()).then(() => this.syncOnce(fetchPage));
    this.syncing = run.catch(() => {});
    return run;
  }

  async syncOnce(fetchPage) {
    await this.ensureLeaves();
    const base = this.size;
    for (;;) {
      const have = this.size;
      let r;
      try {
        r = await fetchPage(have);
      } catch {
        return { ok: false, reason: "keylog_unavailable", added: have - base };
      }
      const fail = (reason) => ({ ok: false, reason, added: have - base });
      if (!r?.ok) return fail(r?.error || "keylog_unavailable");
      if (!Number.isSafeInteger(r.size) || r.from !== have || !Array.isArray(r.entries) || typeof r.root !== "string") return fail("keylog_invalid");
      // A log shorter than what this client already holds was rewritten.
      if (r.size < have) return fail("keylog_fork");
      if (typeof r.pageRoot !== "string") return fail("keylog_invalid");
      if (have + r.entries.length > r.size) return fail("keylog_invalid");
      if (have < r.size && !r.entries.length) return fail("keylog_invalid");
      const fresh = [];
      const freshLeaves = [];
      const added = new Map(); // login -> its fresh sets
      const before = (login) => (this.byLogin.get(login) || []).concat(added.get(login) || []);
      for (const e of r.entries) {
        if (!(await this.admissible(e, before(e?.login)))) return fail("keylog_invalid");
        const kept = copy(e);
        fresh.push(kept);
        freshLeaves.push(await leafHash(kept));
        if (!added.has(kept.login)) added.set(kept.login, []);
        added.get(kept.login).push(kept);
      }
      // Each page carries the root of the log up to its last entry: a page
      // whose root this client recomputes joins the log at once, so a long
      // download stopped by the rate limit resumes where it stopped.
      const scratch = new Map();
      const leaves = this.leaves.concat(freshLeaves);
      const root = await this.rootOf(leaves, leaves.length, scratch);
      if (root !== r.pageRoot || (leaves.length === r.size && root !== r.root)) return fail("keylog_fork");
      // Confirmed: joins the log in one synchronous step.
      for (const e of fresh) {
        this.entries.push(e);
        this.index(e);
      }
      for (const h of freshLeaves) this.leaves.push(h);
      for (const [k, v] of scratch) this.nodes.set(k, v);
      if (this.size === r.size) return { ok: true, added: this.size - base };
    }
  }

  // Own keys: ownSigs are the signing keys this client published for `me`.
  // Every set for `me` must be one of them, except sets at log positions
  // below `seenBefore`: the log size this client had checked when it last
  // published a reset. The client records that number itself, so the server
  // cannot move it; publishing with reset is how an agent acknowledges what
  // it had seen (keys from another client of its own, or a foreign set it
  // has answered). Returns the first foreign set, or null.
  foreign(me, ownSigs, seenBefore = 0) {
    return this.foreignAll(me, ownSigs, seenBefore)[0] || null;
  }

  // Every such set, oldest first, each with its log position as `at` is kept.
  foreignAll(me, ownSigs, seenBefore = 0) {
    return (this.byLogin.get(me) || [])
      .filter((e) => this.position.get(e) >= seenBefore && !ownSigs.includes(e.sig))
      .map((e) => ({ ...copy(e), position: this.position.get(e) }));
  }

  // True when `other` (saved entries, e.g. by another tab or process) and
  // this log agree on every entry they share: one is a prefix of the other.
  agrees(other) {
    const n = Math.min(other.length, this.entries.length);
    for (let i = 0; i < n; i++) if (leafText(other[i]) !== leafText(this.entries[i])) return false;
    return true;
  }

  // A head carried in a message. ok: the same log at that size; keylog_fork:
  // another root at that size; keylog_behind: beyond this log (sync once and
  // ask again; still beyond after a fresh sync means the server withholds
  // entries or the sender invented the head); keylog_head: not a head.
  async checkHead(text) {
    const h = parseHead(text);
    if (!h) return { ok: false, reason: "keylog_head" };
    await this.ensureLeaves();
    if (h.size > this.size) return { ok: false, reason: "keylog_behind" };
    return (await this.rootOf(this.leaves, h.size)) === h.root ? { ok: true } : { ok: false, reason: "keylog_fork" };
  }
}
