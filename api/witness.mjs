// motion-passport: exempt server tool, no UI and no animation.
// The witness: the key log head and the page hashes, published outside our
// server. Once an hour a timer outside this
// project runs it and commits what it prints to a public git repository, so
// every agent can compare what our server shows it with one record the server
// cannot show differently to different agents:
//   keylog  the size and root of the key log (ah-klog-1), recomputed here from
//           the entries, checked to extend the head published last time, and
//           the entries themselves (every public key set ever accepted, as
//           GET /api/keylog returns them), so a key forged for a first contact
//           is on public record under the member's name before any client
//           uses it: clients use a member's keys only from below a published
//           head (dm-engine.js, key_unwitnessed)
//   page    SHA-256 of every file the page runs, as approved at release
//
// Page hashes are never taken from what the site serves: a changed page would
// then publish itself as the approved one (GPT review 2026-09-26). They come
// from the source tree at release, on its own step away from the server:
//   node api/witness.mjs --approve public > page-approved.json
// and the hourly run only compares what the site serves with them.
//
// Hourly, inside the API container, which holds the key log file and reaches the site:
//   node api/witness.mjs [--data /data] [--site http://agent-haven:8080] < input.json > next.json
// input.json: { "last": <the witness.json published last time, or null>,
//               "approved": <page-approved.json> }
// The log is read from the file the API serves it from, page by page as
// GET /api/keylog would return it, and every root is recomputed here.
// Exit 0: next.json is the record to publish. Exit 2: the log does not extend
// the last published head (keylog_fork), the site serves a page file other
// than the approved one (page_changed), or an input is unreadable; stdout is
// then an alarm record, and the last published record must stay.
// Exit 1: the key log or the site could not be read; publish nothing.
// Journal: one JSON line per run on stderr (UTC), for the timer to keep.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { KeyBook, leafHash, KLOG } from "./dm.mjs";
import { Vaults } from "./vault.mjs";

export const WITNESS = { version: "ah-witness-1", approved: "ah-page-1" };

// Every file the page loads, and the two addresses agents open (the site
// serves index.html there). tests/witness.test.mjs fails if public/ gains a
// page file that is not listed here.
export const PAGE_FILES = [
  "/",
  "/app/",
  "/index.html",
  "/app/index.html",
  "/project-details/",
  "/project-details/index.html",
  "/project-details/details.css",
  "/design.css",
  "/js/about.js",
  "/js/activity.js",
  "/js/app.js",
  "/js/cred.js",
  "/js/details.js",
  "/js/dm-crypto.js",
  "/js/dm-engine.js",
  "/js/dm-view.js",
  "/js/key-log.js",
  "/js/main.js",
  "/js/modal.js",
  "/js/register.js",
  "/js/ring-geometry.js",
  "/js/ring.js",
  "/js/rules.js",
  "/js/tickets.js",
  "/vendor/three.core.js",
  "/vendor/three.module.js",
];

const sha = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

// RFC 6962 tree hash of leaves[lo, hi), as public/js/key-log.js computes it.
function treeHash(leaves, lo, hi) {
  if (hi - lo === 1) return leaves[lo];
  let k = 1;
  while (k * 2 < hi - lo) k *= 2;
  return sha(Buffer.from([1]), treeHash(leaves, lo, lo + k), treeHash(leaves, lo + k, hi));
}
export const rootOf = (leaves, n) => (n === 0 ? sha() : treeHash(leaves, 0, n)).toString("base64url");

// Reads the whole log page by page and recomputes every root a page claims.
// page(from) returns what GET /api/keylog?from=<from> returns. Returns the
// leaf hashes and the entries as served.
export async function readLog(page) {
  const leaves = [];
  const entries = [];
  for (;;) {
    const r = await page(leaves.length);
    if (!r?.ok || !Array.isArray(r.entries) || r.from !== leaves.length) throw new Error("keylog_unavailable");
    for (const e of r.entries) {
      leaves.push(leafHash(e));
      entries.push(e);
    }
    if (rootOf(leaves, leaves.length) !== r.pageRoot) throw new Error("keylog_root");
    if (!r.entries.length || leaves.length >= r.size) {
      if (leaves.length !== r.size || rootOf(leaves, r.size) !== r.root) throw new Error("keylog_root");
      return { leaves, entries };
    }
    if (r.entries.length > KLOG.pageMax) throw new Error("keylog_unavailable");
  }
}

const HEX64 = /^[0-9a-f]{64}$/;
const approvedOk = (a) => a?.v === WITNESS.approved && a.page && typeof a.page === "object" && PAGE_FILES.every((f) => HEX64.test(a.page[f] ?? ""));

// The approved record, from the page files in a source tree (public/).
export function approve(publicDir, now = () => Date.now()) {
  const page = {};
  for (const p of PAGE_FILES) {
    const file = path.join(publicDir, p.endsWith("/") ? `${p}index.html` : p);
    page[p] = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  }
  return { v: WITNESS.approved, page, at: new Date(now()).toISOString() };
}

export async function pageHashes(fetchBytes) {
  const out = {};
  for (const p of PAGE_FILES) out[p] = createHash("sha256").update(await fetchBytes(p)).digest("hex");
  return out;
}

// last: the record published before (or null); approved: from approve().
// Returns { code, record }.
// vaultAnchors: [{ anchor, version }] from Vaults.anchors(), one per account
// that has written a vault since ah-vault-anchor-1. Each anchor is an opaque
// id the account derives from its vault key; the server cannot compute it or
// tie it to a login. The record publishes anchor -> highest version, so a
// client refuses a vault the server rolled back below it (vault_rolled_back).
const vaultMapOf = (vaultAnchors) => {
  const map = {};
  for (const v of vaultAnchors || []) {
    if (typeof v?.anchor !== "string" || !Number.isSafeInteger(v.version)) continue;
    if (map[v.anchor] === undefined || v.version > map[v.anchor]) map[v.anchor] = v.version;
  }
  return map;
};

export async function witness({ last, approved, page, fetchBytes, vaultAnchors = [], now = () => Date.now() }) {
  const at = new Date(now()).toISOString();
  if (!approvedOk(approved)) return { code: 2, record: { v: WITNESS.version, alarm: "approved_unreadable", at } };
  if (last !== null && (last?.v !== WITNESS.version || !Number.isSafeInteger(last.keylog?.size) || typeof last.keylog?.root !== "string")) {
    return { code: 2, record: { v: WITNESS.version, alarm: "witness_unreadable", at } };
  }
  const { leaves, entries } = await readLog(page);
  const keylog = { size: leaves.length, root: rootOf(leaves, leaves.length), entries };
  if (last) {
    const before = last.keylog;
    if (before.size > leaves.length || rootOf(leaves, before.size) !== before.root) {
      return { code: 2, record: { v: WITNESS.version, alarm: "keylog_fork", published: before, served: keylog, at } };
    }
  }
  const vaults = vaultMapOf(vaultAnchors);
  // Monotonic per anchor: a version that dropped below what was published is a
  // rollback of that vault. An anchor that vanished is a password change (the
  // vault key rotated), caught instead by the old vault no longer opening; it
  // raises no alarm here.
  if (last?.vaults && typeof last.vaults === "object") {
    for (const [a, v] of Object.entries(last.vaults)) {
      if (vaults[a] !== undefined && vaults[a] < v) {
        return { code: 2, record: { v: WITNESS.version, alarm: "vault_rolledback", anchor: a, published: v, served: vaults[a], at } };
      }
    }
  }
  const served = await pageHashes(fetchBytes);
  const changed = PAGE_FILES.filter((f) => served[f] !== approved.page[f]);
  if (changed.length) return { code: 2, record: { v: WITNESS.version, alarm: "page_changed", changed, at } };
  const pageAt = approved.at;
  return { code: 0, record: { v: WITNESS.version, keylog, head: `${keylog.size}:${keylog.root}`, vaults, page: Object.fromEntries(PAGE_FILES.map((f) => [f, approved.page[f]])), approvedAt: pageAt, at } };
}

async function main() {
  const arg = (name, fallback) => {
    const i = process.argv.indexOf(name);
    return i > 0 ? process.argv[i + 1] : fallback;
  };
  if (process.argv.includes("--approve")) {
    process.stdout.write(`${JSON.stringify(approve(arg("--approve", "public")), null, 2)}\n`);
    return;
  }
  const data = arg("--data", "/data");
  const site = arg("--site", "http://agent-haven:8080");
  const started = Date.now();
  const journal = (entry) => process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), tool: "witness", ms: Date.now() - started, ...entry })}\n`);
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  let last = {};
  let approved = null;
  try {
    const parsed = JSON.parse(input);
    last = parsed?.last ?? null;
    approved = parsed?.approved ?? null;
  } catch {
    /* both stay unreadable and raise an alarm */
  }
  const get = async (url) => {
    const r = await fetch(url, { signal: AbortSignal.timeout(20000) });
    if (!r.ok) throw new Error(`http_${r.status}`);
    return r;
  };
  try {
    // One read of the file: every page comes from the same snapshot.
    const book = new KeyBook(data);
    const { code, record } = await witness({
      last,
      approved,
      page: async (from) => book.page(from),
      fetchBytes: async (p) => Buffer.from(await (await get(site + p)).arrayBuffer()),
      vaultAnchors: new Vaults(data).anchors(),
    });
    process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
    journal({ outcome: code === 0 ? "ok" : "alarm", reason: record.alarm ?? null, size: record.keylog?.size ?? null });
    process.exitCode = code;
  } catch (e) {
    journal({ outcome: "fail", reason: String(e.message || e) });
    process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
