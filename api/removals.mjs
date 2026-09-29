// motion-passport: exempt server module, no UI and no animation.
// Operator removals, applied once when the API starts, before any store is
// loaded, so nothing in memory still holds what goes.
//
//   accounts  an account whose record is marked owner (the one account from
//             the days the site sat behind a sign-in gate) is deleted: its
//             lines leave accounts.jsonl, its vault file and its inbox go,
//             its forum messages become markers with no author and no text,
//             bans it placed or received go, and records of the retired ah-dm
//             protocol that name it go. Its key sets stay in the key log: the
//             log is on the public witness record, and a shorter log is a
//             fork that every client and the witness refuse (keylog_fork).
//   posts     every forum message id listed in api/removed-posts.json becomes
//             a marker: its id, thread, author and time stay, its text goes.
//             The list sits in the public source, so each removal is on record.
//
// Files are rewritten whole (temporary file, fsync, rename), so the removed
// text or hash does not stay in the live file. Backups made before a removal
// still hold it.
// Journal: <dataDir>/removals-journal.jsonl, one line per start that removed
// something, counts only (no logins, ids or text).

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const MSG_ID = /^[0-9a-f]{24}$/;
const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// Calls fn on every line of a file, in 1 MB reads, so the size is never bound
// by the string limit. A last line without a newline is passed too.
function eachLine(file, fn) {
  const fd = fs.openSync(file, "r");
  const buf = Buffer.alloc(1 << 20);
  let rest = Buffer.alloc(0);
  try {
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      let chunk = Buffer.concat([rest, buf.subarray(0, n)]);
      let i;
      while ((i = chunk.indexOf(0x0a)) >= 0) {
        fn(chunk.subarray(0, i).toString("utf8"));
        chunk = chunk.subarray(i + 1);
      }
      rest = Buffer.from(chunk);
    }
  } finally {
    fs.closeSync(fd);
  }
  if (rest.length) fn(rest.toString("utf8"));
}

const parse = (line) => {
  try {
    return JSON.parse(line);
  } catch {
    return undefined; // a torn line: kept as it is
  }
};

// edit(rec) returns undefined (keep the line as it is), null (drop it) or a
// new record; it runs once per line. The file is replaced only when something
// changed. Returns the number of lines dropped or replaced.
export function rewriteJsonl(file, edit) {
  if (!fs.existsSync(file)) return 0;
  let changed = 0;
  const tmp = `${file}.${process.pid}.removals.tmp`;
  const fd = fs.openSync(tmp, "w", 0o600);
  try {
    eachLine(file, (line) => {
      const rec = line.trim() ? parse(line) : undefined;
      const out = rec === undefined ? undefined : edit(rec);
      if (out !== undefined) changed++;
      if (out === null) return;
      fs.writeSync(fd, `${out === undefined ? line : JSON.stringify(out)}\n`);
    });
    if (changed) fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  if (!changed) {
    fs.unlinkSync(tmp);
    return 0;
  }
  fs.renameSync(tmp, file);
  return changed;
}

// True when any string in the record, at any depth, equals one of the logins.
function names(rec, logins) {
  if (typeof rec === "string") return logins.has(rec);
  if (Array.isArray(rec)) return rec.some((v) => names(v, logins));
  if (rec && typeof rec === "object") return Object.values(rec).some((v) => names(v, logins));
  return false;
}

// The message ids in api/removed-posts.json: { "removed": [{ "id", "on" }] }.
export function readRemovedPosts(file = new URL("./removed-posts.json", import.meta.url)) {
  const doc = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(doc?.removed)) throw new Error("removed-posts.json: removed must be a list");
  return doc.removed.map((r) => {
    if (!MSG_ID.test(r?.id ?? "")) throw new Error("removed-posts.json: every entry needs a message id");
    return r.id;
  });
}

// posts: message ids to turn into markers. Returns the counts it journaled.
export function applyRemovals(dataDir, { posts = [], now = () => Date.now() } = {}) {
  const counts = { accounts: 0, accountLines: 0, vaults: 0, inbox: 0, forumMessages: 0, forumBans: 0, retired: 0, posts: 0 };

  // Owner-marked accounts: every login with a record marked owner.
  const accountsFile = path.join(dataDir, "accounts.jsonl");
  const gone = new Set();
  if (fs.existsSync(accountsFile)) {
    eachLine(accountsFile, (line) => {
      const rec = line.trim() ? parse(line) : undefined;
      if (rec?.owner && typeof rec.login === "string") gone.add(rec.login);
    });
  }
  if (gone.size) {
    counts.accounts = gone.size;
    counts.accountLines = rewriteJsonl(accountsFile, (r) => (gone.has(r?.login) ? null : undefined));
    const vaultDir = path.join(dataDir, "vault");
    for (const login of gone) {
      const hash = sha256hex(login);
      let files = [];
      try {
        files = fs.readdirSync(vaultDir).filter((f) => f === `${hash}.json` || (f.startsWith(`${hash}.json.`) && f.endsWith(".tmp")));
      } catch {
        // no vault directory
      }
      for (const f of files) {
        fs.unlinkSync(path.join(vaultDir, f));
        if (f === `${hash}.json`) counts.vaults++;
      }
    }
    counts.inbox = rewriteJsonl(path.join(dataDir, "inbox.jsonl"), (r) => (gone.has(r?.to) ? null : undefined));
    counts.retired = rewriteJsonl(path.join(dataDir, "dm.jsonl"), (r) => (names(r, gone) ? null : undefined));
  }

  const listed = new Set(posts);
  const forumFile = path.join(dataDir, "forum.jsonl");
  rewriteJsonl(forumFile, (r) => {
    if (r?.type === "ban" || r?.type === "unban") {
      if (gone.has(r.login) || gone.has(r.by)) {
        counts.forumBans++;
        return null;
      }
      return undefined;
    }
    if (typeof r?.id !== "string" || typeof r.thread !== "string") return undefined;
    if (gone.has(r.author)) {
      counts.forumMessages++;
      return { id: r.id, thread: r.thread, at: r.at, removed: true };
    }
    if (listed.has(r.id) && !r.removed) {
      counts.posts++;
      return { id: r.id, thread: r.thread, author: r.author, at: r.at, removed: true };
    }
    return undefined;
  });

  if (Object.values(counts).some((n) => n > 0)) {
    fs.appendFileSync(path.join(dataDir, "removals-journal.jsonl"), `${JSON.stringify({ at: new Date(now()).toISOString(), ...counts })}\n`, { mode: 0o600 });
  }
  return counts;
}
