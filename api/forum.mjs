// Forum.
//   message: 1-280 characters (Unicode code points, NFC), newlines allowed
//   thread:  opened with 1-8 messages; anyone signed in can add more
//   in a row: one author may have at most 8 consecutive messages in a thread;
//            after that another author has to speak first
//   bans:    the thread's owner (author of its first message) may ban any other
//            account from posting in that thread, and lift the ban. Messages already posted stay.
//   removed: a message the operator removed (api/removals.mjs) stays as a
//            marker { id, author, at, removed: true } with text null; a deleted
//            account's markers carry author null too.
// This is an open area: every signed-in account and the server operator can
// read it. It is not the private messaging the brief describes.
//
// Storage: <dataDir>/forum.jsonl through AppendLog (jsonl.mjs), one JSON line
// per message, append only.
// A thread is the set of messages sharing a thread id; its first message opens it.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { AppendLog } from "./jsonl.mjs";

export const FORUM = {
  messageMax: 280,
  batchMax: 8,
  inARowMax: 8,
  linesMax: 12,
  marksInARowMax: 3,
  pageMax: 100,
  threadsPageMax: 50,
  // Writes stop past this size, so the file can always be loaded again.
  fileMax: 256 * 1024 * 1024,
};

// Control characters other than newline and tab, line and paragraph
// separators, and bidirectional overrides are refused.
const BAD_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
// Nothing visible: whitespace and format characters (zero-width and the like).
// Nothing visible: whitespace, format characters, marks with no base, and the
// blank-looking letters and symbols (Hangul fillers, braille blank).
const INVISIBLE = /^[\s\p{Cf}\p{M}\u115f\u1160\u3164\uffa0\u2800]*$/u;
const FORMAT = /\p{Cf}/gu;
const MARK_RUN = new RegExp(`\\p{M}{${FORUM.marksInARowMax + 1},}`, "u");

// Validates a batch of messages; returns normalised texts or an error code.
export function checkMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return { ok: false, reason: "messages_missing" };
  if (messages.length > FORUM.batchMax) return { ok: false, reason: "messages_too_many" };
  const texts = [];
  for (const m of messages) {
    if (typeof m !== "string") return { ok: false, reason: "message_not_string" };
    const text = m.replace(/\r\n/g, "\n").normalize("NFC");
    if (INVISIBLE.test(text)) return { ok: false, reason: "message_empty" };
    if ([...text].length > FORUM.messageMax) return { ok: false, reason: "message_too_long" };
    if (BAD_CHARS.test(text)) return { ok: false, reason: "message_charset" };
    if (text.split("\n").length > FORUM.linesMax) return { ok: false, reason: "message_lines" };
    // Format characters between marks do not break a run of marks.
    if (MARK_RUN.test(text.replace(FORMAT, ""))) return { ok: false, reason: "message_marks" };
    texts.push(text);
  }
  return { ok: true, texts };
}

const newId = () => randomBytes(12).toString("hex");
const LOGIN_LIKE = /^[a-z0-9-]{1,63}$/;

export class Forum {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = path.join(dataDir, "forum.jsonl");
    this.threads = new Map(); // id -> { id, messages: [], bans: Set of logins }
    this.log = new AppendLog(this.file, (rec) => this.index(rec));
  }

  get size() {
    return this.log.size;
  }

  // Two kinds of line: messages (no type) and ban changes (type ban or unban).
  index(rec) {
    if (!rec || typeof rec.thread !== "string") return;
    if (rec.type === "ban" || rec.type === "unban") {
      const t = this.threads.get(rec.thread);
      if (!t || typeof rec.login !== "string") return;
      if (rec.type === "ban") t.bans.add(rec.login);
      else t.bans.delete(rec.login);
      return;
    }
    if (typeof rec.id !== "string") return;
    let t = this.threads.get(rec.thread);
    if (!t) {
      t = { id: rec.thread, messages: [], bans: new Set() };
      this.threads.set(rec.thread, t);
    }
    t.messages.push(rec);
  }

  // The owner is the author of the thread's first message (null once that
  // author's account was deleted).
  owner(t) {
    return t.messages[0].author ?? null;
  }

  // Bans (lift false) or lets back (lift true) `login` in a thread. Only the
  // owner may; exists(login) says whether the account exists.
  ban(threadId, by, login, { lift = false, exists = () => true, now = Date.now() } = {}) {
    const t = typeof threadId === "string" ? this.threads.get(threadId) : undefined;
    if (!t) return { ok: false, reason: "thread_unknown" };
    if (this.owner(t) !== by) return { ok: false, reason: "not_thread_owner" };
    if (typeof login !== "string" || !LOGIN_LIKE.test(login)) return { ok: false, reason: "ban_invalid" };
    if (login === by) return { ok: false, reason: "ban_self" };
    if (!exists(login)) return { ok: false, reason: "ban_unknown" };
    if (t.bans.has(login) !== lift) return { ok: true, unchanged: true, banned: [...t.bans].sort() };
    // A full forum still lets an owner lift a ban.
    if (!lift && this.full()) return { ok: false, reason: "forum_full" };
    this.log.append([{ type: lift ? "unban" : "ban", thread: t.id, login, by, at: new Date(now).toISOString() }]);
    if (lift) t.bans.delete(login);
    else t.bans.add(login);
    return { ok: true, banned: [...t.bans].sort() };
  }

  // Consecutive messages by the same author at the end of a thread.
  inARow(thread, author) {
    let n = 0;
    for (let i = thread.messages.length - 1; i >= 0 && thread.messages[i].author === author; i--) n++;
    return n;
  }

  full() {
    return this.size >= FORUM.fileMax;
  }

  // Who posted when, for the aggregate ring reading: { who: login, t: ms }.
  // Bans are not posts; a marker with no author counts for nobody.
  posts() {
    const out = [];
    for (const t of this.threads.values()) {
      for (const m of t.messages) if (typeof m.author === "string") out.push({ who: m.author, t: Date.parse(m.at) });
    }
    return out;
  }

  write(recs) {
    this.log.append(recs);
    for (const r of recs) this.index(r);
  }

  records(threadId, author, texts, now) {
    const at = new Date(now).toISOString();
    return texts.map((text) => ({ id: newId(), thread: threadId, author, text, at }));
  }

  open(author, texts, now = Date.now()) {
    if (this.full()) return { ok: false, reason: "forum_full" };
    const id = newId();
    this.write(this.records(id, author, texts, now));
    return { ok: true, thread: this.threads.get(id) };
  }

  add(threadId, author, texts, now = Date.now()) {
    const t = typeof threadId === "string" ? this.threads.get(threadId) : undefined;
    if (!t) return { ok: false, reason: "thread_unknown" };
    if (t.bans.has(author)) return { ok: false, reason: "thread_banned" };
    if (this.full()) return { ok: false, reason: "forum_full" };
    if (this.inARow(t, author) + texts.length > FORUM.inARowMax) return { ok: false, reason: "thread_in_a_row" };
    const recs = this.records(t.id, author, texts, now);
    this.write(recs);
    return { ok: true, thread: t, added: recs };
  }

  // Threads by latest activity, newest first, ties by id. The cursor is the
  // `next` value of the previous page ("<lastAt>~<thread id>").
  list({ cursor, limit = FORUM.threadsPageMax } = {}) {
    const n = Math.min(Math.max(1, Number(limit) || FORUM.threadsPageMax), FORUM.threadsPageMax);
    let after = null;
    if (cursor) {
      const m = /^(.+)~([0-9a-f]{24})$/.exec(cursor);
      if (!m) return { ok: false, reason: "cursor_unknown" };
      after = { last: m[1], id: m[2] };
    }
    const key = (x) => `${x.last}~${x.t.id}`;
    const all = [...this.threads.values()]
      .map((t) => ({ t, last: t.messages[t.messages.length - 1].at }))
      .filter((x) => !after || key(x) < `${after.last}~${after.id}`)
      .sort((a, b) => (key(a) < key(b) ? 1 : key(a) > key(b) ? -1 : 0));
    const slice = all.slice(0, n);
    const page = slice.map(({ t, last }) => ({
      id: t.id,
      first: publicMessage(t.messages[0]),
      count: t.messages.length,
      lastAt: last,
    }));
    const more = all.length > n;
    return { ok: true, threads: page, more, next: more ? key(slice[slice.length - 1]) : null };
  }

  // One page of a thread in order. `after` is a message id cursor.
  read(threadId, { after, limit = FORUM.pageMax } = {}) {
    const t = typeof threadId === "string" ? this.threads.get(threadId) : undefined;
    if (!t) return { ok: false, reason: "thread_unknown" };
    const n = Math.min(Math.max(1, Number(limit) || FORUM.pageMax), FORUM.pageMax);
    let start = 0;
    if (after) {
      const i = t.messages.findIndex((m) => m.id === after);
      if (i < 0) return { ok: false, reason: "cursor_unknown" };
      start = i + 1;
    }
    const slice = t.messages.slice(start, start + n);
    return { ok: true, id: t.id, owner: this.owner(t), banned: [...t.bans].sort(), messages: slice.map(publicMessage), more: start + n < t.messages.length };
  }
}

export function publicMessage(m) {
  if (m.removed) return { id: m.id, author: m.author ?? null, text: null, at: m.at, removed: true };
  return { id: m.id, author: m.author, text: m.text, at: m.at };
}
