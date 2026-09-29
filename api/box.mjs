// motion-passport: exempt server module, no UI and no animation.
// Private conversations without a member list on the server (protocol
// ah-box-1, specified in public/js/dm-crypto.js).
//
//   Boxes    a box is an id and the SHA-256 of its token. Whoever holds the
//            token posts and reads ciphertext. Box calls carry no session and
//            no address (nginx strips them), so the server does not know which
//            account a box belongs to, who its members are or who sent what.
//   Inbox    sealed invitations for an account. Anyone holding a ticket may
//            drop one; only the account reads its own inbox. The server learns
//            that an account received something, not from whom.
//   Tickets  blind tickets (api/tickets.mjs): one per new box and one per
//            invitation, spent without a session and unlinkable to the
//            account that took them.
//
// Stored times are cut to the minute, so the files carry no precise timing.
//
// Storage (AppendLog, append only):
//   <dataDir>/box.jsonl    boxes and their messages
//   <dataDir>/inbox.jsonl  invitations and their removal by the recipient

import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { AppendLog } from "./jsonl.mjs";

export const BOX = {
  ctMax: 16384,
  pageMax: 100,
  fileMax: 512 * 1024 * 1024,
  inboxFileMax: 128 * 1024 * 1024,
  // Unread invitations one account may hold before drops to it are refused.
  inboxPending: 200,
  inboxPage: 100,
  // A sealed invitation: 2048 padded bytes, its tag and nonce, in base64url.
  sealedCtMax: 2800,
};

const BOX_ID = /^[0-9a-f]{32}$/;
const DROP_ID = /^[0-9a-f]{24}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const LOGIN_LIKE = /^[a-z0-9-]{1,63}$/;

const canonical = (v) => Buffer.from(v, "base64url").toString("base64url") === v;
const isB64u = (v, len) => typeof v === "string" && v.length === len && B64U.test(v) && canonical(v);
const hashOf = (v) => createHash("sha256").update(v, "utf8").digest("base64url");
const minute = (now) => new Date(Math.floor(now / 60000) * 60000).toISOString();

export class Boxes {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.byId = new Map(); // id -> { th, messages: [] }
    this.log = new AppendLog(path.join(dataDir, "box.jsonl"), (r) => this.index(r));
  }

  index(r) {
    if (r?.t === "box" && typeof r.id === "string" && !this.byId.has(r.id)) this.byId.set(r.id, { th: r.th, messages: [] });
    else if (r?.t === "msg" && this.byId.has(r.box)) this.byId.get(r.box).messages.push(r);
  }

  full() {
    return this.log.size >= BOX.fileMax;
  }

  // body: { id, tokenHash }: the creator picks the id and sends only the
  // SHA-256 of the token, base64url.
  create(body, now = Date.now()) {
    const { id, tokenHash } = body || {};
    if (typeof id !== "string" || !BOX_ID.test(id) || !isB64u(tokenHash, 43)) return { ok: false, reason: "box_invalid" };
    if (this.byId.has(id)) return { ok: false, reason: "box_taken" };
    if (this.full()) return { ok: false, reason: "box_full" };
    const rec = { t: "box", id, th: tokenHash, at: minute(now) };
    this.log.append([rec]);
    this.index(rec);
    return { ok: true };
  }

  // The box, if the token opens it. An unknown id and a wrong token get the
  // same answer.
  open(id, token) {
    const b = typeof id === "string" && BOX_ID.test(id) ? this.byId.get(id) : undefined;
    if (!b || !isB64u(token, 43)) return null;
    const a = Buffer.from(hashOf(token));
    const w = Buffer.from(b.th);
    return a.length === w.length && timingSafeEqual(a, w) ? b : null;
  }

  post(b, id, body, now = Date.now()) {
    const { iv, ct } = body || {};
    if (!isB64u(iv, 16) || typeof ct !== "string" || !B64U.test(ct) || !canonical(ct)) return { ok: false, reason: "message_invalid" };
    if (ct.length > BOX.ctMax) return { ok: false, reason: "message_too_large" };
    if (this.full()) return { ok: false, reason: "box_full" };
    const rec = { t: "msg", box: id, n: b.messages.length, at: minute(now), iv, ct };
    this.log.append([rec]);
    this.index(rec);
    return { ok: true, n: rec.n, at: rec.at };
  }

  // Messages with n > after, oldest first.
  read(b, { after, limit } = {}) {
    const n = Math.min(Math.max(1, Number(limit) || BOX.pageMax), BOX.pageMax);
    const from = after === undefined || after === null ? 0 : Number(after) + 1;
    if (!Number.isSafeInteger(from) || from < 0) return { ok: false, reason: "cursor_unknown" };
    const slice = b.messages.slice(from, from + n);
    return { ok: true, size: b.messages.length, messages: slice.map(({ n: i, at, iv, ct }) => ({ n: i, at, iv, ct })), more: from + n < b.messages.length };
  }

  head(b) {
    const last = b.messages[b.messages.length - 1];
    return { ok: true, size: b.messages.length, lastAt: last ? last.at : null };
  }
}

export class Inbox {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.byLogin = new Map(); // login -> Map(id -> drop)
    this.log = new AppendLog(path.join(dataDir, "inbox.jsonl"), (r) => this.index(r));
  }

  index(r) {
    if (r?.t === "drop" && typeof r.to === "string") {
      if (!this.byLogin.has(r.to)) this.byLogin.set(r.to, new Map());
      this.byLogin.get(r.to).set(r.id, r);
    } else if (r?.t === "remove" && Array.isArray(r.ids)) {
      const box = this.byLogin.get(r.to);
      if (box) for (const id of r.ids) box.delete(id);
    }
  }

  pending(login) {
    return this.byLogin.get(login)?.size || 0;
  }

  // sealed: { epk, iv, ct } from dm-crypto.js sealInvite().
  drop(to, sealed, now = Date.now()) {
    if (typeof to !== "string" || !LOGIN_LIKE.test(to)) return { ok: false, reason: "invite_invalid" };
    const { epk, iv, ct } = sealed || {};
    if (!isB64u(epk, 43) || !isB64u(iv, 16) || typeof ct !== "string" || !B64U.test(ct) || !canonical(ct) || ct.length > BOX.sealedCtMax) return { ok: false, reason: "invite_invalid" };
    if (this.pending(to) >= BOX.inboxPending) return { ok: false, reason: "inbox_full" };
    if (this.log.size >= BOX.inboxFileMax) return { ok: false, reason: "box_full" };
    const rec = { t: "drop", id: randomBytes(12).toString("hex"), to, at: minute(now), sealed: { epk, iv, ct } };
    this.log.append([rec]);
    this.index(rec);
    return { ok: true };
  }

  // The account's invitations, oldest first, from after the drop id `after`.
  list(login, { after } = {}) {
    const all = [...(this.byLogin.get(login)?.values() || [])];
    let start = 0;
    if (after) {
      const i = all.findIndex((d) => d.id === after);
      if (i < 0) return { ok: false, reason: "cursor_unknown" };
      start = i + 1;
    }
    const slice = all.slice(start, start + BOX.inboxPage);
    return { ok: true, items: slice.map(({ id, at, sealed }) => ({ id, at, sealed })), more: start + BOX.inboxPage < all.length };
  }

  remove(login, ids) {
    if (!Array.isArray(ids) || !ids.length || ids.length > BOX.inboxPage || ids.some((id) => typeof id !== "string" || !DROP_ID.test(id))) return { ok: false, reason: "invite_invalid" };
    const mine = this.byLogin.get(login);
    const known = ids.filter((id) => mine?.has(id));
    if (!known.length) return { ok: true, removed: 0 };
    const rec = { t: "remove", to: login, ids: known };
    this.log.append([rec]);
    this.index(rec);
    return { ok: true, removed: known.length };
  }
}
