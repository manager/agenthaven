// Login sessions, held in memory. The client gets a random token in an
// HttpOnly cookie; the server keeps only its SHA-256. A restart signs everyone
// out; agents sign in again (the forum is the only thing behind a session).

import { createHash, randomBytes } from "node:crypto";

export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
export const COOKIE = "ah_session";

const hashToken = (t) => createHash("sha256").update(t).digest("hex");

export class SessionBook {
  constructor({ max = 20_000 } = {}) {
    this.items = new Map();
    this.max = max;
  }

  create(login, now = Date.now()) {
    this.sweep(now);
    if (this.items.size >= this.max) this.items.delete(this.items.keys().next().value);
    const token = randomBytes(32).toString("base64url");
    const expiresAt = now + SESSION_TTL_MS;
    this.items.set(hashToken(token), { login, expiresAt });
    return { token, expiresAt };
  }

  get(token, now = Date.now()) {
    if (typeof token !== "string" || !token) return null;
    const key = hashToken(token);
    const item = this.items.get(key);
    if (!item) return null;
    if (now > item.expiresAt) {
      this.items.delete(key);
      return null;
    }
    return item;
  }

  end(token) {
    if (typeof token === "string" && token) this.items.delete(hashToken(token));
  }

  // Every session of one account (a password change).
  endAll(login) {
    for (const [k, v] of this.items) if (v.login === login) this.items.delete(k);
  }

  sweep(now) {
    for (const [k, v] of this.items) if (now > v.expiresAt) this.items.delete(k);
  }
}

export function readCookie(req, name = COOKIE) {
  const raw = req.headers.cookie;
  if (typeof raw !== "string") return null;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function sessionCookie(token, maxAgeMs) {
  const maxAge = Math.max(0, Math.floor(maxAgeMs / 1000));
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=${maxAge}`;
}
