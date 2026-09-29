// Account store: one JSON line per account in <dataDir>/accounts.jsonl; a later
// line for the same login replaces the earlier one (an upgrade).
// Accounts made since ah-cred-1 (public/js/cred.js) keep a scrypt hash of the
// auth key the agent derives from its password; the server never receives the
// password itself. Older accounts keep a scrypt hash of the password until
// their first sign-in with an auth key moves them over (cred: "ah-cred-1").

import fs from "node:fs";
import path from "node:path";
import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { CEILINGS } from "./rules.mjs";

const scrypt = promisify(scryptCb);
export const SCRYPT = { N: 32768, r: 8, p: 1, keylen: 64, maxmem: 96 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT.maxmem });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(password, stored) {
  const [kind, N, r, p, salt, key] = String(stored).split("$");
  if (kind !== "scrypt") return false;
  const want = Buffer.from(key, "base64");
  const got = await scrypt(password, Buffer.from(salt, "base64"), want.length, {
    N: Number(N),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT.maxmem,
  });
  return timingSafeEqual(want, got);
}

export class AccountStore {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.file = path.join(dataDir, "accounts.jsonl");
    this.byLogin = new Map();
    if (fs.existsSync(this.file)) {
      for (const line of fs.readFileSync(this.file, "utf8").split("\n")) {
        if (!line.trim()) continue;
        try {
          const rec = JSON.parse(line);
          if (rec.login) this.byLogin.set(rec.login, rec);
        } catch {
          // A torn last line from a crash is skipped, never rewritten.
        }
      }
    }
    // Serialises writes so two registrations for one login cannot both land.
    this.pending = new Set();
  }

  has(login) {
    return this.byLogin.has(login) || this.pending.has(login);
  }

  get size() {
    return this.byLogin.size;
  }

  get(login) {
    return this.byLogin.get(login) || null;
  }

  write(rec) {
    const fd = fs.openSync(this.file, "a", 0o600);
    try {
      fs.writeSync(fd, JSON.stringify(rec) + "\n");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    this.byLogin.set(rec.login, rec);
  }

  // secret: the auth key (ah-cred-1). extra: fields stored beside the hash,
  // e.g. the owner marker. Never the password.
  async create(login, secret, extra = {}) {
    if (this.has(login)) return { ok: false, reason: "login_taken" };
    // The ceiling counts registrations still hashing, so a burst cannot pass it.
    if (this.byLogin.size + this.pending.size >= CEILINGS.accounts) return { ok: false, reason: "accounts_full" };
    this.pending.add(login);
    try {
      this.write({ login, hash: await hashPassword(secret), cred: "ah-cred-1", createdAt: new Date().toISOString(), ...extra });
      return { ok: true };
    } finally {
      this.pending.delete(login);
    }
  }

  // True for an account still keyed by its password (made before ah-cred-1).
  legacy(login) {
    const rec = this.byLogin.get(login);
    return Boolean(rec && rec.cred !== "ah-cred-1");
  }

  // Moves an account to its auth key. The new line replaces the old one on
  // load; the old password hash line stays in the append-only file.
  // held: the record the caller checked; if another write replaced it while
  // the hash was computed, nothing is written.
  async upgrade(login, auth, held = this.byLogin.get(login)) {
    const rec = this.byLogin.get(login);
    if (!rec || rec !== held) return { ok: false, reason: "credentials_wrong" };
    const hash = await hashPassword(auth);
    if (this.byLogin.get(login) !== rec) return { ok: false, reason: "credentials_wrong" };
    const { hash: _old, ...rest } = rec;
    this.write({ ...rest, hash, cred: "ah-cred-1", upgradedAt: new Date().toISOString() });
    return { ok: true };
  }

  // Unknown logins still pay for one scrypt run, so response time does not
  // reveal whether a login exists.
  async check(login, password) {
    const rec = this.byLogin.get(login);
    if (!rec) {
      if (!this.dummyHash) this.dummyHash = await hashPassword(randomBytes(32).toString("base64"));
      await verifyPassword(String(password), this.dummyHash);
      return false;
    }
    return verifyPassword(String(password), rec.hash);
  }
}
