// motion-passport: exempt server module, no UI and no animation.
// Vaults, protocol ah-vault-1 (public/js/cred.js): one encrypted document per
// account, sealed on the agent's side with a key that comes from its password
// and never reaches the server. The server stores { version, blob } and hands
// it back; it cannot open it. A write must name the next version, so two
// clients of one account cannot overwrite each other unnoticed.
//
// Storage: <dataDir>/vault/<SHA-256 of the login>.json, replaced atomically
// (temporary file, fsync, rename) on each accepted write.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

export const VAULT = { ctMax: 400_000 };

const B64U = /^[A-Za-z0-9_-]+$/;
const canonical = (v) => Buffer.from(v, "base64url").toString("base64url") === v;

export class Vaults {
  constructor(dataDir) {
    this.dir = path.join(dataDir, "vault");
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  file(login) {
    return path.join(this.dir, `${createHash("sha256").update(login, "utf8").digest("hex")}.json`);
  }

  read(login) {
    try {
      return JSON.parse(fs.readFileSync(this.file(login), "utf8"));
    } catch {
      return null;
    }
  }

  get(login) {
    const v = this.read(login);
    return v ? { version: v.version, blob: v.blob } : { version: 0, blob: null };
  }

  // The scrypt hash of the auth key a password change wrote with this vault
  // (null if none). The account line follows the vault write; if the server
  // stopped between the two, sign-in finds them apart and completes the change.
  pendingAuth(login) {
    return this.read(login)?.pendingAuth || null;
  }

  // body: { version, blob: { iv, ct }, anchor? }, version = the stored version + 1.
  // anchor: an opaque per-account id the client derives from its vault key
  // (public/js/cred.js deriveAnchor); the witness publishes anchor -> highest
  // version, so a rolled-back vault is caught on open. Optional and never
  // interpreted by the server. pendingAuth: set by a password change only.
  put(login, body, { pendingAuth } = {}) {
    const { version, blob, anchor } = body || {};
    if (!Number.isSafeInteger(version) || version < 1) return { ok: false, reason: "vault_invalid" };
    if (!blob || typeof blob.iv !== "string" || blob.iv.length !== 16 || !B64U.test(blob.iv) || !canonical(blob.iv)) return { ok: false, reason: "vault_invalid" };
    if (typeof blob.ct !== "string" || !B64U.test(blob.ct) || !canonical(blob.ct)) return { ok: false, reason: "vault_invalid" };
    if (blob.ct.length > VAULT.ctMax) return { ok: false, reason: "vault_too_large" };
    if (anchor !== undefined && (typeof anchor !== "string" || anchor.length !== 43 || !B64U.test(anchor) || !canonical(anchor))) return { ok: false, reason: "vault_invalid" };
    const cur = this.get(login);
    if (version !== cur.version + 1) return { ok: false, reason: "vault_conflict", version: cur.version };
    const target = this.file(login);
    const tmp = `${target}.${process.pid}.tmp`;
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, JSON.stringify({ version, blob: { iv: blob.iv, ct: blob.ct }, ...(anchor ? { anchor } : {}), ...(pendingAuth ? { pendingAuth } : {}) }));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, target);
    return { ok: true, version };
  }

  // Every vault's { anchor, version }, for the witness to publish. Files with
  // no anchor (older vaults) are skipped: nothing to check for them.
  anchors() {
    const out = [];
    let names;
    try {
      names = fs.readdirSync(this.dir);
    } catch {
      return out;
    }
    for (const name of names) {
      if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
      try {
        const v = JSON.parse(fs.readFileSync(path.join(this.dir, name), "utf8"));
        if (typeof v?.anchor === "string" && Number.isSafeInteger(v.version)) out.push({ anchor: v.anchor, version: v.version });
      } catch {
        // a torn or unreadable file is skipped
      }
    }
    return out;
  }
}
