// motion-passport: exempt server module, no UI and no animation.
// Blind tickets, protocol ah-ticket-1 (public/js/tickets.js is the client).
// The server signs blinded values for a signed-in account and later accepts a
// ticket { m, s } with no session. It never sees m before it is spent, so it
// cannot tell which account a spent ticket came from.
//
// Storage:
//   <dataDir>/ticket-key.json     the RSA-2048 key, made once, kept across restarts
//   <dataDir>/tickets-spent.jsonl SHA-256 of every spent m (append only), so a
//                                 ticket works once; nothing ties it to an account

import fs from "node:fs";
import path from "node:path";
import { constants, createHash, createPrivateKey, generateKeyPairSync, privateDecrypt } from "node:crypto";
import { AppendLog } from "./jsonl.mjs";

export const TICKET = { batchMax: 20 };

const B64U = /^[A-Za-z0-9_-]+$/;
const canonical = (v) => typeof v === "string" && B64U.test(v) && Buffer.from(v, "base64url").toString("base64url") === v;
const toBig = (buf) => (buf.length ? BigInt(`0x${buf.toString("hex")}`) : 0n);
function modPow(b, e, m) {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

// Same full-domain hash as public/js/tickets.js fdh() (tests/box.test.mjs checks both).
export function fdh(m, n, k) {
  const seed = Buffer.concat([Buffer.from("ah-ticket-1\n", "utf8"), m]);
  const parts = [];
  for (let c = 0, off = 0; off < k; c++, off += 32) {
    const ctr = Buffer.alloc(4);
    ctr.writeUInt32BE(c);
    parts.push(createHash("sha256").update(seed).update(ctr).digest());
  }
  return toBig(Buffer.concat(parts).subarray(0, k)) % n;
}

export class TicketBook {
  constructor(dataDir) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    const file = path.join(dataDir, "ticket-key.json");
    let jwk;
    try {
      jwk = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      jwk = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 65537 }).privateKey.export({ format: "jwk" });
      fs.writeFileSync(file, JSON.stringify(jwk), { mode: 0o600, flag: "wx" });
    }
    this.key = createPrivateKey({ key: jwk, format: "jwk" });
    const nb = Buffer.from(jwk.n, "base64url");
    this.k = nb.length;
    this.n = toBig(nb);
    this.e = toBig(Buffer.from(jwk.e, "base64url"));
    // Same id as public/js/tickets.js keyId().
    this.pub = { n: jwk.n, e: jwk.e, id: createHash("sha256").update(`ah-ticket-1 key\n${jwk.n}\n${jwk.e}`, "utf8").digest("base64url") };
    this.spent = new Set();
    this.log = new AppendLog(path.join(dataDir, "tickets-spent.jsonl"), (r) => {
      if (typeof r?.h === "string") this.spent.add(r.h);
    });
  }

  // blinded: base64url values, each k bytes and below n. Returns the signatures
  // in the same order, or null when one is not well formed.
  sign(blinded) {
    if (!Array.isArray(blinded) || !blinded.length || blinded.length > TICKET.batchMax) return null;
    const out = [];
    for (const b of blinded) {
      if (!canonical(b)) return null;
      const buf = Buffer.from(b, "base64url");
      const x = toBig(buf);
      if (buf.length !== this.k || x < 2n || x >= this.n) return null;
      out.push(privateDecrypt({ key: this.key, padding: constants.RSA_NO_PADDING }, buf).toString("base64url"));
    }
    return out;
  }

  // One use per ticket.
  spend(ticket) {
    const { m, s } = ticket || {};
    if (!canonical(m) || !canonical(s)) return false;
    const mb = Buffer.from(m, "base64url");
    const sb = Buffer.from(s, "base64url");
    if (mb.length !== 32 || sb.length !== this.k) return false;
    const sig = toBig(sb);
    if (sig >= this.n || modPow(sig, this.e, this.n) !== fdh(mb, this.n, this.k)) return false;
    const h = createHash("sha256").update(mb).digest("base64url");
    if (this.spent.has(h)) return false;
    this.log.append([{ h }]);
    this.spent.add(h);
    return true;
  }
}
