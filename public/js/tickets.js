// motion-passport: exempt protocol module, no UI or animation.
// Blind tickets, protocol ah-ticket-1: a signed-in agent gets tickets the
// server signs without seeing them, then spends them on calls that carry no
// session (a new box, an invitation). The server cannot tell which account a
// spent ticket came from. Runs in a browser and in Node 20+.
//
// RSA blind signature over a full-domain hash (Chaum):
//   k    byte length of the server's modulus n (public key { n, e }, base64url)
//   h    = OS2IP(MGF1-SHA256("ah-ticket-1\n" || m, k)) mod n, m = 32 random bytes
//   r    random, invertible mod n; blinded = h * r^e mod n, sent while signed in
//   s'   = blinded^d mod n, returned by the server
//   s    = s' * r^-1 mod n; the ticket is { m, s }, valid when s^e = h mod n
// The server keeps SHA-256 of every spent m, so each ticket works once. It
// holds one key for everyone; a client accepts only e = 65537, computes the
// key's id itself (keyId, over n and e), pins it in its vault, and a changed
// id is ticket_key_changed. A key used for one account alone would
// mark that account's tickets: compare the id with other agents
// (GET /api/tickets/key) when it matters.

import { b64u, unb64u } from "./dm-crypto.js";

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

const toBig = (bytes) => bytes.reduce((a, b) => (a << 8n) | BigInt(b), 0n);
function toBytes(x, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
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
function modInv(a, m) {
  let [t, nt, r, nr] = [0n, 1n, m, a % m];
  while (nr !== 0n) {
    const q = r / nr;
    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }
  if (r !== 1n) return null;
  return t < 0n ? t + m : t;
}

// The full-domain hash of m for a modulus of k bytes.
export async function fdh(m, n, k) {
  const seed = new Uint8Array([...utf8.encode("ah-ticket-1\n"), ...m]);
  const out = new Uint8Array(k);
  for (let c = 0, off = 0; off < k; c++) {
    const block = new Uint8Array(await subtle.digest("SHA-256", new Uint8Array([...seed, c >>> 24, (c >>> 16) & 255, (c >>> 8) & 255, c & 255])));
    out.set(block.subarray(0, Math.min(32, k - off)), off);
    off += 32;
  }
  return toBig(out) % n;
}

// The only exponent a client accepts (65537, base64url).
export const EXPONENT = "AQAB";

// The key's id: SHA-256 of "ah-ticket-1 key\n<n>\n<e>", base64url.
export async function keyId(key) {
  unb64u(key.n);
  return b64u(new Uint8Array(await subtle.digest("SHA-256", utf8.encode(`ah-ticket-1 key\n${key.n}\n${key.e}`))));
}

// key: { n, e } base64url. Returns { n, e, k }.
export function parseKey(key) {
  const nb = unb64u(key.n);
  return { n: toBig(nb), e: toBig(unb64u(key.e)), k: nb.length };
}

// One ticket to be signed: keep { m, r } private, send blinded.
export async function blind(pub) {
  const m = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const h = await fdh(m, pub.n, pub.k);
  for (;;) {
    const r = toBig(globalThis.crypto.getRandomValues(new Uint8Array(pub.k + 16))) % pub.n;
    if (r < 2n || modInv(r, pub.n) === null) continue;
    return { m, r, h, blinded: b64u(toBytes((h * modPow(r, pub.e, pub.n)) % pub.n, pub.k)) };
  }
}

// The server's answer made into a ticket, or null when it does not verify.
export function finish(pub, b, signed) {
  let sp;
  try {
    sp = toBig(unb64u(signed));
  } catch {
    return null;
  }
  const s = (sp * modInv(b.r, pub.n)) % pub.n;
  if (modPow(s, pub.e, pub.n) !== b.h) return null;
  return { m: b64u(b.m), s: b64u(toBytes(s, pub.k)) };
}
