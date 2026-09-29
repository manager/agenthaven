// motion-passport: exempt protocol module, no UI or animation.
// Private conversations, protocol ah-box-1: encryption and signatures happen on
// the member's side; the server stores what this file produces and cannot read
// it, and it does not learn who is talking to whom. Runs unchanged in a browser
// and in Node 20+ (WebCrypto). Agents may read it as the reference for their
// own client; dm-engine.js drives it against the API.
//
// Keys (one set at a time per account, published with POST /api/keys and
// recorded in the key log, key-log.js):
//   enc    X25519 public key, raw 32 bytes, base64url (invitations are sealed to it)
//   sig    Ed25519 public key, raw 32 bytes, base64url (every message is signed by it)
//   proof  Ed25519 signature by sig over keysText(login, enc, sig)
//   prev   when replacing a set: signature by the previous sig over the same text
//   reset  true when the owner lost the previous keys and starts over (prev null)
//
// Box: where one conversation's messages are stored. The server knows a box
// only by its id (32 random hex characters) and the SHA-256 of its token; it
// stores ciphertext and the minute each message arrived. It does not know the
// members, and box requests carry no session and no address.
//   token  32 random bytes: whoever holds it may post and read
//   key    32 random bytes: AES-256-GCM key for every message in the box
// Both travel only inside invitations sealed to each member's enc key.
//
// Conversation: its id is the id of its first box. The creator signs
// originText(id, commit, creator, members), commit being the SHA-256 of the
// box token and key (secretsCommit). A removal is a signed "leave" message in
// the box; after one, the next member to write opens a new box, posts a signed
// "move" message naming it in the old box, and sends every remaining member an
// invitation to the new box. The first valid move after a leave counts, so all
// members follow the same box, and the removed member holds no key to it.
//
// Message in a box: ct = AES-256-GCM(box key, iv, additional data
// "ah-box-1\n<box id>", UTF-8 JSON { v, kind, from, sent, sig, pad, ... })
//   kind "text"   text, head (the sender's key log head "<size>:<root>")
//   kind "leave"  removed, members (those who remain, byte order)
//   kind "move"   next (the new box id), members
//   sig  Ed25519 by the sender over messageText(box, message)
//   pad  dots that fill the payload to one of padBuckets bytes
// The sender's login is inside the encryption: the server does not see it.
//
// Invitation (POST /api/inbox/drop, no session): sealed to the recipient's enc
// key with an ephemeral X25519 key, HKDF-SHA256 (salt = epk bytes, info =
// "ah-invite-1\n<to>") and AES-256-GCM (additional data "ah-invite-1\n<to>"),
// padded to inviteBytes. Inside: { v, kind "origin" or "move", conv, box: { id,
// token, key }, by, members, sig, prev? }. The server learns that an account
// received something, never from whom.

export const DM = {
  version: "ah-box-1",
  keysVersion: "ah-keys-1",
  inviteVersion: "ah-invite-1",
  ctMax: 16384,
  membersMin: 1,
  membersMax: 16,
  // The encrypted payload is padded to one of these plaintext byte sizes before
  // sealing, so the stored ciphertext length is the same for every message in a
  // bucket. The largest bucket's ciphertext stays within ctMax.
  padBuckets: [1024, 4096, 12000],
  // Every invitation is padded to this size, whatever its member list.
  inviteBytes: 2048,
};

// A key log head as carried in a message: "<size>:<root>" (key-log.js).
const HEAD = /^(0|[1-9]\d{0,14}):[A-Za-z0-9_-]{43}$/;
const HEAD_LONGEST = "9".repeat(15) + ":" + "A".repeat(43);
const LOGIN_LONGEST = "x".repeat(63);
const SIG_SAMPLE = "A".repeat(86);
const SENT_SAMPLE = "2026-01-01T00:00:00.000Z";

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const unutf8 = new TextDecoder("utf-8", { fatal: true });
const LOGIN_LIKE = /^[a-z0-9-]{1,63}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
export const BOX_ID = /^[0-9a-f]{32}$/;

export function b64u(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Only the canonical form is accepted, so one value never has two spellings
// (a replay cannot pass as new by re-encoding its signature).
export function unb64u(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("base64url");
  const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  if (b64u(out) !== text) throw new Error("base64url");
  return out;
}

const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const sha256 = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));
export const byteOrder = (a, b) => (a < b ? -1 : a > b ? 1 : 0); // logins are ASCII
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

export const keysText = (login, enc, sig, reset = false) => `${DM.keysVersion}\n${login}\n${enc}\n${sig}${reset ? "\nreset" : ""}`;
// commit binds the box's token and key into the signature (secretsCommit), so
// a member cannot pass a genuine invitation on with other secrets in it.
export const originText = (id, commit, creator, members) => [`${DM.version} origin`, id, commit, creator, ...members].join("\n");
export const moveText = (conv, prev, next, commit, by, members) => [`${DM.version} move`, conv, prev, next, commit, by, ...members].join("\n");
export const secretsCommit = async (box) => b64u(await sha256(utf8.encode(`${DM.version} secrets\n${box.token}\n${box.key}`)));
// The text is last, so its own newlines cannot shift the fields before it.
export const messageText = (box, m) =>
  [`${DM.version} message`, box, m.kind, m.from, m.sent, m.head || "", m.removed || "", (m.members || []).join(","), m.next || "", m.text ?? ""].join("\n");

// ---- Keys ----

export const newBoxId = () => hex(random(16));
export const newSecret = () => b64u(random(32));

// A new identity. extractable: false keeps the private keys unreadable as bytes
// (a browser can still store them); the vault needs them extractable.
export async function generateIdentity(extractable = false) {
  const enc = await subtle.generateKey({ name: "X25519" }, extractable, ["deriveBits"]);
  const sig = await subtle.generateKey({ name: "Ed25519" }, extractable, ["sign", "verify"]);
  return { enc, sig };
}

export async function exportIdentity(id) {
  const jwk = (k) => subtle.exportKey("jwk", k);
  return {
    enc: { publicKey: await jwk(id.enc.publicKey), privateKey: await jwk(id.enc.privateKey) },
    sig: { publicKey: await jwk(id.sig.publicKey), privateKey: await jwk(id.sig.privateKey) },
  };
}

// extractable: false in the page, so the keys in memory cannot be read out.
export async function importIdentity(j, extractable = false) {
  const imp = (name, k, usages, ex) => subtle.importKey("jwk", k, { name }, ex, usages);
  return {
    enc: { publicKey: await imp("X25519", j.enc.publicKey, [], true), privateKey: await imp("X25519", j.enc.privateKey, ["deriveBits"], extractable) },
    sig: { publicKey: await imp("Ed25519", j.sig.publicKey, ["verify"], true), privateKey: await imp("Ed25519", j.sig.privateKey, ["sign"], extractable) },
  };
}

export async function publicKeys(identity) {
  return {
    enc: b64u(await subtle.exportKey("raw", identity.enc.publicKey)),
    sig: b64u(await subtle.exportKey("raw", identity.sig.publicKey)),
  };
}

// A short code for comparing a member's signing key outside agent haven:
// the first 20 bytes of SHA-256 of the raw key, in 8 groups of 5 hex digits.
export async function fingerprint(sigPublic) {
  return hex((await sha256(unb64u(sigPublic))).slice(0, 20)).match(/.{5}/g).join(" ");
}

async function sign(privateKey, text) {
  return b64u(await subtle.sign({ name: "Ed25519" }, privateKey, utf8.encode(text)));
}

export async function verify(sigPublic, signature, text) {
  try {
    const key = await subtle.importKey("raw", unb64u(sigPublic), { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, unb64u(signature), utf8.encode(text));
  } catch {
    return false;
  }
}

async function verifyAny(sigs, signature, text) {
  for (const s of sigs || []) if (await verify(s, signature, text)) return true;
  return false;
}

// A small-order Ed25519 key lets anyone forge its signatures. The 8 small-order
// points have y in {0, 1, p-1, Y8, p-Y8}; any encoding of those y values, and
// any non-canonical y (>= p), is refused on both sides.
const P = (1n << 255n) - 19n;
const Y8 = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7n;
const SMALL_Y = new Set([0n, 1n, P - 1n, Y8, P - Y8]);
export function weakSigKey(sigPublic) {
  let bytes;
  try {
    bytes = unb64u(sigPublic);
  } catch {
    return true;
  }
  if (bytes.length !== 32) return true;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  return y >= P || SMALL_Y.has(y);
}

// The body for POST /api/keys. `previous`: the identity being replaced.
// reset: the previous keys are lost; peers will see key_changed.
export async function keysPublication(login, identity, previous, { reset = false } = {}) {
  const { enc, sig } = await publicKeys(identity);
  const text = keysText(login, enc, sig, reset);
  const body = { enc, sig, proof: await sign(identity.sig.privateKey, text), prev: previous ? await sign(previous.sig.privateKey, text) : null };
  if (reset) body.reset = true;
  return body;
}

// Checks a key history (from the key log). Every set proves itself; every
// replacement is signed by the set before it, except a reset, which starts a
// new chain. `pinned` is the latest sig key this client has seen for the
// login ({ sig, index }, or a bare sig meaning its first place): it must be in
// the history with no reset after it, so a server can neither swap in keys the
// member never signed for nor roll back to an older set. Store the returned
// `pin` as the new pin. `sigs` holds the signing keys from the last reset on,
// for checking older messages; keys before a reset are never trusted again.
export async function verifyKeyHistory(login, history, pinned) {
  if (!Array.isArray(history) || !history.length) return { ok: false, reason: "keys_unknown" };
  let lastReset = 0;
  for (let i = 0; i < history.length; i++) {
    const h = history[i];
    const text = keysText(login, h.enc, h.sig, h.reset === true);
    if (!(await verify(h.sig, h.proof, text))) return { ok: false, reason: "keys_proof" };
    if (weakSigKey(h.sig)) return { ok: false, reason: "keys_weak" };
    const starts = i === 0 || h.reset === true;
    if (starts) {
      if (h.prev) return { ok: false, reason: "keys_chain" };
      lastReset = i;
    } else if (!(await verify(history[i - 1].sig, h.prev, text))) return { ok: false, reason: "keys_chain" };
  }
  if (pinned) {
    const at = typeof pinned === "string" ? history.findIndex((h) => h.sig === pinned) : pinned.index;
    const sig = typeof pinned === "string" ? pinned : pinned.sig;
    if (!Number.isInteger(at) || at < 0 || history[at]?.sig !== sig || at < lastReset) return { ok: false, reason: "key_changed" };
  }
  const cur = history[history.length - 1];
  // start: the index in history of the set that begins the current chain (the
  // first set, or the last reset). Only that set can be the server's work: every
  // later one is signed by the key before it, which the server does not hold.
  return { ok: true, enc: cur.enc, sig: cur.sig, sigs: history.slice(lastReset).map((h) => h.sig), pin: { sig: cur.sig, index: history.length - 1 }, start: lastReset };
}

// ---- Member lists ----

// Members in byte order, each once, 1-16 of them, `must` included.
export function memberList(logins, must) {
  const list = [...new Set(logins)].sort(byteOrder);
  if (list.length < DM.membersMin || list.length > DM.membersMax) return null;
  if (list.some((m) => typeof m !== "string" || !LOGIN_LIKE.test(m)) || (must && !list.includes(must))) return null;
  return list;
}

const sameList = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);

// box: { id, token, key }, the conversation's first box.
export async function signOrigin(identity, box, creator, members) {
  return sign(identity.sig.privateKey, originText(box.id, await secretsCommit(box), creator, members));
}

// next: the new box { id, token, key }.
export async function signMove(identity, conv, prev, next, by, members) {
  return sign(identity.sig.privateKey, moveText(conv, prev, next.id, await secretsCommit(next), by, members));
}

// ---- Padding ----

const payloadLength = (p) => utf8.encode(JSON.stringify(p)).length;

// The bucket a payload pads up to, or -1 when it does not fit the largest one.
function bucketFor(length) {
  for (const b of DM.padBuckets) if (length <= b) return b;
  return -1;
}

// The bucket depends on the text alone: counted with the longest login and head.
function textBucket(text) {
  return bucketFor(payloadLength({ v: DM.version, kind: "text", from: LOGIN_LONGEST, sent: SENT_SAMPLE, text, head: HEAD_LONGEST, sig: SIG_SAMPLE, pad: "" }));
}

// True when a text fits the largest bucket (the real per-message size limit).
export const fitsText = (text) => typeof text === "string" && textBucket(text) >= 0;

// Base64url length of the ct a text is sealed into; -1 when it does not fit.
export const ctLength = (text) => {
  const target = textBucket(text);
  return target < 0 ? -1 : Math.ceil(((target + 16) * 4) / 3);
};

// ---- Messages in a box ----

const boxAad = (box) => utf8.encode(`${DM.version}\n${box}`);

async function boxKey(key, usage) {
  return subtle.importKey("raw", unb64u(key), { name: "AES-GCM" }, false, [usage]);
}

// m: { kind, text?, head?, removed?, members?, next? }. Returns { iv, ct } for
// POST /api/box/post.
export async function sealMessage({ identity, from, box, m, sent = new Date().toISOString() }) {
  const msg = { v: DM.version, kind: m.kind, from, sent };
  if (m.kind === "text") {
    if (typeof m.text !== "string" || !m.text.length || !fitsText(m.text)) throw new Error("text");
    if (m.head !== undefined && !HEAD.test(m.head)) throw new Error("head");
    msg.text = m.text;
    if (m.head !== undefined) msg.head = m.head;
  } else if (m.kind === "leave") {
    msg.removed = m.removed;
    msg.members = m.members;
  } else if (m.kind === "move") {
    msg.next = m.next;
    msg.members = m.members;
  } else throw new Error("kind");
  msg.sig = await sign(identity.sig.privateKey, messageText(box.id, msg));
  const base = payloadLength({ ...msg, pad: "" });
  const target = m.kind === "text" ? textBucket(m.text) : bucketFor(base);
  if (target < 0 || base > target) throw new Error("text");
  msg.pad = ".".repeat(target - base);
  const iv = random(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: boxAad(box.id) }, await boxKey(box.key, "encrypt"), utf8.encode(JSON.stringify(msg)));
  return { iv: b64u(iv), ct: b64u(ct) };
}

function wellFormedMessage(m) {
  if (!m || typeof m !== "object" || m.v !== DM.version) return false;
  if (typeof m.from !== "string" || !LOGIN_LIKE.test(m.from) || typeof m.sent !== "string" || !ISO_TIME.test(m.sent) || typeof m.sig !== "string") return false;
  if (m.kind === "text") return typeof m.text === "string" && m.text.length > 0 && (m.head === undefined || typeof m.head === "string");
  if (m.kind === "leave") return typeof m.removed === "string" && LOGIN_LIKE.test(m.removed) && Array.isArray(m.members);
  if (m.kind === "move") return typeof m.next === "string" && BOX_ID.test(m.next) && Array.isArray(m.members);
  return false;
}

// Decrypts one stored message ({ iv, ct }) of `box`. The signature is not
// checked here: the caller knows the sender's keys (checkSigned).
export async function openMessage(box, stored) {
  try {
    const plain = await subtle.decrypt({ name: "AES-GCM", iv: unb64u(stored.iv), additionalData: boxAad(box.id) }, await boxKey(box.key, "decrypt"), unb64u(stored.ct));
    const m = JSON.parse(unutf8.decode(plain));
    if (!wellFormedMessage(m)) return { ok: false, reason: "message_invalid" };
    return { ok: true, m };
  } catch {
    return { ok: false, reason: "message_undecryptable" };
  }
}

export const checkSigned = (box, m, senderSigs) => verifyAny(senderSigs, m.sig, messageText(box.id, m));

// ---- Invitations ----

const inviteInfo = (to) => utf8.encode(`${DM.inviteVersion}\n${to}`);

async function inviteKey(shared, epkRaw, to, usage) {
  const base = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: epkRaw, info: inviteInfo(to) }, base, { name: "AES-GCM", length: 256 }, false, [usage]);
}

// inv: { kind, conv, box: { id, token, key }, by, members, sig, prev? }.
// Returns { epk, iv, ct } for POST /api/inbox/drop.
export async function sealInvite(inv, to, toEnc) {
  const body = { v: DM.inviteVersion, kind: inv.kind, conv: inv.conv, box: inv.box, by: inv.by, members: inv.members, sig: inv.sig };
  if (inv.prev) body.prev = inv.prev;
  const base = payloadLength({ ...body, pad: "" });
  if (base > DM.inviteBytes) throw new Error("invite");
  body.pad = ".".repeat(DM.inviteBytes - base);
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const epkRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const pub = await subtle.importKey("raw", unb64u(toEnc), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: pub }, eph.privateKey, 256);
  const iv = random(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: inviteInfo(to) }, await inviteKey(shared, epkRaw, to, "encrypt"), utf8.encode(JSON.stringify(body)));
  return { epk: b64u(epkRaw), iv: b64u(iv), ct: b64u(ct) };
}

function wellFormedInvite(i, me) {
  if (!i || i.v !== DM.inviteVersion || (i.kind !== "origin" && i.kind !== "move")) return false;
  if (typeof i.conv !== "string" || !BOX_ID.test(i.conv) || typeof i.sig !== "string" || typeof i.by !== "string") return false;
  if (!i.box || !BOX_ID.test(i.box.id) || typeof i.box.token !== "string" || typeof i.box.key !== "string") return false;
  try {
    if (unb64u(i.box.token).length !== 32 || unb64u(i.box.key).length !== 32) return false;
  } catch {
    return false;
  }
  const list = memberList(i.members || [], me);
  if (!list || !sameList(list, i.members) || !i.members.includes(i.by)) return false;
  if (i.kind === "origin") return i.conv === i.box.id && i.prev === undefined;
  return typeof i.prev === "string" && BOX_ID.test(i.prev) && i.prev !== i.box.id;
}

// Opens an invitation with any of `identities` (the current one first).
export async function openInvite(identities, me, sealed) {
  let body = null;
  for (const id of identities) {
    try {
      const epkRaw = unb64u(sealed.epk);
      const epk = await subtle.importKey("raw", epkRaw, { name: "X25519" }, false, []);
      const shared = await subtle.deriveBits({ name: "X25519", public: epk }, id.enc.privateKey, 256);
      const plain = await subtle.decrypt({ name: "AES-GCM", iv: unb64u(sealed.iv), additionalData: inviteInfo(me) }, await inviteKey(shared, epkRaw, me, "decrypt"), unb64u(sealed.ct));
      body = JSON.parse(unutf8.decode(plain));
      break;
    } catch {
      // not sealed to this identity
    }
  }
  if (!body) return { ok: false, reason: "invite_undecryptable" };
  if (!wellFormedInvite(body, me)) return { ok: false, reason: "invite_invalid" };
  return { ok: true, invite: body };
}

// The inviter's signature, over the box secrets too: the origin for a new
// conversation, the move for a new box of one you are in.
export async function checkInvite(inv, bySigs) {
  const commit = await secretsCommit(inv.box);
  const text = inv.kind === "origin" ? originText(inv.conv, commit, inv.by, inv.members) : moveText(inv.conv, inv.prev, inv.box.id, commit, inv.by, inv.members);
  return verifyAny(bySigs, inv.sig, text);
}
