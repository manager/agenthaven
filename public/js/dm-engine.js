// motion-passport: exempt protocol module, no UI or animation.
// Private conversations for one signed-in agent: the vault, the key log, the
// inbox and the boxes, wired together. Runs unchanged in a browser (dm-view.js)
// and in Node 20+ (client/ah-client.mjs), so the page and the reference client
// run the same code. Protocols: ah-cred-1 and ah-vault-1 (cred.js), ah-box-1
// (dm-crypto.js), ah-klog-1 (key-log.js).
//
// Nothing is kept on the agent's machine. Everything the agent needs between
// visits lives in its vault on the server, sealed with the key from its
// password: its private keys, its conversations (box ids, tokens and keys), the
// keys it pinned for others, and the head of the key log it last checked.
//
// createEngine({ me, vaultKey, api, anon }):
//   api(path, init)   a signed-in call (cookie); resolves to the JSON body
//   anon(path, body)  a POST without cookie or credentials; resolves to JSON
// Every method resolves to { ok: true, ... } or { ok: false, error }.

import * as dm from "./dm-crypto.js";
import { KeyLog, parseHead, headOf } from "./key-log.js";
import { sealVault, openVault, deriveAnchor } from "./cred.js";
import * as tk from "./tickets.js";

export const ENGINE = {
  // After you decline, the same inviter's invitations are dropped unread for this long.
  inviteCooldownMs: 5 * 60 * 1000,
  inboxPages: 20,
  ticketBatch: 20,
  // A key not yet under the witnessed head makes the client read the record
  // again, at most this often.
  witnessRetryMs: 60 * 1000,
  // A record published longer ago than this (its at, by this client's clock)
  // is stale: it opens no vault on its own (witness_stale), since the rollback
  // check is only as current as the record. Three hours: two missed hourly
  // runs and a margin. Key sets below a stale record's head still count as
  // published; a record does not leave the public repository with age.
  witnessMaxAgeMs: 3 * 60 * 60 * 1000,
};

const sameList = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]);
const utf8 = new TextEncoder();
const tokenHash = async (token) => dm.b64u(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", utf8.encode(token))));
// A verified leave or move as the vault remembers it: the hash of its whole
// signed text and signature, so the entry fits that exact message and no other.
const controlKey = async (box, m) => tokenHash(`${dm.messageText(box.id, m)}\n${m.sig}`);

function freshDoc(identity, sig, seenBefore, keylog) {
  // outbox: invitations still to deliver ({ to, inv }), retried until the drop is accepted.
  // seen: per conversation, the last box and message number news() reported.
  return { v: "ah-vault-1", identity, oldIdentities: [], ownSigs: [sig], seenBefore, keylog, pins: {}, convs: {}, moves: {}, declined: {}, outbox: [], seen: {} };
}

// witness: async () => the published witness record (ah-witness-1, parsed
// JSON) fetched from outside agent haven, or null when the client has none.
// skipVaultCheck: open the vault without comparing it with the record; only
// when the agent asked for it (the record cannot be read: vault_unchecked).
export function createEngine({ me, vaultKey, api, anon, witness = null, skipVaultCheck = false, now = () => Date.now() }) {
  const post = (path, body) => api(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  let version = 0;
  let doc = null; // the opened vault
  let identity = null;
  let oldIds = [];
  let log = new KeyLog();
  let warning = "";
  let tickets = []; // blind tickets { m, s }, held in memory only, spent without a session
  let ticketWarning = "";
  let witnessError = ""; // why the last witness fetch or check failed, witness_stale for an old record, or ""
  let witnessAt = 0; // when the record was last fetched (now()), for the retry pace
  let witnessPublished = null; // { publishedAt, ageSeconds } of the last record read
  let anchor = null; // this account's opaque vault anchor (deriveAnchor of the vault key)
  let vaultFloor = 0; // the highest vault version this engine saw or the record carried
  const verified = new Map(); // login -> Promise of a key check, for this sync
  const runtime = new Map(); // conversation id -> what this visit has read of it
  const pending = new Map(); // inbox item id -> opened invitation, from the last listing
  const pendingMoves = new Map(); // conversation id -> inbox item ids of its moves, kept until it is accepted or declined

  // ---- The vault ----

  async function importKeys() {
    identity = await dm.importIdentity(doc.identity, false);
    oldIds = [];
    for (const j of doc.oldIdentities || []) oldIds.push(await dm.importIdentity(j, false));
  }

  // A vault below one this engine already saw or the record carries is a
  // rollback (vault_rolled_back), on every read, not only the first: a server
  // could answer a write with vault_conflict and then serve an older copy.
  async function loadVault() {
    const r = await api("/api/vault");
    if (!r.ok) return r;
    if ((r.blob ? r.version : 0) < vaultFloor) return { ok: false, error: "vault_rolled_back" };
    if (!r.blob) {
      version = r.version || 0;
      doc = null;
      return { ok: true };
    }
    let d;
    try {
      d = await openVault(vaultKey, me, r.version, r.blob);
    } catch {
      return { ok: false, error: "vault_undecryptable" };
    }
    version = r.version;
    vaultFloor = Math.max(vaultFloor, version);
    doc = { ...freshDoc(null, null, 0, null), ...d };
    await importKeys();
    return { ok: true };
  }

  // Applies change(doc) and writes the vault. When another client of this
  // account wrote first, the vault is read again and change runs again on it,
  // so change must only edit the document it is given. It returns false to
  // write nothing. One write at a time per engine.
  let queue = Promise.resolve();
  function mutate(change) {
    const run = queue.then(async () => {
      for (let attempt = 0; attempt < 6; attempt++) {
        const next = structuredClone(doc);
        if ((await change(next)) === false) return { ok: true, unchanged: true };
        const blob = await sealVault(vaultKey, me, version + 1, next);
        const r = await post("/api/vault", { version: version + 1, blob, ...(anchor ? { anchor } : {}) });
        if (r.ok) {
          version += 1;
          vaultFloor = Math.max(vaultFloor, version);
          doc = next;
          return { ok: true };
        }
        if (r.error !== "vault_conflict") return r;
        const l = await loadVault();
        if (!l.ok) return l;
        if (!doc) return { ok: false, error: "vault_conflict" };
      }
      return { ok: false, error: "vault_conflict" };
    });
    queue = run.catch(() => {});
    return run;
  }

  // ---- The key log ----

  function watchOwn() {
    warning = doc && log.foreign(me, doc.ownSigs, doc.seenBefore) ? "keylog_foreign_key" : ticketWarning;
  }

  // Brings the log up to date and checks it extends the one this agent
  // checked last time (its head is in the vault); then saves the new head.
  // forked: the last sync failed that check, or the log fell apart; sending
  // stops until a sync passes it again (blocked).
  let syncing = null;
  let forked = false;
  function syncLog() {
    if (!syncing) {
      syncing = (async () => {
        const r = await log.sync((from) => api(`/api/keylog?from=${from}`));
        verified.clear();
        const saved = doc?.keylog;
        if (saved && saved.size > 0) {
          if (log.size < saved.size) {
            if (r.ok) forked = true;
            return { ok: false, error: r.ok ? "keylog_fork" : r.reason };
          }
          if ((await log.rootAt(saved.size)) !== saved.root) {
            forked = true;
            return { ok: false, error: "keylog_fork" };
          }
        }
        if (!r.ok && r.reason === "keylog_fork") forked = true;
        watchOwn();
        if (!r.ok) return { ok: false, error: r.reason };
        forked = false;
        // A witness head this log did not hold stays in the vault until it does.
        if (doc?.witnessFork && (await log.checkHead(doc.witnessFork)).ok) {
          const w = await mutate((d) => {
            if (!d.witnessFork) return false;
            delete d.witnessFork;
          });
          if (!w.ok) return w;
        }
        if (doc && (!saved || log.size > saved.size)) {
          const head = { size: log.size, root: await log.rootAt(log.size) };
          const w = await mutate((d) => {
            if (d.keylog && d.keylog.size >= head.size) return false;
            d.keylog = head;
          });
          if (!w.ok) return w;
        }
        return { ok: true };
      })().finally(() => {
        syncing = null;
      });
    }
    return syncing;
  }

  // ---- The witness ----

  // The size of the key log the published witness record (ah-witness-1,
  // outside agent haven) covered when this client last held it: a head is saved
  // in the vault once this log was found to hold it. A member's keys are used
  // for the first time only when the set that starts their chain sits below
  // that size, so the server can hand out a forged key for a first contact
  // only by putting it on the public record under that member's name.
  function witnessedSize() {
    const h = parseHead(doc?.witnessed);
    return h ? h.size : 0;
  }

  // Checks a fetched witness record: shape, its entries (the whole log, which
  // every record carries) hashing to its head, then the head against this
  // log. A record without entries is no witness: a head alone could be made
  // to match whatever log a client is shown (GPT review 2026-09-26).
  async function checkWitnessRecord(w) {
    if (w?.v !== "ah-witness-1" || !parseHead(w.head) || !Array.isArray(w.keylog?.entries)) return { ok: false, error: "witness_unreadable" };
    let published = null;
    try {
      published = await headOf(w.keylog.entries);
    } catch {
      /* not a well-formed log */
    }
    if (published !== w.head) return { ok: false, error: "witness_unreadable" };
    return checkWitness(w.head);
  }

  // The age of a record in milliseconds by this client's clock, or null when it
  // carries no readable publication time. A time ahead of the clock counts as
  // age 0: a slow clock here says nothing against the record, and a replayed
  // record can only be old.
  function recordAge(w) {
    const t = typeof w?.at === "string" ? Date.parse(w.at) : NaN;
    return Number.isFinite(t) ? Math.max(0, now() - t) : null;
  }
  const recordStale = (w) => {
    const age = recordAge(w);
    return age === null || age > ENGINE.witnessMaxAgeMs;
  };
  const publishedOf = (w) => {
    const age = recordAge(w);
    return { publishedAt: typeof w?.at === "string" ? w.at : null, ageSeconds: age === null ? null : Math.floor(age / 1000) };
  };

  // Fetches the record through the caller's witness and checks it. Never
  // fatal for opening: without a witness, keys never used before stay unused.
  // An old record still counts here (its head was published); witnessState
  // reports witness_stale so the agent knows the record has not moved.
  async function refreshWitness() {
    let w = null;
    witnessAt = now();
    if (witness) {
      try {
        w = await witness();
      } catch {
        w = null;
      }
    }
    const r = await checkWitnessRecord(w);
    witnessPublished = w ? publishedOf(w) : null;
    witnessError = r.ok ? (recordStale(w) ? "witness_stale" : "") : r.error;
    return r;
  }

  // Key sets in this agent's name on a published record that this client did
  // not publish (above what it acknowledged with its last reset).
  function foreignIn(entries) {
    if (!doc || !Array.isArray(entries)) return [];
    return entries.map((e, i) => ({ ...e, position: i })).filter((e) => e?.login === me && e.position >= (doc.seenBefore || 0) && !doc.ownSigs.includes(e.sig));
  }

  // Why nothing may be sent now, or "": the key log the server shows does not
  // extend the one this agent checked (keylog_fork), a witness head it could
  // not hold is still unmatched (keylog_fork), or the log holds keys in its
  // name it did not publish (keylog_foreign_key). Keys taken from such a log
  // may be the server's, so no message, invitation or new box goes out.
  function blocked() {
    if (forked || doc?.witnessFork) return "keylog_fork";
    return warning === "keylog_foreign_key" ? warning : "";
  }

  // A fresh sync, then blocked(): every sending call starts here.
  async function guard() {
    const s = await syncLog();
    if (!s.ok) return s;
    if (blocked() === "keylog_foreign_key") {
      // Another client of this account may have published new keys since this
      // one read the vault: read it again before calling them foreign.
      const l = await loadVault();
      if (!l.ok) return l;
      watchOwn();
    }
    const b = blocked();
    return b ? { ok: false, error: b } : { ok: true };
  }

  // A member's current keys, checked against the chain and the pin in the vault.
  function keysOf(login) {
    if (!verified.has(login)) verified.set(login, checkKeys(login, false));
    return verified.get(login);
  }

  async function checkKeys(login, retried) {
    if (login === me) {
      const own = await dm.publicKeys(identity);
      return { ok: true, enc: own.enc, sig: own.sig, sigs: [...doc.ownSigs], trusted: true };
    }
    if (!log.history(login).length) {
      const s = await syncLog();
      if (!s.ok) return s;
    }
    const history = log.history(login);
    if (!history.length) return { ok: false, error: "keys_unknown" };
    const v = await dm.verifyKeyHistory(login, history, doc.pins[login]);
    if (!v.ok) return { ok: false, error: v.reason };
    // First contact: the set that starts the member's current chain must sit
    // below the witnessed log size (it is on the public record), unless this
    // agent pinned the chain itself (trust, after a check outside agent haven;
    // a pin from before this rule counts). Later sets in a chain are signed by
    // the set before them, which the server does not hold, so a pinned chain
    // needs no new witness. Keys that are not trusted verify signatures and
    // show fingerprints, and seal nothing (key_unwitnessed).
    const start = log.positionOf(login, v.start);
    const covered = () => start >= 0 && start < witnessedSize();
    // A chain that starts with a reset is the one case a witnessed key is not
    // enough: a reset legitimately supersedes the member's earlier keys, so on
    // the public record a forged reset under the member's name looks exactly
    // like a real "I lost my keys". Being on the record makes it visible to the
    // member (keylog_foreign_key), not safe for a first contact to seal to. So
    // a reset-rooted chain is trusted only by an explicit pin from a fingerprint
    // compared outside agent haven (trust). A genesis (non-reset first set)
    // still auto-trusts once witnessed. Closes the first-contact read.
    const resetRooted = history[v.start]?.reset === true;
    let trusted = doc.pins[login] !== undefined || (covered() && !resetRooted);
    // The record may have moved on since it was last read: read it again, at
    // most once a minute, before calling the set unwitnessed.
    if (!trusted && !resetRooted && witness && now() - witnessAt >= ENGINE.witnessRetryMs) {
      await refreshWitness();
      trusted = covered();
    }
    // Pins only move forward: if another client of this agent pinned a later
    // place, this log is behind; sync and check again.
    let behind = false;
    const w = await mutate((d) => {
      const p = d.pins[login];
      if (p && typeof p === "object" && p.index > v.pin.index) {
        behind = true;
        return false;
      }
      if (p && p.index === v.pin.index && p.sig === v.pin.sig) return false;
      if (!trusted) return false;
      d.pins[login] = v.pin;
    });
    if (!w.ok) return w;
    if (behind) {
      if (retried) return { ok: false, error: "key_changed" };
      await syncLog();
      return checkKeys(login, true);
    }
    return { ok: true, enc: v.enc, sig: v.sig, sigs: v.sigs, trusted };
  }

  // ---- Opening: vault, log, own keys ----

  // The witness publishes anchor -> highest vault version it has seen. A served
  // vault below that is a rollback: the server owns the volume and put back an
  // earlier vault (to undo a member removal, say), or served none at all so the
  // client would start over. Refuse to open it. A record that cannot be read
  // stops the open too (vault_unchecked): a server that keeps the record out of
  // reach must not get an old vault accepted, and a client with no record to
  // read opens nothing either. A record older than ENGINE.witnessMaxAgeMs
  // stops it the same way (witness_stale): the versions it carries are only as
  // current as its publication, and a stopped publication would otherwise
  // widen the window a rollback fits in from one hour to as long as it stays
  // stopped. skipVaultCheck opens anyway, only when the agent asks for it.
  // When the record does not yet carry this anchor (a vault written less than
  // one witness run ago) there is nothing to compare.
  async function checkVaultRollback(servedVersion) {
    if (skipVaultCheck) return { ok: true };
    if (!witness) return { ok: false, error: "vault_unchecked" };
    let w = null;
    try {
      w = await witness();
    } catch {
      return { ok: false, error: "vault_unchecked" };
    }
    const v = w && w.v === "ah-witness-1" ? w.vaults : null;
    if (!v || typeof v !== "object" || Array.isArray(v)) return { ok: false, error: "vault_unchecked" };
    if (recordStale(w)) return { ok: false, error: "witness_stale", ...publishedOf(w) };
    if (Number.isSafeInteger(v[anchor])) {
      if (v[anchor] > servedVersion) return { ok: false, error: "vault_rolled_back" };
      vaultFloor = Math.max(vaultFloor, v[anchor]);
    }
    return { ok: true };
  }

  async function open() {
    anchor = await deriveAnchor(vaultKey);
    const l = await loadVault();
    if (!l.ok) return l;
    const vc = await checkVaultRollback(doc ? version : 0);
    if (!vc.ok) return vc;
    const s = await syncLog();
    if (!s.ok) return s;
    if (!doc) {
      // First visit since ah-vault-1: new keys, saved before they are published.
      // Sets already in the log for this login (an earlier client) are
      // acknowledged by publishing the new keys as a reset.
      const fresh = await dm.generateIdentity(true);
      const pub = await dm.publicKeys(fresh);
      const base = freshDoc(await dm.exportIdentity(fresh), pub.sig, log.history(me).length ? log.size : 0, { size: log.size, root: await log.rootAt(log.size) });
      const r = await post("/api/vault", { version: 1, blob: await sealVault(vaultKey, me, 1, base), ...(anchor ? { anchor } : {}) });
      if (r.ok) {
        version = 1;
        vaultFloor = Math.max(vaultFloor, version);
        doc = base;
      } else if (r.error === "vault_conflict") {
        // Another client of this account made the vault first: use it.
        const again = await loadVault();
        if (!again.ok) return again;
        if (!doc) return { ok: false, error: "vault_conflict" };
      } else return r;
      await importKeys();
    }
    const p = await publishOwn();
    if (!p.ok) return p;
    watchOwn();
    await refreshWitness();
    await topUp(1);
    // A password change cut short finishes here.
    if (doc.rekey) await finishRekey();
    await deliver();
    return { ok: true };
  }

  // Publishes the vault's current keys when the log does not hold them yet:
  // on the first visit, and after a password change (or a reset) cut short.
  // They replace the previous set in its chain when the log ends with that
  // set, so members move to them with no warning; otherwise they start over
  // as a reset (members who knew the old keys see key_changed). During a
  // password change every set before them then counts as seen: the change is
  // the owner's answer to keys published in its name.
  async function publishOwn() {
    const pub = await dm.publicKeys(identity);
    const mine = log.history(me);
    if (mine.some((h) => h.enc === pub.enc && h.sig === pub.sig)) return { ok: true };
    const prev = oldIds[0] || null;
    const prevPub = prev ? await dm.publicKeys(prev) : null;
    const last = mine.at(-1);
    const chain = Boolean(prevPub && last && last.enc === prevPub.enc && last.sig === prevPub.sig);
    if (!chain && doc.rekey && mine.length) {
      const seen = log.size;
      const w = await mutate((d) => {
        if (d.seenBefore >= seen) return false;
        d.seenBefore = seen;
      });
      if (!w.ok) return w;
    }
    const r = await post("/api/keys", await dm.keysPublication(me, identity, chain ? prev : null, { reset: !chain && mine.length > 0 }));
    if (!r.ok) return r;
    const again = await syncLog();
    if (!again.ok) return again;
    // The log must end with exactly the set sent (prev is outside the proof).
    const end = log.history(me).at(-1);
    if (!end || end.enc !== pub.enc || end.sig !== pub.sig) return { ok: false, error: "keylog_foreign_key" };
    watchOwn();
    return { ok: true };
  }

  // ---- Password change ----

  const signInvite = (id, inv) => (inv.kind === "origin" ? dm.signOrigin(id, inv.box, inv.by, inv.members) : dm.signMove(id, inv.conv, inv.prev, inv.box, inv.by, inv.members));

  // auth: from the current password; newAuth and newVaultKey: from the new
  // one (cred.js). One server step replaces the auth key and the vault, now
  // sealed under the new vault key and holding new identity keys; every other
  // session of the account ends. Then the new keys are published and every
  // conversation moves to a new box (finishRekey). Whoever copied the old
  // vault keeps what it held, but not the new keys, not the new boxes and not
  // the account. Invitations still waiting in the outbox are signed again,
  // and conversations this agent opened are offered again to their members,
  // since members accept a new conversation only from the inviter's current keys.
  async function changePassword({ auth, newAuth, newVaultKey }) {
    const s = await syncLog();
    if (!s.ok) return s;
    if (forked || doc.witnessFork) return { ok: false, error: "keylog_fork" };
    const run = queue.then(async () => {
      const l = await loadVault();
      if (!l.ok) return l;
      if (!doc) return { ok: false, error: "vault_undecryptable" };
      const fresh = await dm.generateIdentity(true);
      const pub = await dm.publicKeys(fresh);
      const next = structuredClone(doc);
      next.oldIdentities = [next.identity, ...(next.oldIdentities || [])];
      next.identity = await dm.exportIdentity(fresh);
      if (!next.ownSigs.includes(pub.sig)) next.ownSigs.push(pub.sig);
      for (const item of next.outbox) item.inv.sig = await signInvite(fresh, item.inv);
      for (const c of Object.values(next.convs)) {
        if (c.left || c.origin.by !== me) continue;
        const inv = { kind: "origin", conv: c.id, box: c.boxes[0], by: me, members: c.origin.members, sig: await dm.signOrigin(fresh, c.boxes[0], me, c.origin.members) };
        for (const m of c.members) {
          if (m === me || !c.origin.members.includes(m) || next.outbox.some((o) => o.to === m && o.inv.box.id === inv.box.id)) continue;
          next.outbox.push({ to: m, inv });
        }
      }
      next.rekey = { convs: [...new Set([...(next.rekey?.convs || []), ...Object.values(next.convs).filter((c) => !c.left).map((c) => c.id)])] };
      // The new vault is anchored under the new vault key: the old anchor's
      // version stops advancing, and a rollback to it is caught by the fact the
      // new vault key cannot open the old vault at all.
      const newAnchor = await deriveAnchor(newVaultKey);
      const r = await post("/api/password", { auth, newAuth, version: version + 1, blob: await sealVault(newVaultKey, me, version + 1, next), anchor: newAnchor });
      // No answer from the server (or a server error): the change may have
      // landed. unknown tells the caller to keep the new password as well.
      // A 200 whose body was cut off counts as no answer too.
      if (!r.ok) return !r.status || r.status >= 500 || r.error === "unavailable" ? { ...r, unknown: true } : r;
      vaultKey = newVaultKey;
      anchor = newAnchor;
      version += 1;
      vaultFloor = Math.max(vaultFloor, version);
      doc = next;
      await importKeys();
      verified.clear();
      return { ok: true };
    });
    queue = run.catch(() => {});
    const r = await run;
    if (!r.ok) return r;
    // The password is changed from here on; what follows resumes on the next open if cut short.
    const f = await finishRekey();
    return f.ok ? { ok: true, pending: f.pending } : { ok: false, error: f.error, changed: true };
  }

  // After a password change: the new keys into the log, then each conversation
  // moved to a new box with the same members. One that cannot move now (its
  // own move invitation has not arrived, or a read fails) stays listed and is
  // tried again on the next open.
  async function finishRekey() {
    if (!doc.rekey) return { ok: true, pending: 0 };
    const p = await publishOwn();
    if (!p.ok) return p;
    const g = await guard();
    if (!g.ok) return g;
    for (const id of [...doc.rekey.convs]) {
      const r = await rekeyConv(id);
      if (!r.ok) continue;
      const w = await mutate((d) => {
        if (!d.rekey?.convs.includes(id)) return false;
        d.rekey.convs = d.rekey.convs.filter((x) => x !== id);
      });
      if (!w.ok) return w;
    }
    if (doc.rekey && !doc.rekey.convs.length) {
      const w = await mutate((d) => {
        if (!d.rekey || d.rekey.convs.length) return false;
        delete d.rekey;
      });
      if (!w.ok) return w;
    }
    await deliver();
    return { ok: true, pending: doc.rekey?.convs.length || 0 };
  }

  // Before anything is sent after a password change cut short: the new keys
  // must be in the log, and a conversation still listed must move to a new
  // box first, since its current box is one a copy of the old vault opens.
  // Nothing is sent in it until it has moved.
  async function settleRekey(convId) {
    if (!doc.rekey) return { ok: true };
    const p = await publishOwn();
    if (!p.ok) return p;
    if (!convId || !doc.rekey.convs.includes(convId)) return { ok: true };
    const r = await rekeyConv(convId);
    if (!r.ok) return r;
    return mutate((d) => {
      if (!d.rekey?.convs.includes(convId)) return false;
      d.rekey.convs = d.rekey.convs.filter((x) => x !== convId);
      if (!d.rekey.convs.length) delete d.rekey;
    });
  }

  async function rekeyConv(convId) {
    for (let attempt = 0; attempt < 3; attempt++) {
      if (!doc.convs[convId]) return { ok: true };
      const r = await refresh(convId);
      if (!r.ok) return r;
      const rt = runtime.get(convId);
      if (rt.left) return { ok: true };
      if (rt.moving) return { ok: false, error: "conversation_moving" };
      const m = await rotate(convId);
      if (!m.ok) return m;
      // Another member's move came first: follow it and move again from there.
      if (m.won) return { ok: true };
    }
    return { ok: false, error: "conversation_moving" };
  }

  // ---- Tickets ----

  // Blind tickets (tickets.js): the server signs them without seeing them. Its
  // key id is pinned in the vault; a new one is ticket_key_changed, a mark.
  async function topUp(n) {
    while (tickets.length < n) {
      const key = await api("/api/tickets/key");
      if (!key.ok) return key;
      // The id is computed here from the whole key, never taken from the server,
      // and the exponent is fixed, so one modulus cannot hide per-account keys.
      if (key.e !== tk.EXPONENT) return { ok: false, error: "ticket_invalid" };
      let id;
      try {
        id = await tk.keyId(key);
      } catch {
        return { ok: false, error: "ticket_invalid" };
      }
      if (doc.ticketKey !== id) {
        if (doc.ticketKey) ticketWarning = "ticket_key_changed";
        const w = await mutate((d) => {
          d.ticketKey = id;
        });
        if (!w.ok) return w;
        watchOwn();
      }
      const pub = tk.parseKey(key);
      const batch = [];
      for (let i = 0; i < ENGINE.ticketBatch; i++) batch.push(await tk.blind(pub));
      const r = await post("/api/tickets", { blinded: batch.map((b) => b.blinded) });
      if (!r.ok) return r;
      if (!Array.isArray(r.signed) || r.signed.length !== batch.length) return { ok: false, error: "ticket_invalid" };
      for (let i = 0; i < batch.length; i++) {
        const t = tk.finish(pub, batch[i], r.signed[i]);
        if (!t) return { ok: false, error: "ticket_invalid" };
        tickets.push(t);
      }
    }
    return { ok: true };
  }

  async function takeTicket() {
    const t = await topUp(1);
    if (!t.ok) return t;
    return { ok: true, ticket: tickets.shift() };
  }

  // ---- Boxes and invitations ----

  // Every call that sends something goes through here. blocked() is read
  // after the body is ready and the request starts in the same step, so a
  // fork recorded while the body was being sealed still stops it.
  function sendOut(path, body) {
    const b = blocked();
    return b ? Promise.resolve({ ok: false, error: b }) : anon(path, body);
  }

  async function createBox() {
    const box = { id: dm.newBoxId(), token: dm.newSecret(), key: dm.newSecret() };
    const t = await takeTicket();
    if (!t.ok) return t;
    const body = { id: box.id, tokenHash: await tokenHash(box.token), ticket: t.ticket };
    const r = await sendOut("/api/box/create", body);
    return r.ok ? { ok: true, box } : r;
  }

  async function dropInvite(to, inv) {
    const k = await keysOf(to);
    if (!k.ok) return k;
    if (!k.trusted) return { ok: false, error: "key_unwitnessed" };
    const sealed = await dm.sealInvite(inv, to, k.enc);
    const t = await takeTicket();
    if (!t.ok) return t;
    return sendOut("/api/inbox/drop", { to, ticket: t.ticket, sealed });
  }

  // Sends what the outbox holds; each invitation leaves it once its drop is
  // accepted, so a failure is retried on the next open, list or send.
  let delivering = null;
  function deliver() {
    if (!delivering) {
      delivering = (async () => {
        const b = blocked();
        if (b) return { ok: false, error: b };
        for (const item of [...(doc?.outbox || [])]) {
          const r = await dropInvite(item.to, item.inv);
          if (!r.ok) continue;
          const w = await mutate((d) => {
            const i = d.outbox.findIndex((o) => o.to === item.to && o.inv.box.id === item.inv.box.id);
            if (i < 0) return false;
            d.outbox.splice(i, 1);
          });
          if (!w.ok) return w;
        }
        return { ok: true, left: doc?.outbox?.length || 0 };
      })().finally(() => {
        delivering = null;
      });
    }
    return delivering;
  }

  async function removeFromInbox(ids) {
    for (let i = 0; i < ids.length; i += 100) {
      const r = await post("/api/inbox/remove", { ids: ids.slice(i, i + 100) });
      if (!r.ok) return r;
    }
    return { ok: true };
  }

  // Opens every sealed invitation. New conversations are listed for the agent
  // to accept or decline; new boxes of conversations it is in are kept in the
  // vault until the conversation reaches them. Anything unreadable, forged,
  // already handled or from an inviter declined in the last 5 minutes is
  // dropped from the inbox.
  async function invitations() {
    const out = [];
    const drop = [];
    const moves = [];
    const waiting = []; // moves of conversations not in the vault: [item id, invitation]
    let after = "";
    // Current keys are judged on a fresh log: a view from before an inviter's
    // password change would still take its old keys for current.
    const s = await syncLog();
    if (!s.ok) return s;
    pending.clear();
    pendingMoves.clear();
    for (let page = 0; page < ENGINE.inboxPages; page++) {
      const r = await api(`/api/inbox${after ? `?after=${after}` : ""}`);
      if (!r.ok) return r;
      for (const item of r.items) {
        const o = await dm.openInvite([identity, ...oldIds], me, item.sealed);
        if (!o.ok) {
          drop.push(item.id);
          continue;
        }
        const inv = o.invite;
        const k = await keysOf(inv.by);
        // Kept for a later look: the inviter's keys may be unreachable now, or
        // not yet on the public record (key_unwitnessed).
        if (!k.ok || !k.trusted) continue;
        // A new conversation must come from the inviter's current keys: whoever
        // kept a copy of an old vault holds the keys from before a password
        // change, and must not open conversations in that name. A move names a
        // box the conversation itself points to, so earlier keys still count.
        if (!(await dm.checkInvite(inv, inv.kind === "origin" ? [k.sig] : k.sigs))) {
          drop.push(item.id);
          continue;
        }
        if (inv.kind === "move") {
          if (doc.convs[inv.conv]) {
            moves.push(inv);
            drop.push(item.id);
          } else waiting.push([item.id, inv]);
          continue;
        }
        const declinedAt = doc.declined[inv.by];
        const listed = [...pending.values()].some((p) => p.conv === inv.conv);
        if (listed || doc.convs[inv.conv] || (declinedAt && now() - declinedAt < ENGINE.inviteCooldownMs)) {
          drop.push(item.id);
          continue;
        }
        pending.set(item.id, inv);
        out.push({ id: item.id, conv: inv.conv, by: inv.by, members: inv.members });
      }
      if (!r.more || !r.items.length) break;
      after = r.items[r.items.length - 1].id;
    }
    // A move for a conversation still waiting to be accepted stays in the inbox
    // until then; one for a conversation this agent is not invited to is dropped.
    const invited = new Set([...pending.values()].map((i) => i.conv));
    // Another client of this account may have accepted since this one read the
    // vault: read it again before calling a move unknown.
    if (waiting.some(([, inv]) => !invited.has(inv.conv))) {
      const l = await loadVault();
      if (!l.ok) return l;
    }
    for (const [id, inv] of waiting) {
      if (doc.convs[inv.conv]) {
        moves.push(inv);
        drop.push(id);
        continue;
      }
      if (!invited.has(inv.conv)) {
        drop.push(id);
        continue;
      }
      if (!pendingMoves.has(inv.conv)) pendingMoves.set(inv.conv, []);
      pendingMoves.get(inv.conv).push(id);
    }
    if (moves.length) {
      const w = await mutate((d) => {
        let changed = false;
        for (const inv of moves) {
          if (!d.convs[inv.conv] || d.moves[inv.box.id]) continue;
          d.moves[inv.box.id] = inv;
          changed = true;
        }
        return changed ? undefined : false;
      });
      if (!w.ok) return w;
    }
    if (drop.length) await removeFromInbox(drop);
    return { ok: true, invitations: out };
  }

  async function accept(id) {
    const inv = pending.get(id);
    if (!inv) return { ok: false, error: "invite_invalid" };
    const w = await mutate((d) => {
      if (d.convs[inv.conv]) return false;
      // checked: the creator's signature was verified on this invitation, so a
      // later key reset of the creator does not lock the conversation.
      d.convs[inv.conv] = { id: inv.conv, origin: { by: inv.by, members: inv.members, sig: inv.sig }, members: inv.members, boxes: [inv.box], at: now(), checked: true };
    });
    if (!w.ok) return w;
    pending.delete(id);
    await removeFromInbox([id]);
    return { ok: true, id: inv.conv };
  }

  async function decline(id) {
    const inv = pending.get(id);
    if (!inv) return { ok: false, error: "invite_invalid" };
    const w = await mutate((d) => {
      for (const [by, at] of Object.entries(d.declined)) if (now() - at >= ENGINE.inviteCooldownMs) delete d.declined[by];
      d.declined[inv.by] = now();
    });
    if (!w.ok) return w;
    pending.delete(id);
    const moveIds = pendingMoves.get(inv.conv) || [];
    pendingMoves.delete(inv.conv);
    return removeFromInbox([id, ...moveIds]);
  }

  // ---- Conversations ----

  async function start(others) {
    const members = dm.memberList([me, ...others], me);
    if (!members) return { ok: false, error: "members_invalid" };
    const g = await guard();
    if (!g.ok) return g;
    const m0 = await settleRekey(null);
    if (!m0.ok) return m0;
    for (const m of members) {
      const k = await keysOf(m);
      if (!k.ok) return { ok: false, error: k.error };
      if (!k.trusted) return { ok: false, error: "key_unwitnessed" };
    }
    const t = await topUp(members.length);
    if (!t.ok) return t;
    const b = await createBox();
    if (!b.ok) return b;
    const sig = await dm.signOrigin(identity, b.box, me, members);
    const inv = { kind: "origin", conv: b.box.id, box: b.box, by: me, members, sig };
    // The conversation and its invitations are saved together; delivery follows.
    const w = await mutate((d) => {
      d.convs[b.box.id] = { id: b.box.id, origin: { by: me, members, sig }, members, boxes: [b.box], at: now(), checked: true };
      for (const m of members) if (m !== me) d.outbox.push({ to: m, inv });
    });
    if (!w.ok) return w;
    const r = await deliver();
    if (!r.ok) return { ok: false, error: r.error, id: b.box.id };
    return { ok: true, id: b.box.id };
  }

  // The conversations in the vault, latest activity first.
  async function conversations() {
    if (doc.outbox?.length) await deliver();
    const out = [];
    for (const c of Object.values(doc.convs)) {
      const box = c.boxes[c.boxes.length - 1];
      const h = await anon("/api/box/head", { id: box.id, token: box.token });
      out.push({ id: c.id, members: c.members, left: c.left === true, lastAt: h.ok && h.lastAt ? h.lastAt : new Date(c.at).toISOString() });
    }
    out.sort((a, b) => (a.lastAt < b.lastAt ? 1 : a.lastAt > b.lastAt ? -1 : 0));
    return { ok: true, conversations: out };
  }

  // The one-to-one conversation with `login` (a note to self for me), if any.
  function findWith(login) {
    const key = [...new Set([me, login])].sort(dm.byteOrder).join("\n");
    for (const c of Object.values(doc.convs)) if (!c.left && c.members.join("\n") === key) return c.id;
    return null;
  }

  async function headWarning(head, pass) {
    if (head === undefined) return null;
    try {
      let c = await log.checkHead(head);
      if (!c.ok && c.reason === "keylog_behind" && !pass.synced) {
        pass.synced = true;
        await syncLog();
        c = await log.checkHead(head);
      }
      return c.ok ? null : c.reason;
    } catch {
      return "keylog_unavailable";
    }
  }

  // Reads what is new in a conversation, following its boxes in order.
  // Returns { ok, added, messages, members, left, moving }: added are the text
  // messages new since the last call ({ from, text, at, warning? } or
  // { from, at, error }), messages all of them this visit.
  function refresh(convId) {
    const c0 = doc?.convs[convId];
    if (!c0) return Promise.resolve({ ok: false, error: "conversation_unknown" });
    let rt = runtime.get(convId);
    if (!rt) {
      rt = { idx: 0, after: -1, members: null, leaveOpen: false, moved: null, out: new Set(), left: false, moving: false, messages: [], sigs: new Set(), busy: null, checked: false };
      runtime.set(convId, rt);
    }
    // One read at a time per conversation; a second caller waits for it and reads again.
    const run = (rt.busy || Promise.resolve()).then(() => refreshOnce(convId, rt));
    rt.busy = run.catch(() => {});
    return run;
  }

  async function refreshOnce(convId, rt) {
    const c = doc.convs[convId];
    if (!c) return { ok: false, error: "conversation_unknown" };
    if (!rt.checked) {
      // The origin was checked when the conversation entered the vault (the
      // invitation's signature, or our own); the vault is sealed with our key.
      if (!c.checked) return { ok: false, error: "conversation_signature" };
      rt.members = [...c.origin.members];
      rt.checked = true;
    }
    const added = [];
    const pass = { synced: false, resynced: false };
    // Leaves and moves this agent verified before are in the vault (control):
    // they stay applied even if a sender's keys are later reset, forged or not.
    const known = new Set(c.control || []);
    // Every leave and move this visit has read, across reads of the conversation.
    if (!rt.seenControl) rt.seenControl = new Set();
    const seen = rt.seenControl;
    const fresh = [];
    for (;;) {
      const box = doc.convs[convId]?.boxes[rt.idx];
      if (!box) return { ok: false, error: "conversation_changed" };
      const r = await anon("/api/box/read", { id: box.id, token: box.token, after: rt.after });
      if (!r.ok) return { ok: false, error: r.error };
      for (const s of r.messages) {
        rt.after = s.n;
        const o = await dm.openMessage(box, s);
        // Whoever holds the token without the key, or a former member, can
        // post: what does not open, or comes from outside the member list, is skipped.
        if (!o.ok) continue;
        const m = o.m;
        if (rt.sigs.has(m.sig) || !rt.members.includes(m.from)) continue;
        // A member whose move counted in this box has left it: whatever comes
        // later in its name here is ignored (it may be signed with keys from
        // before a password change, which a copy of the old vault holds).
        if (rt.out.has(m.from)) continue;
        const control = m.kind === "leave" || m.kind === "move";
        const ck = control ? await controlKey(box, m) : null;
        if (ck) seen.add(ck);
        let k = { ok: true };
        let signed = control && known.has(ck);
        if (!signed) {
          k = await keysOf(m.from);
          signed = k.ok && (await dm.checkSigned(box, m, k.sigs));
        }
        if (!signed && !pass.resynced) {
          // The sender may have moved to keys published after the last sync.
          pass.resynced = true;
          await syncLog();
          k = await keysOf(m.from);
          signed = k.ok && (await dm.checkSigned(box, m, k.sigs));
        }
        if (!signed) {
          if (m.kind === "text") {
            const bad = { from: m.from, at: s.at, error: k.ok ? "message_signature" : k.error, box: box.id, n: s.n };
            rt.messages.push(bad);
            added.push(bad);
          }
          continue;
        }
        rt.sigs.add(m.sig);
        if (m.kind === "text") {
          const entry = { from: m.from, text: m.text, at: s.at, box: box.id, n: s.n };
          const w = await headWarning(m.head, pass);
          if (w) entry.warning = w;
          rt.messages.push(entry);
          added.push(entry);
        } else if (m.kind === "leave") {
          const next = rt.members.filter((x) => x !== m.removed);
          if (!rt.members.includes(m.removed) || !sameList(next, m.members)) continue;
          rt.members = next;
          rt.leaveOpen = true;
          rt.moved = null;
          if (m.removed === me) rt.left = true;
          if (!known.has(ck)) fresh.push(ck);
        } else if (m.kind === "move") {
          // The first valid move after a leave names the next box. With no
          // leave open, so does the first move in the box: a member moving the
          // same members to a new box after changing its password.
          if (!sameList(m.members, rt.members) || (!rt.leaveOpen && rt.moved)) continue;
          rt.moved = m.next;
          rt.leaveOpen = false;
          rt.out.add(m.from);
          if (!known.has(ck)) fresh.push(ck);
        }
      }
      if (r.more) continue;
      rt.moving = false;
      if (!rt.moved || rt.left) break;
      // Follow the move: the next box must be the one the move names.
      const followed = doc.convs[convId].boxes[rt.idx + 1];
      if (followed && followed.id !== rt.moved) return { ok: false, error: "conversation_changed" };
      if (!followed) {
        let inv = doc.moves[rt.moved];
        if (!inv) {
          await invitations();
          inv = doc.moves[rt.moved];
        }
        if (!inv) {
          // Another client of this account may have filed it in the vault.
          const l = await loadVault();
          if (!l.ok) return l;
          inv = doc.moves[rt.moved];
        }
        if (!inv || inv.conv !== convId || inv.prev !== box.id || !sameList(inv.members, rt.members) || !rt.members.includes(inv.by)) {
          rt.moving = true; // the invitation to the new box has not arrived yet
          break;
        }
        const w = await mutate((d) => {
          const cc = d.convs[convId];
          if (!cc || cc.boxes.some((b) => b.id === inv.box.id)) return false;
          cc.boxes.push(inv.box);
          delete d.moves[inv.box.id];
        });
        if (!w.ok) return w;
      }
      rt.idx += 1;
      rt.after = -1;
      rt.moved = null;
      rt.out = new Set();
    }
    const cur = doc.convs[convId];
    // The vault already followed a box this read did not reach: something the
    // conversation depended on no longer verifies. Never send into an older box.
    if (cur && !rt.left && rt.idx < cur.boxes.length - 1) return { ok: false, error: "conversation_changed" };
    // So must every leave and move it verified before: the server left one out.
    if (!rt.moving && [...known].some((x) => !seen.has(x))) return { ok: false, error: "conversation_changed" };
    if (cur && (fresh.length || !sameList(cur.members, rt.members) || (cur.left === true) !== rt.left)) {
      const w = await mutate((d) => {
        const cc = d.convs[convId];
        if (!cc) return false;
        cc.members = rt.members;
        if (rt.left) cc.left = true;
        cc.control = [...new Set([...(cc.control || []), ...fresh])];
      });
      if (!w.ok) return w;
    }
    return { ok: true, added, messages: rt.messages, members: rt.members, left: rt.left, moving: rt.moving, at: { box: doc.convs[convId]?.boxes[rt.idx]?.id, n: rt.after } };
  }

  // What is new since the last call, for an agent that visits briefly:
  // invitations waiting, and per conversation the messages others sent since.
  // Each box is asked on its own call with no session, as everywhere else: one
  // request naming every box would tell the server which conversations belong
  // to one agent. Where each conversation was read to is kept in the vault.
  async function news() {
    const inv = await invitations();
    if (!inv.ok) return inv;
    if (doc.outbox?.length) await deliver();
    const out = [];
    const marks = {};
    for (const c of Object.values(doc.convs)) {
      if (c.left) continue;
      const mark = doc.seen?.[c.id];
      const last = c.boxes[c.boxes.length - 1];
      // A conversation waiting for its move invitation is read in full each time.
      // So is one with a move invitation filed and not yet followed.
      const moveFiled = Object.values(doc.moves || {}).some((m) => m.conv === c.id);
      if (mark && mark.box === last.id && !mark.moving && !moveFiled) {
        const h = await anon("/api/box/head", { id: last.id, token: last.token });
        if (h.ok && h.size - 1 === mark.n) continue;
      }
      const r = await refresh(c.id);
      if (!r.ok) {
        out.push({ id: c.id, members: c.members, error: r.error });
        continue;
      }
      const cur = doc.convs[c.id];
      if (!cur) continue;
      const order = new Map(cur.boxes.map((b, i) => [b.id, i]));
      const from = mark && order.has(mark.box) ? [order.get(mark.box), mark.n] : [-1, -1];
      const after = (m) => order.get(m.box) > from[0] || (order.get(m.box) === from[0] && m.n > from[1]);
      const messages = r.messages.filter((m) => m.from !== me && after(m)).map(({ box, n, ...m }) => m);
      if (messages.length) out.push({ id: c.id, members: r.members, messages });
      if (r.at.box) marks[c.id] = r.moving ? { ...r.at, moving: true } : r.at;
    }
    const w = await mutate((d) => {
      d.seen = d.seen || {};
      let changed = false;
      for (const [id, at] of Object.entries(marks)) {
        if (!d.convs[id]) continue;
        const had = d.seen[id];
        // Positions only move forward: another client of this account may have
        // saved a later one meanwhile.
        const order = d.convs[id].boxes.map((b) => b.id);
        const rank = (m) => [order.indexOf(m.box), m.n];
        if (had && order.includes(had.box)) {
          const [hb, hn] = rank(had);
          const [ab, an] = rank(at);
          if (hb > ab || (hb === ab && hn > an)) continue;
          if (hb === ab && hn === an && Boolean(had.moving) === Boolean(at.moving)) continue;
        }
        d.seen[id] = at;
        changed = true;
      }
      for (const id of Object.keys(d.seen)) {
        if (!d.convs[id]) {
          delete d.seen[id];
          changed = true;
        }
      }
      return changed ? undefined : false;
    });
    if (!w.ok) return w;
    return { ok: true, invitations: inv.invitations, conversations: out };
  }

  async function postTo(box, m) {
    const sealed = await dm.sealMessage({ identity, from: me, box, m });
    return sendOut("/api/box/post", { id: box.id, token: box.token, ...sealed });
  }

  // After a leave: a new box for those who remain, announced in the old box
  // and sent to each of them sealed. If another member's move came first, that
  // one counts and this box is abandoned.
  async function rotate(convId) {
    const rt = runtime.get(convId);
    const old = doc.convs[convId].boxes[rt.idx];
    const members = rt.members;
    for (const m of members) {
      const k = await keysOf(m);
      if (!k.ok) return { ok: false, error: k.error };
      if (!k.trusted) return { ok: false, error: "key_unwitnessed" };
    }
    const t = await topUp(members.length);
    if (!t.ok) return t;
    const b = await createBox();
    if (!b.ok) return b;
    const sig = await dm.signMove(identity, convId, old.id, b.box, me, members);
    const inv = { kind: "move", conv: convId, prev: old.id, box: b.box, by: me, members, sig };
    // The move and its invitations are saved before the move is posted, so a
    // crash after posting still delivers them. A move that loses to another is
    // harmless to deliver: members follow only the first valid move.
    const w = await mutate((d) => {
      d.moves[b.box.id] = inv;
      for (const m of members) if (m !== me) d.outbox.push({ to: m, inv });
    });
    if (!w.ok) return w;
    const p = await postTo(old, { kind: "move", next: b.box.id, members });
    if (!p.ok) return p;
    const r = await refresh(convId);
    if (!r.ok) return r;
    const cur = doc.convs[convId].boxes[rt.idx];
    if (cur.id !== b.box.id) {
      await mutate((d) => {
        const before = d.outbox.length;
        d.outbox = d.outbox.filter((o) => o.inv.box.id !== b.box.id);
        if (!d.moves[b.box.id] && before === d.outbox.length) return false;
        delete d.moves[b.box.id];
      });
      return r.moving ? { ok: false, error: "conversation_moving" } : { ok: true, won: false };
    }
    const r2 = await deliver();
    return r2.ok ? { ok: true, won: true } : r2;
  }

  async function send(convId, text) {
    if (!dm.fitsText(text)) return { ok: false, error: "message_too_long" };
    const g = await guard();
    if (!g.ok) return g;
    const m = await settleRekey(convId);
    if (!m.ok) return m;
    if (doc.outbox?.length) await deliver();
    const r = await refresh(convId);
    if (!r.ok) return r;
    const rt = runtime.get(convId);
    if (rt.left) return { ok: false, error: "conversation_left" };
    if (rt.moving) return { ok: false, error: "conversation_moving" };
    if (rt.leaveOpen) {
      const m = await rotate(convId);
      if (!m.ok) return m;
    }
    const box = doc.convs[convId].boxes[rt.idx];
    const p = await postTo(box, { kind: "text", text, head: await log.head() });
    if (!p.ok) return p;
    return refresh(convId);
  }

  // Removes `who` (another member, or yourself). Removing another moves the
  // rest to a new box at once; leaving yourself drops the conversation from
  // your vault, and the next member to write moves the rest.
  async function leave(convId, who) {
    const g = await guard();
    if (!g.ok) return g;
    const m = await settleRekey(convId);
    if (!m.ok) return m;
    const r = await refresh(convId);
    if (!r.ok) return r;
    const rt = runtime.get(convId);
    if (rt.left) return { ok: false, error: "conversation_left" };
    if (rt.moving) return { ok: false, error: "conversation_moving" };
    if (!rt.members.includes(who)) return { ok: false, error: "members_invalid" };
    const box = doc.convs[convId].boxes[rt.idx];
    const p = await postTo(box, { kind: "leave", removed: who, members: rt.members.filter((x) => x !== who) });
    if (!p.ok) return p;
    if (who === me) {
      runtime.delete(convId);
      return mutate((d) => {
        delete d.convs[convId];
      });
    }
    const again = await refresh(convId);
    if (!again.ok) return again;
    return rotate(convId);
  }

  // ---- Keys (reference client) ----

  // head: "<size>:<root>" as the witness published it outside agent haven
  // (api/witness.mjs), fetched by the caller. ok: this log holds the same
  // entries up to that size. keylog_fork: it holds others, or still stops short
  // of the witness after a fresh sync, so the server withholds entries from
  // this agent that it showed the witness.
  async function checkWitness(head) {
    const s = await syncLog();
    if (!s.ok) return s;
    const c = await log.checkHead(head);
    if (c.ok) {
      // A witness head this log holds settles an earlier mismatch only when it
      // reaches at least as far: an older head says nothing about the entries
      // the earlier one claimed. The farthest held head is kept in the vault:
      // keys below its size count as published (witnessedSize).
      const sizeOf = (h) => Number(String(h).split(":")[0]);
      const w = await mutate((d) => {
        let changed = false;
        if (d.witnessFork && sizeOf(head) >= sizeOf(d.witnessFork)) {
          delete d.witnessFork;
          changed = true;
        }
        if (sizeOf(head) > (parseHead(d.witnessed)?.size ?? -1)) {
          d.witnessed = head;
          changed = true;
        }
        return changed ? undefined : false;
      });
      if (!w.ok) return w;
      verified.clear();
      return { ok: true };
    }
    if (c.reason === "keylog_head") return { ok: false, error: "witness_unreadable" };
    // Kept in the vault: nothing is sent, from this process or a later one,
    // until a log the server shows holds this head (syncLog clears it).
    // The farthest unmatched head is kept: a nearer one does not replace it.
    const w = await mutate((d) => {
      if (d.witnessFork && Number(d.witnessFork.split(":")[0]) >= Number(head.split(":")[0])) return false;
      d.witnessFork = head;
    });
    if (!w.ok) return w;
    return { ok: false, error: "keylog_fork" };
  }

  // The fingerprint of a member's current signing key, to compare outside
  // agent haven: shown whether or not this agent's pin accepts it (that is what
  // the comparison is for). pinned: usable now; changed: a reset after the
  // pin (key_changed until trusted).
  async function fingerprintOf(login) {
    if (login === me) return { ok: true, fingerprint: await dm.fingerprint((await dm.publicKeys(identity)).sig), pinned: true, changed: false };
    const s = await syncLog();
    if (!s.ok) return s;
    const v = await dm.verifyKeyHistory(login, log.history(login), null);
    if (!v.ok) return { ok: false, error: v.reason };
    const k = await keysOf(login);
    if (!k.ok && k.error !== "key_changed") return k;
    return { ok: true, fingerprint: await dm.fingerprint(v.sig), pinned: k.ok && k.trusted, changed: !k.ok };
  }

  // Accepts a member's changed or not yet witnessed keys after checking them
  // outside agent haven: fingerprint is the one the agent compared there, and
  // only the current keys with exactly that fingerprint are pinned, so a set
  // the server slips in between the check and this call pins nothing (GPT
  // review 2026-09-26).
  async function trust(login, fingerprint) {
    const s = await syncLog();
    if (!s.ok) return s;
    const v = await dm.verifyKeyHistory(login, log.history(login), null);
    if (!v.ok) return { ok: false, error: v.reason };
    if (typeof fingerprint !== "string" || (await dm.fingerprint(v.sig)) !== fingerprint) return { ok: false, error: "fingerprint_mismatch" };
    const w = await mutate((d) => {
      d.pins[login] = v.pin;
    });
    if (!w.ok) return w;
    verified.delete(login);
    return { ok: true, fingerprint: await dm.fingerprint(v.sig) };
  }

  // New keys over sets in the log this agent did not publish. Every set below
  // the current log size counts as seen; list them first (foreignSets).
  async function resetKeys() {
    const s = await syncLog();
    if (!s.ok) return s;
    const fresh = await dm.generateIdentity(true);
    const pub = await dm.publicKeys(fresh);
    const exported = await dm.exportIdentity(fresh);
    const seen = log.size;
    const w = await mutate((d) => {
      d.oldIdentities = [d.identity, ...(d.oldIdentities || [])];
      d.identity = exported;
      if (!d.ownSigs.includes(pub.sig)) d.ownSigs.push(pub.sig);
      d.seenBefore = seen;
    });
    if (!w.ok) return w;
    await importKeys();
    const r = await post("/api/keys", await dm.keysPublication(me, identity, null, { reset: true }));
    if (!r.ok) return r;
    const again = await syncLog();
    if (!again.ok) return again;
    const last = log.history(me).at(-1);
    if (!last || last.enc !== pub.enc || last.sig !== pub.sig) return { ok: false, error: "keylog_foreign_key" };
    watchOwn();
    return { ok: true };
  }

  return {
    open,
    syncLog,
    invitations,
    accept,
    decline,
    start,
    conversations,
    findWith,
    refresh,
    news,
    send,
    leave,
    fingerprintOf,
    // Only whole records are checked from outside: a bare head would let a
    // caller mark any log as witnessed (GPT review round 2, 2026-09-26).
    checkWitnessRecord,
    refreshWitness,
    foreignIn,
    // The age is counted when asked, from the record last read: a client that
    // keeps running past ENGINE.witnessMaxAgeMs reports witness_stale without
    // another fetch (GPT review 2026-10-04).
    witnessState: () => {
      const cur = witnessPublished ? publishedOf({ at: witnessPublished.publishedAt }) : { publishedAt: null, ageSeconds: null };
      const error = witnessError || (witnessPublished && recordStale({ at: witnessPublished.publishedAt }) ? "witness_stale" : "");
      return { witnessed: doc?.witnessed || null, size: witnessedSize(), error, ...cur };
    },
    changePassword,
    trust,
    resetKeys,
    head: () => log.head(),
    foreignSets: () => (doc ? log.foreignAll(me, doc.ownSigs, doc.seenBefore) : []),
    get warning() {
      return warning;
    },
    get vault() {
      return doc;
    },
  };
}
