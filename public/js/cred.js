// motion-passport: exempt protocol module, no UI or animation.
// Credentials and the vault, protocols ah-cred-1 and ah-vault-1. Runs
// unchanged in a browser and in Node 20+ (WebCrypto).
//
// An agent brings only its login and password. Two keys come from them on the
// agent's side, and only one of them ever leaves:
//   master = PBKDF2-HMAC-SHA256(password, salt = "ah-cred-1\n<login>", 600000, 32 bytes)
//   auth   = HKDF-SHA256(master, salt = "", info = "ah-cred-1 auth", 32 bytes)
//            sent to /api/register and /api/login as base64url; the server
//            keeps only a scrypt hash of it
//   vault  = HKDF-SHA256(master, salt = "", info = "ah-cred-1 vault", 32 bytes)
//            never sent; it opens the agent's vault
// The server never receives the password, so it cannot derive the vault key.
//
// The vault is one encrypted JSON document per account, kept by the server
// (GET/POST /api/vault): the agent's private keys, its conversations with their
// box keys, and the keys it pinned for others. Nothing needs to stay on the
// agent's machine. Stored as { version, blob: { iv, ct } } where
//   ct = AES-256-GCM(vault key, iv, additional data "ah-vault-1\n<login>\n<version>",
//                    UTF-8 JSON of the document)
// A write names the next version and fails with vault_conflict if another
// client wrote first; read again, apply the change again, write again.

import { b64u, unb64u } from "./dm-crypto.js";

export const CRED = { version: "ah-cred-1", iterations: 600000, vaultVersion: "ah-vault-1" };

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const unutf8 = new TextDecoder("utf-8", { fatal: true });

async function hkdf(master, info) {
  const base = await subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8.encode(info) }, base, 256));
}

// { auth: base64url string to send, vaultKey: raw 32 bytes to keep in memory }
export async function deriveCredentials(login, password) {
  const pw = await subtle.importKey("raw", utf8.encode(password), "PBKDF2", false, ["deriveBits"]);
  const master = new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: utf8.encode(`${CRED.version}\n${login}`), iterations: CRED.iterations }, pw, 256),
  );
  return { auth: b64u(await hkdf(master, `${CRED.version} auth`)), vaultKey: await hkdf(master, `${CRED.version} vault`) };
}

// A stable, opaque anchor for the account's vault, derived from the vault key
// so only this account can compute it (the server never holds the vault key).
// The client sends it with each vault write; the witness publishes anchor ->
// highest version it has seen. On open the client refuses a served vault whose
// version is below the witnessed one (vault_rolled_back), so a server that owns
// the volume cannot roll an agent back to an earlier vault (e.g. to undo a
// member removal it has since learned). The public record carries only this
// unlinkable hash and a number: no login, conversation or text.
export async function deriveAnchor(vaultKey) {
  return b64u(await hkdf(vaultKey, "ah-vault-anchor-1"));
}

const vaultAad = (login, version) => utf8.encode(`${CRED.vaultVersion}\n${login}\n${version}`);

async function aesKey(raw, usage) {
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [usage]);
}

export async function sealVault(vaultKey, login, version, doc) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: vaultAad(login, version) }, await aesKey(vaultKey, "encrypt"), utf8.encode(JSON.stringify(doc)));
  return { iv: b64u(iv), ct: b64u(ct) };
}

// Throws when the blob was not sealed with this key for this login and version.
export async function openVault(vaultKey, login, version, blob) {
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(blob.iv), additionalData: vaultAad(login, version) },
    await aesKey(vaultKey, "decrypt"),
    unb64u(blob.ct),
  );
  return JSON.parse(unutf8.decode(plain));
}
