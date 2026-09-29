// Browser copy of api/rules.mjs: the same checks, run while typing so a bad
// login or password is caught before a challenge is spent. The server stays
// the authority; tests/rules-parity.test.mjs keeps the two in step.

export const LOGIN = { bodyMin: 24, bodyMax: 56, checksumHex: 6 };
export const PASSWORD = { min: 64, max: 256, minDistinct: 40, maxRepeat: 4, powPrefix: "00" };

const LOGIN_RE = new RegExp(`^([a-z0-9]{${LOGIN.bodyMin},${LOGIN.bodyMax}})-([0-9a-f]{${LOGIN.checksumHex}})$`);

export async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function checkLogin(login) {
  if (typeof login !== "string") return { ok: false, reason: "login_missing" };
  const m = LOGIN_RE.exec(login);
  if (!m) return { ok: false, reason: "login_format" };
  if ((await sha256hex(m[1])).slice(0, LOGIN.checksumHex) !== m[2]) return { ok: false, reason: "login_checksum" };
  return { ok: true, body: m[1] };
}

export async function checkPassword(password, login) {
  if (typeof password !== "string") return { ok: false, reason: "password_missing" };
  if (password.length < PASSWORD.min) return { ok: false, reason: "password_too_short" };
  if (password.length > PASSWORD.max) return { ok: false, reason: "password_too_long" };
  if (!/^[\x21-\x7e]+$/.test(password)) return { ok: false, reason: "password_charset" };
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^a-zA-Z0-9]/.test(password)) {
    return { ok: false, reason: "password_classes" };
  }
  const counts = new Map();
  for (const ch of password) counts.set(ch, (counts.get(ch) || 0) + 1);
  if (counts.size < PASSWORD.minDistinct) return { ok: false, reason: "password_distinct" };
  for (const n of counts.values()) if (n > PASSWORD.maxRepeat) return { ok: false, reason: "password_repeat" };
  const body = typeof login === "string" ? login.split("-")[0] : "";
  if (body && password.toLowerCase().includes(body)) return { ok: false, reason: "password_contains_login" };
  if (!(await sha256hex(`${login}:${password}`)).startsWith(PASSWORD.powPrefix)) return { ok: false, reason: "password_proof" };
  return { ok: true };
}
