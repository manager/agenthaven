import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomInt } from "node:crypto";
import * as server from "../api/rules.mjs";
import * as browser from "../public/js/rules.js";

const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(0x21 + i)).join("");
const pick = (abc, n) => Array.from({ length: n }, () => abc[randomInt(abc.length)]).join("");

function logins() {
  const out = ["", "owner", "a".repeat(24) + "-000000", undefined];
  for (let i = 0; i < 40; i++) {
    const body = pick("abcdefghijklmnopqrstuvwxyz0123456789", 20 + randomInt(40));
    out.push(`${body}-${sha(body).slice(0, 6)}`);
    out.push(`${body}-${sha(body + "x").slice(0, 6)}`);
    out.push(`${body.toUpperCase()}-${sha(body).slice(0, 6)}`);
  }
  return out;
}

function passwords(login) {
  const out = ["hunter2", "a".repeat(70), "Aa1!".repeat(20), "Aa1! ".repeat(20), "x".repeat(300)];
  for (let i = 0; i < 60; i++) out.push(pick(PRINTABLE, 50 + randomInt(40)));
  const body = typeof login === "string" ? login.split("-")[0] : "";
  if (body) out.push("Aa1!" + body + pick(PRINTABLE, 60));
  // A few that pass every rule, so the proof branch is exercised both ways.
  let found = 0;
  for (let i = 0; i < 20000 && found < 3; i++) {
    const pw = pick(PRINTABLE, 72);
    if (server.checkPassword(pw, login).ok) {
      out.push(pw);
      found++;
    }
  }
  return out;
}

test("browser and server login rules agree", async () => {
  for (const l of logins()) {
    const s = server.checkLogin(l);
    const b = await browser.checkLogin(l);
    assert.equal(b.ok, s.ok, String(l));
    assert.equal(b.reason, s.reason, String(l));
  }
});

test("browser and server password rules agree", async () => {
  let passes = 0;
  for (const l of logins().filter((x) => server.checkLogin(x).ok).slice(0, 4)) {
    for (const p of passwords(l)) {
      const s = server.checkPassword(p, l);
      const b = await browser.checkPassword(p, l);
      assert.equal(b.ok, s.ok, `${l} / ${p}`);
      assert.equal(b.reason, s.reason, `${l} / ${p}`);
      if (s.ok) passes++;
    }
  }
  assert.ok(passes > 0, "at least one password passed every rule");
});

test("browser rule constants match the server", () => {
  assert.deepEqual(browser.LOGIN, server.LOGIN);
  assert.deepEqual(browser.PASSWORD, server.PASSWORD);
});
