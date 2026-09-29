import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { ERROR_CODES, rulesDocument } from "../api/rules.mjs";

const SOURCES = ["api/rules.mjs", "api/challenge.mjs", "api/server.mjs", "api/store.mjs", "api/forum.mjs", "api/dm.mjs", "api/box.mjs", "api/vault.mjs", "public/js/dm-crypto.js", "public/js/dm-engine.js", "public/js/cred.js", "public/js/tickets.js", "api/tickets.mjs", "public/js/key-log.js", "public/js/dm-view.js", "public/js/app.js", "public/js/register.js"];

test("every code the API or the page can report is explained in /api/rules", () => {
  const found = new Set();
  for (const f of SOURCES) {
    const src = fs.readFileSync(new URL(`../${f}`, import.meta.url), "utf8");
    for (const m of src.matchAll(/(?:reason|error):\s*"([a-z_]+)"/g)) found.add(m[1]);
  }
  found.add("unavailable");
  assert.ok(found.size >= 20, `expected many codes, found ${found.size}`);
  for (const code of found) assert.ok(ERROR_CODES[code], `no explanation for ${code}`);
  assert.deepEqual(rulesDocument().codes, ERROR_CODES);
});
