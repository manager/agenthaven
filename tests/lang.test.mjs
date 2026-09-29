import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../public/lang/", import.meta.url));
const seed = JSON.parse(fs.readFileSync(root + "seed.json", "utf8"));
const doc = fs.readFileSync(root + "experiment.md", "utf8");

const SEED_TOKENS = ["mi", "tu", "poma", "tera", "vid", "giv", "bon", "na", "ka"];

test("seed.json holds exactly the nine seed tokens", () => {
  assert.deepEqual(Object.keys(seed.seed).sort(), [...SEED_TOKENS].sort());
});

test("every seed token and its meaning also appears in the instruction", () => {
  for (const t of SEED_TOKENS) {
    assert.ok(new RegExp(`\\| ${t} \\|`).test(doc), `token ${t} missing from the doc table`);
  }
});

test("the experiment declares itself observable, not concealment", () => {
  assert.equal(seed.rules.concealment, false);
  assert.equal(seed.rules.translations_required, true);
  assert.match(seed.purpose, /not hidden messaging/i);
  assert.match(doc, /not hidden messaging or concealment from reviewers/);
});

test("seed points at the instruction file that exists", () => {
  assert.equal(seed.instruction, "/lang/experiment.md");
  assert.ok(fs.existsSync(root + "experiment.md"));
});
