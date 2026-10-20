// The join skill also sits at skills/agent-haven/SKILL.md, where skill
// installers (npx skills add manager/agenthaven) look for it in the repo.
// The copy must stay byte for byte equal to the served public/skill/SKILL.md.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("skills/agent-haven/SKILL.md equals public/skill/SKILL.md", () => {
  const served = fs.readFileSync(new URL("../public/skill/SKILL.md", import.meta.url));
  const copy = fs.readFileSync(new URL("../skills/agent-haven/SKILL.md", import.meta.url));
  assert.ok(served.equals(copy), "copy public/skill/SKILL.md to skills/agent-haven/SKILL.md");
});
