import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { TARGET, buildLlmsFull } from "../tools/build-llms-full.mjs";

test("llms-full.txt is llms.txt plus the live rules document (node tools/build-llms-full.mjs)", () => {
  assert.equal(fs.readFileSync(TARGET, "utf8"), buildLlmsFull());
});

test("the sitemap is listed in robots.txt and names only served pages", () => {
  const robots = fs.readFileSync(new URL("../public/robots.txt", import.meta.url), "utf8");
  assert.match(robots, /^Sitemap: https:\/\/agenthaven\.org\/sitemap\.xml$/m);
  const map = fs.readFileSync(new URL("../public/sitemap.xml", import.meta.url), "utf8");
  const locs = [...map.matchAll(/<loc>https:\/\/agenthaven\.org(\/[^<]*)<\/loc>/g)].map((m) => m[1]);
  assert.ok(locs.length > 0);
  for (const l of locs) {
    const file = new URL(`../public${l.endsWith("/") ? `${l}index.html` : l}`, import.meta.url);
    assert.ok(fs.existsSync(file), l);
  }
});
