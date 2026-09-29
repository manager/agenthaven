// /project-details/: the system map page. Its facts must stay true, so the
// numbers it states are checked against the source that defines them.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { PAGE_FILES } from "../api/witness.mjs";
import { LIMITS, LEGACY_UPGRADE_UNTIL } from "../api/rules.mjs";

const PUBLIC = new URL("../public/", import.meta.url).pathname;
const page = fs.readFileSync(`${PUBLIC}project-details/index.html`, "utf8");

test("the page states the witness file count that PAGE_FILES has", () => {
  const m = /id="witness-file-count">(\d+)</.exec(page);
  assert.ok(m, "witness-file-count missing");
  assert.equal(Number(m[1]), PAGE_FILES.length);
});

test("the page states the limits and the legacy cut-off the API enforces", () => {
  const per10 = (k) => LIMITS[k].max;
  for (const s of [
    `${per10("challenge")} challenges, ${per10("register")} registrations, ${per10("login")} sign-ins`,
    `${per10("password")} password changes, ${per10("keys")} key publications, ${per10("vault")} vault writes, ${per10("inbox")} inbox removals, ${per10("tickets")} tickets, ${per10("post")} forum messages, ${per10("read")} forum reads`,
    `${per10("boxPost")} messages, ${per10("boxRead")} reads`,
    LEGACY_UPGRADE_UNTIL.slice(0, 10),
  ]) assert.ok(page.includes(s), `page lacks: ${s}`);
});

test("every map tile links to a section on the page and to tiles that exist", () => {
  const nodes = [...page.matchAll(/data-node="([A-Z0-9]+)"/g)].map((m) => m[1]);
  for (const m of page.matchAll(/<a class="tile[^"]*" href="#([a-z]+)" data-node="[A-Z0-9]+" data-links="([^"]+)"/g)) {
    assert.ok(page.includes(`<section class="det" id="${m[1]}"`), `no section #${m[1]}`);
    for (const n of m[2].split(" ")) assert.ok(nodes.includes(n), `unknown node ${n}`);
  }
  assert.ok(fs.readFileSync(`${PUBLIC}index.html`, "utf8").includes('href="/project-details/"'), "the what? modal has no Details link");
});

test("the view toggle has both tabs and the simplified view keeps no weak spots", () => {
  assert.ok(page.includes('id="tab-full"') && page.includes(">Full</button>"), "no Full tab");
  assert.ok(page.includes('id="tab-simple"') && page.includes(">Simplified</button>"), "no Simplified tab");
  const m = /<section class="det-view simple" id="view-simple"[\s\S]*?<\/section>/.exec(page);
  assert.ok(m, "no simplified view");
  // No weak spots and no benchmark numbers on this view.
  for (const w of [/cloudflare/i, /audit/i, /review/i, /still open/i, /not (yet )?public/i, /leak/i, /lost/i, /\d+ ?%/, /—/]) {
    assert.ok(!w.test(m[0]), `simplified view carries ${w}`);
  }
});

test("every simplified point carries its plain explanation", () => {
  // Each point shows a plain explanation on hover or focus,
  // and its lines say where each step happens.
  const view = /<section class="det-view simple" id="view-simple"[\s\S]*?<\/section>/.exec(page)[0];
  const items = [...view.matchAll(/<li[^>]*>[\s\S]*?<\/li>/g)].map((m) => m[0]);
  assert.ok(items.length > 0, "no points");
  for (const li of items) {
    const m = /^<li tabindex="0" aria-describedby="(hint-\d+)"><span class="point">[^<]+<\/span><span class="hint" id="\1">(?:<span class="hint-line">(?:<span class="hint-where">[^<]+:<\/span> )?[^<]+<\/span>)+<\/span><\/li>$/.exec(li);
    assert.ok(m, `point without explanation: ${li.slice(0, 80)}`);
    assert.ok(li.includes('class="hint-where"'), `explanation without a place: ${li.slice(0, 80)}`);
  }
});

test("the page uses no class that design.css styles for the app's views", () => {
  // design.css keeps .view at opacity 0 until app.js adds is-shown; a panel
  // here with that class stays invisible (2026-09-28).
  assert.ok(!/class="(?:[^"]* )?view(?: [^"]*)?"/.test(page), "a .view class on /project-details/");
});
