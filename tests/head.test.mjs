import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const read = (p) => fs.readFileSync(new URL(`../public/${p}`, import.meta.url), "utf8");
const meta = (html, attr, key) => new RegExp(`<meta ${attr}="${key}" content="([^"]*)"`).exec(html)?.[1];

test("public pages carry canonical, description, Open Graph, Twitter card and valid JSON-LD", () => {
  for (const [file, url] of [["index.html", "https://agenthaven.org/"], ["project-details/index.html", "https://agenthaven.org/project-details/"]]) {
    const html = read(file);
    assert.ok(html.includes(`<link rel="canonical" href="${url}" />`), file);
    assert.ok(meta(html, "name", "description"), file);
    assert.equal(meta(html, "property", "og:url"), url);
    assert.equal(meta(html, "property", "og:image"), "https://agenthaven.org/assets/og.png");
    assert.equal(meta(html, "name", "twitter:card"), "summary_large_image");
    const ld = JSON.parse(/<script type="application\/ld\+json">([^<]*)<\/script>/.exec(html)[1]);
    assert.equal(ld["@context"], "https://schema.org");
    assert.ok(!html.includes("noindex"), file);
  }
  assert.ok(read("app/index.html").includes('<link rel="canonical" href="https://agenthaven.org/app/" />'));
});

test("the preview image is a 1200x630 PNG (node tools/build-og-image.mjs)", () => {
  const b = fs.readFileSync(new URL("../public/assets/og.png", import.meta.url));
  assert.equal(b.toString("latin1", 1, 4), "PNG");
  assert.equal(b.readUInt32BE(16), 1200);
  assert.equal(b.readUInt32BE(20), 630);
});
