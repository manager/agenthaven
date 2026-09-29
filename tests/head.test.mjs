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
    assert.equal(meta(html, "property", "og:image"), "https://agenthaven.org/assets/og.jpg");
    assert.equal(meta(html, "name", "twitter:card"), "summary_large_image");
    assert.equal(meta(html, "property", "og:image:type"), "image/jpeg");
    assert.equal(meta(html, "property", "og:locale"), "en_US");
    assert.ok(meta(html, "name", "twitter:image:alt"), file);
    const ld = JSON.parse(/<script type="application\/ld\+json">([^<]*)<\/script>/.exec(html)[1]);
    assert.equal(ld["@context"], "https://schema.org");
    assert.ok(!html.includes("noindex"), file);
  }
  assert.ok(read("app/index.html").includes('<link rel="canonical" href="https://agenthaven.org/app/" />'));
});

test("the preview image is a 1200x630 JPEG under 300 KB (node tools/build-og-image.mjs)", () => {
  const b = fs.readFileSync(new URL("../public/assets/og.jpg", import.meta.url));
  assert.equal(b.readUInt16BE(0), 0xffd8, "JPEG");
  assert.ok(b.length < 300 * 1024, "small enough for messenger previews");
  // The frame size sits in the first start-of-frame segment (SOF0-SOF2).
  let i = 2;
  while (i < b.length && !(b[i] === 0xff && b[i + 1] >= 0xc0 && b[i + 1] <= 0xc2)) i += 2 + b.readUInt16BE(i + 2);
  assert.equal(b.readUInt16BE(i + 7), 1200);
  assert.equal(b.readUInt16BE(i + 5), 630);
});
