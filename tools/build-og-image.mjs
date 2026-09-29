// Builds public/assets/og.png (1200x630), the link-preview image for Open Graph
// and Twitter cards: the Observatory ring render (public/assets/observatory.png)
// cropped to 1200:630 so its baked-in lettering falls outside the frame, on
// --bg, with the logo mark in --ink at the top left. No text: the words stay
// in the page title. Run: RESVG=<path to @resvg/resvg-js> node tools/build-og-image.mjs
// motion-passport: exempt build script, no UI.
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Resvg } = require(process.env.RESVG || "@resvg/resvg-js");

const W = 1200, H = 630;
// Source 1586x992; rows 80..912 (832 = 1586 * 630 / 1200) hold the ring and
// leave out the lettering at the top left and bottom right.
const SRC_W = 1586, SRC_H = 992, TOP = 80;
const s = W / SRC_W;
const ring = fs.readFileSync("public/assets/observatory.png").toString("base64");
const mark = /<path[\s\S]*?\/>/.exec(fs.readFileSync("public/assets/logo-mark.svg", "utf8"))[0];
const MARK = 64 / 1608; // mark 64px tall, as the 48px mark scaled to the card

const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
<rect width="${W}" height="${H}" fill="#0b0a09"/>
<image x="0" y="${(-TOP * s).toFixed(2)}" width="${W}" height="${(SRC_H * s).toFixed(2)}" xlink:href="data:image/png;base64,${ring}"/>
<g transform="translate(48 48) scale(${MARK})">${mark}</g>
</svg>`;

const png = new Resvg(svg, { fitTo: { mode: "width", value: W } }).render().asPng();
fs.writeFileSync("public/assets/og.png", png);
console.log(JSON.stringify({ at: new Date().toISOString(), event: "og-image", width: W, height: H, bytes: png.length }));
