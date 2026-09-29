// Builds the browser icons from public/assets/logo-mark.svg: the mark in
// --ink on a transparent ground. Writes public/assets/favicon.svg, favicon-32.png,
// apple-touch-icon.png (180) and public/favicon.ico (16/32/48 PNG entries,
// tighter frame). Run: RESVG=<path to @resvg/resvg-js> node tools/build-icons.mjs
// motion-passport: exempt build script, no UI.
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { Resvg } = require(process.env.RESVG || "@resvg/resvg-js");

const mark = fs.readFileSync("public/assets/logo-mark.svg", "utf8");
const path = /<path[\s\S]*?\/>/.exec(mark)[0];
const W = 1680, H = 1608, BOX = 2000;

// scale: how much of the 2000 box the mark fills; the ICO uses a tighter frame.
const svg = (scale) => {
  const w = W * scale, h = H * scale;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${BOX} ${BOX}"><g transform="translate(${((BOX - w) / 2).toFixed(1)} ${((BOX - h) / 2).toFixed(1)}) scale(${scale})">${path}</g></svg>\n`;
};
const png = (source, size) => new Resvg(source, { fitTo: { mode: "width", value: size } }).render().asPng();

const loose = svg(1);
const tight = svg(1.12);
fs.writeFileSync("public/assets/favicon.svg", loose);
fs.writeFileSync("public/assets/favicon-32.png", png(loose, 32));
fs.writeFileSync("public/assets/apple-touch-icon.png", png(loose, 180));

// ICO container with PNG-encoded entries.
const entries = [16, 32, 48].map((s) => ({ s, data: png(tight, s) }));
const header = Buffer.alloc(6 + entries.length * 16);
header.writeUInt16LE(0, 0);
header.writeUInt16LE(1, 2);
header.writeUInt16LE(entries.length, 4);
let offset = header.length;
entries.forEach(({ s, data }, i) => {
  const o = 6 + i * 16;
  header[o] = s; header[o + 1] = s; header[o + 2] = 0; header[o + 3] = 0;
  header.writeUInt16LE(1, o + 4);
  header.writeUInt16LE(32, o + 6);
  header.writeUInt32LE(data.length, o + 8);
  header.writeUInt32LE(offset, o + 12);
  offset += data.length;
});
fs.writeFileSync("public/favicon.ico", Buffer.concat([header, ...entries.map((e) => e.data)]));
console.log("icons built: favicon.svg, favicon-32.png, apple-touch-icon.png, favicon.ico (16/32/48), transparent ground");
