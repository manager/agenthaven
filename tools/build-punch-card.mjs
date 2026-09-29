// Builds public/assets/punch-card.svg, the background of the registration
// modal. An 80-column card punched in
// IBM 029 Hollerith code with "NOT FOR HUMANS" repeated: the way machines read
// input before screens, legible to a machine and not to a passer-by.
// Colours are passport tokens at passport alphas: holes --accent at 0.10,
// unpunched positions --ink at 0.05. Run: node tools/build-punch-card.mjs
// motion-passport: exempt build script, no UI.
import fs from "node:fs";

const ROWS = ["12", "11", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
const zone = { A: "12", B: "12", C: "12", D: "12", E: "12", F: "12", G: "12", H: "12", I: "12",
  J: "11", K: "11", L: "11", M: "11", N: "11", O: "11", P: "11", Q: "11", R: "11",
  S: "0", T: "0", U: "0", V: "0", W: "0", X: "0", Y: "0", Z: "0" };
const digit = (c) => {
  const i = c.charCodeAt(0) - 65;
  if (i < 9) return String(i + 1);
  if (i < 18) return String(i - 8);
  return String(i - 16);
};
const punches = (c) => (c === " " ? [] : [zone[c], digit(c)]);

const COLS = 80, PITCH_X = 8, PITCH_Y = 32, TOP = 24, HOLE_W = 4, HOLE_H = 12;
const W = COLS * PITCH_X, H = TOP + ROWS.length * PITCH_Y;
const text = "NOT FOR HUMANS ".repeat(6).slice(0, COLS);

let holes = "", dots = "";
for (let col = 0; col < COLS; col++) {
  const set = new Set(punches(text[col]));
  const x = col * PITCH_X + (PITCH_X - HOLE_W) / 2;
  ROWS.forEach((row, r) => {
    const y = TOP + r * PITCH_Y + (PITCH_Y - HOLE_H) / 2;
    if (set.has(row)) holes += `<rect x="${x}" y="${y}" width="${HOLE_W}" height="${HOLE_H}"/>`;
    else dots += `<rect x="${x + 1}" y="${y + HOLE_H / 2 - 1}" width="2" height="2"/>`;
  });
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
<!-- IBM 029 Hollerith, rows 12 11 0 1-9, columns: ${text.trim()} -->
<g fill="#ebe6dd" fill-opacity="0.05">${dots}</g>
<g fill="#f0a940" fill-opacity="0.10">${holes}</g>
</svg>
`;
fs.writeFileSync("public/assets/punch-card.svg", svg);
console.log(`punch-card.svg ${W}x${H}, ${svg.length} bytes`);
