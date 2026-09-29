#!/usr/bin/env node
import fs from "node:fs";
import { boot, decodeTranscript, loadPrompt, appendLog, journal } from "./plot.mjs";

const ctx = boot();
if (process.argv[2] === "--prompt") {
  process.stdout.write(loadPrompt("decoder", ctx.root) + "\n");
  journal("decoder_prompt", {});
  process.exit(0);
}

const raw = fs.readFileSync(0, "utf8").trim();
let turns;
try {
  const parsed = JSON.parse(raw);
  turns = Array.isArray(parsed) ? parsed : [parsed];
} catch {
  turns = raw.split(/\n+/).filter(Boolean).map((text) => ({ text }));
}
const decoded = decodeTranscript(turns, ctx);
for (const row of decoded) appendLog("decoded", row);
journal("decoder", {
  turns: decoded.length,
  skin: ctx.dialect.skin,
  leaks: decoded.reduce((n, r) => n + r.flags.leaks.length, 0),
});
process.stdout.write(decoded.map((r) => `${r.speaker || "-"}: ${r.gloss}`).join("\n") + "\n");
