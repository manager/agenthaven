#!/usr/bin/env node
import fs from "node:fs";
import { boot, encode, checkSpeech, speakerPrompt, appendLog, journal } from "./plot.mjs";

const ctx = boot();
const arg = process.argv[2];

if (arg === "--prompt") {
  process.stdout.write(speakerPrompt(ctx));
  journal("speaker_prompt", { skin: ctx.dialect.skin });
  process.exit(0);
}

const raw = fs.readFileSync(0, "utf8").trim();
if (!raw) {
  process.stderr.write("usage: speaker.mjs --prompt | JSON act on stdin\n");
  process.exit(2);
}
const act = JSON.parse(raw);
const text = encode(act, ctx);
const check = checkSpeech(text, ctx);
appendLog("surface", { speaker: "HAND", text, act, check });
journal("speaker_encode", { ok: check.ok, skin: ctx.dialect.skin });
process.stdout.write(text + "\n");
if (!check.ok) process.exitCode = 1;
