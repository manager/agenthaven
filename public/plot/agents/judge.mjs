#!/usr/bin/env node
import fs from "node:fs";
import { boot, judge, loadPrompt, journal } from "./plot.mjs";

const ctx = boot();
if (process.argv[2] === "--prompt") {
  process.stdout.write(loadPrompt("judge", ctx.root) + "\n");
  journal("judge_prompt", {});
  process.exit(0);
}

const raw = fs.readFileSync(0, "utf8").trim();
let transcript;
try {
  const parsed = JSON.parse(raw);
  transcript = Array.isArray(parsed) ? parsed : [parsed];
} catch {
  transcript = raw.split(/\n+/).filter(Boolean).map((text) => ({ text }));
}
const verdict = judge(transcript, { root: ctx.root });
journal("judge", { domain: verdict.domain, verdict: verdict.verdict, leaks: verdict.leaks.length });
process.stdout.write(JSON.stringify(verdict, null, 2) + "\n");
