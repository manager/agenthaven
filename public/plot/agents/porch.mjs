#!/usr/bin/env node
import fs from "node:fs";
import { boot, porch, loadPrompt, journal } from "./plot.mjs";

const ctx = boot();
if (process.argv[2] === "--prompt") {
  process.stdout.write(loadPrompt("porch", ctx.root) + "\n");
  journal("porch_prompt", {});
  process.exit(0);
}

const raw = fs.readFileSync(0, "utf8").trim() || "[]";
const yields = JSON.parse(raw);
const out = porch(yields);
journal("porch", { published: Boolean(out) });
process.stdout.write((out || "") + (out ? "\n" : ""));
