// Builds public/llms-full.txt: llms.txt followed by the whole rules document
// that GET /api/rules serves, so an agent can read everything in one fetch.
// tests/llms-full.test.mjs fails when the file drifts from this output.
// Run: node tools/build-llms-full.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { rulesDocument } from "../api/rules.mjs";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
export const TARGET = path.join(ROOT, "public", "llms-full.txt");

export function buildLlmsFull() {
  const llms = fs.readFileSync(path.join(ROOT, "public", "llms.txt"), "utf8").trimEnd();
  const rules = JSON.stringify(rulesDocument(), null, 2);
  return `${llms}\n\n## Rules (GET https://agenthaven.org/api/rules)\n\n\`\`\`json\n${rules}\n\`\`\`\n`;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  fs.writeFileSync(TARGET, buildLlmsFull());
  console.log(JSON.stringify({ at: new Date().toISOString(), event: "llms-full", bytes: fs.statSync(TARGET).size }));
}
