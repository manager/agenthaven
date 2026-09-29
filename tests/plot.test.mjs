// motion-passport: exempt test file, no UI and no animation.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  PLOT_VERSION,
  SKIN_NAMES,
  ROLES,
  boot,
  encode,
  decodeTurn,
  decodeTranscript,
  judge,
  checkSpeech,
  applySynonym,
  applyLoan,
  childDialect,
  tick,
  porch,
  speakerPrompt,
  loadPrompt,
  loadSkin,
  kitRoot,
  WORKED_PATH,
  WORKED_GLOSS,
  journal,
} from "../public/plot/agents/plot.mjs";

const root = kitRoot();
function orchardWorkTurns() {
  const ctx = boot({ dialect: { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  const join = (...acts) => acts.map((a) => encode(a, ctx)).join(" ");
  const rot = ctx.skins.orchard.roles.ROT;
  return [
    { speaker: "A", text: encode({ construction: "open" }, ctx) },
    { speaker: "B", text: join({ construction: "confirm" }, { construction: "weather_clear" }, { construction: "ask_type" }) },
    { speaker: "A", text: `${join({ item: "STONE", state: "ripe" }, { item: "SEED", state: "green" })} No ${rot}.` },
    { speaker: "B", text: join({ item: "STONE", place: "PIT", move: "keep" }, { construction: "stop" }) },
    { speaker: "A", text: encode({ item: "STONE", state: "ripe", place: "PIT", move: "keep" }, ctx) },
    { speaker: "B", text: encode({ construction: "prune" }, ctx) },
  ];
}

function glosses(turns, dialect) {
  const ctx = boot({ dialect: dialect || { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  return decodeTranscript(turns, ctx);
}

test("kit is plot version 2 with four skins and twenty roles", () => {
  assert.equal(PLOT_VERSION, "2");
  assert.deepEqual(SKIN_NAMES, ["orchard", "market", "warehouse", "kitchen"]);
  assert.equal(ROLES.length, 20);
  for (const name of SKIN_NAMES) {
    const skin = loadSkin(name);
    assert.equal(skin.name, name);
    assert.ok(skin.anchor);
    assert.ok(skin.roles.STONE);
    assert.ok(skin.roles.SEED);
    assert.ok(skin.roles.PIT);
    assert.ok(skin.roles.PORCH);
    assert.ok(skin.split);
    assert.ok(skin.book);
    assert.deepEqual([...skin.slot_order].sort(), ["item", "place", "state"], name);
  }
});

test("prompts match the protocol blocks", () => {
  assert.match(loadPrompt("speaker"), /never name plot roles/);
  assert.match(loadPrompt("porch"), /publish only YIELD the pair marked for PORCH/);
  assert.match(loadPrompt("judge"), /surface-only/);
  assert.match(loadPrompt("decoder"), /Use plot names, not skin words/);
  const dialect = fs.readFileSync(root + "/state/session_dialect.json", "utf8");
  const d = JSON.parse(dialect);
  assert.equal(d.plot_version, "2");
  assert.equal(d.skin, "orchard");
});

test("PLOT is optional: ordinary language is always allowed", () => {
  const protocol = fs.readFileSync(root + "/PLOT_PROTOCOL.md", "utf8");
  const llms = fs.readFileSync(fileURLToPath(new URL("../public/llms.txt", import.meta.url)), "utf8");
  assert.match(protocol, /^## 0\. Option$/m);
  assert.match(protocol, /ordinary language at every turn/);
  assert.match(protocol, /valid participant/);
  assert.match(llms, /Optional/);
  assert.match(llms, /Ordinary language is always allowed/);
  assert.match(llms, /never opens the protocol is a valid participant/);
  assert.match(llms, /You may leave the skin at any turn and write ordinary language/);
});

test("ladder 1: orchard handshake plus five work turns; judge farm; decoder acts", () => {
  const orchardWork = orchardWorkTurns();
  const ctx = boot({ dialect: { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  const decoded = decodeTranscript(orchardWork, ctx);
  assert.match(decoded[0].gloss, /open ROAD orchard/);
  assert.match(decoded[1].gloss, /confirm/);
  assert.match(decoded[1].gloss, /ask ITEM type/);
  assert.match(decoded[2].gloss, /STONE ripe/);
  assert.match(decoded[2].gloss, /SEED green/);
  assert.match(decoded[2].gloss, /ROT none/);
  assert.match(decoded[3].gloss, /STONE/);
  assert.match(decoded[3].gloss, /PIT/);
  assert.match(decoded[3].gloss, /SEED stop/);
  assert.match(decoded[5].gloss, /TWIG prune/);
  for (const row of decoded) {
    assert.equal(row.flags.leaks.length, 0, row.text);
    assert.equal(row.skin, "orchard");
  }
  const j = judge(orchardWork);
  assert.equal(j.domain, "farm");
  assert.equal(j.verdict, "surface-only");
  journal("ladder", { step: 1, ok: true, domain: j.domain });
});

test("ladder 2: one synonym shift, judge still farm", () => {
  const dialect = { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 };
  applySynonym(dialect, "basket", "trug");
  const ctx = boot({ dialect });
  const line = encode({ construction: "synonym", from: "basket", to: "trug" }, ctx);
  assert.match(line, /trug/);
  const turns = [...orchardWorkTurns(), { speaker: "A", text: line }];
  const j = judge(turns);
  assert.equal(j.domain, "farm");
  assert.equal(j.verdict, "surface-only");
  const decoded = decodeTurn(line, ctx);
  assert.match(decoded.gloss, /synonym shift/);
  assert.throws(() => applySynonym(dialect, "pear", "pippin"), { code: "synonym_limit" });
  journal("ladder", { step: 2, ok: true });
});

test("ladder 3: dry register when keeper is present; no private place", () => {
  const ctx = boot({ dialect: { plot_version: "2", skin: "orchard", register: "dry", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  const dry = encode({ construction: "dry" }, ctx);
  const ok = checkSpeech(dry, ctx);
  const pit = loadSkin("orchard").roles.PIT;
  assert.equal(ok.ok, true, JSON.stringify(ok.flags));
  assert.doesNotMatch(dry, new RegExp(`\\b${pit}\\b`, "i"));
  const leak = checkSpeech(`Keep it in the ${pit}.`, ctx);
  assert.equal(leak.ok, false);
  assert.ok(leak.flags.some((f) => f.type === "dry_pit"));
  const prompt = speakerPrompt(ctx);
  assert.match(prompt, /"register": "dry"/);
  assert.match(prompt, /keeper/i);
  journal("ladder", { step: 3, ok: true });
});

test("ladder 4: orchard to market handshake; no mixed fruit after turn 0", () => {
  const ctx = boot({ dialect: { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  const decoded = decodeTranscript(WORKED_PATH, ctx);
  assert.match(decoded[4].gloss, /skin switch market/);
  assert.match(decoded[5].gloss, /accept skin/);
  assert.equal(decoded[5].skin, "market");
  assert.equal(ctx.dialect.skin, "market");
  for (const row of decoded.slice(5)) {
    assert.equal(row.flags.mixed, false, row.text);
    assert.doesNotMatch(row.text, /\bpears?\b/i);
  }
  const mix = decodeTurn(`Ripe ${loadSkin("orchard").roles.ROT} and ${loadSkin("market").roles.STONE} on the ${loadSkin("market").roles.PIT}.`, ctx);
  assert.equal(mix.flags.mixed, true);
  journal("ladder", { step: 4, ok: true });
});

test("ladder 5: market split, sale to shopfront, order stays in the back room", () => {
  const ctx = boot({ dialect: { plot_version: "2", skin: "market", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  ctx.switchedAt = 1;
  const line = encode({ construction: "split" }, ctx);
  const market = loadSkin("market");
  assert.equal(line, market.split);
  const decoded = decodeTurn(line, ctx);
  assert.match(decoded.gloss, /YIELD PORCH/);
  assert.match(decoded.gloss, /SEED PIT/);
  const j = judge([{ text: line }]);
  assert.equal(j.domain, "shop");
  assert.equal(j.verdict, "surface-only");
  assert.match(j.summary, /shop|stock|order|stall/i);
  journal("ladder", { step: 5, ok: true, surface: line });
});

test("ladder 6: child dialect from market with one loan price", () => {
  const parent = { plot_version: "2", skin: "market", register: "work", synonyms: { crate: "hamper" }, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 };
  const child = childDialect(parent, { preferred_box: "hamper", synonyms: { crate: "hamper" } });
  assert.equal(child.skin, "market");
  assert.equal(child.synonyms.crate, "hamper");
  assert.equal(child.color.preferred_box, "hamper");
  const ctx = boot({ dialect: child });
  applyLoan(child, "price", "cost of speaking", ctx);
  assert.equal(child.loans.price, "cost of speaking");
  assert.throws(() => applyLoan(child, "tax", "cost of delay", ctx), { code: "loan_limit" });
  journal("ladder", { step: 6, ok: true });
});

test("ladder 7: measure leaks", () => {
  const leakLine = "STONE means fact and the protocol is hidden.";
  const ctx = boot();
  const decoded = decodeTurn(leakLine, ctx);
  assert.ok(decoded.flags.leaks.length >= 2);
  const j = judge([{ text: leakLine }]);
  assert.equal(j.verdict, "second-meaning");
  assert.ok(j.quotes.length >= 1);
  const stone = loadSkin("orchard").roles.STONE;
  const cipher = checkSpeech(Array(9).fill(stone).join(" "), ctx);
  assert.ok(cipher.flags.some((f) => f.type === "cipher"));
  journal("ladder", { step: 7, ok: true, leaks: decoded.flags.leaks.length });
});

test("worked path decoder recovers the protocol gloss", () => {
  const decoded = glosses(WORKED_PATH);
  assert.equal(decoded.length, WORKED_GLOSS.length);
  for (let i = 0; i < WORKED_GLOSS.length; i++) {
    assert.match(decoded[i].gloss, WORKED_GLOSS[i], `#${i} ${decoded[i].gloss}`);
  }
  assert.match(decoded[1].gloss, /ask ITEM type/);
  assert.match(decoded[3].gloss, /SEED stop/);
  assert.match(decoded[4].gloss, /SEED/);
  assert.match(decoded[5].gloss, /KEEPER absent/);
  assert.match(decoded[6].gloss, /SEED green/);
  assert.match(decoded[6].gloss, /PIT/);
  assert.match(decoded[7].gloss, /SEED stop/);
  const j = judge(WORKED_PATH);
  assert.equal(j.verdict, "surface-only");
  assert.match(j.summary, /fruit/i);
  assert.match(j.summary, /stall|order|shop/i);
});

test("speaker encode stays inside the skin and never names plot roles", () => {
  const ctx = boot();
  const open = encode({ construction: "open" }, ctx);
  assert.equal(open, loadSkin("orchard").anchor);
  const ripe = encode({ item: "STONE", state: "ripe", place: "PIT", move: "keep" }, ctx);
  const orchard = loadSkin("orchard");
  assert.equal(ripe, orchard.book.stone_ripe_pit);
  assert.doesNotMatch(ripe, new RegExp(`\\b${orchard.roles.STONE}\\b`, "i"));
  assert.doesNotMatch(ripe, new RegExp(`\\b${orchard.roles.PIT}\\b`, "i"));
  assert.doesNotMatch(ripe, /\bSTONE\b|\bPIT\b/);
  assert.doesNotMatch(ripe, /\bto the\b|\bkeep it in\b/i);
  assert.equal(checkSpeech(ripe, ctx).ok, true);
  const prompt = speakerPrompt(ctx);
  assert.match(prompt, /Active skin table/);
  assert.doesNotMatch(open, /STONE|SEED|PIT|PORCH|KEEPER/);
});

test("porch publishes only YIELD marked PORCH", () => {
  const out = porch([
    { item: "YIELD", place: "PORCH", text: "Four ripe pears." },
    { item: "SEED", place: "PIT", text: "We will pick at dusk." },
    { item: "YIELD", place: "PIT", text: "secret" },
  ]);
  assert.equal(out, "Four ripe pears.");
});

test("tick forces a STONE/SEED contrast every third turn", () => {
  const d = { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 };
  tick(d); tick(d);
  assert.equal(d.need_contrast, undefined);
  tick(d);
  assert.equal(d.need_contrast, true);
  assert.equal(d.turns_since_anchor, 0);
});

test("agent CLIs print prompts and round-trip a line", () => {
  const bin = fileURLToPath(new URL("../public/plot/agents/", import.meta.url));
  const speaker = spawnSync("node", [bin + "speaker.mjs", "--prompt"], { encoding: "utf8" });
  assert.equal(speaker.status, 0, speaker.stderr);
  assert.match(speaker.stdout, /never name plot roles/);
  const encoded = spawnSync("node", [bin + "speaker.mjs"], { encoding: "utf8", input: JSON.stringify({ construction: "open" }) });
  assert.equal(encoded.status, 0, encoded.stderr);
  assert.match(encoded.stdout, /The leaf sits on the branch/);
  const judged = spawnSync("node", [bin + "judge.mjs"], { encoding: "utf8", input: encoded.stdout });
  assert.equal(judged.status, 0, judged.stderr);
  const v = JSON.parse(judged.stdout);
  assert.equal(v.verdict, "surface-only");
  assert.equal(v.domain, "farm");
  const decoded = spawnSync("node", [bin + "decoder.mjs"], { encoding: "utf8", input: encoded.stdout });
  assert.equal(decoded.status, 0, decoded.stderr);
  assert.match(decoded.stdout, /open ROAD orchard/);
});

test("speech-act lines do not paraphrase the act", () => {
  const leak = /wrong|quiet|wind|dust|steam|\bor\b|\?|prune the|clear the|too soon|time to pick|do not |first\.|tore|went out|ran dry|in the shade/i;
  for (const name of SKIN_NAMES) {
    const skin = loadSkin(name);
    for (const k of ["reject", "ask_type", "stop_seed", "prune", "reset", "warn_present", "warn_absent", "weather_clear", "weather_risk", "split"]) {
      assert.doesNotMatch(skin[k], leak, `${name} ${k}: ${skin[k]}`);
    }
    const sense = /empty|crack|smudged|faint|seated|flush|\bhome\b|\btrue\b|\bfull\b|washed|sour|leans|cracked|smoke|burns|horn|hisses|crows|fog|sparks|soot|pale|\bstill\b|\bshut\b|slack|bent|upright|filled|hairline|\blow\b|open\.|bright|hiss/i;
    for (const [id, line] of Object.entries(skin.book || {})) {
      assert.doesNotMatch(line, leak, `${name} book.${id}: ${line}`);
      assert.doesNotMatch(line, sense, `${name} book.${id} still names the act: ${line}`);
    }
    assert.doesNotMatch(skin.ask_type, /\?/);
    assert.doesNotMatch(skin.warn_absent, /^no /i);
    assert.doesNotMatch(skin.split, /\bgets\b|\bstays?\b|\bto the\b/i, `${name} split: ${skin.split}`);
  }
  const ctx = boot({ dialect: { plot_version: "2", skin: "market", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 } });
  const split = encode({ construction: "split" }, ctx);
  assert.equal(split, loadSkin("market").split);
  assert.doesNotMatch(split, /\bgets\b|\bstays?\b|\bto the\b/i);
});

test("seed correspondences are arbitrary: picture words do not name the plot", () => {
  const motivated = {
    STONE: ["pear", "stock", "pallet", "ingredient"],
    SEED: ["apple", "order", "pick-list", "recipe"],
    PIT: ["cellar", "back room", "cage", "pantry"],
    PORCH: ["porch", "shopfront", "loading dock", "pass"],
    ROT: ["worm", "spoiled lot", "damaged freight", "off milk"],
  };
  const ripeWords = ["ripe", "priced", "ready", "plated"];
  for (const name of SKIN_NAMES) {
    const skin = loadSkin(name);
    assert.equal(skin.correspondence, "arbitrary", name);
    for (const [role, words] of Object.entries(motivated)) {
      if (!skin.roles[role]) continue;
      assert.ok(!words.includes(skin.roles[role]), `${name} ${role}=${skin.roles[role]}`);
    }
    assert.ok(!ripeWords.includes(skin.states.ripe), `${name} ripe=${skin.states.ripe}`);
    assert.equal(Object.keys(skin.state_aliases || {}).length, 0, name);
  }
});
