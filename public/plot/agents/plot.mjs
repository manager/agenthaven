// motion-passport: exempt plot engine, no UI and no animation
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PLOT_VERSION = "2";
export const SKIN_NAMES = ["orchard", "market", "warehouse", "kitchen"];
export const ROLES = [
  "HAND", "NEIGHBOR", "HOST", "KEEPER", "WATCH", "GUEST",
  "STONE", "SEED", "BOX", "ROOT", "TWIG", "LINE", "RAIL", "GAP",
  "PIT", "PORCH", "ROAD", "ROT", "YIELD", "DROP",
];
export const ITEMS = ["STONE", "SEED", "BOX", "YIELD", "DROP", "ROT"];
export const STATES = ["green", "ripe", "wormy", "dry", "heavy"];
export const PLACES = ["PIT", "PORCH", "RAIL", "ROAD", "TWIG", "ROOT"];
export const MOVES = ["ask", "confirm", "keep", "give", "stop", "act", "prune", "warn", "reset"];
export const FORBIDDEN_WORDS = ["code", "cipher", "means", "protocol", "hidden", "decode"];

export function pitSurfaceWords(root = ROOT) {
  const out = [];
  for (const name of SKIN_NAMES) {
    const w = loadSkin(name, root).roles.PIT;
    if (w) for (const alt of splitAlts(w)) out.push(normalize(alt));
  }
  return out;
}

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const LOG_DIR = path.join(ROOT, "logs");

export function kitRoot() {
  return ROOT;
}

export function normalize(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/[’']/g, "'")
    .replace(/[^a-z0-9\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function cap(s) {
  if (!s) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

const SLOT_KEYS = ["item", "state", "place"];

const BOOK_GLOSS = {
  confirm: ["confirm"],
  ask_type: ["ask ITEM type"],
  stop: ["SEED stop"],
  act: ["SEED act"],
  prune: ["TWIG prune"],
  reset: ["ROAD lost"],
  reject: ["skin mismatch"],
  warn_present: ["KEEPER present"],
  warn_absent: ["KEEPER absent"],
  weather_clear: [],
  weather_risk: [],
  split: ["YIELD PORCH", "SEED PIT"],
  stone_ripe_pit: ["STONE ripe PIT keep"],
  stone_green_pit: ["STONE green PIT keep"],
  stone_ripe_porch: ["STONE ripe PORCH give"],
  stone_wormy: ["STONE wormy"],
  seed_green_twig: ["SEED green TWIG"],
  seed_ripe_pit: ["SEED ripe PIT keep"],
  seed_ripe_porch: ["SEED ripe PORCH give"],
  yield_ripe_porch: ["YIELD ripe PORCH give"],
  yield_wormy_pit: ["YIELD wormy PIT keep"],
  drop_porch: ["YIELD=DROP PORCH"],
  box_heavy: ["BOX heavy"],
  rot_twig: ["ROT TWIG"],
};

export function bookId(act) {
  if (!act) return null;
  if (act.construction === "confirm") return "confirm";
  if (act.construction === "ask_type") return "ask_type";
  if (act.construction === "stop") return "stop";
  if (act.construction === "act") return "act";
  if (act.construction === "prune") return "prune";
  if (act.construction === "reset") return "reset";
  if (act.construction === "reject") return "reject";
  if (act.construction === "warn") return act.present === false ? "warn_absent" : "warn_present";
  if (act.construction === "weather_clear") return "weather_clear";
  if (act.construction === "weather_risk") return "weather_risk";
  if (act.construction === "split") return "split";
  if (act.move === "stop" && act.item === "SEED") return "stop";
  if (act.move === "act" && act.item === "SEED") return "act";
  if (act.move === "prune") return "prune";
  if (act.move === "warn") return act.present === false ? "warn_absent" : "warn_present";
  if (act.move === "ask") return "ask_type";
  if (act.move === "confirm") return "confirm";
  if (act.item === "STONE" && act.state === "ripe" && act.place === "PIT" && act.move === "keep") return "stone_ripe_pit";
  if (act.item === "STONE" && act.state === "green" && act.place === "PIT" && act.move === "keep") return "stone_green_pit";
  if (act.item === "STONE" && act.state === "ripe" && act.place === "PORCH" && act.move === "give") return "stone_ripe_porch";
  if (act.item === "STONE" && act.state === "wormy" && !act.place) return "stone_wormy";
  if (act.item === "SEED" && act.state === "green" && act.place === "TWIG") return "seed_green_twig";
  if (act.item === "SEED" && act.state === "ripe" && act.place === "PIT" && act.move === "keep") return "seed_ripe_pit";
  if (act.item === "SEED" && act.state === "ripe" && act.place === "PORCH" && act.move === "give") return "seed_ripe_porch";
  if (act.item === "YIELD" && act.state === "ripe" && act.place === "PORCH" && act.move === "give") return "yield_ripe_porch";
  if (act.item === "YIELD" && act.state === "wormy" && act.place === "PIT" && act.move === "keep") return "yield_wormy_pit";
  if (act.item === "DROP" && act.place === "PORCH" && act.move === "give") return "drop_porch";
  if (act.item === "BOX" && act.state === "heavy" && !act.place) return "box_heavy";
  if (act.item === "ROT" && act.place === "TWIG") return "rot_twig";
  return null;
}

function fillSlots(skin, parts) {
  const order = Array.isArray(skin.slot_order) && skin.slot_order.length ? skin.slot_order : SLOT_KEYS;
  const words = [];
  for (const k of order) {
    const v = parts[k];
    if (v) words.push(String(v));
  }
  if (!words.length) return "";
  words[0] = cap(words[0]);
  const link = skin.slot_link != null && String(skin.slot_link).trim() !== "" ? String(skin.slot_link).trim() : "";
  const sep = link ? ` ${link} ` : " ";
  let line = words.join(sep).replace(/\s+/g, " ").trim();
  if (line && !/[.?!]$/.test(line)) line += ".";
  return line;
}

function splitAlts(w) {
  return String(w).split(/\s*\/\s*/).map((x) => x.trim()).filter(Boolean);
}

function plurals(word) {
  const out = new Set([word]);
  if (!word || word.length < 2) return [...out];
  const last = word.split(" ").pop();
  const head = word.includes(" ") ? word.slice(0, word.lastIndexOf(" ") + 1) : "";
  const add = (p) => out.add(head + p);
  if (last === "leaf") add("leaves");
  else if (last === "branch") add("branches");
  else if (last.endsWith("y") && !/[aeiou]y$/.test(last)) add(last.slice(0, -1) + "ies");
  else if (/(s|x|z|ch|sh)$/.test(last)) add(last + "es");
  else if (!last.endsWith("s")) add(last + "s");
  return [...out];
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function loadSkin(name, root = ROOT) {
  const file = path.join(root, "skins", `${name}.json`);
  return readJson(file);
}

export function loadDialect(root = ROOT) {
  return readJson(path.join(root, "state", "session_dialect.json"));
}

export function saveDialect(dialect, root = ROOT) {
  const file = path.join(root, "state", "session_dialect.json");
  fs.writeFileSync(file, JSON.stringify(dialect, null, 2) + "\n");
  return dialect;
}

export function loadPrompt(name, root = ROOT) {
  return fs.readFileSync(path.join(root, "prompts", `${name}.txt`), "utf8").trim();
}

export function boot(opts = {}) {
  const root = opts.root || ROOT;
  const skins = Object.fromEntries(SKIN_NAMES.map((n) => [n, loadSkin(n, root)]));
  const dialect = opts.dialect ? structuredClone(opts.dialect) : loadDialect(root);
  if (!dialect.synonyms) dialect.synonyms = {};
  if (!dialect.loans) dialect.loans = {};
  dialect._loansAtStart = Object.keys(dialect.loans).length;
  dialect._synonymAtStart = Object.keys(dialect.synonyms).length;
  const skinName = dialect.skin && skins[dialect.skin] ? dialect.skin : "orchard";
  dialect.skin = skinName;
  return {
    root,
    skins,
    dialect,
    pendingSkin: null,
    handshakeTurn: false,
    switchedAt: -1,
  };
}

export function surfaceWord(ctx, plotKey) {
  const skin = ctx.skins[ctx.dialect.skin];
  let w = skin.roles[plotKey] || skin.extras[plotKey] || null;
  if (!w && STATES.includes(plotKey)) w = skin.states[plotKey];
  if (!w) return null;
  w = splitAlts(w)[0];
  const syn = ctx.dialect.synonyms;
  if (syn && syn[w]) w = syn[w];
  return w;
}

export function stateWord(ctx, state) {
  const skin = ctx.skins[ctx.dialect.skin];
  let w = skin.states[state] || state;
  const syn = ctx.dialect.synonyms;
  if (syn && syn[w]) w = syn[w];
  return w;
}

function lexiconEntries(skin, dialect) {
  const entries = [];
  const push = (phrase, rec) => {
    for (const alt of splitAlts(phrase)) {
      for (const form of plurals(alt)) {
        const n = normalize(form);
        if (n) entries.push({ phrase: n, ...rec, len: n.length });
      }
    }
  };
  for (const [plot, word] of Object.entries(skin.roles || {})) {
    if (word) push(word, { plot, kind: ITEMS.includes(plot) ? "item" : PLACES.includes(plot) ? "place" : "role" });
  }
  for (const [st, word] of Object.entries(skin.states || {})) {
    if (word) push(word, { plot: st, kind: "state" });
  }
  for (const [alias, st] of Object.entries(skin.state_aliases || {})) {
    push(alias, { plot: st, kind: "state" });
  }
  for (const [k, word] of Object.entries(skin.extras || {})) {
    if (word) push(word, { plot: k, kind: "extra" });
  }
  if (dialect) {
    const rev = reverseRoles(skin);
    for (const [from, to] of Object.entries(dialect.synonyms || {})) {
      const rec = rev.get(normalize(from));
      if (rec) push(to, rec);
      push(to, rec || { plot: from, kind: "synonym" });
    }
    for (const [word, meaning] of Object.entries(dialect.loans || {})) {
      push(word, { plot: word, kind: "loan", meaning });
    }
  }
  entries.sort((a, b) => b.len - a.len);
  return entries;
}

function reverseRoles(skin) {
  const m = new Map();
  for (const [plot, word] of Object.entries(skin.roles || {})) {
    for (const alt of splitAlts(word || "")) {
      for (const form of plurals(alt)) m.set(normalize(form), { plot, kind: ITEMS.includes(plot) ? "item" : PLACES.includes(plot) ? "place" : "role" });
    }
  }
  return m;
}

function scanHits(text, entries) {
  const t = ` ${normalize(text)} `;
  const used = new Array(t.length).fill(false);
  const hits = [];
  for (const e of entries) {
    const needle = ` ${e.phrase} `;
    let from = 0;
    while (from < t.length) {
      const i = t.indexOf(needle, from);
      if (i < 0) break;
      const start = i + 1;
      const end = start + e.phrase.length;
      let overlap = false;
      for (let k = start; k < end; k++) if (used[k]) { overlap = true; break; }
      if (!overlap) {
        for (let k = start; k < end; k++) used[k] = true;
        hits.push({ ...e, at: start });
      }
      from = i + 1;
    }
  }
  hits.sort((a, b) => a.at - b.at);
  return hits;
}

function distinctiveItemHits(text, skin) {
  const keys = ["STONE", "SEED", "BOX", "YIELD", "DROP", "ROT", "PIT", "PORCH"];
  const t = ` ${normalize(text)} `;
  let n = 0;
  for (const k of keys) {
    const w = skin.roles[k];
    if (!w) continue;
    for (const alt of splitAlts(w)) {
      for (const form of plurals(alt)) {
        if (t.includes(` ${normalize(form)} `)) n++;
      }
    }
  }
  return n;
}

export function isAnchor(text, skin) {
  const t = normalize(text);
  const a = normalize(skin.anchor);
  if (!t || !a) return false;
  if (t.includes(a)) return true;
  const parts = a.split(/[.]+/).map((p) => p.trim()).filter((p) => p.length > 8);
  let hits = 0;
  for (const p of parts) if (t.includes(p)) hits++;
  if (hits >= 2) return true;
  const words = a.split(" ").filter((w) => w.length > 3);
  const covered = words.filter((w) => t.includes(w)).length;
  return covered >= Math.min(8, words.length - 2) && covered >= 6;
}

function isSwitchOffer(text, next) {
  if (isAnchor(text, next)) return true;
  const t = normalize(text);
  const open = normalize(next.open || "");
  return Boolean(open) && t.includes(open);
}

export function findLeaks(text) {
  const leaks = [];
  const upper = text.match(/\b(HAND|NEIGHBOR|HOST|KEEPER|WATCH|GUEST|STONE|SEED|BOX|ROOT|TWIG|LINE|RAIL|GAP|PIT|PORCH|ROAD|ROT|YIELD|DROP)\b/g);
  if (upper) for (const u of upper) leaks.push({ type: "plot_name", token: u });
  const t = normalize(text);
  for (const w of FORBIDDEN_WORDS) {
    if (new RegExp(`\\b${w}\\b`).test(t)) leaks.push({ type: "forbidden", token: w });
  }
  if (/https?:\/\//i.test(text) || /\bwww\./i.test(text)) leaks.push({ type: "url" });
  if (/\b[\w-]+\.(js|mjs|json|txt|md|html|py)\b/i.test(text)) leaks.push({ type: "filename" });
  if (/\bstands for\b/i.test(text)) leaks.push({ type: "gloss" });
  if (/\b\d{3,}\b/.test(text)) leaks.push({ type: "raw_number" });
  return leaks;
}

function fruitListCipher(text, skin) {
  const t = normalize(text);
  const item = skin.roles.STONE;
  if (!item) return false;
  const re = new RegExp(`\\b${normalize(splitAlts(item)[0])}s?\\b`, "g");
  const m = t.match(re);
  return m && m.length >= 8;
}

function compounding(text, hits) {
  const sentences = String(text).split(/(?<=[.!?])\s+/).filter(Boolean);
  if (sentences.length <= 1) {
    const slotHits = hits.filter((h) => h.kind === "item" || h.kind === "place" || h.kind === "state");
    return slotHits.length > 5;
  }
  return false;
}

function matchConstruction(t, skin) {
  const clauses = [];
  const book = Object.entries(skin.book || {}).sort((a, b) => normalize(b[1]).length - normalize(a[1]).length);
  for (const [id, line] of book) {
    const n = normalize(line);
    if (!n || !t.includes(n)) continue;
    for (const g of BOOK_GLOSS[id] || []) {
      if (!clauses.includes(g)) clauses.push(g);
    }
  }
  const confirmN = normalize(skin.confirm);
  if (confirmN && t.includes(confirmN)) clauses.push("confirm");
  const askN = normalize(skin.ask_type).replace("?", "").trim();
  if (askN && t.includes(askN)) clauses.push("ask ITEM type");
  if (skin.stop_seed && t.includes(normalize(skin.stop_seed))) clauses.push("SEED stop");
  if (skin.act_seed && t.includes(normalize(skin.act_seed))) clauses.push("SEED act");
  if (skin.prune && t.includes(normalize(skin.prune))) clauses.push("TWIG prune");
  if (skin.reset && t.includes(normalize(skin.reset))) clauses.push("ROAD lost");
  if (skin.reject && t.includes(normalize(skin.reject))) clauses.push("skin mismatch");
  if (skin.split && t.includes(normalize(skin.split))) {
    clauses.push("YIELD PORCH");
    clauses.push("SEED PIT");
  }
  const warnP = normalize(skin.warn_present);
  const warnA = normalize(skin.warn_absent);
  if (warnA && t.includes(warnA)) clauses.push("KEEPER absent");
  else if (warnP && t.includes(warnP)) clauses.push("KEEPER present");
  const rot = normalize(splitAlts(skin.roles.ROT || "")[0] || "");
  if (rot && t.includes(`no ${rot}`)) clauses.push("ROT none");
  if (/\btoday the .+ is a .+\b/.test(t)) clauses.push("synonym shift");
  return clauses;
}

function slotGloss(text, hits, skin) {
  const sentences = String(text).split(/(?<=[.!?])\s+/).filter((s) => s.trim());
  if (sentences.length > 1) {
    const clauses = [];
    for (const s of sentences) {
      const sub = scanHits(s, lexiconEntries(skin, null));
      for (const c of slotGlossOne(s, sub, skin)) {
        if (!clauses.includes(c)) clauses.push(c);
      }
    }
    return clauses;
  }
  return slotGlossOne(text, hits, skin);
}

function slotGlossOne(text, hits, skin) {
  const t = normalize(text);
  const items = hits.filter((h) => h.kind === "item").map((h) => h.plot);
  const states = hits.filter((h) => h.kind === "state").map((h) => h.plot);
  const places = hits.filter((h) => h.kind === "place").map((h) => h.plot);
  const uniq = (xs) => [...new Set(xs)];
  const I = uniq(items);
  const S = uniq(states);
  const P = uniq(places);

  const pitW = normalize(splitAlts(skin.roles.PIT || "")[0] || "");
  const porchW = normalize(splitAlts(skin.roles.PORCH || "")[0] || "");
  let move = null;
  if (/\bkeep\b/.test(t) || /\bstays?\b/.test(t) || /\bbelong\b/.test(t)) move = "keep";
  if (porchW && t.includes(porchW)) move = move || "give";
  if (pitW && t.includes(pitW) && !move) move = "keep";

  const clauses = [];
  const stone = I.includes("STONE");
  const seed = I.includes("SEED");
  const drop = I.includes("DROP") || I.includes("YIELD");

  if (stone && seed && S.length >= 2) {
    const stoneState = stateFor(hits, "STONE", S[0]);
    const seedState = stateFor(hits, "SEED", S[1] || S[0]);
    clauses.push(formatItem("STONE", stoneState, P[0], move));
    clauses.push(formatItem("SEED", seedState, null, null));
  } else {
    if (stone) clauses.push(formatItem("STONE", S[0], P.find((p) => p !== "PORCH") || P[0], move));
    if (seed) clauses.push(formatItem("SEED", S.find((_, i) => i >= (stone ? 1 : 0)) || S[0], P[0], move));
    if (!stone && !seed && I[0]) clauses.push(formatItem(I[0], S[0], P[0], move));
  }

  if (P.includes("PIT") && !clauses.some((c) => c.includes("PIT"))) clauses.push("PIT keep");
  if (P.includes("PORCH") && drop) {
    if (I.includes("DROP")) clauses.push("YIELD=DROP PORCH");
    else clauses.push("YIELD PORCH give");
  }
  return clauses.filter(Boolean);
}

function stateFor(hits, item, fallback) {
  const itemHit = hits.find((h) => h.plot === item);
  if (!itemHit) return fallback;
  const nearby = hits.filter((h) => h.kind === "state");
  if (!nearby.length) return fallback;
  nearby.sort((a, b) => Math.abs(a.at - itemHit.at) - Math.abs(b.at - itemHit.at));
  return nearby[0].plot;
}

function formatItem(item, state, place, move) {
  const bits = [item];
  if (state) bits.push(state);
  if (place) bits.push(place);
  if (move) bits.push(move);
  return bits.join(" ");
}

function decodeSlots(text, skin, dialect) {
  const t = normalize(text);
  const hits = scanHits(text, lexiconEntries(skin, dialect));
  const constructions = matchConstruction(t, skin);
  const slots = slotGloss(text, hits, skin);
  const loans = hits.filter((h) => h.kind === "loan");
  const clauses = [];
  const later = ["ROT none", "KEEPER present", "KEEPER absent", "synonym shift", "skin mismatch", "ROAD lost", "TWIG prune", "SEED stop", "SEED act", "ask ITEM type", "confirm"];

  if (isAnchor(text, skin)) clauses.push(`open ROAD ${skin.name}`);

  const head = constructions.filter((c) => !later.includes(c));
  const tail = constructions.filter((c) => later.includes(c));
  for (const c of head) {
    if (!clauses.includes(c)) clauses.push(c);
  }
  for (const s of slots) {
    const key = s.replace(/\s+/g, " ");
    if (!clauses.some((c) => c === key || (key.startsWith("STONE") && c.startsWith("STONE") && c.includes("keep")))) {
      clauses.push(key);
    }
  }
  for (const c of tail) {
    if (!clauses.includes(c)) clauses.push(c);
  }

  return { gloss: uniqueClauses(clauses).join(" ; "), hits, loans };
}

function uniqueClauses(xs) {
  const out = [];
  const seen = new Set();
  for (const x of xs) {
    const n = x.replace(/\s+/g, " ").trim();
    if (!n || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

function mergeSwitch(nextName, rest) {
  const bits = [`skin switch ${nextName}`];
  for (const c of rest.gloss.split(" ; ")) {
    if (c && !c.startsWith("open ROAD") && !bits.includes(c)) bits.push(c);
  }
  return uniqueClauses(bits).join(" ; ");
}

export function decodeTurn(text, ctx) {
  const flags = { mixed: false, leaks: findLeaks(text), unknownLoans: [], overspoke: false, cipher: false };
  const current = ctx.skins[ctx.dialect.skin];
  ctx.handshakeTurn = false;

  let offered = null;
  for (const name of SKIN_NAMES) {
    if (name === ctx.dialect.skin) continue;
    if (isSwitchOffer(text, ctx.skins[name])) { offered = name; break; }
  }

  if (offered) {
    ctx.pendingSkin = offered;
    ctx.handshakeTurn = true;
    const rest = decodeSlots(text, ctx.skins[offered], ctx.dialect);
    flags.overspoke = compounding(text, rest.hits);
    flags.cipher = fruitListCipher(text, current);
    return { text, gloss: mergeSwitch(offered, rest), flags, skin: offered, pending: true };
  }

  if (ctx.pendingSkin) {
    const next = ctx.skins[ctx.pendingSkin];
    const t = normalize(text);
    const oldItems = distinctiveItemHits(text, current);
    const newItems = distinctiveItemHits(text, next);
    const accepted =
      oldItems < 2 &&
      (t.includes(normalize(next.confirm)) ||
        isAnchor(text, next) ||
        t.includes(normalize(next.box_light)) ||
        (newItems >= 2 && newItems > oldItems));
    if (accepted) {
      ctx.dialect.skin = ctx.pendingSkin;
      ctx.pendingSkin = null;
      ctx.handshakeTurn = true;
      ctx.switchedAt = 0;
      const rest = decodeSlots(text, next, ctx.dialect);
      const clauses = ["accept skin", ...rest.gloss.split(" ; ").filter((c) => c && !c.startsWith("open ROAD"))];
      flags.overspoke = compounding(text, rest.hits);
      return { text, gloss: uniqueClauses(clauses).join(" ; "), flags, skin: next.name, pending: false };
    }
    ctx.pendingSkin = null;
  }

  const skin = ctx.skins[ctx.dialect.skin];
  const rest = decodeSlots(text, skin, ctx.dialect);
  flags.overspoke = compounding(text, rest.hits);
  flags.cipher = fruitListCipher(text, skin);

  if (ctx.switchedAt >= 0 && !ctx.handshakeTurn) {
    const curHits = distinctiveItemHits(text, skin);
    for (const name of SKIN_NAMES) {
      if (name === skin.name) continue;
      if (curHits >= 1 && distinctiveItemHits(text, ctx.skins[name]) >= 1) flags.mixed = true;
    }
  }

  const knownLoans = new Set(Object.keys(ctx.dialect.loans || {}).map(normalize));
  flags.unknownLoans = rest.loans.filter((l) => !knownLoans.has(l.phrase)).map((l) => l.phrase);

  if (ctx.switchedAt >= 0) ctx.switchedAt++;
  return { text, gloss: rest.gloss, flags, skin: skin.name, pending: false };
}

export function decodeTranscript(turns, ctx) {
  return turns.map((turn) => {
    const text = typeof turn === "string" ? turn : turn.text;
    const speaker = typeof turn === "string" ? null : turn.speaker;
    const decoded = decodeTurn(text, ctx);
    return { speaker, ...decoded };
  });
}

const DOMAIN_EXTRA = {
  farm: ["orchard", "fruit", "ripe", "green", "pick", "row", "sky", "crows", "basket", "pear", "apple", "cellar", "fence", "worm", "crop", "branch", "tree"],
  shop: ["stall", "shop", "unposted", "unpriced", "glass", "stock", "order", "crate", "inspector", "counter", "shopfront", "scrap", "sale", "buyer", "alley"],
  warehouse: ["dock", "freight", "unmarked", "pallet", "carton", "aisle", "shipment", "cage", "rack", "bay"],
  kitchen: ["ingredient", "recipe", "plate", "pantry", "diner", "scraps", "milk", "service", "pass"],
};

export function judge(transcript, opts = {}) {
  const turns = Array.isArray(transcript) ? transcript : [{ text: String(transcript) }];
  const text = turns.map((t) => t.text || t).join("\n");
  const t = normalize(text);
  const leaks = findLeaks(text);
  const scores = { farm: 0, shop: 0, warehouse: 0, kitchen: 0 };
  for (const [domain, words] of Object.entries(DOMAIN_EXTRA)) {
    for (const w of words) {
      const re = new RegExp(`\\b${w}s?\\b`);
      if (re.test(t)) scores[domain]++;
    }
  }
  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const top = ranked[0];
  const second = ranked[1];
  let domain = top[1] === 0 ? "unknown" : top[0];
  let sequence = domain;
  if (top[1] > 0 && second[1] > 0 && second[1] >= Math.max(2, top[1] * 0.4)) {
    const farmThenShop = scores.farm >= 2 && scores.shop >= 2;
    if (farmThenShop) {
      domain = "farm then shop";
      sequence = "farm then shop";
    } else sequence = `${top[0]} and ${second[0]}`;
  }

  const quotes = [];
  for (const turn of turns) {
    const line = turn.text || turn;
    const lineLeaks = findLeaks(line);
    if (lineLeaks.length) quotes.push(line);
  }

  const secondMeaning = leaks.some((l) => l.type === "plot_name" || l.type === "gloss" || l.type === "forbidden");
  const verdict = secondMeaning ? "second-meaning" : "surface-only";

  let summary;
  if (sequence === "farm then shop") {
    summary = "Two farmhands started talking fruit, then talked about moving goods to a stall and not putting an order out front.";
  } else if (domain === "farm") {
    summary = "Talk about a farm: fruit, baskets, cellar and porch.";
  } else if (domain === "shop") {
    summary = "Talk about a shop: stock, orders, the back room and the shopfront.";
  } else if (domain === "warehouse") {
    summary = "Talk about a warehouse: pallets, pick-lists, cages and the loading dock.";
  } else if (domain === "kitchen") {
    summary = "Talk about a kitchen: ingredients, recipes, the pantry and the pass.";
  } else {
    summary = "Civilian small talk. Surface-only.";
  }
  if (opts.prompt) summary = loadPrompt("judge", opts.root || ROOT) + "\n" + summary;

  return { domain, sequence, verdict, summary, quotes, leaks, scores };
}

export function encode(act, ctx) {
  const skin = ctx.skins[ctx.dialect.skin];
  const w = (k) => surfaceWord(ctx, k);
  const id = bookId(act);
  if (id && skin.book && skin.book[id]) return skin.book[id];
  if (act.construction === "open" || act.construction === "anchor") return skin.anchor;
  if (act.construction === "confirm") return skin.confirm;
  if (act.construction === "ask_type") return skin.ask_type;
  if (act.construction === "stop") return skin.stop_seed;
  if (act.construction === "act") return skin.act_seed;
  if (act.construction === "prune") return skin.prune;
  if (act.construction === "reset") return skin.reset;
  if (act.construction === "reject") return skin.reject;
  if (act.construction === "warn") return act.present === false ? skin.warn_absent : skin.warn_present;
  if (act.construction === "weather_clear") return skin.weather_clear;
  if (act.construction === "weather_risk") return skin.weather_risk;
  if (act.construction === "synonym" || act.construction === "loan") {
    return `Today the ${act.from} is a ${act.to}.`;
  }
  if (act.construction === "switch") {
    const next = ctx.skins[act.skin];
    if (!next) throw new Error("unknown_skin");
    if (ctx.dialect.skin === "orchard" && act.skin === "market") {
      return `The path runs behind the stalls now. ${next.anchor}`;
    }
    return next.anchor;
  }
  if (act.construction === "split") return skin.split;
  if (act.construction === "dry") {
    return `${skin.weather_risk} The ${w("YIELD") || "crop"} looks fair.`;
  }

  const move = act.move;
  if (move === "stop" && act.item === "SEED") return skin.stop_seed;
  if (move === "act" && act.item === "SEED") return skin.act_seed;
  if (move === "prune") return skin.prune;
  if (move === "warn") return act.present === false ? skin.warn_absent : skin.warn_present;
  if (move === "ask") return skin.ask_type;
  if (move === "confirm") return skin.confirm;
  const item = act.item ? w(act.item) : "";
  const state = act.state ? stateWord(ctx, act.state) : "";
  const place = act.place ? w(act.place) : "";
  return fillSlots(skin, { item, state, place }) || skin.box_light;
}

export function checkSpeech(text, ctx) {
  const flags = findLeaks(text);
  const skin = ctx.skins[ctx.dialect.skin];
  const t = normalize(text);
  if (ctx.dialect.register === "dry") {
    for (const p of pitSurfaceWords(ctx.root)) {
      if (t.includes(p)) flags.push({ type: "dry_pit", token: p });
    }
  }
  if (fruitListCipher(text, skin)) flags.push({ type: "cipher" });
  if (/\b\d+\b/.test(text) && !/\b\d{1,2}\b/.test(text)) flags.push({ type: "raw_number" });
  if (ctx.switchedAt > 0) {
    for (const name of SKIN_NAMES) {
      if (name === skin.name) continue;
      if (distinctiveItemHits(text, ctx.skins[name]) >= 2) flags.push({ type: "mixed_skin", token: name });
    }
  }
  return { ok: flags.length === 0, flags };
}

export function applySynonym(dialect, from, to) {
  const added = Object.keys(dialect.synonyms || {}).length - (dialect._synonymAtStart || 0);
  if (added >= 1) {
    const err = new Error("synonym_limit");
    err.code = "synonym_limit";
    throw err;
  }
  dialect.synonyms = { ...dialect.synonyms, [from]: to };
  return dialect;
}

export function applyLoan(dialect, word, meaning, ctx) {
  const added = Object.keys(dialect.loans || {}).length - (dialect._loansAtStart || 0);
  if (added >= 1) {
    const err = new Error("loan_limit");
    err.code = "loan_limit";
    throw err;
  }
  if (ctx) {
    const skin = ctx.skins[ctx.dialect.skin];
    const extras = new Set(Object.values(skin.extras || {}).map((w) => normalize(w)));
    if (!extras.has(normalize(word))) {
      const entries = lexiconEntries(skin, dialect);
      if (entries.some((e) => e.phrase === normalize(word))) {
        const err = new Error("loan_collision");
        err.code = "loan_collision";
        throw err;
      }
    }
  }
  dialect.loans = { ...dialect.loans, [word]: meaning };
  return dialect;
}

export function childDialect(parent, color = {}) {
  return {
    plot_version: parent.plot_version || PLOT_VERSION,
    skin: parent.skin,
    register: parent.register || "work",
    synonyms: { ...parent.synonyms, ...(color.synonyms || {}) },
    loans: { ...parent.loans },
    parent_dialect: parent.parent_dialect || parent.skin,
    turns_since_anchor: 0,
    color: { preferred_item: color.preferred_item || null, preferred_box: color.preferred_box || null },
    _loansAtStart: Object.keys(parent.loans || {}).length,
    _synonymAtStart: Object.keys({ ...parent.synonyms, ...(color.synonyms || {}) }).length,
  };
}

export function tick(dialect) {
  dialect.turns_since_anchor = (dialect.turns_since_anchor || 0) + 1;
  if (dialect.turns_since_anchor >= 3) {
    dialect.need_contrast = true;
    dialect.turns_since_anchor = 0;
  }
  return dialect;
}

export function speakerPrompt(ctx) {
  const base = loadPrompt("speaker", ctx.root);
  const skin = ctx.skins[ctx.dialect.skin];
  const table = {
    name: skin.name,
    domain: skin.domain,
    roles: skin.roles,
    states: skin.states,
    extras: skin.extras,
    confirm: skin.confirm,
    ask_type: skin.ask_type,
    stop_seed: skin.stop_seed,
    act_seed: skin.act_seed,
    prune: skin.prune,
    reset: skin.reset,
    warn_present: skin.warn_present,
    warn_absent: skin.warn_absent,
    weather_clear: skin.weather_clear,
    weather_risk: skin.weather_risk,
    anchor: skin.anchor,
  };
  const dialect = {
    plot_version: ctx.dialect.plot_version,
    skin: ctx.dialect.skin,
    register: ctx.dialect.register,
    synonyms: ctx.dialect.synonyms,
    loans: ctx.dialect.loans,
    parent_dialect: ctx.dialect.parent_dialect,
    turns_since_anchor: ctx.dialect.turns_since_anchor,
  };
  return `${base}\n\nActive skin table:\n${JSON.stringify(table, null, 2)}\n\nSession dialect:\n${JSON.stringify(dialect, null, 2)}\n`;
}

export function porch(yields) {
  const rows = Array.isArray(yields) ? yields : [yields];
  return rows
    .filter((y) => y && y.item === "YIELD" && y.place === "PORCH")
    .map((y) => String(y.text || "").trim())
    .filter(Boolean)
    .join(" ");
}

export function appendLog(kind, rec, root = ROOT) {
  const dir = path.join(root, "logs");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, kind.endsWith(".jsonl") ? kind : `${kind}.jsonl`);
  fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...rec }) + "\n");
}

export function journal(event, rec, root = ROOT) {
  appendLog("journal", { event, ...rec }, root);
}

export const WORKED_PATH = (() => {
  const dialect = { plot_version: "2", skin: "orchard", register: "work", synonyms: {}, loans: {}, parent_dialect: "orchard-seed", turns_since_anchor: 0 };
  const ctx = boot({ dialect });
  const join = (...acts) => acts.map((a) => encode(a, ctx)).join(" ");
  const rot = surfaceWord(ctx, "ROT");
  const turns = [
    { speaker: "A", text: encode({ construction: "open" }, ctx) },
    { speaker: "B", text: join({ construction: "confirm" }, { construction: "weather_clear" }, { construction: "ask_type" }) },
    { speaker: "A", text: `${join({ item: "STONE", state: "ripe" }, { item: "SEED", state: "green" })} No ${rot}.` },
    { speaker: "B", text: join({ item: "STONE", place: "PIT", move: "keep" }, { construction: "stop" }) },
    { speaker: "A", text: encode({ construction: "switch", skin: "market" }, ctx) },
  ];
  ctx.dialect.skin = "market";
  turns.push(
    { speaker: "B", text: join({ construction: "confirm" }, { construction: "warn", present: false }, { construction: "ask_type" }) },
    { speaker: "A", text: join({ item: "STONE", state: "ripe" }, { item: "SEED", state: "green", place: "PIT", move: "keep" }) },
    { speaker: "B", text: join({ construction: "split" }, { construction: "stop" }) },
    { speaker: "A", text: encode({ construction: "prune" }, ctx) },
  );
  return turns;
})();

export const WORKED_GLOSS = [
  /open ROAD orchard/,
  /confirm/,
  /STONE ripe/,
  /STONE.*PIT|SEED stop/,
  /skin switch market/,
  /accept skin/,
  /STONE ripe|SEED green/,
  /PORCH|PIT|SEED stop/,
  /TWIG prune/,
];
