// /project-details/: draws the system map's lines over the tile grid and
// runs the page's interactions. The tiles and every fact are static HTML in
// /project-details/index.html; without this script the page still reads
// in full, the lines and the eased opening are the only things missing.

const NS = "http://www.w3.org/2000/svg";
const map = document.getElementById("map");
const svg = document.getElementById("map-lines");
document.documentElement.classList.add("js");

// Every flow on the map. kind: ct (ciphertext), pt (plaintext), meta
// (metadata or a check). route: v (vertical, tile to tile), h (horizontal,
// same row), wc (a client down and across to the witness). Labels sit only
// where the grid leaves room for 16px text: beside vertical lines, and for
// the witness runs in the empty cell under the client, on the far side of
// the vertical run (two lines, so the text never reaches the witness tile).
const EDGES = [
  { from: "A", to: "C1", kind: "pt", route: "v", label: "text and password" },
  { from: "C1", to: "E", kind: "ct", route: "h" },
  { from: "E", to: "S", kind: "ct", route: "h" },
  { from: "S", to: "C2", kind: "ct", route: "h" },
  { from: "C2", to: "B", kind: "pt", route: "v", label: "text" },
  { from: "R", to: "S", kind: "meta", route: "v", label: "with cookie" },
  { from: "S", to: "W", kind: "meta", route: "v", label: "key log head" },
  { from: "C1", to: "W", kind: "meta", route: "wc", both: true, label: "compare head\nand page hashes" },
  { from: "C2", to: "W", kind: "meta", route: "wc", both: true, label: "compare head\nand page hashes" },
];

const tiles = new Map();
for (const t of map.querySelectorAll(".tile")) tiles.set(t.dataset.node, t);

const el = (name, attrs = {}) => {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
};

// Arrowheads, one per kind, coloured through CSS.
const defs = el("defs");
for (const kind of ["ct", "pt", "meta"]) {
  const m = el("marker", { id: `arrow-${kind}`, viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse" });
  const p = el("path", { d: "M 0 0 L 10 5 L 0 10 z" });
  p.setAttribute("class", `arrow ${kind}`);
  m.append(p);
  defs.append(m);
}
svg.append(defs);

const drawn = EDGES.map((e, i) => {
  const base = el("path", { "marker-end": `url(#arrow-${e.kind})` });
  base.setAttribute("class", `edge ${e.kind}`);
  if (e.both) base.setAttribute("marker-start", `url(#arrow-${e.kind})`);
  const pulse = el("path", { pathLength: "1" });
  pulse.setAttribute("class", `pulse ${e.kind}`);
  pulse.style.animationDelay = `${-(i * 533)}ms`;
  const label = e.label ? el("text") : null;
  if (label) {
    label.setAttribute("class", "edge-label");
    e.label.split("\n").forEach((line, n) => {
      const t = el("tspan", { x: "0", dy: n ? "24" : "0" });
      t.textContent = line;
      label.append(t);
    });
  }
  svg.append(base, pulse);
  if (label) svg.append(label);
  return { ...e, base, pulse, label };
});

const rectOf = (node) => {
  const m = map.getBoundingClientRect();
  const r = tiles.get(node).getBoundingClientRect();
  const left = r.left - m.left;
  const top = r.top - m.top;
  return { left, top, right: left + r.width, bottom: top + r.height, cx: left + r.width / 2, cy: top + r.height / 2 };
};

function draw() {
  const m = map.getBoundingClientRect();
  svg.setAttribute("viewBox", `0 0 ${m.width} ${m.height}`);
  for (const e of drawn) {
    const a = rectOf(e.from);
    const b = rectOf(e.to);
    let d = "";
    let lx = 0;
    let ly = 0;
    let anchor = "start";
    if (e.route === "v") {
      const down = a.bottom <= b.top;
      const x = a.cx >= b.left && a.cx <= b.right ? a.cx : b.cx;
      const y1 = down ? a.bottom : a.top;
      const y2 = down ? b.top : b.bottom;
      d = `M ${x} ${y1} L ${x} ${y2}`;
      lx = x + 12;
      ly = (y1 + y2) / 2 + 6;
    } else if (e.route === "h") {
      const y = a.cy;
      d = `M ${a.right} ${y} L ${b.left} ${y}`;
    } else {
      // From near the client's inner edge down to the witness row, then
      // across. The label sits on the outer side of the vertical run, above
      // the horizontal one, where the empty cell leaves the most room.
      const toRight = a.cx < b.left;
      const x1 = toRight ? a.right - 24 : a.left + 24;
      const x2 = toRight ? b.left : b.right;
      d = `M ${x1} ${a.bottom} L ${x1} ${b.cy} L ${x2} ${b.cy}`;
      lx = toRight ? x1 - 12 : x1 + 12;
      ly = b.cy - 12 - 24;
      anchor = toRight ? "end" : "start";
    }
    e.base.setAttribute("d", d);
    e.pulse.setAttribute("d", d);
    if (e.label) {
      e.label.setAttribute("y", ly);
      e.label.setAttribute("text-anchor", anchor);
      for (const t of e.label.querySelectorAll("tspan")) t.setAttribute("x", lx);
    }
  }
}

draw();
new ResizeObserver(draw).observe(map);
window.addEventListener("load", draw);

// Hover or focus on a tile: light its lines and the tiles they reach.
function light(node) {
  map.classList.toggle("is-focus", Boolean(node));
  for (const [id, t] of tiles) {
    t.classList.toggle("is-lit", id === node);
    t.classList.toggle("is-near", Boolean(node) && id !== node && (tiles.get(node).dataset.links || "").split(" ").includes(id));
  }
  for (const e of drawn) {
    const on = Boolean(node) && (e.from === node || e.to === node);
    e.base.classList.toggle("is-lit", on);
    e.pulse.classList.toggle("is-lit", on);
    if (e.label) e.label.classList.toggle("is-lit", on);
  }
}

for (const [id, t] of tiles) {
  t.addEventListener("pointerenter", () => light(id));
  t.addEventListener("pointerleave", () => light(null));
  t.addEventListener("focus", () => light(id));
  t.addEventListener("blur", () => light(null));
}

// View toggle: Full (the map and sections) or Simplified. #simplified in the
// URL opens the simplified view; any other hash is a section of the full one.
const views = {
  full: { tab: document.getElementById("tab-full"), panel: document.getElementById("view-full") },
  simple: { tab: document.getElementById("tab-simple"), panel: document.getElementById("view-simple") },
};

function showView(name, focus = false) {
  for (const [id, v] of Object.entries(views)) {
    const on = id === name;
    if (v.tab.getAttribute("aria-selected") === String(on)) continue;
    v.tab.setAttribute("aria-selected", String(on));
    v.tab.tabIndex = on ? 0 : -1;
    v.panel.hidden = !on;
    v.panel.classList.toggle("is-in", on);
    if (on && focus) v.tab.focus();
  }
  // The Simplified view wears the HUD backdrop (details.css, .is-hud).
  document.querySelector(".details").classList.toggle("is-hud", name === "simple");
  if (name === "full") draw();
}

const hashView = () => (location.hash === "#simplified" ? "simple" : "full");
showView(hashView());
window.addEventListener("hashchange", () => showView(hashView()));

for (const [id, v] of Object.entries(views)) {
  v.tab.addEventListener("click", () => {
    showView(id);
    history.replaceState(null, "", id === "simple" ? "#simplified" : location.pathname + location.search);
  });
  v.tab.addEventListener("keydown", (ev) => {
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    ev.preventDefault();
    const next = id === "full" ? "simple" : "full";
    showView(next, true);
    history.replaceState(null, "", next === "simple" ? "#simplified" : location.pathname + location.search);
  });
}

// Simplified readouts beside the mouse pointer. The readout keeps the
// point's width, sits 16px right of the pointer (left when the right has no
// room) and stays inside the window. Keyboard focus and touch keep it under
// the point (details.css, .hint).
const GAP = 16;
for (const li of document.querySelectorAll(".simple-card li")) {
  const hint = li.querySelector(".hint");
  if (!hint) continue;
  let frame = 0;
  let px = 0;
  let py = 0;
  const place = () => {
    frame = 0;
    const box = li.getBoundingClientRect();
    const w = Math.min(box.width, window.innerWidth - GAP * 2);
    li.style.setProperty("--hint-w", `${w}px`);
    const h = hint.offsetHeight;
    let x = px + GAP;
    if (x + w > window.innerWidth - GAP) x = px - GAP - w;
    x = Math.max(GAP, x);
    const y = Math.max(GAP, Math.min(py - h / 2, window.innerHeight - GAP - h));
    li.style.setProperty("--hint-x", `${x - box.left}px`);
    li.style.setProperty("--hint-y", `${y - box.top}px`);
    li.classList.add("at-pointer");
  };
  li.addEventListener("pointermove", (ev) => {
    if (ev.pointerType === "touch") return;
    px = ev.clientX;
    py = ev.clientY;
    if (!frame) frame = requestAnimationFrame(place);
  });
  li.addEventListener("focus", () => {
    if (li.matches(":focus-visible") && !li.matches(":hover")) li.classList.remove("at-pointer");
  });
}

// Sub-tiles: <details> that ease open and closed (grid-template-rows 0fr to
// 1fr) instead of snapping. Closing waits for the transition, then hides.
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
for (const sub of document.querySelectorAll(".sub")) {
  const body = sub.querySelector(".sub-body");
  if (sub.open) sub.classList.add("is-open");
  sub.querySelector(".sub-head").addEventListener("click", (ev) => {
    ev.preventDefault();
    if (!sub.open) {
      sub.open = true;
      requestAnimationFrame(() => requestAnimationFrame(() => sub.classList.add("is-open")));
      return;
    }
    sub.classList.remove("is-open");
    if (reduced.matches) {
      sub.open = false;
      return;
    }
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      if (!sub.classList.contains("is-open")) sub.open = false;
    };
    body.addEventListener("transitionend", (t) => t.target === body && finish(), { once: true });
    setTimeout(finish, 700);
  });
}
