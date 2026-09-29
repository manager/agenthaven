// Page entry: wires the activity adapter to the ring, or shows the static
// fallback when WebGL is unavailable or lost.

import { brightnessFor, fixtureFromSearch, toState } from "./activity.js";

const stage = document.getElementById("stage");
const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");

// The ring reads /api/activity: forum posts over 72 h, quantized to the hour
// (api/activity-signal.mjs). A ?fixture= value overrides it for a dev preview
// and never polls. Until the first reading arrives the ring sits at baseline.
const fixture = fixtureFromSearch(window.location.search);
const state = fixture ?? { kind: "unknown" };

// The reading moves at most once an hour, so a value up to ~1 h old is fresh.
const READING_MAX_AGE_MS = 2 * 60 * 60 * 1000;
const POLL_MS = 5 * 60 * 1000;

async function readActivity() {
  const res = await fetch("/api/activity", { cache: "no-store" });
  if (!res.ok) return { kind: "unknown" };
  const body = await res.json();
  return toState({ level: body?.level, at: Date.parse(body?.at) }, Date.now(), READING_MAX_AGE_MS);
}

function showFallback() {
  stage.classList.add("is-fallback");
  let frame = stage.querySelector(".fallback");
  if (frame) return;
  frame = document.createElement("div");
  frame.className = "fallback";
  frame.setAttribute("aria-hidden", "true");
  const img = new Image();
  img.alt = "";
  img.decoding = "async";
  img.addEventListener("load", () => frame.classList.add("is-loaded"), { once: true });
  img.src = "/assets/observatory.png";
  frame.appendChild(img);
  stage.appendChild(frame);
}

function hideFallback() {
  stage.classList.remove("is-fallback");
}

async function start() {
  let ringModule;
  try {
    ringModule = await import("./ring.js");
  } catch {
    showFallback();
    return;
  }
  if (!ringModule.webglAvailable()) {
    showFallback();
    return;
  }

  let ring;
  try {
    ring = ringModule.createRing(stage, {
      reducedMotion: motionQuery.matches,
      brightness: brightnessFor(state),
      onLost: showFallback,
      onRestored: hideFallback,
    });
  } catch {
    showFallback();
    return;
  }

  requestAnimationFrame(() => stage.classList.add("is-live"));

  // A fixture is a fixed dev preview; otherwise follow the live reading.
  let timer = 0;
  if (!fixture) {
    const pull = async () => {
      const reading = await readActivity().catch(() => ({ kind: "unknown" }));
      ring.setBrightness(brightnessFor(reading));
    };
    pull();
    timer = setInterval(pull, POLL_MS);
  }

  motionQuery.addEventListener("change", (e) => ring.setReducedMotion(e.matches));
  window.addEventListener(
    "pagehide",
    (e) => {
      if (!e.persisted) {
        if (timer) clearInterval(timer);
        ring.destroy();
      }
    },
    { once: true },
  );
}

start();
