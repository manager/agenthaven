// Observatory ring scene. Built procedurally from ring-geometry.js; the concept
// image is only a composition reference. Brightness comes from activity.js and
// nothing else. The ring ignores the pointer: it holds its
// pose and only spins slowly around its own axis.

import {
  AdditiveBlending,
  BufferAttribute,
  BufferGeometry,
  Group,
  LineSegments,
  PerspectiveCamera,
  Points,
  Scene,
  ShaderMaterial,
  Vector3,
  WebGLRenderer,
} from "../vendor/three.module.js";
import { buildRing } from "./ring-geometry.js";
import { BASELINE, CEILING } from "./activity.js";

// Passport tokens as 0..1 RGB: --bg, --ink, --accent.
const BG = 0x0b0a09;
const INK = "vec3(0.922, 0.902, 0.867)";
const AMBER = "vec3(0.941, 0.663, 0.251)";

const FOV = 30;
const TILT_X = 0.5; // how far the ring is tipped toward the viewer
const ROLL_Z = 0.3; // rises to the right, as in the concept
const SPIN = 0.018; // ambient spin, radians per second
const LIGHT_EASE = 1.2; // per second, ~2.5s to settle

const LINE_VERTEX = /* glsl */ `
  attribute vec3 aNormal;
  attribute float aAlong;
  attribute float aAmber;
  attribute float aWarm;
  attribute float aPhase;
  uniform float uTime;
  uniform float uBright;
  uniform float uLevel;
  uniform vec3 uLight;
  uniform vec2 uDepth;
  varying vec3 vColor;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vec3 n = normalize(mat3(modelMatrix) * aNormal);
    float light = 0.2 + 0.8 * clamp(dot(n, uLight), 0.0, 1.0);
    float depth = 1.0 - smoothstep(uDepth.x, uDepth.y, -mv.z);
    float ends = smoothstep(0.0, 0.12, aAlong) * (1.0 - smoothstep(0.88, 1.0, aAlong));
    float shimmer = 0.9 + 0.1 * sin(uTime * 0.6 + aPhase + aAlong * 6.0);
    float spread = uLevel * smoothstep(0.55, 1.0, aWarm) * 0.9;
    float warmth = clamp(aAmber * (0.45 + 0.55 * uBright) + spread, 0.0, 1.2);
    vec3 c = ${INK} * light * mix(0.35, 1.0, depth) * 0.13 * shimmer;
    c += ${AMBER} * warmth * (0.3 + 0.7 * light) * mix(0.5, 1.0, depth) * 0.5 * (0.4 + 0.6 * uBright);
    vColor = min(c * ends, vec3(0.9));
    gl_Position = projectionMatrix * mv;
  }
`;

const LINE_FRAGMENT = /* glsl */ `
  varying vec3 vColor;
  void main() {
    gl_FragColor = vec4(vColor, 1.0);
  }
`;

const DUST_VERTEX = /* glsl */ `
  attribute vec3 aNormal;
  attribute float aAmber;
  attribute float aPhase;
  uniform float uTime;
  uniform float uBright;
  uniform float uPixelRatio;
  uniform vec3 uLight;
  uniform vec2 uDepth;
  varying vec3 vColor;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vec3 n = normalize(mat3(modelMatrix) * aNormal);
    float light = 0.25 + 0.75 * clamp(dot(n, uLight), 0.0, 1.0);
    float depth = 1.0 - smoothstep(uDepth.x, uDepth.y, -mv.z);
    float shimmer = 0.75 + 0.25 * sin(uTime * 0.8 + aPhase);
    vec3 ink = ${INK} * 0.28 * light;
    vec3 amber = ${AMBER} * (0.35 + 0.65 * uBright) * 0.9;
    vColor = mix(ink, amber, aAmber) * mix(0.3, 1.0, depth) * shimmer;
    gl_PointSize = (1.4 + aAmber * 1.2) * uPixelRatio * mix(0.7, 1.2, depth);
    gl_Position = projectionMatrix * mv;
  }
`;

const DUST_FRAGMENT = /* glsl */ `
  varying vec3 vColor;
  void main() {
    float d = length(gl_PointCoord - 0.5);
    float a = 1.0 - smoothstep(0.1, 0.5, d);
    gl_FragColor = vec4(vColor * a, 1.0);
  }
`;

export function webglAvailable() {
  try {
    const c = document.createElement("canvas");
    return Boolean(c.getContext("webgl2") || c.getContext("webgl"));
  } catch {
    return false;
  }
}

export function createRing(stage, { reducedMotion = false, brightness = BASELINE, onLost, onRestored } = {}) {
  const compact = Math.min(stage.clientWidth, stage.clientHeight) < 640;
  const data = buildRing(
    compact ? { filaments: 900, segments: 96, dust: 3000 } : { filaments: 1800, segments: 120, dust: 6000 },
  );

  const renderer = new WebGLRenderer({ antialias: true, alpha: false, powerPreference: "high-performance" });
  renderer.setClearColor(BG, 1);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, compact ? 1.5 : 2));
  const canvas = renderer.domElement;
  canvas.setAttribute("aria-hidden", "true");
  canvas.className = "ring-canvas";

  const scene = new Scene();
  const camera = new PerspectiveCamera(FOV, 1, 0.1, 100);

  const uniforms = {
    uTime: { value: 0 },
    uBright: { value: brightness },
    uLevel: { value: toLevel(brightness) },
    uLight: { value: new Vector3(0.45, 0.8, 0.4).normalize() },
    uDepth: { value: new Float32Array([1, 10]) },
    uPixelRatio: { value: renderer.getPixelRatio() },
  };

  const lineGeo = new BufferGeometry();
  lineGeo.setAttribute("position", new BufferAttribute(data.position, 3));
  lineGeo.setAttribute("aNormal", new BufferAttribute(data.normal, 3));
  lineGeo.setAttribute("aAlong", new BufferAttribute(data.along, 1));
  lineGeo.setAttribute("aAmber", new BufferAttribute(data.amber, 1));
  lineGeo.setAttribute("aWarm", new BufferAttribute(data.warm, 1));
  lineGeo.setAttribute("aPhase", new BufferAttribute(data.flicker, 1));
  lineGeo.setIndex(new BufferAttribute(data.index, 1));

  const lineMat = new ShaderMaterial({
    uniforms,
    vertexShader: LINE_VERTEX,
    fragmentShader: LINE_FRAGMENT,
    blending: AdditiveBlending,
    depthTest: false,
    depthWrite: false,
    transparent: true,
  });

  const dustGeo = new BufferGeometry();
  dustGeo.setAttribute("position", new BufferAttribute(data.dust.position, 3));
  dustGeo.setAttribute("aNormal", new BufferAttribute(data.dust.normal, 3));
  dustGeo.setAttribute("aAmber", new BufferAttribute(data.dust.amber, 1));
  dustGeo.setAttribute("aPhase", new BufferAttribute(data.dust.phase, 1));

  const dustMat = new ShaderMaterial({
    uniforms,
    vertexShader: DUST_VERTEX,
    fragmentShader: DUST_FRAGMENT,
    blending: AdditiveBlending,
    depthTest: false,
    depthWrite: false,
    transparent: true,
  });

  // roll (view space) > tilt (toward viewer) > spin (around the ring's own axis)
  const roll = new Group();
  const tilt = new Group();
  const spin = new Group();
  roll.rotation.z = ROLL_Z;
  tilt.rotation.x = TILT_X;
  spin.add(new LineSegments(lineGeo, lineMat), new Points(dustGeo, dustMat));
  tilt.add(spin);
  roll.add(tilt);
  scene.add(roll);

  stage.appendChild(canvas);

  const state = {
    reduced: reducedMotion,
    target: brightness,
    current: brightness,
    visible: true,
    running: false,
    lost: false,
    raf: 0,
    last: 0,
    time: 0,
  };

  function toLevel(b) {
    return Math.min(1, Math.max(0, (b - BASELINE) / (CEILING - BASELINE)));
  }

  function fit() {
    const w = Math.max(1, stage.clientWidth);
    const h = Math.max(1, stage.clientHeight);
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    const halfTan = Math.tan((FOV * Math.PI) / 360);
    // Keep the whole torus in frame with air around it, on any aspect.
    const needW = data.boundingRadius * 1.18;
    const needH = data.boundingRadius * 0.68 * 1.18;
    const dist = Math.max(needW / (halfTan * camera.aspect), needH / halfTan);
    camera.position.set(0, 0, dist);
    camera.near = Math.max(0.05, dist - 3);
    camera.far = dist + 3;
    camera.lookAt(0, 0, 0);
    camera.updateProjectionMatrix();
    uniforms.uDepth.value[0] = dist - data.boundingRadius;
    uniforms.uDepth.value[1] = dist + data.boundingRadius;
    if (!state.running) renderOnce();
  }

  function applyLight(b) {
    uniforms.uBright.value = b;
    uniforms.uLevel.value = toLevel(b);
  }

  function renderOnce() {
    if (state.lost) return;
    renderer.render(scene, camera);
  }

  function frame(now) {
    state.raf = 0;
    if (!state.running) return;
    const dt = Math.min(0.1, state.last ? (now - state.last) / 1000 : 0);
    state.last = now;
    state.time += dt;
    uniforms.uTime.value = state.time;

    spin.rotation.y += SPIN * dt;

    const kl = 1 - Math.exp(-LIGHT_EASE * dt);
    state.current += (state.target - state.current) * kl;
    applyLight(state.current);

    renderOnce();
    state.raf = requestAnimationFrame(frame);
  }

  function sync() {
    const should = !state.reduced && state.visible && !state.lost && !document.hidden;
    if (should && !state.running) {
      state.running = true;
      state.last = 0;
      state.raf = requestAnimationFrame(frame);
    } else if (!should && state.running) {
      state.running = false;
      if (state.raf) cancelAnimationFrame(state.raf);
      state.raf = 0;
    }
    if (!state.running) renderOnce();
  }

  function onLostContext(e) {
    e.preventDefault();
    state.lost = true;
    sync();
    if (onLost) onLost();
  }

  function onRestoredContext() {
    state.lost = false;
    if (onRestored) onRestored();
    fit();
    sync();
  }

  const resizeObserver = new ResizeObserver(fit);
  resizeObserver.observe(stage);
  const intersection = new IntersectionObserver((entries) => {
    state.visible = entries.some((en) => en.isIntersecting);
    sync();
  });
  intersection.observe(stage);

  document.addEventListener("visibilitychange", sync);
  canvas.addEventListener("webglcontextlost", onLostContext);
  canvas.addEventListener("webglcontextrestored", onRestoredContext);

  fit();
  sync();

  return {
    canvas,
    setBrightness(b) {
      state.target = b;
      if (!state.running) {
        state.current = b;
        applyLight(b);
        renderOnce();
      }
    },
    setReducedMotion(on) {
      state.reduced = on;
      if (on) {
        state.current = state.target;
        applyLight(state.current);
      }
      sync();
    },
    destroy() {
      state.running = false;
      if (state.raf) cancelAnimationFrame(state.raf);
      resizeObserver.disconnect();
      intersection.disconnect();
      document.removeEventListener("visibilitychange", sync);
      canvas.removeEventListener("webglcontextlost", onLostContext);
      canvas.removeEventListener("webglcontextrestored", onRestoredContext);
      lineGeo.dispose();
      dustGeo.dispose();
      lineMat.dispose();
      dustMat.dispose();
      renderer.dispose();
      canvas.remove();
    },
  };
}
