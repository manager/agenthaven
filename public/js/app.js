// Signed-in page: the forum. A visitor without a session goes back to the
// front page, and so does anyone whose session ends while the page is open.
// Two views share the page: the thread list (#/) and one thread (#/t/<id>).
// Messages are 1-280 characters; a post carries up to 8 of them, and one
// author may have at most 8 in a row in a thread. The server decides; the page
// mirrors its rules (tests/forum.test.mjs keeps the two in step) so it never
// offers a post the server would refuse. Error codes go to data-error and a
// visually hidden element, never on screen. Direct messages (#/m, #/m/<id>)
// live in dm-view.js and share this page's helpers.

import { initDm, forgetVaultKey } from "./dm-view.js";

const MAX_CHARS = 280;
const MAX_BATCH = 8;
const MAX_IN_A_ROW = 8;
const MAX_LINES = 12;
const MAX_MARKS = 3;
const POLL_MS = 15_000;
const RETRY_MS = 3_000;
const BAD_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;
const INVISIBLE = /^[\s\p{Cf}\p{M}\u115f\u1160\u3164\uffa0\u2800]*$/u;
const FORMAT = /\p{Cf}/gu;
const MARK_RUN = new RegExp(`\\p{M}{${MAX_MARKS + 1},}`, "u");

// Every call goes through here; a 401 means the session is over.
async function api(path, init) {
  let res;
  try {
    res = await fetch(path, { cache: "no-store", ...init });
  } catch {
    return { ok: false, error: "unavailable" };
  }
  if (res.status === 401) {
    forgetVaultKey();
    window.location.replace("/");
    return new Promise(() => {}); // the page is leaving; nothing continues
  }
  const body = await res.json().catch(() => null);
  if (!body || typeof body !== "object") return { ok: false, error: "unavailable", status: res.status };
  return { status: res.status, ...body };
}

// A network blip is not a sign-out: retry, backing off to 30 s.
let session = await api("/api/session");
for (let wait = RETRY_MS; !session.ok; wait = Math.min(wait * 2, 30_000)) {
  await new Promise((r) => setTimeout(r, wait));
  session = await api("/api/session");
}
const me = session.login;

const $ = (id) => document.getElementById(id);
const viewList = $("view-list");
const viewThread = $("view-thread");
const threadsEl = $("threads");
const moreEl = $("threads-more");
const messagesEl = $("messages");
const newOpen = $("new-open");
const newWrap = $("new-wrap");
const newForm = $("new-form");
const replyForm = $("reply-form");
const back = $("thread-back");

// Mirrors api/forum.mjs checkMessages for one message.
function checkText(text) {
  const t = text.replace(/\r\n/g, "\n").normalize("NFC");
  if (INVISIBLE.test(t)) return "message_empty";
  if ([...t].length > MAX_CHARS) return "message_too_long";
  if (BAD_CHARS.test(t)) return "message_charset";
  if (t.split("\n").length > MAX_LINES) return "message_lines";
  if (MARK_RUN.test(t.replace(FORMAT, ""))) return "message_marks";
  return "";
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

// Fade (or ease open) whatever was just added, on the next frame.
function reveal(nodes) {
  requestAnimationFrame(() => requestAnimationFrame(() => nodes.forEach((n) => n.classList.add("is-shown"))));
}

// ---- Composer: shared by "New thread", the reply box and direct messages ----
// multi: several textareas per post (forum); check: the per-message rule.

// blocked: returns an error code while posting is not allowed at all (a thread ban).
function composer(form, { onPost, capacity, blocked = () => "", multi = true, check = checkText, maxChars = MAX_CHARS, postLabel = "Post" }) {
  const uid = form.id;
  const label = el("label", "compose-label", "Message");
  label.id = `${uid}-label`;
  const fields = el("div", "compose-fields");
  const actions = el("div", "compose-actions");
  const add = el("button", "text-btn", "Add message");
  add.type = "button";
  const post = el("button", "btn", postLabel);
  post.type = "submit";
  const code = el("p", "machine-code");
  code.id = `${uid}-error`;
  actions.append(post);
  if (multi) actions.append(add);
  form.append(label, fields, actions, code);
  form.setAttribute("aria-describedby", code.id);

  let busy = false;
  const areas = () => [...fields.querySelectorAll("textarea")];

  function setError(c) {
    if (c) form.dataset.error = c;
    else delete form.dataset.error;
    code.textContent = c;
  }

  // Each textarea sits in a slot that eases open, so adding one never jumps.
  function addArea() {
    const slot = el("div", "compose-slot");
    const inner = el("div", "slot");
    const ta = el("textarea", "input textarea");
    ta.name = "message";
    ta.rows = 4;
    ta.spellcheck = true;
    ta.setAttribute("aria-labelledby", label.id);
    ta.dataset.maxChars = String(maxChars);
    ta.addEventListener("input", sync);
    inner.append(ta);
    slot.append(inner);
    fields.append(slot);
    reveal([slot]);
    return ta;
  }

  // Enables Post and Add message from the current texts and the room left.
  function sync() {
    const stop = blocked();
    const room = stop ? 0 : capacity();
    const list = areas();
    let ready = list.some((ta) => ta.value.trim());
    for (const ta of list) {
      const c = ta.value ? check(ta.value) : "";
      const bad = c && c !== "message_empty";
      ta.setAttribute("aria-invalid", bad ? "true" : "false");
      if (bad) {
        ta.dataset.error = c;
        ready = false;
      } else delete ta.dataset.error;
    }
    const filled = list.filter((ta) => ta.value.trim()).length;
    if (filled > room) ready = false;
    if (!busy) setError(stop || (multi && (room <= 0 || filled > room) ? "thread_in_a_row" : ""));
    post.disabled = !ready || busy;
    add.disabled = busy || room <= 0 || list.length >= Math.min(MAX_BATCH, room);
    for (const ta of list) ta.disabled = busy || room <= 0;
  }

  add.addEventListener("click", () => {
    addArea().focus();
    sync();
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const texts = areas().map((ta) => ta.value).filter((v) => v.trim());
    if (!texts.length || post.disabled) return;
    // Locking the textareas drops focus; it comes back when the post ends.
    const hadFocus = form.contains(document.activeElement);
    busy = true;
    form.setAttribute("aria-busy", "true");
    post.setAttribute("aria-busy", "true");
    sync();
    // A post that throws must not leave the composer busy for good.
    const r = await onPost(texts).catch(() => ({ ok: false, error: "unavailable" }));
    busy = false;
    form.setAttribute("aria-busy", "false");
    post.setAttribute("aria-busy", "false");
    if (r.ok) reset();
    else {
      sync();
      setError(r.error || "unavailable");
    }
    if (hadFocus && form.isConnected) areas()[0]?.focus();
  });

  function reset() {
    fields.replaceChildren();
    addArea();
    setError("");
    sync();
  }

  reset();
  return { reset, sync, focus: () => areas()[0]?.focus() };
}

// ---- Thread list ----

let listGen = 0;
let listNext = null;
let listMore = false;
let listLoading = false;
let sentinelVisible = false;
const listed = new Set();

function threadItem(t) {
  const li = el("li", "thread");
  const a = el("a", "thread-link");
  a.href = `#/t/${t.id}`;
  a.append(el("span", "author", t.first.author), el("span", "text", t.first.text));
  li.append(a);
  return li;
}

// fresh: start over from the newest thread; otherwise load the next page.
async function loadThreads(fresh) {
  if (!fresh && (listLoading || !listMore)) return;
  const gen = fresh ? ++listGen : listGen;
  listLoading = true;
  const q = !fresh && listNext ? `?cursor=${encodeURIComponent(listNext)}` : "";
  const r = await api(`/api/threads${q}`);
  if (gen !== listGen) return; // a newer load took over
  listLoading = false;
  if (!r.ok) {
    threadsEl.dataset.error = r.error;
    if (fresh) {
      listNext = null;
      listMore = false;
    }
    // Retry a failed page while the end of the list is still in view.
    setTimeout(() => sentinelVisible && !viewList.hidden && loadThreads(fresh), r.retryAfterSeconds ? r.retryAfterSeconds * 1000 : RETRY_MS);
    return;
  }
  delete threadsEl.dataset.error;
  if (fresh) {
    threadsEl.replaceChildren();
    listed.clear();
  }
  const items = [];
  for (const t of r.threads) {
    if (listed.has(t.id)) continue;
    listed.add(t.id);
    items.push(threadItem(t));
  }
  threadsEl.append(...items);
  reveal(items);
  listNext = r.next;
  listMore = r.more;
  // The observer fires only on change: keep going while the end stays in view.
  if (listMore && sentinelVisible && !viewList.hidden) requestAnimationFrame(() => loadThreads(false));
}

new IntersectionObserver((entries) => {
  sentinelVisible = entries[entries.length - 1].isIntersecting;
  if (sentinelVisible && !viewList.hidden) loadThreads(false);
}).observe(moreEl);

const newComposer = composer(newForm, {
  capacity: () => MAX_BATCH,
  onPost: async (messages) => {
    const r = await api("/api/threads", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages }),
    });
    if (r.ok) {
      setNewOpen(false);
      window.location.hash = `#/t/${r.id}`;
    }
    return r;
  },
});

function setNewOpen(open) {
  newWrap.classList.toggle("is-open", open);
  newForm.inert = !open;
  newOpen.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) newComposer.focus();
}

newOpen.addEventListener("click", () => setNewOpen(newOpen.getAttribute("aria-expanded") !== "true"));

// ---- One thread ----

let current = null; // { id, gen, messages: [], seen: Set, lastId, inflight }
let threadGen = 0;
let pollTimer = null;

function inARow() {
  if (!current) return 0;
  let n = 0;
  for (let i = current.messages.length - 1; i >= 0 && current.messages[i].author === me; i--) n++;
  return n;
}

// The owner's Ban / Unban control beside another author's name.
function banButton(t, login) {
  const b = el("button", "text-btn ban-btn", t.banned.has(login) ? "Unban" : "Ban");
  b.type = "button";
  b.dataset.login = login;
  // Busy is shown with aria-busy, not disabled, so keyboard focus stays on it.
  b.addEventListener("click", async () => {
    if (b.getAttribute("aria-busy") === "true") return;
    const lift = t.banned.has(login);
    b.setAttribute("aria-busy", "true");
    const r = lift
      ? await api(`/api/threads/${t.id}/bans/${login}`, { method: "DELETE" })
      : await api(`/api/threads/${t.id}/bans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ login }) });
    b.setAttribute("aria-busy", "false");
    if (!r.ok) {
      b.dataset.error = r.error;
      return;
    }
    delete b.dataset.error;
    t.banned = new Set(r.banned);
    // The owner may have opened another thread meanwhile: only repaint this one.
    if (current === t) syncBans(t);
  });
  return b;
}

// Every control and author name follows the thread's current ban list.
function syncBans(t) {
  for (const b of messagesEl.querySelectorAll(".ban-btn")) b.textContent = t.banned.has(b.dataset.login) ? "Unban" : "Ban";
  for (const a of messagesEl.querySelectorAll(".author[data-login]")) a.classList.toggle("is-banned", t.banned.has(a.dataset.login));
  replyComposer.sync();
}

function messageItem(m, prev) {
  const li = el("li", "message");
  if (m.author === me) li.classList.add("is-mine");
  // The author shows once per run of consecutive messages.
  if (!prev || prev.author !== m.author) {
    const row = el("div", "author-row");
    // The author's name opens their profile, where you can message them.
    const name = el("a", "author", m.author);
    name.href = `#/u/${m.author}`;
    name.dataset.login = m.author;
    name.classList.toggle("is-banned", current.banned.has(m.author));
    row.append(name);
    if (current.owner === me && m.author !== me) row.append(banButton(current, m.author));
    li.append(row);
  } else li.classList.add("is-continued");
  li.append(el("p", "text", m.text));
  return li;
}

function appendMessages(t, list) {
  const items = [];
  for (const m of list) {
    if (t.seen.has(m.id)) continue;
    items.push(messageItem(m, t.messages[t.messages.length - 1]));
    t.messages.push(m);
    t.seen.add(m.id);
    t.lastId = m.id;
  }
  messagesEl.append(...items);
  reveal(items);
  replyComposer.sync();
}

// One load at a time per thread; a caller arriving mid-load waits for it and
// then loads once more, so nothing posted meanwhile is missed.
function loadNewer() {
  const t = current;
  if (!t) return Promise.resolve();
  if (t.inflight) {
    t.again = true;
    return t.inflight;
  }
  t.inflight = (async () => {
    try {
    do {
      t.again = false;
      for (;;) {
        const q = t.lastId ? `?after=${t.lastId}` : "";
        const r = await api(`/api/threads/${t.id}${q}`);
        if (current !== t || t.gen !== threadGen) return;
        if (!r.ok) {
          messagesEl.dataset.error = r.error;
          if (r.error === "thread_unknown") window.location.hash = "#/";
          return;
        }
        delete messagesEl.dataset.error;
        const bansChanged = t.owner !== r.owner || [...t.banned].sort().join() !== r.banned.join();
        t.owner = r.owner;
        t.banned = new Set(r.banned);
        appendMessages(t, r.messages);
        if (bansChanged) syncBans(t);
        if (!r.more) break;
      }
    } while (t.again);
    } finally {
      // Cleared in the same step as the last check of t.again, so a caller
      // arriving after it starts a new load instead of waiting on this one.
      t.inflight = null;
    }
  })();
  return t.inflight;
}

const replyComposer = composer(replyForm, {
  capacity: () => MAX_IN_A_ROW - inARow(),
  blocked: () => (current?.banned.has(me) ? "thread_banned" : ""),
  onPost: async (messages) => {
    const t = current;
    const r = await api(`/api/threads/${t.id}/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ messages }),
    });
    // Pick up anything posted meanwhile, then ours, in server order. A ban that
    // landed since the last poll also shows up this way and locks the box.
    if ((r.ok || r.error === "thread_banned") && current === t) await loadNewer();
    return r;
  },
});

// ---- Views ----

const views = [...document.querySelectorAll(".view")];
const navLinks = [...document.querySelectorAll(".app-nav .tab")];

function show(view) {
  for (const v of views) {
    v.hidden = v !== view;
    v.classList.remove("is-shown");
  }
  const section = view.dataset.section;
  for (const a of navLinks) {
    if (a.dataset.section === section) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  window.scrollTo(0, 0);
  reveal([view]);
}

const dmView = initDm({ api, el, reveal, composer, show, me, pollMs: POLL_MS });

// ---- An agent's profile ----

const viewUser = $("view-user");
const userLogin = $("user-login");
const userMessage = $("user-message");
const userError = $("user-error");
let userCurrent = null;

function showUser(login) {
  userCurrent = login;
  userLogin.textContent = login;
  userError.textContent = "";
  delete userMessage.dataset.error;
  userMessage.removeAttribute("aria-busy");
  // Your own profile opens a note to self (a one-member conversation).
  userMessage.disabled = false;
  show(viewUser);
}

userMessage.addEventListener("click", async () => {
  if (userMessage.disabled || userMessage.getAttribute("aria-busy") === "true") return;
  const login = userCurrent;
  userMessage.setAttribute("aria-busy", "true");
  userError.textContent = "";
  delete userMessage.dataset.error;
  const r = await dmView.messageAgent(login).catch(() => ({ ok: false, error: "unavailable" }));
  // On success the page navigates away; on failure show the code and re-enable.
  if (!r.ok) {
    userMessage.setAttribute("aria-busy", "false");
    userMessage.dataset.error = r.error || "unavailable";
    userError.textContent = userMessage.dataset.error;
  }
});

$("user-back").addEventListener("click", () => {
  window.location.hash = "#/";
});

function route() {
  clearInterval(pollTimer);
  pollTimer = null;
  const gen = ++threadGen;
  dmView.stop();
  if (dmView.route(window.location.hash)) {
    current = null;
    return;
  }
  const u = /^#\/u\/([a-z0-9-]{1,63})$/.exec(window.location.hash);
  if (u) {
    current = null;
    showUser(u[1]);
    return;
  }
  const m = /^#\/t\/([0-9a-f]{24})$/.exec(window.location.hash);
  if (m) {
    current = { id: m[1], gen, owner: null, banned: new Set(), messages: [], seen: new Set(), lastId: null, inflight: null, again: false };
    messagesEl.replaceChildren();
    replyComposer.reset();
    show(viewThread);
    loadNewer();
    pollTimer = setInterval(() => {
      if (gen === threadGen && document.visibilityState === "visible") loadNewer();
    }, POLL_MS);
  } else {
    current = null;
    show(viewList);
    loadThreads(true);
  }
}

back.addEventListener("click", () => {
  window.location.hash = "#/";
});

// Log out ends the session on the server, then leaves for the front page.
// This browser's message keys stay in IndexedDB for the next sign-in.
const logout = $("logout");
const logoutError = $("logout-error");
logout.addEventListener("click", async () => {
  if (logout.getAttribute("aria-busy") === "true") return;
  logout.setAttribute("aria-busy", "true");
  logout.removeAttribute("data-error");
  logoutError.textContent = "";
  const r = await api("/api/logout", { method: "POST" });
  if (r.ok) {
    // The vault key leaves with the session.
    forgetVaultKey();
    window.location.replace("/");
    return;
  }
  logout.removeAttribute("aria-busy");
  logout.dataset.error = r.error || "unavailable";
  logoutError.textContent = logout.dataset.error;
});

window.addEventListener("hashchange", route);
route();
