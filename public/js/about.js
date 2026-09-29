// The "what?" and "why?" modals on the home page, both read-only.

import { bindModal } from "./modal.js";

bindModal(document.getElementById("about-dialog"), {
  openBtn: document.getElementById("about-open"),
  closeBtn: document.getElementById("about-close"),
});

bindModal(document.getElementById("why-dialog"), {
  openBtn: document.getElementById("why-open"),
  closeBtn: document.getElementById("why-close"),
});
