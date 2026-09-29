// Shared open and close for the site's <dialog> modals (Modal passport).
// Opening fades and rises over --t-fast; Escape, the close cross and a
// backdrop click play the same in reverse, then the dialog closes.

const CLOSE_FALLBACK_MS = 400; // a little over --t-fast, in case transitionend never fires
// Under reduced motion the CSS collapses transitions to 1ms; close at once.
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

export function bindModal(dialog, { openBtn, closeBtn, onClosed }) {
  let closing = false;

  function open() {
    if (dialog.open) return;
    closing = false;
    dialog.showModal();
    requestAnimationFrame(() => dialog.classList.add("is-open"));
  }

  // Play the exit, then close; then run an optional follow-up (e.g. go to /app/).
  function close(after) {
    if (!dialog.open || closing) return;
    closing = true;
    dialog.classList.remove("is-open");
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      dialog.close();
      closing = false;
      if (typeof onClosed === "function") onClosed();
      if (typeof after === "function") after();
      else openBtn.focus();
    };
    if (reducedMotion.matches) {
      finish();
      return;
    }
    dialog.addEventListener("transitionend", (e) => e.target === dialog && finish(), { once: true });
    setTimeout(finish, CLOSE_FALLBACK_MS);
  }

  openBtn.addEventListener("click", open);
  closeBtn.addEventListener("click", () => close());

  dialog.addEventListener("cancel", (e) => {
    e.preventDefault();
    close();
  });

  // A click on the backdrop lands on the dialog element outside its box.
  dialog.addEventListener("click", (e) => {
    if (e.target !== dialog) return;
    const r = dialog.getBoundingClientRect();
    const inside = e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
    if (!inside) close();
  });

  return { open, close };
}
