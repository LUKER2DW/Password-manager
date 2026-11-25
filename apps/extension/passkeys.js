// Runs in every https page (top frame only), in the extension's isolated world, before the
// page's scripts: the relay between passkeys-page.js, in the page's own world, and the
// background worker.
//
// A request carries only what the page itself gave navigator.credentials; the background
// worker takes the page's address from the browser, never from it. Anything that is not
// understood, or an extension that was reloaded meanwhile, sends the page to the browser's
// own handler.
//
// Before the app makes or signs anything for a request, and again before its answer comes
// back, the worker asks this very document (by the browser's document id) whether it still
// waits for that request. A request the page cancelled, or a page that went away (another
// page, a reload, the back/forward cache), gets nothing made or sent for it.

(() => {
  const CHANNEL = "vault-passkeys";
  const origin = location.origin;
  /** This document's requests that wait for Vault's answer, by their id. */
  const open = new Set();
  const answer = (id, reply) =>
    window.postMessage({ channel: CHANNEL, direction: "answer", id, answer: reply ?? { fallback: true } }, origin);

  async function relay(message) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch {
      return undefined;
    }
  }

  window.addEventListener("message", async (event) => {
    if (event.source !== window || event.origin !== origin) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || typeof data.id !== "string" || data.id.length > 64) return;
    if (data.direction === "cancel") {
      open.delete(data.id);
      relay({ kind: "passkey-cancel", id: data.id });
      return;
    }
    if (data.direction !== "ask" || !data.request || typeof data.request !== "object") return;
    open.add(data.id);
    const reply = await relay({ kind: "passkey", id: data.id, request: data.request });
    open.delete(data.id);
    answer(data.id, reply);
  });

  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.kind === "passkey-waiting") respond({ waiting: open.has(message.id) });
  });

  // Leaving the page (or going into the back/forward cache) ends its requests: the worker
  // closes their windows now rather than at the person's next click.
  window.addEventListener("pagehide", () => {
    for (const id of open) relay({ kind: "passkey-cancel", id });
    open.clear();
  });
})();
