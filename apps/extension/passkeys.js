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
//
// A request for the suggestions of a field (`mediation: "conditional"`) that Vault takes
// waits here, in the document, for as long as the page waits: the worker answered it at once
// (`waits`) and may be stopped by the browser meanwhile. When a sign-in field is focused,
// content.js tells the worker about it again (`VaultPasskeys.waiting`), and the frame under the
// field lists the site's passkeys; the worker sends the answer here (`passkey-answer`) once the
// person has picked one.

(() => {
  // A sandboxed document (opaque origin, content.js) relays nothing: its requests stay with
  // the browser, which refuses them.
  if (globalThis.origin !== location.origin) return;
  const CHANNEL = "vault-passkeys";
  const origin = location.origin;
  /** This document's requests that wait for Vault's answer, by their id. */
  const open = new Set();
  /** The request for a field's suggestions that waits in this document: `{ id, request }`. */
  let suggesting = null;
  const answer = (id, reply) =>
    window.postMessage({ channel: CHANNEL, direction: "answer", id, answer: reply ?? { fallback: true } }, origin);

  // The frame under a field counts a click only when the browser vouches that nothing covers
  // it (IntersectionObserver v2, `isVisible`). A browser that can't (Firefox) shows no frame
  // in pages (content.js), so a field's suggestions there are the browser's own; and so are
  // they while an AI agent or another program drives the browser (agent.js), in any browser.
  // A request that opens Vault's own passkey window is still Vault's.
  const framed = typeof IntersectionObserverEntry === "function" && "isVisible" in IntersectionObserverEntry.prototype;
  /** Whether a field's suggestions may be Vault's: once it is known that no program drives the browser. */
  async function suggests() {
    const agent = globalThis.VaultAgent;
    if (!framed || !agent) return false;
    await agent.ready;
    return !agent.driven();
  }

  async function relay(message) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch {
      return undefined;
    }
  }

  /**
   * The page's request as plain data of this world, or `null`. (In Firefox the page's object
   * is seen here through a wrapper, which the extension's messages may not carry.) The worker
   * checks and bounds every field again.
   */
  function copied(request) {
    try {
      const json = JSON.stringify(request);
      return typeof json === "string" && json.length <= 256 * 1024 ? JSON.parse(json) : null;
    } catch {
      return null;
    }
  }

  /** Request `id` no longer waits here; the worker is told. */
  function end(id) {
    open.delete(id);
    if (suggesting?.id === id) suggesting = null;
    relay({ kind: "passkey-cancel", id });
  }

  /** Answers the request waiting for a field's suggestions, and forgets it. */
  function settle(reply) {
    if (!suggesting) return;
    const { id } = suggesting;
    suggesting = null;
    open.delete(id);
    answer(id, reply);
  }

  window.addEventListener("message", async (event) => {
    if (event.source !== window || event.origin !== origin) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || typeof data.id !== "string" || data.id.length > 64) return;
    if (data.direction === "cancel") {
      end(data.id);
      return;
    }
    if (data.direction !== "ask" || !data.request || typeof data.request !== "object") return;
    const id = data.id;
    const request = copied(data.request);
    // A later request ends the one waiting for a field's suggestions (passkeys-page.js says
    // so first; this holds whatever the page posts).
    if (suggesting) {
      const earlier = suggesting.id;
      settle({ error: "AbortError" });
      relay({ kind: "passkey-cancel", id: earlier });
    }
    if (!request) {
      answer(id, { fallback: true });
      return;
    }
    open.add(id);
    if (request.conditional === true && !(await suggests())) {
      // Cancelled meanwhile: the page no longer waits for an answer.
      if (open.delete(id)) answer(id, { fallback: true });
      return;
    }
    if (!open.has(id)) return;
    const reply = await relay({ kind: "passkey", id, request });
    if (reply?.waits === true && request.conditional === true) {
      // Vault has passkeys for this site: the page waits for a pick under a field (unless it
      // cancelled meanwhile, which the worker heard too).
      if (open.has(id)) suggesting = { id, request };
      return;
    }
    open.delete(id);
    answer(id, reply);
  });

  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.kind === "passkey-waiting") respond({ waiting: open.has(message.id) });
    if (message?.kind === "passkey-answer" && suggesting && message.id === suggesting.id) {
      settle(message.answer && typeof message.answer === "object" ? message.answer : { error: "NotAllowedError" });
    }
  });

  // Passkeys left to the browser (the extension's setting): the browser's own handler takes
  // the request that waits, as it takes every later one.
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.vaultPasskeys?.newValue === false) settle({ fallback: true });
    });
  } catch {
    // The extension is gone (reloaded or updated): nothing waits for it.
  }

  /** For content.js, in this same isolated world (the page can't reach it). */
  globalThis.VaultPasskeys = Object.freeze({
    /** The request for a field's suggestions that waits in this document, or `undefined`. */
    waiting: () => (suggesting ? { id: suggesting.id, request: suggesting.request } : undefined),
  });

  // Leaving the page (or going into the back/forward cache) ends its requests: the worker
  // closes their windows now rather than at the person's next click. One waiting for a
  // field's suggestions is answered too, so a page brought back from that cache can ask again.
  window.addEventListener("pagehide", () => {
    const ids = [...open];
    settle({ error: "AbortError" });
    open.clear();
    for (const id of ids) relay({ kind: "passkey-cancel", id });
  });
})();
