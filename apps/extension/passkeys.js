// Runs in every https page (top frame only), in the extension's isolated world, before the
// page's scripts: the relay between passkeys-page.js, in the page's own world, and the
// background worker.
//
// A request carries only what the page itself gave navigator.credentials; the background
// worker takes the page's address from the browser, never from it. Anything that is not
// understood, or an extension that was reloaded meanwhile, sends the page to the browser's
// own handler.

(() => {
  const CHANNEL = "vault-passkeys";
  const origin = location.origin;
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
      relay({ kind: "passkey-cancel", id: data.id });
      return;
    }
    if (data.direction !== "ask" || !data.request || typeof data.request !== "object") return;
    answer(data.id, await relay({ kind: "passkey", id: data.id, request: data.request }));
  });
})();
