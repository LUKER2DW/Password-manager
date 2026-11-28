// Whether an AI agent or another program is driving this browser, in which case Vault shows
// nothing in pages: no card under a field, no save card, no passkeys in a field's suggestions.
// Only the extension's own window offers logins then, with its usual checks.
//
// A page's content is within an agent's reach (what is filled stays in the page's fields) and
// a prompt injection can steer it; and the frame's click checks (`isTrusted`, fully visible
// for 400 ms, the pointer resting 150 ms) don't stop a program that sends trusted input
// through the browser's debugging protocol and waits. So the card is not offered at all.
//
// Two signals, either one enough:
// - the browser's own word, `navigator.webdriver` (true under WebDriver, Marionette and
//   WebDriver BiDi, a headless browser, and Chrome started with `--enable-automation`,
//   `--remote-debugging-pipe` or `--remote-debugging-port=0`). Read in this script's world,
//   which a page's scripts can't change. Agents can hide it (a fixed debugging port, a flag
//   that turns it off, an extension driving the browser through `chrome.debugger`), and no
//   other standard signal exists: browsers built around an agent say nothing a page or an
//   extension can read;
// - the person's choice in the extension's window, "An AI agent or a program is using this
//   browser" (`vaultAgent` in `chrome.storage.local`, kept until turned off).
//
// Until the choice is read, it counts as on: nothing is drawn in that moment.
//
// Loaded before content.js and passkeys.js (as a content script) and before inline.js (in the
// frame): each reads `globalThis.VaultAgent`, in its own world.

(() => {
  if (globalThis.VaultAgent) return;
  const KEY = "vaultAgent";
  /** The browser says a program drives it. */
  const automated = () => {
    try {
      return globalThis.navigator?.webdriver === true;
    } catch {
      return false;
    }
  };
  // `undefined` until read; then whether the person said an agent uses this browser.
  let chosen;
  const listeners = new Set();
  const driven = () => automated() || chosen !== false;
  function set(value) {
    const before = driven();
    chosen = value === true;
    if (driven() === before) return;
    for (const listener of listeners) {
      try {
        listener(driven());
      } catch {
        // One listener's failure is no reason to skip the others.
      }
    }
  }
  let ready = Promise.resolve();
  try {
    ready = chrome.storage.local.get(KEY).then(
      (stored) => set(stored?.[KEY]),
      () => {},
    );
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && KEY in changes) set(changes[KEY].newValue);
    });
  } catch {
    // The extension is gone (reloaded or updated): the choice stays unknown, so on.
  }
  globalThis.VaultAgent = Object.freeze({
    /** Whether nothing may be shown in pages: a program drives the browser, the person said an agent uses it, or that isn't known yet. */
    driven,
    /** Whether the browser itself says a program drives it (`navigator.webdriver`). */
    automated,
    /** Settles once the person's choice has been read (or couldn't be). */
    ready,
    /** `listener(driven)` hears each change of `driven()`. */
    watch: (listener) => listeners.add(listener),
  });
})();
