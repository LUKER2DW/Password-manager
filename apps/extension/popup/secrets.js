// A password or code shown in this window is kept on screen no longer than it is looked at:
// it goes after its time (SHOW_FOR_MS at most), when the window shows something else, and
// when the window closes or is hidden. Nothing shown is ever written anywhere (no
// `chrome.storage`): it lives in the page's text, and that text is emptied.

import { SHOW_FOR_MS } from "./countdown.js";

const shown = new Set();

function drop(secret) {
  if (!shown.delete(secret)) return;
  clearTimeout(secret.timer);
  try {
    secret.hide();
  } catch {
    // Hiding one never stops the others from hiding.
  }
}

/**
 * Something shown; `hide` takes it off the screen. It goes by itself after `ms`. Returns the
 * function that hides it sooner (the eye clicked again).
 */
export function keepShown(hide, ms = SHOW_FOR_MS) {
  const secret = { hide, timer: 0 };
  secret.timer = setTimeout(() => drop(secret), Math.max(0, Math.min(ms, SHOW_FOR_MS)));
  shown.add(secret);
  return () => drop(secret);
}

/** Takes everything shown off the screen (another view, the window closing). */
export function hideSecrets() {
  for (const secret of [...shown]) drop(secret);
}

addEventListener("pagehide", hideSecrets);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") hideSecrets();
});
