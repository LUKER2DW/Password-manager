// A newer extension: the background worker keeps what it learned in `chrome.storage.local`
// as `extensionUpdate: { version, manual }`; the window shows a notice when that version is
// newer than its own.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

const VERSION = /^\d{1,9}(\.\d{1,9}){0,3}$/;

/** -1, 0 or 1 as version `a` is older than, the same as or newer than `b` ("0.4.10" > "0.4.9"). */
export function compareVersions(a, b) {
  const left = String(a).split(".").map(Number);
  const right = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i] ?? 0;
    const y = right[i] ?? 0;
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

/**
 * The notice to show for what the worker kept, against this extension's `current` version:
 * `{ version, manual }`, or `undefined` when there is none (nothing kept, not newer, or not a
 * version). Only an explicit `manual: false` offers the button that updates by itself.
 */
export function updateNotice(stored, current) {
  if (!stored || typeof stored.version !== "string" || !VERSION.test(stored.version)) return undefined;
  if (!VERSION.test(String(current)) || compareVersions(stored.version, current) <= 0) return undefined;
  return { version: stored.version, manual: stored.manual !== false };
}
