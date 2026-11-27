// Keeping the extension as new as the desktop app.
//
// The app writes the extension's files into a folder of its own (Settings → Browser extension →
// Add to a browser): the newest GitHub release's, or the copy built into the app, or a folder
// of the person's. It writes them again when a new version of the app starts and when it takes
// a newer release. An extension loaded from that folder ("Load unpacked", or Firefox's temporary
// add-on) takes a new version by reloading itself: `chrome.runtime.reload()` reads its folder
// again. One loaded from elsewhere (this project's folder, the release's zip) can't, and the
// person is told to update it by hand.
//
// The app names the version in use in its answers to `status` and `logins` (`extension_version`,
// app.js hands it over), so a new one is noticed at the extension's next request; a `status` is
// also asked when the worker starts, at most every ten minutes. An app that doesn't name one, or
// a version that isn't newer, changes nothing. A reload is tried once per version. It waits while
// something is under way that it would lose (a login waiting to be saved, the extension's window
// or the passkey window open): the window then offers it, and sends `{ kind: "apply-update" }`
// (background.js) when the person chooses.
//
// What the extension's window reads, `chrome.storage.local.extensionUpdate`:
//   { version, manual: false }  version is ready and waits for the person ("apply-update");
//   { version, manual: true }   reloading didn't bring it: this copy isn't loaded from the
//                               app's folder, and must be updated by hand;
//   absent                      up to date (or nothing known).
//
// Pages already open keep the content script they had until they are reloaded.

import { ask, onExtensionVersion, savesWaiting } from "./app.js";

const UPDATE = "extensionUpdate";
/** The version a reload was last tried for (kept across the reload). */
const TRIED = "extensionUpdateTried";
/** When the app was last asked, in this browser session (forgotten by a reload). */
const CHECKED = "extensionUpdateChecked";
/** The worker starts often (each event wakes it): the app is asked at most this often. */
export const CHECK_EVERY_MS = 10 * 60 * 1000;
/** A reload comes this long after the answer to the message that asked for it. */
const RELOAD_AFTER_MS = 150;

/** A reload is on its way in this run of the worker. */
let reloading = false;
/** What was heard is acted on one at a time. */
let acting = Promise.resolve();

/** "1.2.3" as numbers, or undefined when it isn't a version (at most four parts, as Chrome's). */
export function versionParts(text) {
  if (typeof text !== "string" || !/^\d{1,9}(\.\d{1,9}){0,3}$/.test(text)) return undefined;
  return text.split(".").map(Number);
}

/** Whether version `a` is newer than `b` (parts compared as numbers; missing parts are 0). */
export function newer(a, b) {
  const [x, y] = [versionParts(a), versionParts(b)];
  if (!x || !y) return false;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const [p, q] = [x[i] ?? 0, y[i] ?? 0];
    if (p !== q) return p > q;
  }
  return false;
}

function running() {
  try {
    return chrome.runtime.getManifest?.()?.version;
  } catch {
    return undefined;
  }
}

async function stored(key) {
  return (await chrome.storage.local.get(key))[key];
}

/** Whether a reload now would lose something under way. */
async function busy() {
  if (await savesWaiting()) return true;
  try {
    // The extension's window or the passkey window (a page of the extension in a tab or a
    // window of its own): open means in use.
    const open = await chrome.runtime.getContexts?.({ contextTypes: ["POPUP", "TAB"] });
    return Array.isArray(open) && open.length > 0;
  } catch {
    return false;
  }
}

/** Reloads into `version`, remembering that it was tried (so it is tried once). */
async function reloadInto(version) {
  reloading = true;
  await chrome.storage.local.set({ [TRIED]: version, [UPDATE]: { version, manual: false } });
  setTimeout(() => chrome.runtime.reload(), RELOAD_AFTER_MS);
}

/**
 * Acts on the version the app has in use: "current" (nothing waits), "reloading", "waiting"
 * (for the person), "manual", or "unknown" (no version to go by).
 */
async function act(offered) {
  const version = running();
  if (!versionParts(version) || !versionParts(offered)) return "unknown";
  if (reloading) return "reloading";
  await chrome.storage.session.set({ [CHECKED]: Date.now() });
  if (!newer(offered, version)) {
    // Up to date: what waited goes.
    if ((await stored(UPDATE)) !== undefined || (await stored(TRIED)) !== undefined) {
      await chrome.storage.local.remove([UPDATE, TRIED]);
    }
    return "current";
  }
  if ((await stored(TRIED)) === offered) {
    // Reloaded for it once, and still the older one: not loaded from the app's folder.
    await chrome.storage.local.set({ [UPDATE]: { version: offered, manual: true } });
    return "manual";
  }
  if (await busy()) {
    await chrome.storage.local.set({ [UPDATE]: { version: offered, manual: false } });
    return "waiting";
  }
  await reloadInto(offered);
  return "reloading";
}

/** Acts on `offered` once what was heard before is done with. */
export function heard(offered) {
  const run = acting.then(() => act(offered));
  acting = run.catch(() => {});
  return run;
}

// Any answer of the app that names the version (status, logins).
onExtensionVersion((version) => {
  heard(version).catch(() => {});
});

/**
 * Asks the app which version it has in use and acts on it (see `act`); "checked" when it was
 * asked a moment ago. `force` asks even then.
 */
export async function checkForUpdate({ force = false } = {}) {
  if (!versionParts(running())) return "unknown";
  if (!force) {
    const at = (await chrome.storage.session.get(CHECKED))[CHECKED];
    if (typeof at === "number" && Date.now() - at < CHECK_EVERY_MS) return "checked";
  }
  const status = await ask({ type: "status" });
  // Not connected, the app not running, or an app that doesn't say: nothing to go by.
  const offered = status?.type === "status" ? status.extension_version : undefined;
  if (!versionParts(offered)) return "unknown";
  return heard(offered);
}

/**
 * The person chose to update now (`{ kind: "apply-update" }` from the extension's window):
 * reloads into the version waiting, once its answer is sent. `{ reloading }`.
 */
export async function applyUpdate() {
  if (reloading) return { reloading: true };
  const waiting = await stored(UPDATE);
  if (!waiting || waiting.manual || !newer(waiting.version, running())) return { reloading: false };
  await reloadInto(waiting.version);
  return { reloading: true };
}
