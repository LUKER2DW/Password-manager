// Talking to the desktop app: one question, one answer, through the native host.
//
// Used by the extension's window and by its background worker. Every question except the
// first "connect" is sealed with the connection key, and so is every answer (see link.js).

import { loadKey, opened, seal } from "./link.js";

const HOST = "vault.desktop.browser_host";

/** Sends one raw message to the app. Failures come back as an error reply, never thrown. */
export async function send(message) {
  try {
    const reply = await chrome.runtime.sendNativeMessage(HOST, message);
    return reply && typeof reply.type === "string" ? reply : { type: "error", code: "bad_request" };
  } catch {
    // The host could not be started: the app is closed or its browser link is off.
    return { type: "error", code: "not_running" };
  }
}

/**
 * One sealed question to the desktop app, and its answer once opened (link.js `opened`: an
 * answer a program between the browser and the app changed or made up is `bad_answer`). A
 * refusal as "not paired" is tried once more with a fresh counter before it is believed: the
 * extension then really is unknown to the app (it was disconnected there, or another vault is
 * open), and the caller offers to connect again. An app older than sealed questions answers
 * "not understood" (`bad_request`): the window says to update it.
 */
export async function ask(request) {
  const key = await loadKey();
  if (!key) return { type: "error", code: "not_paired" };
  let sent = await seal(key, request);
  let reply = await opened(key, sent, await send(sent.message));
  if (reply.code !== "not_paired") return heard(reply);
  await new Promise((done) => setTimeout(done, 120));
  sent = await seal(key, request);
  return heard(await opened(key, sent, await send(sent.message)));
}

// The version of the extension the app has in use, named in its answers to `status` and
// `logins` (an answer opened, so the app's own): told to update.js, which reloads into a newer
// one at the extension's next request.
let versionListener = () => {};

/** `listener(version)` hears the version of the extension the app has in use. */
export function onExtensionVersion(listener) {
  versionListener = listener;
}

function heard(reply) {
  if (typeof reply?.extension_version === "string") {
    try {
      versionListener(reply.extension_version);
    } catch {
      // Nothing to do with the answer itself.
    }
  }
  return reply;
}

/** The origin of an address, or "" when it has none worth comparing. */
export function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

// A login typed into a page and not saved yet waits here, per tab, for the person's answer.
// `chrome.storage.session` lives in memory only, is never written to disk, and is closed to
// content scripts; an offer not answered within two minutes is dropped.
//
// The extension's setting "Vault offers to save passwords, not the browser" decides whether
// anything typed is kept at all. Turned off, Vault keeps and offers nothing typed into
// sign-in forms (the browser's own saving takes over): the background worker reads nothing
// a page sends, an offer already waiting is dropped, and none is handed out or saved.

const PENDING = "pendingSaves";
const PENDING_FOR_MS = 2 * 60 * 1000;

/** Whether Vault keeps and offers to save what is typed into sign-in forms (on unless turned off). */
export async function vaultSaves() {
  const { vaultSaves: on = true } = await chrome.storage.local.get("vaultSaves");
  return on === true;
}

// The waiting logins are one stored map, read and written by the worker and the extension's
// window: every change runs alone (a lock both share), so one based on an old copy can't
// bring back an offer just dropped or lose another tab's.
let queue = Promise.resolve();
function alone(work) {
  const locks = globalThis.navigator?.locks;
  if (locks?.request) return locks.request(PENDING, () => work());
  // No Web Locks here (not in an extension): one at a time in this context.
  const run = queue.then(work, work);
  queue = run.catch(() => {});
  return run;
}

async function stored() {
  return (await chrome.storage.session.get(PENDING))[PENDING] || {};
}

/**
 * The mark on the toolbar button for a login waiting to be saved in tab `tabId`: set where the
 * browser shows no card in pages (content.js, background.js), taken off with the offer.
 */
export function markOffer(tabId, on) {
  try {
    chrome.action.setBadgeText({ tabId: Number(tabId), text: on ? "1" : "" }).catch(() => {});
  } catch {
    // No toolbar button to mark (or no such tab any more).
  }
}

// The helpers below run inside `alone` only.

async function clearAll() {
  const all = await stored();
  if (Object.keys(all).length === 0) return;
  await chrome.storage.session.set({ [PENDING]: {} });
  for (const tab of Object.keys(all)) {
    chrome.tabs.sendMessage(Number(tab), { kind: "close", which: "save" }, { frameId: 0 }).catch(() => {});
    markOffer(tab, false);
  }
}

async function current() {
  if (!(await vaultSaves())) {
    await clearAll();
    return {};
  }
  const all = await stored();
  const now = Date.now();
  let dropped = false;
  for (const tab of Object.keys(all)) {
    if (now - all[tab].at > PENDING_FOR_MS) {
      delete all[tab];
      markOffer(tab, false);
      dropped = true;
    }
  }
  if (dropped) await chrome.storage.session.set({ [PENDING]: all });
  return all;
}

/** Drops every login waiting to be saved, and closes the cards that offer them. */
export function dropPendingSaves() {
  return alone(clearAll);
}

/** Whether a login waits to be saved in any tab (an update that reloads the extension waits too). */
export async function savesWaiting() {
  return Object.keys(await stored()).length > 0;
}

/** The login waiting to be saved for this tab, or `undefined` (always, while saving is off). */
export function pendingSave(tabId) {
  return alone(async () => (await current())[tabId]);
}

/** Keeps (or, with `undefined`, drops) the login waiting for this tab; kept only while saving is on. */
export function setPendingSave(tabId, pending) {
  return alone(async () => {
    const all = await current();
    if (pending && !(await vaultSaves())) return;
    if (pending) all[tabId] = { ...pending, at: Date.now() };
    else {
      delete all[tabId];
      markOffer(tabId, false);
    }
    await chrome.storage.session.set({ [PENDING]: all });
    // Turned off while this was written: nothing typed stays.
    if (pending && !(await vaultSaves())) await clearAll();
  });
}

/**
 * Drops the login waiting for this tab only if it still is offer `id` (the one a card or the
 * window acted on), never a newer one that came meanwhile. Whether it was dropped.
 */
export function dropPendingSave(tabId, id) {
  return alone(async () => {
    const all = await current();
    if (typeof id !== "string" || all[tabId]?.id !== id) return false;
    delete all[tabId];
    markOffer(tabId, false);
    await chrome.storage.session.set({ [PENDING]: all });
    return true;
  });
}

/**
 * The request that updates the saved password of a waiting offer. With the stamp the app gave
 * when it compared (newer apps), it is bound to that version of the login and its username:
 * the app refuses (`changed_since`) a login changed since. An older app gave none, and gets
 * the request it knows.
 */
export function updateRequest(pending) {
  const request = { type: "update", url: pending.url, id: pending.update.id, password: pending.password };
  if (pending.update.stamp) Object.assign(request, { username: pending.username, stamp: pending.update.stamp });
  return request;
}
