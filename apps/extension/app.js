// Talking to the desktop app: one question, one answer, through the native host.
//
// Used by the extension's window and by its background worker. Every question except the
// first "connect" is signed with the connection key (see link.js).

import { loadKey, sign } from "./link.js";

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
 * One signed question to the desktop app. A refusal as "not paired" is tried once more with a
 * fresh counter before it is believed: the extension then really is unknown to the app (it
 * was disconnected there, or another vault is open), and the caller offers to connect again.
 */
export async function ask(request) {
  const key = await loadKey();
  if (!key) return { type: "error", code: "not_paired" };
  const reply = await send(await sign(key, request));
  if (reply.code !== "not_paired") return reply;
  await new Promise((done) => setTimeout(done, 120));
  return send(await sign(key, request));
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

const PENDING = "pendingSaves";
const PENDING_FOR_MS = 2 * 60 * 1000;

async function pendingSaves() {
  const all = (await chrome.storage.session.get(PENDING))[PENDING] || {};
  const now = Date.now();
  let dropped = false;
  for (const tab of Object.keys(all)) {
    if (now - all[tab].at > PENDING_FOR_MS) {
      delete all[tab];
      dropped = true;
    }
  }
  if (dropped) await chrome.storage.session.set({ [PENDING]: all });
  return all;
}

/** The login waiting to be saved for this tab, or `undefined`. */
export async function pendingSave(tabId) {
  return (await pendingSaves())[tabId];
}

export async function setPendingSave(tabId, pending) {
  const all = await pendingSaves();
  if (pending) all[tabId] = { ...pending, at: Date.now() };
  else delete all[tabId];
  await chrome.storage.session.set({ [PENDING]: all });
}
