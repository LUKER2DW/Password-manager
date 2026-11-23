// Passkey requests from pages (passkeys-page.js, relayed by passkeys.js), answered by the
// background worker for the tab's own address.
//
// Rules it keeps, whatever a page does:
// - the page a request is about is the tab's top-level address as the browser reports it;
//   which site (relying party id) that page may speak for is checked by the app;
// - the person decides in a window of the extension's own (passkey.html), which a page can't
//   cover or click in; nothing is made or signed before they choose there;
// - an answer goes back only while the tab still shows the origin it was made for;
// - one request per tab at a time, and a closed window is a "no".
//
// When Vault has nothing to offer (passkeys left to the browser in the extension's settings,
// the app not running, no passkey for the site), the page is told to use the browser's own
// handler, as if Vault weren't there.

import { ask, originOf } from "./app.js";

const PAGE = chrome.runtime.getURL("passkey.html");
const WINDOW = { width: 400, height: 500 };
/** Requests waiting for the person, by the token of the window that asks. */
const asking = new Map();

/** Whether a message comes from the extension's passkey window. */
export const fromPasskeyWindow = (sender) => typeof sender.url === "string" && sender.url.startsWith(PAGE);

/** Whether Vault answers passkey requests (the extension's setting; on unless turned off). */
export async function vaultPasskeys() {
  const { vaultPasskeys: on = true } = await chrome.storage.local.get("vaultPasskeys");
  return on;
}

const text = (value, max) => (typeof value === "string" && value.length <= max ? value : null);
const ids = (value) =>
  Array.isArray(value) ? value.filter((id) => typeof id === "string" && id.length <= 1400).slice(0, 64) : [];

/** The request as plain, bounded data, or `null` when it isn't one. */
export function cleaned(request) {
  if (!request || typeof request !== "object") return null;
  const rpId = text(request.rpId ?? "", 253);
  const challenge = text(request.challenge, 1400);
  if (rpId === null || !challenge) return null;
  if (request.kind === "get") return { kind: "get", rpId, challenge, allow: ids(request.allow) };
  if (request.kind !== "create") return null;
  const userId = text(request.userId, 100);
  const userName = text(request.userName ?? "", 256);
  const displayName = text(request.displayName ?? "", 256);
  if (!userId || userName === null || displayName === null) return null;
  return {
    kind: "create",
    rpId,
    rpName: text(request.rpName ?? "", 256) ?? "",
    userId,
    userName,
    displayName,
    challenge,
    algorithms: Array.isArray(request.algorithms) ? request.algorithms.filter(Number.isSafeInteger).slice(0, 16) : [],
    exclude: ids(request.exclude),
  };
}

/**
 * What the app says before the person is asked: the passkeys for the site (for a new one,
 * whether the page may make one there), or that the vault is locked. `answer` when the page
 * goes on without asking anyone.
 */
async function look(asked, url) {
  const listed = await ask({
    type: "passkeys",
    url,
    rp_id: asked.rpId,
    allow: asked.kind === "get" ? asked.allow : [],
  });
  if (listed.type === "passkeys") {
    if (asked.kind === "get" && listed.items.length === 0) return { answer: { fallback: true } };
    return { listed };
  }
  if (listed.code === "wrong_site") return { answer: { error: "SecurityError" } };
  if (listed.code === "locked") return { locked: true };
  return { answer: { fallback: true } };
}

/** A page's request: answered when the person has chosen in the extension's window. */
export async function passkeyFromPage(tab, id, request) {
  if (!(await vaultPasskeys())) return { fallback: true };
  const asked = cleaned(request);
  const url = tab.url;
  if (!asked || typeof url !== "string" || !url.startsWith("https://")) return { fallback: true };
  for (const wait of asking.values()) {
    if (wait.tabId === tab.id) return { error: "NotAllowedError" };
  }
  const state = await look(asked, url);
  if (state.answer) return state.answer;
  return new Promise((resolve) => {
    openWindow(tab, { id: String(id), asked, url, origin: originOf(url), state, resolve });
  });
}

async function openWindow(tab, wait) {
  const token = crypto.randomUUID();
  asking.set(token, { ...wait, tabId: tab.id, windowId: undefined });
  let place = {};
  try {
    const over = await chrome.windows.get(tab.windowId);
    place = {
      left: Math.max(0, Math.round(over.left + (over.width - WINDOW.width) / 2)),
      top: Math.max(0, Math.round(over.top + 90)),
    };
  } catch {
    // Wherever the browser puts it.
  }
  try {
    const opened = await chrome.windows.create({ url: `${PAGE}?ask=${token}`, type: "popup", focused: true, ...WINDOW, ...place });
    const still = asking.get(token);
    if (still) still.windowId = opened.id;
    else chrome.windows.remove(opened.id).catch(() => {});
  } catch {
    finish(token, { fallback: true });
  }
}

/** Gives the page its answer and closes the window. */
function finish(token, answer) {
  const wait = asking.get(token);
  if (!wait) return;
  asking.delete(token);
  wait.resolve(answer);
  if (wait.windowId !== undefined) chrome.windows.remove(wait.windowId).catch(() => {});
}

/** The page aborted its request (its AbortSignal). */
export function passkeyCancelled(tabId, id) {
  for (const [token, wait] of asking) {
    if (wait.tabId === tabId && wait.id === id) finish(token, { error: "AbortError" });
  }
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [token, wait] of asking) {
    if (wait.windowId === windowId) finish(token, { error: "NotAllowedError" });
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  for (const [token, wait] of asking) {
    if (wait.tabId === tabId) finish(token, { error: "NotAllowedError" });
  }
});
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (!change.url) return;
  for (const [token, wait] of asking) {
    if (wait.tabId === tabId && originOf(change.url) !== wait.origin) finish(token, { error: "NotAllowedError" });
  }
});

// ---- the window ----

/** What the window shows. */
function shown(wait) {
  const listed = wait.state.listed;
  const site = listed?.rp_id || wait.asked.rpId || new URL(wait.url).hostname;
  return {
    kind: wait.asked.kind,
    site,
    origin: wait.origin,
    locked: Boolean(wait.state.locked),
    check: listed?.check ?? "app",
    hello: Boolean(listed?.hello),
    items:
      wait.asked.kind === "get"
        ? (listed?.items ?? []).map(({ id, credential, title, user_name, display_name, locked }) => ({
            id,
            credential,
            title,
            userName: user_name,
            displayName: display_name,
            locked,
          }))
        : [],
    userName: wait.asked.userName ?? "",
    displayName: wait.asked.displayName ?? "",
  };
}

const typed = (value) => (typeof value === "string" && value.length > 0 && value.length <= 256 ? value : undefined);

/** Hands the answer to the page if the tab still shows the origin it was made for. */
async function deliver(token, wait, origin, answer) {
  const tab = await chrome.tabs.get(wait.tabId).catch(() => undefined);
  if (!tab || origin !== wait.origin || originOf(tab.url) !== origin) {
    finish(token, { error: "NotAllowedError" });
    return { code: "page_changed" };
  }
  finish(token, answer);
  return { done: true };
}

function refused(token, reply) {
  if (reply.code === "wrong_site") {
    finish(token, { error: "SecurityError" });
    return { gone: true };
  }
  // The item lock, a locked vault, an app that went away: the window says so.
  return { code: reply.code || "failed", check: reply.check, left: reply.left };
}

/** A message from the passkey window (`token` names its request). */
export async function passkeyFromWindow(message) {
  const token = String(message.token ?? "");
  const wait = asking.get(token);
  if (!wait) return { gone: true };
  switch (message.kind) {
    case "passkey-window":
      return shown(wait);
    case "passkey-ping":
      return {};
    case "passkey-retry": {
      const state = await look(wait.asked, wait.url);
      if (state.answer) {
        finish(token, state.answer);
        return { gone: true };
      }
      wait.state = state;
      return shown(wait);
    }
    case "passkey-use": {
      const entry = (wait.state.listed?.items ?? []).find(
        (item) => item.id === message.id && item.credential === message.credential,
      );
      if (!entry) return { code: "no_match" };
      const reply = await ask({
        type: "passkey_get",
        url: wait.url,
        rp_id: wait.asked.rpId,
        id: entry.id,
        credential: entry.credential,
        challenge: wait.asked.challenge,
        check: typed(message.check),
        hello: message.hello === true,
      });
      if (reply.type === "assertion") return deliver(token, wait, reply.origin, { assertion: reply });
      return refused(token, reply);
    }
    case "passkey-save": {
      if (wait.asked.kind !== "create") return { code: "bad_request" };
      const asked = wait.asked;
      const reply = await ask({
        type: "passkey_create",
        url: wait.url,
        rp_id: asked.rpId,
        user_id: asked.userId,
        user_name: asked.userName,
        display_name: asked.displayName,
        challenge: asked.challenge,
        exclude: asked.exclude,
        algorithms: asked.algorithms,
        check: typed(message.check),
        hello: message.hello === true,
      });
      if (reply.type === "attestation") return deliver(token, wait, reply.origin, { attestation: reply });
      if (reply.code === "exists") {
        finish(token, { error: "InvalidStateError" });
        return { gone: true };
      }
      if (reply.code === "unsupported") {
        finish(token, { fallback: true });
        return { gone: true };
      }
      return refused(token, reply);
    }
    case "passkey-other":
      finish(token, { fallback: true });
      return { gone: true };
    case "passkey-no":
      finish(token, { error: "NotAllowedError" });
      return { gone: true };
    default:
      return undefined;
  }
}
