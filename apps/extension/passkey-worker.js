// Passkey requests from pages (passkeys-page.js, relayed by passkeys.js), answered by the
// background worker for the tab's own address.
//
// Rules it keeps, whatever a page does:
// - the page a request is about is the tab's top-level address as the browser reports it;
//   which site (relying party id) that page may speak for is checked by the app;
// - the person decides in a window of the extension's own (passkey.html), which a page can't
//   cover or click in; nothing is made or signed before they choose there, and only the
//   window opened for a request speaks for it;
// - the app makes or signs only while the very document that asked (same tab, same document,
//   same origin) still waits for that request and Vault still answers passkeys; the same is
//   checked again before the answer goes back (`work`);
// - one request per tab at a time, and a closed window is a "no" (until the person chose and
//   the app is at work, see `work`).
//
// When Vault has nothing to offer (passkeys left to the browser in the extension's settings,
// the app not running, no passkey for the site), the page is told to use the browser's own
// handler, as if Vault weren't there.

import { ask, originOf } from "./app.js";

const PAGE = chrome.runtime.getURL("passkey.html");
const WINDOW = { width: 400, height: 500 };
/**
 * Requests, by the token of the window that asks. A request is in here before the app is
 * asked anything about it, so a second request of the tab, the page cancelling, a
 * navigation, the tab closing or the setting turned off all find it from the start.
 */
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

/**
 * A page's request: answered when the person has chosen in the extension's window.
 * `documentId` is the browser's id for the document that asked (`sender.documentId`).
 */
export async function passkeyFromPage(tab, id, request, documentId) {
  if (!(await vaultPasskeys())) return { fallback: true };
  const asked = cleaned(request);
  const url = tab.url;
  if (!asked || typeof url !== "string" || !url.startsWith("https://")) return { fallback: true };
  if (typeof documentId !== "string" || !documentId) return { fallback: true };
  for (const wait of asking.values()) {
    if (wait.tabId === tab.id && !wait.settled) return { error: "NotAllowedError" };
  }
  // Taken before the app is asked (nothing is awaited between the check above and this).
  const token = crypto.randomUUID();
  let resolve;
  const answer = new Promise((done) => {
    resolve = done;
  });
  const wait = {
    id: String(id),
    asked,
    url,
    origin: originOf(url),
    tabId: tab.id,
    documentId,
    resolve,
    state: undefined,
    windowId: undefined,
    settled: false,
    working: false,
  };
  asking.set(token, wait);
  prepare(tab, token, wait).catch(() => finish(token, { fallback: true }));
  return answer;
}

/** Asks the app what it has for the request, then opens the window (or answers at once). */
async function prepare(tab, token, wait) {
  const state = await look(wait.asked, wait.url);
  // Cancelled, navigated away, closed or turned off meanwhile: the page has its answer.
  if (asking.get(token) !== wait) return;
  if (state.answer) {
    finish(token, state.answer);
  } else {
    wait.state = state;
    openWindow(tab, token);
  }
}

async function openWindow(tab, token) {
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

/**
 * Gives the page its answer (once) and drops the request, closing its window unless
 * `keepWindow`. While the app is at work on the request, only the page is answered: the
 * request stays for `work`, which ends it when the app is done.
 */
function finish(token, answer, keepWindow = false) {
  const wait = asking.get(token);
  if (!wait) return;
  if (!wait.settled) {
    wait.settled = true;
    wait.resolve(answer);
  }
  if (wait.working) return;
  asking.delete(token);
  if (!keepWindow && wait.windowId !== undefined) chrome.windows.remove(wait.windowId).catch(() => {});
}

/** The page aborted its request (its AbortSignal). */
export function passkeyCancelled(tabId, id) {
  for (const [token, wait] of asking) {
    if (wait.tabId === tabId && wait.id === id) finish(token, { error: "AbortError" });
  }
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [token, wait] of asking) {
    if (wait.windowId !== windowId) continue;
    // Closed after the person chose, while the app is at work: that choice stands (`work`).
    if (wait.working) wait.windowId = undefined;
    else finish(token, { error: "NotAllowedError" });
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
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !("vaultPasskeys" in changes) || changes.vaultPasskeys.newValue !== false) return;
  // Turned off: the browser's own handler takes what waits, as it takes every later request.
  // One the app is already at work on finds out when the app is done (`work`).
  for (const [token, wait] of asking) {
    if (!wait.working) finish(token, { fallback: true });
  }
});

// ---- the window ----

/**
 * What the window shows. `site` is the relying party the passkey belongs to, `host` the page
 * that asks: a page under example.com may use example.com's passkeys, and the window names
 * both when they differ, so a subdomain can't pass for its parent. The site is named only
 * as the app checked it: while the vault is locked the app hasn't, and the window names the
 * page alone (never the `rpId` the page wrote, which could be anyone's name, or any words).
 */
function shown(wait) {
  const listed = wait.state.listed;
  const page = new URL(wait.url);
  const site = (typeof listed?.rp_id === "string" && listed.rp_id) || page.host;
  return {
    kind: wait.asked.kind,
    site,
    host: page.host,
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

/**
 * `undefined` while the request is still wanted, otherwise what the page is to get: Vault
 * still answers passkeys, the tab still shows the origin it was asked for, and the very
 * document that asked still waits for this request. That last one is asked of the document
 * itself (passkeys.js, by the browser's document id): one that navigated, reloaded, closed
 * or went into the back/forward cache doesn't answer, and one whose page cancelled the
 * request says it no longer waits.
 */
async function unwanted(wait, before) {
  if (wait.settled) return { error: "NotAllowedError" };
  // Turned off before anything was made: the browser's handler takes it.
  if (!(await vaultPasskeys())) return before ? { fallback: true } : { error: "NotAllowedError" };
  const tab = await chrome.tabs.get(wait.tabId).catch(() => undefined);
  if (!tab || originOf(tab.url) !== wait.origin) return { error: "NotAllowedError" };
  const there = await chrome.tabs
    .sendMessage(wait.tabId, { kind: "passkey-waiting", id: wait.id }, { documentId: wait.documentId })
    .catch(() => undefined);
  if (there?.waiting !== true) return { error: "NotAllowedError" };
  // Nothing ended it while these were asked.
  return wait.settled ? { error: "NotAllowedError" } : undefined;
}

/**
 * Has the app sign or make a passkey for the person's choice, and answers the page with it.
 * The request must still be wanted (`unwanted`) before the app is asked and again before its
 * answer goes to the page: in between the app may take a while (a PIN, Windows Hello), and
 * the page may cancel, navigate or close, or the setting be turned off.
 *
 * What goes wrong in between is decided so that nothing is left half done unseen:
 * - before the app is asked: nothing is made or signed, and the page is answered as for any
 *   refusal (or sent to the browser's handler, when passkeys were turned off);
 * - after the app signed: the signature is dropped, nothing is kept of it;
 * - after the app made a passkey: the vault keeps it (the app wrote it, and the extension
 *   can't take it back), but the site never got it. The page gets "not allowed", and the
 *   window stays open to tell the person, so it isn't left unused in the vault unknown. When
 *   it replaced a passkey kept before for the same site and account (the app does, like a
 *   security key), that earlier one is gone from the vault while the site may still expect
 *   it: the window says that too, and that the person signs in another way to make one again.
 * Closing the window while the app is at work doesn't undo the choice already made there:
 * the answer still goes to the page if it still waits, which for a new passkey is the only
 * way it isn't left unused.
 */
async function work(token, wait, request) {
  if (wait.working) return { code: "busy" };
  wait.working = true;
  let reply;
  let refusal;
  try {
    refusal = await unwanted(wait, true);
    if (!refusal) {
      reply = await ask(request);
      if (reply.type === "assertion" || reply.type === "attestation") {
        refusal = reply.origin === wait.origin ? await unwanted(wait, false) : { error: "NotAllowedError" };
      }
    }
  } finally {
    wait.working = false;
  }
  if (refusal) {
    if (reply?.type === "attestation") {
      finish(token, refusal, true);
      // When it took the place of the passkey kept before for this account (as a security
      // key does), that one is gone too: the window says so, since the site still expects it.
      return reply.replaced === true ? { code: "made_not_sent", replaced: true } : { code: "made_not_sent" };
    }
    finish(token, refusal);
    return { code: "page_changed" };
  }
  if (reply.type === "assertion") {
    finish(token, { assertion: reply });
    return { done: true };
  }
  if (reply.type === "attestation") {
    finish(token, { attestation: reply });
    return { done: true };
  }
  const making = request.type === "passkey_create";
  let ended;
  if (reply.code === "wrong_site") ended = { error: "SecurityError" };
  else if (making && reply.code === "exists") ended = { error: "InvalidStateError" };
  else if (making && reply.code === "unsupported") ended = { fallback: true };
  // Ended meanwhile, or its window closed: nobody is left to choose again.
  else if (wait.settled || wait.windowId === undefined) ended = { error: "NotAllowedError" };
  if (ended) {
    finish(token, ended);
    return { gone: true };
  }
  // The item lock, a locked vault, an app that went away: the window says so.
  return { code: reply.code || "failed", check: reply.check, left: reply.left };
}

/** The request token of the window a message comes from (its `?ask=`), or "". */
function windowToken(sender) {
  try {
    return new URL(sender.url).searchParams.get("ask") || "";
  } catch {
    return "";
  }
}

/** A message from the passkey window (`token` names its request). */
export async function passkeyFromWindow(message, sender) {
  const token = String(message.token ?? "");
  const wait = asking.get(token);
  // Only the window opened for this request speaks for it.
  if (!wait || windowToken(sender) !== token) return { gone: true };
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
      if (wait.asked.kind !== "get") return { code: "bad_request" };
      const entry = (wait.state.listed?.items ?? []).find(
        (item) => item.id === message.id && item.credential === message.credential,
      );
      if (!entry) return { code: "no_match" };
      return work(token, wait, {
        type: "passkey_get",
        url: wait.url,
        rp_id: wait.asked.rpId,
        id: entry.id,
        credential: entry.credential,
        challenge: wait.asked.challenge,
        check: typed(message.check),
        hello: message.hello === true,
      });
    }
    case "passkey-save": {
      if (wait.asked.kind !== "create") return { code: "bad_request" };
      const asked = wait.asked;
      return work(token, wait, {
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
    }
    case "passkey-other":
    case "passkey-no":
      // While the app is at work, the choice made stands: what came of it is told when it ends.
      if (wait.working) return { code: "busy" };
      finish(token, message.kind === "passkey-other" ? { fallback: true } : { error: "NotAllowedError" });
      return { gone: true };
    default:
      return undefined;
  }
}
