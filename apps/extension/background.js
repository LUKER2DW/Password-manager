// The background worker: what the in-page suggestion and the save offer need from the app.
//
// The browser starts it when a message arrives and stops it when idle; it keeps nothing
// between runs except a login waiting to be saved (in memory, see app.js).
//
// Rules it enforces, whatever a page does:
// - the page a request is about is the tab's own top-level address, as the browser reports
//   it, never one named in a message;
// - a password goes from the app into the page through `fillLogin` only, and only into the
//   site the login is saved for (the app checks, and `fillLogin` checks again);
// - the small frame shown in a page (inline.html) gets names and usernames, never a
//   password;
// - a page's passkey request is answered only after the person chose in the extension's own
//   window, or in the frame under a field for the page's own request for a field's
//   suggestions, and only for the tab's own origin (passkey-worker.js).

import {
  ask,
  dropPendingSave,
  dropPendingSaves,
  markOffer,
  originOf,
  pendingSave,
  setPendingSave,
  updateRequest,
  vaultSaves,
} from "./app.js";
import { fillCode, fillLogin } from "./fill.js";
import { fallbacks, patternTest, rulesFor } from "./generator.js";
import {
  fromPasskeyWindow,
  passkeyCancelled,
  passkeyFromFrame,
  passkeyFromPage,
  passkeyFromWindow,
  passkeySuggestions,
  passkeysForField,
} from "./passkey-worker.js";
import { applyUpdate, checkForUpdate } from "./update.js";

const INLINE = chrome.runtime.getURL("inline.html");

// ---- Chrome's own password saving ----
//
// While the person leaves it to Vault (the default), Chrome's "Offer to save passwords and
// passkeys" is off, and Chrome's settings say that this extension controls it, with a way to
// take it back. Turning it off here gives the setting back, and Vault then keeps and offers
// nothing typed into sign-in forms (`vaultSaves` in app.js): what the page sends is not read,
// an offer already waiting is dropped, and Save refuses. The `privacy` permission is used for
// this one setting only.

/** Applies the setting to Chrome's own, when this extension may control it. */
export async function applySaving() {
  const saving = chrome.privacy.services.passwordSavingEnabled;
  const details = await saving.get({});
  if (!["controllable_by_this_extension", "controlled_by_this_extension"].includes(details.levelOfControl)) {
    return details.levelOfControl;
  }
  if (await vaultSaves()) await saving.set({ value: false });
  else await saving.clear({});
  return details.levelOfControl;
}

chrome.runtime.onInstalled.addListener(() => applySaving().catch(() => {}));
chrome.runtime.onStartup.addListener(() => applySaving().catch(() => {}));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !("vaultSaves" in changes) || changes.vaultSaves.newValue === true) return;
  // Turned off: what was typed and still waits goes too.
  usernames.clear();
  dropPendingSaves().catch(() => {});
});

// Answers for "does this page have logins?", kept a few seconds per tab so that clicking
// between two fields does not ask the app twice.
const known = new Map();
const KNOWN_FOR_MS = 8000;
// The username typed on the first page of a two-step sign-in, per tab.
const usernames = new Map();
// What the focused new-password field allows, and the password suggested for it, per tab.
const fresh = new Map();

async function loginsFor(tab) {
  const cached = known.get(tab.id);
  if (cached && cached.url === tab.url && Date.now() - cached.at < KNOWN_FOR_MS) return cached.reply;
  const reply = await ask({ type: "logins", url: tab.url });
  known.set(tab.id, { url: tab.url, at: Date.now(), reply });
  return reply;
}

function tell(tabId, message) {
  // The page may be navigating away: nobody to hear it, nothing to do.
  chrome.tabs.sendMessage(tabId, message, { frameId: 0 }).catch(() => {});
}

/** Stores what the person must finish in the extension's window, and opens it. */
async function continueInPopup() {
  try {
    await chrome.action.openPopup();
    return true;
  } catch {
    return false;
  }
}

/**
 * A strong password for a new-password field, made by the app's generator with what the
 * field allows. When the field has a pattern the first one misses, narrower options are
 * asked for (a few times at most).
 */
async function suggestFor(tab, rules) {
  const fits = patternTest(rules.pattern);
  for (const options of fallbacks(rulesFor(rules))) {
    for (let i = 0; i < (fits ? 3 : 1); i++) {
      const made = await ask({ type: "generate", ...options, url: tab.url });
      if (made.type !== "generated") return undefined;
      if (!fits || fits(made.password)) return made;
    }
    if (!fits) break;
  }
  return undefined;
}

async function fillFromFrame(tab, id, offer) {
  const listed = await loginsFor(tab);
  const entry = listed.type === "logins" ? listed.items.find((item) => item.id === id) : undefined;
  if (!entry) return { done: false };
  const reply = await ask({ type: "fill", url: tab.url, id, hello: entry.locked && listed.hello });
  if (reply.type !== "fill") {
    // Windows Hello is not set up, or was closed: the PIN is typed in the extension's own
    // window, never inside a page.
    const popup = reply.code === "item_locked" && (await continueInPopup());
    return { done: false, popup };
  }
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return { done: false };
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: fillLogin,
      // The card's offer: only the field it was shown under, and that field's form, get it.
      args: [reply.origin, reply.username, reply.password, offer],
    });
    return { done: ["both", "password", "username"].includes(result?.result) };
  } catch {
    return { done: false };
  }
}

/** Types the current one-time code of login `id` into the page's code field. */
async function codeFromFrame(tab, id, offer) {
  const listed = await loginsFor(tab);
  const entry =
    listed.type === "logins" ? listed.items.find((item) => item.id === id && item.has_code) : undefined;
  if (!entry) return { done: false };
  const reply = await ask({ type: "code", url: tab.url, id, hello: entry.locked && listed.hello });
  if (reply.type !== "code") {
    const popup = reply.code === "item_locked" && (await continueInPopup());
    return { done: false, popup };
  }
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return { done: false };
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: fillCode,
      args: [reply.origin, reply.code, offer],
    });
    return { done: result?.result === "filled" };
  } catch {
    return { done: false };
  }
}

async function submitted(tab, message) {
  // Saving left to the browser: nothing typed is kept, compared or offered.
  if (!(await vaultSaves())) return;
  const password = typeof message.password === "string" ? message.password : "";
  let username = typeof message.username === "string" ? message.username : "";
  if (!password || password.length > 1024 || username.length > 1024) return;
  const step = usernames.get(tab.id);
  if (!username && step && step.origin === originOf(tab.url)) username = step.username;
  known.delete(tab.id);
  const listed = await loginsFor(tab);
  // Saving logins from the browser is turned off in the app: nothing is offered.
  if (listed.saves === false) return;
  // Not connected or not https: nothing is offered (and nothing is kept). Locked is fine: the
  // app keeps the login sealed and adds it at the next unlock.
  const page = originOf(tab.url);
  const origin =
    listed.type === "logins" ? listed.origin : listed.code === "locked" && page.startsWith("https://") ? page : "";
  if (!origin) return;
  const saved = listed.type === "logins" && listed.items.find((item) => item.username === username);
  let update;
  if (saved) {
    // Already saved: offered again only as an update, when the app says the password typed is
    // another one (or can't tell, for a locked login).
    //
    // The page can see whether the card appears, so for an open login it learns whether the
    // password in its fields was the saved one. That is kept on purpose rather than made
    // indistinguishable (a card after every sign-in, or one that always asks): the card is
    // shown only on the site the login is saved for, which Vault fills that very password
    // into when asked and whose own sign-in already answers "right or wrong" for any guess,
    // faster and without anyone's help. Here each guess needs the person's own click or
    // Enter in that form (content.js takes a submit only right after one, since a submit a
    // page script asks for is trusted too), and a login behind the item lock is never
    // compared (the app answers "can't tell", and the card always comes).
    const reply = await ask({ type: "changed", url: tab.url, username, password });
    if (reply.type !== "changed" || reply.changed === false) return;
    // The stamp names the version of the login the app compared: the update the card offers
    // is for that version only (`updateRequest`).
    const stamp = typeof reply.stamp === "string" && reply.stamp.length <= 128 ? reply.stamp : "";
    update = { id: reply.id, locked: reply.changed === null || saved.locked, stamp };
  }
  // Each offer has an id: the card says which login it shows, and Save acts on that one only,
  // never on a later offer of the same tab (another sign-in, another page) it didn't show.
  await setPendingSave(tab.id, { id: crypto.randomUUID(), url: tab.url, origin, username, password, update });
  tell(tab.id, { kind: "offer-save" });
}

/**
 * Saves (or updates) the login of offer `offer`, the one the card shows. The card may sit on
 * another site than the one the login was typed on (a sign-in that leads to another host): it
 * names that site, and the login is saved for the address it was typed on (`pending.url`),
 * whatever the tab shows now. `stale` when the offer is no longer the tab's (replaced by a
 * newer one, run out, dropped): the card then shows what waits now, or says nothing was saved.
 */
async function saveFromFrame(tab, offer) {
  // Saving left to the browser meanwhile: the offer is gone (`pendingSave` drops it too).
  if (!(await vaultSaves())) return { done: false, stale: true };
  const pending = await pendingSave(tab.id);
  if (!pending || typeof offer !== "string" || pending.id !== offer) return { done: false, stale: true };
  if (pending.update) {
    const listed = await loginsFor(tab);
    const hello = pending.update.locked && listed.type === "logins" && listed.hello;
    const reply = await ask({ ...updateRequest(pending), hello });
    if (reply.type === "updated") {
      // Only this offer is done with: one that came meanwhile stays.
      await dropPendingSave(tab.id, pending.id);
      known.delete(tab.id);
      return { done: true, queued: false };
    }
    if (reply.code === "changed_since") {
      // The login was changed since the card was offered: nothing was replaced, and this
      // offer can't be taken again.
      await dropPendingSave(tab.id, pending.id);
      known.delete(tab.id);
      return { done: false, changed: true };
    }
    const popup = reply.code === "item_locked" && (await continueInPopup());
    return { done: false, popup };
  }
  const reply = await ask({
    type: "save",
    url: pending.url,
    username: pending.username,
    password: pending.password,
  });
  if (reply.type === "saved") {
    await dropPendingSave(tab.id, pending.id);
    known.delete(tab.id);
    // Queued: the vault is locked; the frame says so before it closes.
    return { done: true, queued: Boolean(reply.queued) };
  }
  const popup = reply.code === "item_locked" && (await continueInPopup());
  return { done: false, popup };
}

async function handle(message, sender) {
  const tab = sender.tab;
  if (sender.id !== chrome.runtime.id || typeof message?.kind !== "string") return undefined;
  // The extension's window: take the new version that waits (update.js).
  if (message.kind === "apply-update") {
    return !tab && typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL("popup.html"))
      ? applyUpdate()
      : undefined;
  }
  if (fromPasskeyWindow(sender)) {
    return message.kind.startsWith("passkey-") ? passkeyFromWindow(message, sender) : undefined;
  }
  if (!tab?.id) return undefined;
  const fromFrame = typeof sender.url === "string" && sender.url.startsWith(INLINE);
  const fromPage = !fromFrame && sender.frameId === 0;
  // The browser says which document sent it: a sandboxed one ("null") or one whose origin
  // isn't the tab's is not the site, and gets nothing (content.js already stays silent there).
  if (fromPage && typeof sender.origin === "string" && sender.origin !== originOf(tab.url)) {
    return undefined;
  }

  if (fromPage) {
    switch (message.kind) {
      case "field-focused": {
        if (message.code) {
          const listed = await loginsFor(tab);
          return { show: listed.type === "logins" && listed.items.some((item) => item.has_code) };
        }
        if (message.fresh) {
          const rules = message.rules && typeof message.rules === "object" ? message.rules : {};
          fresh.set(tab.id, {
            origin: originOf(tab.url),
            rules: {
              maxLength: Number(rules.maxLength) || undefined,
              minLength: Number(rules.minLength) || undefined,
              pattern: typeof rules.pattern === "string" ? rules.pattern : undefined,
              passwordRules: typeof rules.passwordRules === "string" ? rules.passwordRules : undefined,
            },
          });
          // The app makes the password: offered whenever it answers, locked or not (its
          // generator needs no vault).
          const status = await loginsFor(tab);
          return { show: status.type === "logins" || status.code === "locked" };
        }
        const listed = await loginsFor(tab);
        // The site's passkeys too, when this document waits for a field's suggestions.
        const passkeys = await passkeysForField(tab, sender.documentId, message.passkey);
        return { show: (listed.type === "logins" && listed.items.length > 0) || passkeys > 0 };
      }
      case "username-step":
        if (!(await vaultSaves())) return undefined;
        if (typeof message.username === "string" && message.username.length <= 1024) {
          usernames.set(tab.id, { origin: originOf(tab.url), username: message.username });
        }
        return undefined;
      case "submitted":
        await submitted(tab, message);
        return undefined;
      case "pending":
        return { offer: Boolean(await pendingSave(tab.id)) };
      case "offer-waiting":
        // A browser that shows no card in pages (content.js): the toolbar button says that a
        // login waits to be saved, and the extension's window offers it.
        if (await pendingSave(tab.id)) markOffer(tab.id, true);
        return undefined;
      case "passkey":
        // The document that asked (the browser's id for it): answered for that document only.
        return passkeyFromPage(tab, String(message.id), message.request, sender.documentId);
      case "passkey-cancel":
        passkeyCancelled(tab.id, String(message.id));
        return undefined;
      default:
        return undefined;
    }
  }
  if (!fromFrame) return undefined;
  switch (message.kind) {
    case "frame-logins": {
      const listed = await loginsFor(tab);
      // The site's passkeys, when the page waits for a field's suggestions: who they are
      // for, never a key.
      const passkeys = passkeySuggestions(tab);
      if (listed.type !== "logins") return passkeys ? { origin: passkeys.origin, items: [], passkeys } : { items: [] };
      return {
        origin: listed.origin,
        hello: listed.hello,
        check: listed.check,
        items: listed.items.map(({ id, title, username, locked, has_code }) => ({
          id,
          title,
          username,
          locked,
          has_code,
        })),
        passkeys,
      };
    }
    case "frame-passkey": {
      const outcome = await passkeyFromFrame(tab, { id: String(message.id), credential: String(message.credential) });
      tell(tab.id, { kind: "close", which: "logins" });
      return outcome;
    }
    case "frame-fill": {
      const outcome = await fillFromFrame(tab, String(message.id), String(message.offer ?? ""));
      tell(tab.id, { kind: "close", which: "logins" });
      return outcome;
    }
    case "frame-code": {
      const outcome = await codeFromFrame(tab, String(message.id), String(message.offer ?? ""));
      tell(tab.id, { kind: "close", which: "logins" });
      return outcome;
    }
    case "frame-suggest": {
      const entry = fresh.get(tab.id);
      // The field it was asked for is on the site still in front.
      if (!entry || entry.origin !== originOf(tab.url)) return {};
      const made = await suggestFor(tab, entry.rules);
      if (!made) return {};
      entry.password = made.password;
      entry.id = made.id;
      return { password: made.password, bits: made.bits };
    }
    case "frame-use-password": {
      const entry = fresh.get(tab.id);
      if (!entry?.password || entry.origin !== originOf(tab.url)) return { done: false };
      tell(tab.id, { kind: "put-password", password: entry.password });
      fresh.delete(tab.id);
      // The app adds it to its history of generated passwords.
      await ask({ type: "keep", id: entry.id });
      return { done: true };
    }
    case "frame-save-info": {
      const pending = await pendingSave(tab.id);
      return pending
        ? { id: pending.id, origin: pending.origin, username: pending.username, update: Boolean(pending.update) }
        : {};
    }
    case "frame-save": {
      const outcome = await saveFromFrame(tab, message.offer);
      // A stale offer or a changed login: the card says so itself (or shows the newer offer).
      if ((outcome.done && !outcome.queued) || outcome.popup) tell(tab.id, { kind: "close", which: "save" });
      return outcome;
    }
    case "frame-manage": {
      // The extension's own window, on the logins of this site.
      tell(tab.id, { kind: "close", which: "logins" });
      await continueInPopup();
      return undefined;
    }
    case "frame-dismiss":
      if (message.which === "save") {
        // "Not now" drops the offer the card shows, never a newer one: with a newer one
        // waiting, the card shows that one instead of closing.
        const pending = await pendingSave(tab.id);
        if (pending && pending.id !== String(message.offer ?? "")) return { redraw: true };
        if (pending) await dropPendingSave(tab.id, pending.id);
      }
      tell(tab.id, { kind: "close", which: message.which === "save" ? "save" : "logins" });
      return undefined;
    case "frame-size":
      tell(tab.id, {
        kind: "size",
        which: message.which === "save" ? "save" : "logins",
        height: Math.max(40, Math.min(Number(message.height) || 0, 360)),
      });
      return undefined;
    default:
      return undefined;
  }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  handle(message, sender).then(respond, () => respond(undefined));
  return true;
});

// Each start of the worker: is the app carrying a newer version of the extension? (At most
// every few minutes; update.js.)
checkForUpdate().catch(() => {});

chrome.tabs.onRemoved.addListener((tabId) => {
  known.delete(tabId);
  usernames.delete(tabId);
  fresh.delete(tabId);
  setPendingSave(tabId, undefined);
});
