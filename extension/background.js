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
//   password.

import { ask, originOf, pendingSave, setPendingSave } from "./app.js";
import { fillLogin } from "./fill.js";
import { fallbacks, patternTest, rulesFor } from "./generator.js";

const INLINE = chrome.runtime.getURL("inline.html");

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

async function fillFromFrame(tab, id) {
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
      args: [reply.origin, reply.username, reply.password],
    });
    return { done: ["both", "password", "username"].includes(result?.result) };
  } catch {
    return { done: false };
  }
}

async function submitted(tab, message) {
  const password = typeof message.password === "string" ? message.password : "";
  let username = typeof message.username === "string" ? message.username : "";
  if (!password || password.length > 1024 || username.length > 1024) return;
  const step = usernames.get(tab.id);
  if (!username && step && step.origin === originOf(tab.url)) username = step.username;
  known.delete(tab.id);
  const listed = await loginsFor(tab);
  // Locked, not connected, not https: nothing is offered (and nothing is kept).
  if (listed.type !== "logins") return;
  if (listed.items.some((item) => item.username === username)) return;
  await setPendingSave(tab.id, { url: tab.url, origin: listed.origin, username, password });
  tell(tab.id, { kind: "offer-save" });
}

async function saveFromFrame(tab) {
  const pending = await pendingSave(tab.id);
  if (!pending) return { done: false };
  const reply = await ask({
    type: "save",
    url: pending.url,
    username: pending.username,
    password: pending.password,
    hello: true,
  });
  if (reply.type === "saved") {
    await setPendingSave(tab.id, undefined);
    known.delete(tab.id);
    return { done: true };
  }
  const popup = reply.code === "item_locked" && (await continueInPopup());
  return { done: false, popup };
}

async function handle(message, sender) {
  const tab = sender.tab;
  if (sender.id !== chrome.runtime.id || !tab?.id || typeof message?.kind !== "string") return undefined;
  const fromFrame = typeof sender.url === "string" && sender.url.startsWith(INLINE);
  const fromPage = !fromFrame && sender.frameId === 0;

  if (fromPage) {
    switch (message.kind) {
      case "field-focused": {
        if (message.fresh) {
          const rules = message.rules && typeof message.rules === "object" ? message.rules : {};
          fresh.set(tab.id, {
            rules: {
              maxLength: Number(rules.maxLength) || undefined,
              minLength: Number(rules.minLength) || undefined,
              pattern: typeof rules.pattern === "string" ? rules.pattern : undefined,
              passwordRules: typeof rules.passwordRules === "string" ? rules.passwordRules : undefined,
            },
          });
          // The app makes the password: offered only when it can answer.
          const status = await loginsFor(tab);
          return { show: status.type === "logins" };
        }
        const listed = await loginsFor(tab);
        return { show: listed.type === "logins" && listed.items.length > 0 };
      }
      case "username-step":
        if (typeof message.username === "string" && message.username.length <= 1024) {
          usernames.set(tab.id, { origin: originOf(tab.url), username: message.username });
        }
        return undefined;
      case "submitted":
        await submitted(tab, message);
        return undefined;
      case "pending":
        return { offer: Boolean(await pendingSave(tab.id)) };
      default:
        return undefined;
    }
  }
  if (!fromFrame) return undefined;
  switch (message.kind) {
    case "frame-logins": {
      const listed = await loginsFor(tab);
      if (listed.type !== "logins") return { items: [] };
      return {
        origin: listed.origin,
        hello: listed.hello,
        check: listed.check,
        items: listed.items.map(({ id, title, username, locked }) => ({ id, title, username, locked })),
      };
    }
    case "frame-fill": {
      const outcome = await fillFromFrame(tab, String(message.id));
      tell(tab.id, { kind: "close", which: "logins" });
      return outcome;
    }
    case "frame-suggest": {
      const entry = fresh.get(tab.id);
      if (!entry) return {};
      const made = await suggestFor(tab, entry.rules);
      if (!made) return {};
      entry.password = made.password;
      entry.id = made.id;
      return { password: made.password, bits: made.bits };
    }
    case "frame-use-password": {
      const entry = fresh.get(tab.id);
      if (!entry?.password) return { done: false };
      tell(tab.id, { kind: "put-password", password: entry.password });
      fresh.delete(tab.id);
      // The app adds it to its history of generated passwords.
      await ask({ type: "keep", id: entry.id });
      return { done: true };
    }
    case "frame-save-info": {
      const pending = await pendingSave(tab.id);
      return pending ? { origin: pending.origin, username: pending.username } : {};
    }
    case "frame-save": {
      const outcome = await saveFromFrame(tab);
      if (outcome.done || outcome.popup) tell(tab.id, { kind: "close", which: "save" });
      return outcome;
    }
    case "frame-manage": {
      // The extension's own window, on the logins of this site.
      tell(tab.id, { kind: "close", which: "logins" });
      await continueInPopup();
      return undefined;
    }
    case "frame-dismiss":
      if (message.which === "save") await setPendingSave(tab.id, undefined);
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

chrome.tabs.onRemoved.addListener((tabId) => {
  known.delete(tabId);
  usernames.delete(tabId);
  fresh.delete(tabId);
  setPendingSave(tabId, undefined);
});
