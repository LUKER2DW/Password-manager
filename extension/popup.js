// The extension's own window: the only place a login is ever chosen.
//
// Nothing is drawn inside web pages, so a page can't cover, move or click it (the trick
// behind "extension clickjacking"). The extension keeps no passwords: it asks the desktop app
// through the native host, and a password passes through here only on its way into the page
// the person is looking at.

import { fillLogin } from "./fill.js";

const HOST = "vault.desktop.browser_host";
const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;

/** One question to the desktop app. A host that can't be started counts as "not running". */
async function ask(message) {
  try {
    const reply = await chrome.runtime.sendNativeMessage(HOST, message);
    return reply && typeof reply.type === "string" ? reply : { type: "error", code: "bad_request" };
  } catch {
    return { type: "error", code: "not_running" };
  }
}

const $ = (id) => document.getElementById(id);

/** Shows a title and a sentence in place of the list. */
function say(title, text, isError = false) {
  $("list").replaceChildren();
  $("heading").hidden = true;
  $("message").hidden = false;
  $("message-title").textContent = title;
  $("message-text").textContent = text;
  $("message").classList.toggle("error", isError);
}

function explain(code, origin = "") {
  switch (code) {
    case "not_running":
      return say(t("notRunningTitle"), t("notRunningText"));
    case "locked":
      return say(t("lockedTitle"), t("lockedText"));
    case "insecure_page":
      return say(t("insecureTitle"), t("insecureText"));
    case "not_a_website":
      return say(t("notAWebsiteTitle"), t("notAWebsiteText"));
    case "item_locked":
      return say(t("lockedTitle"), t("itemLockedText"));
    case "no_match":
      return say(t("noLoginsTitle"), t("noLoginsText", origin));
    default:
      return say(t("failed"), "", true);
  }
}

/** The origin of a tab address, or "" when it has none worth comparing. */
function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

async function fill(tab, entry) {
  const reply = await ask({ type: "fill", url: tab.url, id: entry.id });
  if (reply.type !== "fill") {
    return explain(reply.code, originOf(tab.url));
  }
  // The tab may have navigated while the app answered: look again, and let the page-side
  // function check once more where it really runs.
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) {
    return say(t("pageChanged"), "", true);
  }
  let outcome = "none";
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillLogin,
      args: [reply.origin, reply.username, reply.password],
    });
    outcome = result?.result ?? "none";
  } catch {
    outcome = "failed";
  }
  switch (outcome) {
    case "both":
    case "password":
      return window.close();
    case "username":
      return say(t("filledUsername"), "");
    case "wrong_page":
      return say(t("pageChanged"), "", true);
    case "none":
      return say(t("noFields"), "", true);
    default:
      return say(t("failed"), "", true);
  }
}

function show(tab, reply) {
  if (reply.items.length === 0) {
    return explain("no_match", reply.origin);
  }
  $("message").hidden = true;
  $("heading").hidden = false;
  $("heading-text").textContent = t("pick");
  $("origin").textContent = reply.origin.replace(/^https:\/\//, "");
  const rows = reply.items.map((entry) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "login";
    row.disabled = entry.locked;
    const title = document.createElement("span");
    title.className = "title";
    title.textContent = entry.title;
    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = entry.locked ? t("lockedItem") : entry.username || t("noUsername");
    row.append(title, detail);
    row.addEventListener("click", () => {
      for (const other of document.querySelectorAll(".login")) other.disabled = true;
      fill(tab, entry);
    });
    return row;
  });
  $("list").replaceChildren(...rows);
  rows.find((row) => !row.disabled)?.focus();
}

async function main() {
  say(t("checking"), "");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) {
    return explain("not_a_website");
  }
  const reply = await ask({ type: "logins", url: tab.url });
  if (reply.type === "logins" && Array.isArray(reply.items)) {
    return show(tab, reply);
  }
  explain(reply.code, originOf(tab.url));
}

main();
