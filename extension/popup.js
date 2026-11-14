// The extension's own window: the only place a login is ever chosen.
//
// Nothing is drawn inside web pages, so a page can't cover, move or click it (the trick
// behind "extension clickjacking"). The extension keeps no passwords: it asks the desktop app
// through the native host, and a password passes through here only on its way into the page
// the person is looking at.
//
// What it does keep is a connection key, made when the person connects it to the app and
// allowed there. Every request is signed with it; the browser holds it as a key object that
// scripts (this one included) can use but not read.

import { fillLogin } from "./fill.js";
import { dropKey, loadKey, saveKey, sign } from "./link.js";

const HOST = "vault.desktop.browser_host";
const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);

async function send(message) {
  try {
    const reply = await chrome.runtime.sendNativeMessage(HOST, message);
    return reply && typeof reply.type === "string" ? reply : { type: "error", code: "bad_request" };
  } catch {
    // The host could not be started: the app is closed or its browser link is off.
    return { type: "error", code: "not_running" };
  }
}

/** One signed question to the desktop app. */
async function ask(request) {
  const key = await loadKey();
  if (!key) return { type: "error", code: "not_paired" };
  return send(await sign(key, request));
}

// ---- views ----

const VIEWS = ["site", "list", "check", "pair", "message"];

function view(...shown) {
  for (const id of VIEWS) $(id).hidden = !shown.includes(id);
}

/** A title and a sentence in place of everything else. */
function say(title, text = "", isError = false) {
  view("message");
  $("message-title").textContent = title;
  $("message-text").textContent = text;
  $("message").classList.toggle("error", isError);
}

function explain(code, tab) {
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
      return say(t("noLoginsTitle"), t("noLoginsText", originOf(tab?.url)));
    case "not_paired":
      return offerPairing(tab);
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

// ---- connecting to the app ----

/** First use (or the app forgot us): ask the app to connect, then show its code. */
async function offerPairing(tab) {
  await dropKey();
  view("pair");
  $("pair-title").textContent = t("pairTitle");
  $("pair-text").textContent = t("pairText");
  $("pair-code").hidden = true;
  const button = $("pair-button");
  button.textContent = t("pairButton");
  button.disabled = false;
  button.onclick = async () => {
    button.disabled = true;
    const reply = await send({ type: "pair" });
    if (reply.type !== "pairing" || typeof reply.key !== "string") {
      return explain(reply.code === "not_paired" ? "failed" : reply.code, tab);
    }
    await saveKey(reply.key);
    $("pair-title").textContent = t("pairWaitTitle");
    $("pair-text").textContent = t("pairWaitText");
    $("pair-code").textContent = reply.code;
    $("pair-code").hidden = false;
    button.textContent = t("pairDone");
    button.disabled = false;
    button.onclick = () => main();
  };
  button.focus();
}

// ---- filling ----

/**
 * Asks the app for the login and types it into the page. A locked login is opened by
 * Windows Hello (`how.hello`: the app shows the system's prompt) or by the PIN or item
 * password typed here (`how.check`), which goes to the app with this one request and is
 * kept nowhere. Returns the app's reply when it wants the PIN (again).
 */
async function fill(tab, entry, how = {}) {
  const request = { type: "fill", url: tab.url, id: entry.id };
  if (how.check) request.check = how.check;
  if (how.hello) request.hello = true;
  const reply = await ask(request);
  if (reply.type === "error" && (reply.code === "wrong_check" || (reply.code === "item_locked" && reply.check !== "app"))) {
    return reply;
  }
  if (reply.type !== "fill") {
    return explain(reply.code, tab);
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
      return say(t("filledUsername"));
    case "wrong_page":
      return say(t("pageChanged"), "", true);
    case "none":
      return say(t("noFields"), "", true);
    default:
      return say(t("failed"), "", true);
  }
}

/** The PIN view: the login picked, one field, Fill. */
function askCheck(tab, entry, kind, back) {
  const pin = kind === "pin";
  view("site", "check");
  $("check-title").textContent = entry.title;
  $("check-username").textContent = entry.username;
  $("check-text").textContent = t(pin ? "pinText" : "passwordText");
  $("check-error").textContent = "";
  $("check-fill").textContent = t("fillButton");
  $("check-back").textContent = t("backButton");
  const input = $("check-input");
  input.value = "";
  input.placeholder = t(pin ? "pinLabel" : "passwordLabel");
  input.inputMode = pin ? "numeric" : "text";
  input.maxLength = pin ? 8 : 256;
  input.focus();
  $("check-back").onclick = back;
  $("check").onsubmit = async (event) => {
    event.preventDefault();
    const typed = input.value;
    if (!typed) return;
    input.value = "";
    $("check-fill").disabled = true;
    const reply = await fill(tab, entry, { check: typed });
    $("check-fill").disabled = false;
    if (reply?.code === "wrong_check") {
      $("check-error").textContent = reply.left === 1 ? t("wrongCheckLast") : t("wrongCheck", String(reply.left));
      input.focus();
    }
  };
}

function show(tab, reply) {
  $("origin").textContent = reply.origin.replace(/^https:\/\//, "");
  if (reply.items.length === 0) {
    return say(t("noLoginsTitle"), t("noLoginsText", reply.origin));
  }
  view("site", "list");
  const typed = reply.check === "pin" || reply.check === "password";
  const again = () => show(tab, reply);
  const rows = reply.items.map((entry) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "login";
    const opens = entry.locked && (reply.hello || typed);
    row.disabled = entry.locked && !opens;
    const title = document.createElement("span");
    title.className = "title";
    title.textContent = entry.title;
    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = entry.username || t("noUsername");
    row.append(title, detail);
    if (entry.locked) {
      const asks = document.createElement("span");
      asks.className = "asks";
      asks.textContent = !opens ? t("lockedItem") : reply.hello ? t("asksHello") : t(reply.check === "pin" ? "asksPin" : "asksPassword");
      row.append(asks);
    }
    row.addEventListener("click", async () => {
      if (opens && !reply.hello) return askCheck(tab, entry, reply.check, again);
      for (const other of document.querySelectorAll(".login")) other.disabled = true;
      // Windows Hello closed or unavailable, or locked meanwhile in the app: the PIN.
      const answer = await fill(tab, entry, { hello: opens });
      if (answer?.code === "item_locked") askCheck(tab, entry, answer.check, again);
    });
    return row;
  });
  $("list").replaceChildren(...rows);
  rows.find((row) => !row.disabled)?.focus();
}

async function main() {
  say(t("checking"));
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) {
    return explain("not_a_website", tab);
  }
  if (!(await loadKey())) {
    return offerPairing(tab);
  }
  const reply = await ask({ type: "logins", url: tab.url });
  if (reply.type === "logins" && Array.isArray(reply.items)) {
    return show(tab, reply);
  }
  explain(reply.code, tab);
}

main();
