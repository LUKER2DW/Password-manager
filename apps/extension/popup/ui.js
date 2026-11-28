// The window's shared pieces: words, views, notices, the messages that replace a view, the
// tile in front of a login, the connection code's boxes and a coloured password.

import { originOf } from "../app.js";
import { asksFor } from "./asks.js";
import { cellsOf, codeGroups } from "./cells.js";
import { lookIcon } from "./favicons.js";
import { icon } from "./icons.js";
import { hideSecrets } from "./secrets.js";
import { here, routes } from "./state.js";
import { hostKey, initial, tintOf } from "./tint.js";

export const t = (key, ...parts) => chrome.i18n.getMessage(key, parts.map(String)) || key;
export const $ = (id) => document.getElementById(id);

/**
 * Words that name Windows Hello have a twin that names the PIN only (`…Pin`), said where
 * there is no Windows Hello (Linux, macOS). Where the app offers Windows Hello for a login
 * (`hello` in its answer) it is Windows, and the words name it.
 */
const NAMES_HELLO = new Set(["setupTitle", "setupText", "setupShort", "lockedText"]);
export function forPlatform(key) {
  return NAMES_HELLO.has(key) && here.os !== "win" ? `${key}Pin` : key;
}

// ---- views ----

const VIEWS = ["tabs", "site", "vault", "codes", "gen", "new-login", "entry", "check", "pair", "message", "prefs", "foot"];

/**
 * Shows the views named and hides the rest. Whatever secret was on screen goes first, and a
 * PIN typed and not sent goes with its form.
 */
export function view(...shown) {
  hideSecrets();
  for (const id of VIEWS) $(id).hidden = !shown.includes(id);
  $("check-input").value = "";
  $("main").scrollTop = 0;
}

/** Marks the tab of the window that is shown. */
export function mark(place) {
  here.place = place;
  for (const name of ["site", "vault", "codes", "gen"]) {
    $(`tab-${name}`).setAttribute("aria-pressed", String(place === name));
  }
}

let toastTimer = 0;
/** A short confirmation above the footer ("Copied", "Saved"), never over what is read. */
export function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2800);
}

// ---- messages in place of a view ----

/**
 * A title and a sentence in place of the views. `chrome` keeps the tabs and the footer
 * around it (the window is connected), so the person can go on from there.
 */
export function say(title, text = "", { isError = false, chrome: keep = false, mark: symbol } = {}) {
  view(...(keep ? ["tabs", "message", "foot"] : ["message"]));
  $("message").classList.toggle("error", isError);
  $("message-icon").replaceChildren(...(symbol ? [icon(symbol)] : []));
  $("message-icon").hidden = !symbol;
  $("message-title").textContent = title;
  $("message-text").textContent = text;
}

/** The app's refusal `code` in words, with what to do about it. */
export function explain(code) {
  const connected = { chrome: Boolean(here.vault || here.site) };
  switch (code) {
    case "not_running":
      return say(t("notRunningTitle"), t("notRunningText"));
    case "locked":
      // The generator still works: the app makes passwords without opening the vault.
      return say(t("lockedTitle"), t(forPlatform("lockedText")), { chrome: true, mark: "lock" });
    case "insecure_page":
      return say(t("insecureTitle"), t("insecureText"), connected);
    case "not_a_website":
      return say(t("notAWebsiteTitle"), t("notAWebsiteText"), connected);
    case "item_locked":
      return say(t("lockedTitle"), t("itemLockedText"), { ...connected, mark: "lock" });
    case "no_match":
      return say(t("goneTitle"), t("goneText"), connected);
    case "turned_off":
      return say(t("turnedOffTitle"), t("turnedOffText"), connected);
    case "site_rule":
      // The person's rule for this site forbids it (popup/rules.js).
      return say(t("siteRuleTitle"), t("siteRuleText"), connected);
    case "not_saved":
      // The app could not write it (the vault file changed elsewhere, or the disk refused):
      // nothing was kept, and it may be tried again.
      return say(t("notSavedTitle"), t("notSavedText"), { ...connected, isError: true });
    case "changed_since":
      // The login an update was offered for was changed since: nothing was replaced.
      return say(t("changedSinceTitle"), t("changedSinceText"), { ...connected, isError: true });
    case "not_paired":
      return routes.connect();
    case "bad_answer":
      // An answer that didn't come from the app as it was: something between the browser and
      // the app changed it, and it was ignored.
      return say(t("badAnswerTitle"), t("badAnswerText"), { ...connected, isError: true });
    case "bad_request":
      // The app didn't understand: it is older than this extension (sealed requests, the key
      // agreement).
      return say(t("oldAppTitle"), t("oldAppText"), { isError: true });
    case "outdated_extension":
      // The app accepts no extension this old (an old copy put back in its folder, one loaded
      // from elsewhere): it answers nothing until the extension is the newest.
      return say(t("outdatedTitle"), t("outdatedText"), { isError: true });
    default:
      return say(t("failed"), "", { ...connected, isError: true });
  }
}

/**
 * The app's refusal of a secret for a login of `listing`. A login it would open only with
 * the master password says so; when the app asks before the browser gets any password and
 * nothing is set up for that, the person is sent to set it up in Vault.
 */
export function explainRefusal(reply, listing) {
  if (reply?.code !== "item_locked") return explain(reply?.code);
  const connected = { chrome: Boolean(here.vault || here.site), mark: "lock" };
  if (listing?.hello) return say(t("helloRefusedTitle"), t("helloRefusedText"), connected);
  if (listing?.always_asks) return say(t(forPlatform("setupTitle")), t(forPlatform("setupText")), connected);
  return explain("item_locked");
}

/** A fill that ended in the page: its outcome in words, in place of the views. */
export function outcome(key) {
  say(t(key), "", { chrome: Boolean(here.vault || here.site), isError: true });
}

// ---- what a login asks ----

const ASKS_ICON = { hello: "fingerprint", pin: "lock", password: "lock", setup: "warning", app: "lock" };

/** The few words on a locked row's padlock: what opening it asks for. */
export function asksTitle(kind) {
  return {
    hello: t("asksHelloLong"),
    pin: t("asksPinLong"),
    password: t("asksPasswordLong"),
    setup: t(forPlatform("setupShort")),
    app: t("lockedItem"),
  }[kind];
}

/**
 * The line said before acting on locked logins: `keys` maps each kind to its message key.
 * Hidden when nothing is asked.
 */
export function asksLine(element, kind, keys) {
  element.hidden = kind === "none" || !keys[kind];
  element.classList.toggle("needs-setup", kind === "setup");
  if (element.hidden) return;
  element.replaceChildren(icon(ASKS_ICON[kind] ?? "lock"), document.createTextNode(t(forPlatform(keys[kind]))));
}

// ---- rows ----

/** The address a saved website stands for (`example.com`, `*.example.com` → https://…). */
export function siteUrl(site) {
  const bare = (site || "").trim().replace(/^\*\./, "");
  if (!bare) return "";
  return originOf(/^https?:\/\//i.test(bare) ? bare : `https://${bare}`);
}

/** A site written for reading: no scheme, no `*.`. */
export function siteName(site) {
  return (site || "").trim().replace(/^https?:\/\//i, "").replace(/^\*\./, "").replace(/\/$/, "");
}

/**
 * The login's initial on its colour, as in the app, replaced by the site's icon once the
 * browser's cache turns one up (favicons.js: nothing is fetched from the site). `size` is the
 * shown size in pixels.
 */
export function siteIcon(site, title, size = 28) {
  const tile = document.createElement("span");
  tile.className = `tile tint-${tintOf(hostKey(site) || title || "")}`;
  tile.textContent = initial(title || hostKey(site));
  tile.setAttribute("aria-hidden", "true");
  if (!siteUrl(site)) return tile;
  lookIcon(site, here.tab?.url, size * 2).then((src) => {
    if (!src || !tile.isConnected) return;
    const img = document.createElement("img");
    img.className = "favicon";
    img.alt = "";
    img.width = size;
    img.height = size;
    img.src = src;
    tile.replaceWith(img);
  });
  return tile;
}

/**
 * One login in a list: its tile, name and who it is; a padlock when opening it asks for
 * something (with what, in its title), unless the line above the list already says that
 * every login asks the same (`marks: false`). `onPick` runs for a click on the row; `extra`
 * buttons sit beside it (fill the code, details).
 */
export function loginRow(entry, listing, { detail, site, onPick, extra = [], marks = true }) {
  const wrap = document.createElement("div");
  wrap.className = "login-row";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "login";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = entry.title || entry.username || t("noUsername");
  const sub = document.createElement("span");
  sub.className = "detail";
  sub.textContent = detail || t("noUsername");
  button.append(siteIcon(site ?? entry.site, entry.title || entry.username), title, sub);
  const kind = asksFor(entry, listing);
  if (marks && kind !== "none") {
    button.append(icon(kind === "hello" ? "fingerprint" : "lock", "ic lock", asksTitle(kind)));
  }
  button.addEventListener("click", () => onPick(entry));
  wrap.append(button, ...extra);
  return wrap;
}

/** A small button beside a row: an icon, or a word, and its label. */
export function sideButton(label, { glyph, text, onClick }) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = text ? "side word" : "side";
  button.title = label;
  button.setAttribute("aria-label", label);
  if (glyph) button.append(icon(glyph));
  if (text) button.append(document.createTextNode(text));
  button.addEventListener("click", onClick);
  return button;
}

/** Sets an eye button open (the secret is shown) or shut, with its accessible name. */
export function eye(button, open) {
  button.setAttribute("aria-pressed", String(open));
  button.setAttribute("aria-label", t(open ? "hideButton" : "showButton"));
  button.title = t(open ? "hideButton" : "showButton");
}

// ---- secrets as data ----

/** The connection code as two groups of boxes with a dash between, read as one label. */
export function drawCode(element, code) {
  const groups = codeGroups(code);
  const parts = [];
  groups.forEach((group, i) => {
    if (i > 0) {
      const dash = document.createElement("span");
      dash.className = "dash";
      dash.textContent = "–";
      parts.push(dash);
    }
    for (const char of group) {
      const box = document.createElement("span");
      box.className = "box";
      box.textContent = char;
      parts.push(box);
    }
  });
  for (const part of parts) part.setAttribute("aria-hidden", "true");
  element.replaceChildren(...parts);
  element.setAttribute("role", "group");
  element.setAttribute("aria-label", t("pairCodeLabel", groups.map((group) => group.join("")).join(" ")));
}

/** Colours the digits and symbols of a generated password (text only; nothing secret kept). */
export function drawColoured(element, text) {
  element.replaceChildren(
    ...cellsOf(text).map((cell) => {
      if (cell.kind === "upper" || cell.kind === "lower") return document.createTextNode(cell.char);
      const span = document.createElement("span");
      span.className = cell.kind;
      span.textContent = cell.char;
      return span;
    }),
  );
}
