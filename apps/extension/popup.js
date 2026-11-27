// The extension's own window.
//
// The extension keeps no passwords: it asks the desktop app through the native host. A
// password passes through here only on its way into the page the person is looking at, or
// while they asked to see it; copying is done by the app itself, so a copied password never
// reaches the browser.
//
// What it does keep is a connection key, agreed with the app when the person connects it and
// allowed there. Every request and every answer is sealed with keys derived from it; the
// browser holds it as a key object that scripts (this one included) can use but not read.

import {
  ask,
  dropPendingSave,
  dropPendingSaves,
  originOf,
  pendingSave,
  send,
  updateRequest,
  vaultSaves,
} from "./app.js";
import { fillCode, fillLogin } from "./fill.js";
import { agree, dropKey, loadKey, saveKey, startWaiting, stopWaiting, waitingCode } from "./link.js";

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);

/** The tab this window was opened over, and what the app said about it. */
const here = { tab: undefined, site: undefined, vault: undefined, place: "site" };

// ---- views ----

const VIEWS = ["tabs", "site", "offer", "list", "vault", "gen", "new-login", "entry", "check", "pair", "message", "prefs", "foot"];

function view(...shown) {
  for (const id of VIEWS) $(id).hidden = !shown.includes(id);
}

/** A title and a sentence in place of the lists. `chrome` keeps the tabs around it. */
function say(title, text = "", { isError = false, chrome: keep = false } = {}) {
  view(...(keep ? ["tabs", "message", "foot"] : ["message"]));
  $("message-title").textContent = title;
  $("message-text").textContent = text;
  $("message").classList.toggle("error", isError);
}

let toastTimer = 0;
function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2600);
}

function explain(code) {
  const connected = { chrome: Boolean(here.vault || here.site) };
  switch (code) {
    case "not_running":
      return say(t("notRunningTitle"), t("notRunningText"));
    case "locked":
      // The generator still works: the app makes passwords without opening the vault.
      return say(t("lockedTitle"), t("lockedText"), { chrome: true });
    case "insecure_page":
      return say(t("insecureTitle"), t("insecureText"), connected);
    case "not_a_website":
      return say(t("notAWebsiteTitle"), t("notAWebsiteText"), connected);
    case "item_locked":
      return say(t("lockedTitle"), t("itemLockedText"), connected);
    case "no_match":
      return say(t("goneTitle"), t("goneText"), connected);
    case "turned_off":
      return say(t("turnedOffTitle"), t("turnedOffText"), connected);
    case "not_saved":
      // The app could not write it (the vault file changed elsewhere, or the disk refused):
      // nothing was kept, and it may be tried again.
      return say(t("notSavedTitle"), t("notSavedText"), { ...connected, isError: true });
    case "changed_since":
      // The login an update was offered for was changed since: nothing was replaced.
      return say(t("changedSinceTitle"), t("changedSinceText"), { ...connected, isError: true });
    case "not_paired":
      return connect();
    case "bad_answer":
      // An answer that didn't come from the app as it was: something between the browser and
      // the app changed it, and it was ignored.
      return say(t("badAnswerTitle"), t("badAnswerText"), { ...connected, isError: true });
    case "bad_request":
      // The app didn't understand: it is older than this extension (sealed requests, the key
      // agreement).
      return say(t("oldAppTitle"), t("oldAppText"), { isError: true });
    default:
      return say(t("failed"), "", { isError: true });
  }
}

// ---- connecting to the app ----

/** Not connected: carry on with a connection the app is still asking about, or offer one. */
async function connect() {
  const code = await waitingCode();
  return code ? waitForApp(code) : offerPairing();
}

/**
 * First use, or the app no longer knows this extension (disconnected there, or another vault
 * is open): one button that sends the person to the app. The old connection key is dropped
 * only when they choose to connect again, never by itself.
 */
async function offerPairing() {
  watching = 0;
  const known = Boolean(await loadKey());
  view("pair");
  $("pair-title").textContent = t(known ? "pairAgainTitle" : "pairTitle");
  $("pair-text").textContent = t(known ? "pairAgainText" : "pairText");
  $("pair-code").hidden = true;
  $("pair-restart").hidden = true;
  const button = $("pair-button");
  button.hidden = false;
  button.textContent = t(known ? "pairAgainButton" : "pairButton");
  button.disabled = false;
  button.onclick = async () => {
    button.disabled = true;
    await dropKey();
    // The key and the code are kept before the app comes forward (which may close this
    // window); a connection the app then refuses leaves neither behind.
    const agreed = await agree(send, async (key, code) => {
      await saveKey(key);
      await startWaiting(code);
    });
    if (agreed.error) {
      await dropKey();
      return explain(agreed.error === "not_paired" ? "failed" : agreed.error);
    }
    waitForApp(agreed.code);
  };
  button.focus();
}

/** Counts the waits started, so an older one stops when a newer view takes over. */
let watching = 0;

/**
 * The app has come forward and asks for the master password. Nothing more to do here: this
 * window asks again every second and carries on by itself once the app has connected it.
 */
function waitForApp(code) {
  view("pair");
  $("pair-title").textContent = t("pairWaitTitle");
  $("pair-text").textContent = t("pairWaitText");
  $("pair-code").textContent = code;
  $("pair-code").hidden = false;
  $("pair-button").hidden = true;
  const restart = $("pair-restart");
  restart.textContent = t("pairRestart");
  restart.hidden = false;
  restart.onclick = () => offerPairing();
  const mine = ++watching;
  const look = async () => {
    if (mine !== watching) return;
    const reply = await ask({ type: "vault" });
    if (mine !== watching) return;
    if (reply.code === "not_paired" || reply.code === "locked") {
      return setTimeout(look, 1000);
    }
    watching = 0;
    await stopWaiting();
    start();
  };
  setTimeout(look, 1000);
}

// ---- the item lock ----

/** What a locked login will ask for, in a word; "" when nothing typed here opens it. */
function asksFor(listing) {
  if (listing.hello) return t("asksHello");
  if (listing.check === "pin") return t("asksPin");
  if (listing.check === "password") return t("asksPassword");
  return "";
}

/**
 * Sends `request` for a login that may be locked. Windows Hello first when the app offers it
 * (its prompt belongs to the system); otherwise, or when Hello is closed, the PIN or item
 * password typed here, which goes to the app with this one request and is kept nowhere.
 * Resolves with the app's final reply, or `undefined` when the person turned back.
 */
async function guarded(entry, listing, request, goLabel, back) {
  const reply = await ask({ ...request, hello: entry.locked && listing.hello });
  if (reply.code !== "item_locked" || !["pin", "password"].includes(reply.check)) return reply;
  return new Promise((resolve) => {
    const pin = reply.check === "pin";
    view("check");
    $("check-title").textContent = entry.title;
    $("check-username").textContent = entry.username;
    $("check-text").textContent = t(pin ? "pinText" : "passwordText");
    $("check-error").textContent = "";
    $("check-go").textContent = goLabel;
    $("check-back").textContent = t("backButton");
    const input = $("check-input");
    input.value = "";
    input.placeholder = t(pin ? "pinLabel" : "passwordLabel");
    input.inputMode = pin ? "numeric" : "text";
    input.maxLength = pin ? 8 : 256;
    input.focus();
    $("check-back").onclick = () => {
      back();
      resolve(undefined);
    };
    $("check").onsubmit = async (event) => {
      event.preventDefault();
      const typed = input.value;
      if (!typed) return;
      input.value = "";
      $("check-go").disabled = true;
      const answer = await ask({ ...request, check: typed });
      $("check-go").disabled = false;
      if (answer.code === "wrong_check") {
        $("check-error").textContent =
          answer.left === 1 ? t("wrongCheckLast") : t("wrongCheck", String(answer.left));
        return input.focus();
      }
      resolve(answer);
    };
  });
}

// ---- filling ----

async function fill(entry, back) {
  const tab = here.tab;
  const reply = await guarded(entry, here.site, { type: "fill", url: tab.url, id: entry.id }, t("fillButton"), back);
  if (!reply) return;
  if (reply.type !== "fill") return explain(reply.code);
  // The tab may have navigated while the app answered: look again, and let the page-side
  // function check once more where it really runs.
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) {
    return say(t("pageChanged"), "", { isError: true });
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
      return say(t("pageChanged"), "", { isError: true });
    case "choose_field":
      return say(t("chooseField"), "", { isError: true });
    case "insecure_form":
      return say(t("insecureForm"), "", { isError: true });
    case "none":
      return say(t("noFields"), "", { isError: true });
    default:
      return say(t("failed"), "", { isError: true });
  }
}

/** Sets an eye button open (the secret is shown) or shut, with its accessible name. */
function eye(button, open) {
  button.setAttribute("aria-pressed", String(open));
  button.setAttribute("aria-label", t(open ? "hideButton" : "showButton"));
  button.title = t(open ? "hideButton" : "showButton");
}

// ---- rows ----

/** The address a saved website stands for (`example.com`, `*.example.com` → https://…). */
function siteUrl(site) {
  const bare = (site || "").trim().replace(/^\*\./, "");
  if (!bare) return "";
  return originOf(/^https?:\/\//i.test(bare) ? bare : `https://${bare}`);
}

/**
 * The site's icon as the browser already has it (nothing is fetched), or a letter tile.
 * `size` is the shown size in pixels.
 */
function siteIcon(site, letter, size = 24) {
  const tile = () => {
    const span = document.createElement("span");
    span.className = "tile";
    span.textContent = (letter || "?").trim().charAt(0);
    return span;
  };
  const url = siteUrl(site);
  if (!url) return tile();
  const img = document.createElement("img");
  img.className = "favicon";
  img.alt = "";
  img.src = `${chrome.runtime.getURL("/_favicon/")}?pageUrl=${encodeURIComponent(url)}&size=${size * 2}`;
  img.addEventListener("error", () => img.replaceWith(tile()));
  return img;
}

function lockIcon(title) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "lock");
  const label = document.createElementNS(ns, "title");
  label.textContent = title;
  const body = document.createElementNS(ns, "rect");
  for (const [name, value] of Object.entries({ x: 4, y: 10.5, width: 16, height: 10.5, rx: 2.5 })) {
    body.setAttribute(name, String(value));
  }
  const shackle = document.createElementNS(ns, "path");
  shackle.setAttribute("d", "M8 10.5V7.5a4 4 0 0 1 8 0v3");
  svg.append(label, body, shackle);
  return svg;
}

function row(entry, listing, { detail, site, onPick, onMore }) {
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
  if (entry.locked) {
    const asks = asksFor(listing);
    button.append(lockIcon(asks ? t("entryAsks", asks) : t("lockedItem")));
  }
  button.addEventListener("click", () => onPick(entry));
  if (!onMore) return button;
  // The row fills; the small button beside it opens the login instead.
  const wrap = document.createElement("div");
  wrap.className = "with-more";
  const more = document.createElement("button");
  more.type = "button";
  more.className = "quiet more";
  more.textContent = t("detailsButton");
  more.addEventListener("click", () => onMore(entry));
  wrap.append(button, more);
  return wrap;
}

// ---- this site ----

function showSite() {
  here.place = "site";
  mark();
  const reply = here.site;
  if (!reply) return explain(here.siteProblem || "not_a_website");
  $("origin").textContent = reply.origin.replace(/^https:\/\//, "");
  const shown = ["tabs", "site", "foot"];
  if (here.pending) shown.push("offer");
  if (reply.items.length === 0) {
    view(...shown, "message");
    $("message").classList.remove("error");
    $("message-title").textContent = t("noLoginsTitle");
    $("message-text").textContent = t("noLoginsText", reply.origin);
    return;
  }
  view(...shown, "list");
  const rows = reply.items.map((entry) =>
    row(entry, reply, {
      detail: entry.username,
      site: reply.origin,
      onPick: (picked) => {
        for (const other of document.querySelectorAll("#list button")) other.disabled = true;
        fill(picked, showSite);
      },
      onMore: (picked) => showEntry({ ...picked, site: reply.origin, has_password: true }, reply, showSite),
    }),
  );
  $("list").replaceChildren(...rows);
  $("list").querySelector("button:enabled")?.focus();
}

/** A login typed into this page and not saved yet: offer it at the top. */
/** Types the current one-time code of `entry` into this page. */
async function fillTheCode(entry, back) {
  const tab = here.tab;
  const reply = await guarded(entry, here.site, { type: "code", url: tab.url, id: entry.id }, t("fillCode"), back);
  if (!reply) return;
  if (reply.type !== "code") return explain(reply.code);
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return say(t("pageChanged"), "", { isError: true });
  let outcome = "none";
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillCode,
      args: [reply.origin, reply.code],
    });
    outcome = result?.result ?? "none";
  } catch {
    outcome = "failed";
  }
  if (outcome === "filled") return window.close();
  if (outcome === "wrong_page") return say(t("pageChanged"), "", { isError: true });
  if (outcome === "choose_field") return say(t("chooseCodeField"), "", { isError: true });
  if (outcome === "insecure_form") return say(t("insecureForm"), "", { isError: true });
  return say(t(outcome === "none" ? "noCodeField" : "failed"), "", { isError: true });
}

function showOffer() {
  const pending = here.pending;
  if (!pending) return;
  const update = pending.update;
  $("offer-text").textContent = t(update ? "offerUpdateText" : "offerText", pending.username || t("noUsername"));
  const yes = $("offer-yes");
  const no = $("offer-no");
  yes.textContent = t(update ? "updateYes" : "saveYes");
  no.textContent = t("saveNo");
  const done = async () => {
    here.pending = undefined;
    // Only the offer shown here is done with: a newer one of the tab stays.
    if (!(await dropPendingSave(here.tab.id, pending.id))) return;
    chrome.tabs.sendMessage(here.tab.id, { kind: "close", which: "save" }).catch(() => {});
  };
  no.onclick = async () => {
    await done();
    showSite();
  };
  yes.onclick = async () => {
    // Still the offer shown here: not answered in the page meanwhile, not run out, and not
    // dropped because saving was left to the browser.
    if ((await pendingSave(here.tab.id))?.id !== pending.id) {
      here.pending = undefined;
      return showSite();
    }
    yes.disabled = true;
    // A new login asks for nothing (no PIN, no Windows Hello): the item lock seals it later.
    const title = originOf(pending.url).replace(/^https:\/\//, "");
    if (update) {
      // Changing a locked login's password opens it first, as a fill does.
      const entry = { title, username: pending.username, locked: update.locked };
      const listing = here.site || { hello: false };
      // For the version of the login the app compared, and its username (`updateRequest`).
      const request = updateRequest(pending);
      const reply = await guarded(entry, listing, request, t("updateYes"), showSite);
      yes.disabled = false;
      if (!reply) return;
      // Changed since: nothing was replaced, and this offer can't be taken again.
      if (reply.code === "changed_since") await done();
      if (reply.type !== "updated") return explain(reply.code);
      await done();
      toast(t(reply.changed ? "updatedToast" : "alreadySavedToast"));
      await load();
      showSite();
      return;
    }
    const entry = { title, username: pending.username, locked: false };
    const listing = here.site || { hello: true };
    const request = { type: "save", url: pending.url, username: pending.username, password: pending.password };
    const reply = await guarded(entry, { ...listing, hello: true }, request, t("saveYes"), showSite);
    yes.disabled = false;
    if (!reply) return;
    if (reply.type !== "saved") return explain(reply.code);
    await done();
    toast(t(reply.queued ? "savedQueued" : "savedToast"));
    await load();
    showSite();
  };
}

// ---- the whole vault ----

function showVault() {
  here.place = "vault";
  mark();
  const reply = here.vault;
  if (!reply) return explain(here.vaultProblem || "failed");
  view("tabs", "vault", "foot");
  const search = $("search");
  search.placeholder = t("searchLabel");
  const draw = () => {
    const words = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    const found = reply.items.filter((entry) => {
      const text = `${entry.title} ${entry.username} ${entry.site}`.toLowerCase();
      return words.every((word) => text.includes(word));
    });
    $("vault-list").replaceChildren(
      ...found.map((entry) =>
        row(entry, reply, {
          detail: entry.username || entry.site,
          onPick: (picked) => showEntry(picked, reply, showVault),
        }),
      ),
    );
    const empty = $("vault-empty");
    empty.hidden = found.length > 0;
    empty.textContent = reply.items.length === 0 ? t("vaultEmpty") : t("searchEmpty");
  };
  search.oninput = draw;
  draw();
  search.focus();
}

// ---- one login ----

let hideTimer = 0;

function showEntry(entry, listing, back) {
  clearTimeout(hideTimer);
  const again = () => showEntry(entry, listing, back);
  view("entry", "foot");
  $("entry-back").textContent = t("backToList");
  $("entry-back").onclick = back;
  $("entry-tile").replaceChildren(siteIcon(entry.site, entry.title || entry.username, 32));
  $("entry-title").textContent = entry.title;
  for (const name of ["username", "password", "code", "site"]) {
    $(`label-${name}`).textContent = t(`label_${name}`);
  }
  for (const id of ["copy-username", "copy-password", "copy-code"]) $(id).textContent = t("copyButton");

  /** Asks the app to copy; the value never comes here. */
  const copy = (what) => async () => {
    const needsCheck = what !== "username";
    const request = { type: "copy", id: entry.id, what };
    const reply = needsCheck
      ? await guarded(entry, listing, request, t("copyButton"), again)
      : await ask(request);
    if (!reply) return;
    if (reply.type !== "copied") return explain(reply.code);
    again();
    toast(reply.seconds ? t("copiedSecret", String(reply.seconds)) : t("copied"));
  };

  $("field-username").hidden = !entry.username;
  $("value-username").textContent = entry.username;
  $("copy-username").onclick = copy("username");

  $("field-password").hidden = entry.has_password === false;
  const password = $("value-password");
  password.textContent = "••••••••••";
  password.classList.remove("shown");
  const show = $("show-password");
  eye(show, false);
  show.onclick = async () => {
    if (password.classList.contains("shown")) return again();
    const reply = await guarded(entry, listing, { type: "reveal", id: entry.id }, t("showButton"), again);
    if (!reply) return;
    if (reply.type !== "reveal") return explain(reply.code);
    again();
    $("value-password").textContent = reply.password;
    $("value-password").classList.add("shown");
    eye($("show-password"), true);
    hideTimer = setTimeout(again, 30000);
  };
  $("copy-password").onclick = copy("password");

  $("field-code").hidden = !entry.has_code;
  $("value-code").textContent = "••• •••";
  $("copy-code").onclick = copy("code");

  const address = (entry.site || "").replace(/^\*\./, "");
  $("field-site").hidden = !address;
  $("value-site").textContent = (entry.site || "").replace(/^https:\/\//, "");
  $("open-site").textContent = t("openButton");
  $("open-site").onclick = () => {
    const url = /^https?:\/\//i.test(address) ? address : `https://${address}`;
    if (originOf(url)) chrome.tabs.create({ url });
  };

  const asks = entry.locked ? asksFor(listing) : "";
  $("entry-asks").textContent = entry.locked ? (asks ? t("entryAsks", asks) : t("itemLockedText")) : "";

  // Offered only when this login belongs to the page in front: the app decides that.
  const fits = here.site?.items.some((item) => item.id === entry.id);
  const fillButton = $("entry-fill");
  fillButton.hidden = !fits;
  fillButton.textContent = t("fillHere");
  fillButton.onclick = () => fill(entry, again);
  const codeButton = $("entry-fill-code");
  codeButton.hidden = !fits || !entry.has_code;
  codeButton.textContent = t("fillCode");
  codeButton.onclick = () => fillTheCode(entry, again);
}

// ---- start ----

function mark() {
  for (const place of ["site", "vault", "gen"]) {
    $(`tab-${place}`).setAttribute("aria-pressed", String(here.place === place));
  }
}

// ---- the generator: the app makes the password ----

/** The last password the app made here, and the id that keeps it in the app's history. */
let made;
/** Characters or words, and the slider's value for each. */
const genState = { words: false, length: 20, count: 6 };

function generatorOptions() {
  if (genState.words) {
    return {
      words: genState.count,
      separator: $("gen-separator").value,
      capitalize: $("gen-capitalize").checked,
      number: $("gen-number").checked,
    };
  }
  return {
    length: genState.length,
    upper: $("gen-upper").checked,
    lower: $("gen-lower").checked,
    digits: $("gen-digits").checked,
    symbols: $("gen-symbols").checked,
    avoid_ambiguous: $("gen-ambiguous").checked,
  };
}

async function generate(options = generatorOptions()) {
  const reply = await ask({ type: "generate", ...options, url: here.tab?.url });
  if (reply.type !== "generated") return undefined;
  made = { id: reply.id, password: reply.password, bits: reply.bits };
  return made;
}

function setMode(words) {
  genState.words = words;
  $("gen-mode-chars").setAttribute("aria-pressed", String(!words));
  $("gen-mode-words").setAttribute("aria-pressed", String(words));
  $("gen-chars").hidden = words;
  $("gen-words").hidden = !words;
  const slider = $("gen-count");
  slider.min = words ? "3" : "8";
  slider.max = words ? "12" : "64";
  slider.value = String(words ? genState.count : genState.length);
  $("gen-count-label").textContent = t(words ? "wordsLabel" : "lengthLabel");
  $("gen-count-value").textContent = slider.value;
}

async function showGenerator() {
  here.place = "gen";
  mark();
  view("tabs", "gen", "foot");
  $("gen-mode-chars").textContent = t("modeChars");
  $("gen-mode-words").textContent = t("modeWords");
  $("gen-ambiguous-label").textContent = t("avoidAmbiguous");
  $("gen-capitalize-label").textContent = t("capitalize");
  $("gen-number-label").textContent = t("addNumber");
  $("gen-separator-label").textContent = t("separatorLabel");
  $("gen-again").title = t("anotherButton");
  $("gen-again").setAttribute("aria-label", t("anotherButton"));
  $("gen-copy").textContent = t("copyButton");
  $("gen-use").textContent = t("useForLogin");
  $("gen-note").textContent = t("genNote");
  const draw = async () => {
    const result = await generate();
    $("gen-password").textContent = result ? result.password : t("genImpossible");
    $("gen-bits").textContent = result ? t("strengthBits", String(result.bits)) : "";
    const meter = $("gen-meter");
    meter.style.width = `${Math.min(100, ((result?.bits || 0) / 128) * 100)}%`;
    meter.classList.toggle("weak", (result?.bits || 0) < 60);
    $("gen-copy").disabled = !result;
    $("gen-use").disabled = !result;
  };
  setMode(genState.words);
  $("gen-mode-chars").onclick = () => {
    setMode(false);
    draw();
  };
  $("gen-mode-words").onclick = () => {
    setMode(true);
    draw();
  };
  $("gen-count").oninput = () => {
    $("gen-count-value").textContent = $("gen-count").value;
    genState[genState.words ? "count" : "length"] = Number($("gen-count").value);
  };
  $("gen-count").onchange = draw;
  for (const id of ["gen-upper", "gen-lower", "gen-digits", "gen-symbols", "gen-ambiguous", "gen-capitalize", "gen-number", "gen-separator"]) {
    $(id).onchange = draw;
  }
  $("gen-again").onclick = draw;
  $("gen-copy").onclick = async () => {
    if (!made) return;
    // The app copies it (out of clipboard history, cleared later) and keeps it in its history.
    const reply = await ask({ type: "keep", id: made.id, copy: true });
    if (reply.type === "copied") toast(t("copiedSecret", String(reply.seconds)));
    else if (reply.code === "no_match") await draw();
    else explain(reply.code);
  };
  $("gen-use").onclick = () => made && showNewLogin(made);
  await draw();
}

// ---- a new login ----

function showNewLogin(generated) {
  view("new-login", "foot");
  $("new-title").textContent = t("newLoginTitle");
  $("new-site-label").textContent = t("label_site");
  $("new-name-label").textContent = t("nameLabel");
  $("new-user-label").textContent = t("label_username");
  $("new-pass-label").textContent = t("label_password");
  eye($("new-show"), false);
  $("new-generate").textContent = t("generateButton");
  $("new-save").textContent = t("saveYes");
  $("new-cancel").textContent = t("cancelButton");
  $("new-error").textContent = "";
  const site = $("new-site");
  const page = originOf(here.tab?.url || "");
  site.value = page.startsWith("https://") ? page.replace(/^https:\/\//, "") : "";
  $("new-name").value = "";
  $("new-name").placeholder = t("nameHint");
  $("new-user").value = "";
  const pass = $("new-pass");
  pass.type = "password";
  pass.value = generated?.password || "";
  let kept = generated;
  $("new-show").onclick = () => {
    pass.type = pass.type === "password" ? "text" : "password";
    eye($("new-show"), pass.type === "text");
  };
  $("new-generate").onclick = async () => {
    kept = await generate({ length: 20 });
    if (kept) {
      pass.value = kept.password;
      pass.type = "text";
      eye($("new-show"), true);
    }
  };
  $("new-cancel").onclick = () => (here.place === "gen" ? showGenerator() : showVault());
  (site.value ? $("new-user") : site).focus();
  $("new-login").onsubmit = async (event) => {
    event.preventDefault();
    const address = site.value.trim();
    const url = /^https?:\/\//i.test(address) ? address : `https://${address}`;
    if (!originOf(url).startsWith("https://")) {
      $("new-error").textContent = t("newSiteError");
      return;
    }
    if (!pass.value) return pass.focus();
    $("new-save").disabled = true;
    const entry = { title: $("new-name").value || address, username: $("new-user").value, locked: false };
    const listing = here.vault || here.site || { hello: false };
    const request = {
      type: "save",
      url,
      title: $("new-name").value.trim() || undefined,
      username: $("new-user").value.trim(),
      password: pass.value,
    };
    const reply = await guarded(entry, listing, request, t("saveYes"), () => showNewLogin(kept));
    $("new-save").disabled = false;
    if (!reply) return;
    if (reply.type !== "saved") return explain(reply.code);
    if (reply.existing) {
      $("new-error").textContent = t("newExists");
      return;
    }
    if (kept && kept.password === request.password) await ask({ type: "keep", id: kept.id });
    pass.value = "";
    toast(t(reply.queued ? "savedQueued" : "savedToast"));
    await load();
    showVault();
  };
}

/**
 * The extension's own settings: whether Vault offers to save passwords instead of Chrome
 * (Chrome's "Offer to save passwords and passkeys" is then off, and Chrome says this extension
 * controls it). Turned off, Vault keeps and offers nothing typed into sign-in forms (app.js).
 * Back goes to where the person was.
 */
async function showPrefs(back) {
  view("prefs", "foot");
  $("prefs-title").textContent = t("prefsTitle");
  $("prefs-saving-label").textContent = t("prefsSaving");
  $("prefs-saving-hint").textContent = t("prefsSavingHint");
  $("prefs-passkeys-label").textContent = t("prefsPasskeys");
  $("prefs-passkeys-hint").textContent = t("prefsPasskeysHint");
  const passkeys = $("prefs-passkeys");
  chrome.storage.local.get("vaultPasskeys").then(({ vaultPasskeys = true }) => {
    passkeys.checked = vaultPasskeys;
  });
  passkeys.onchange = () => chrome.storage.local.set({ vaultPasskeys: passkeys.checked });
  $("prefs-back").textContent = t("back");
  $("prefs-back").onclick = back;
  const box = $("prefs-saving");
  const state = $("prefs-saving-state");
  const saving = chrome.privacy.services.passwordSavingEnabled;
  const mine = (details) =>
    ["controllable_by_this_extension", "controlled_by_this_extension"].includes(details.levelOfControl);
  // The box is what Vault does with what is typed into sign-in forms, whoever holds the
  // browser's own setting; the line under it says when that one isn't Vault's to turn off.
  const refresh = async () => {
    const details = await saving.get({});
    box.checked = await vaultSaves();
    state.textContent = mine(details)
      ? ""
      : t(details.levelOfControl === "not_controllable" ? "prefsSavingPolicy" : "prefsSavingOther");
  };
  box.onchange = async () => {
    await chrome.storage.local.set({ vaultSaves: box.checked });
    if (!box.checked) {
      // Off: an offer still waiting goes, here and in the page.
      here.pending = undefined;
      await dropPendingSaves();
    }
    if (mine(await saving.get({}))) {
      if (box.checked) await saving.set({ value: false });
      else await saving.clear({});
    }
    await refresh();
  };
  await refresh();
}

/** Asks the app for this page's logins and for the vault's list. */
async function load() {
  const tab = here.tab;
  const [site, vault, status] = await Promise.all([
    tab?.url ? ask({ type: "logins", url: tab.url }) : { type: "error", code: "not_a_website" },
    ask({ type: "vault" }),
    // Signed like the rest: the app tells the vault's name to the connected extension only.
    ask({ type: "status" }),
  ]);
  if (status.code === "locked") status.locked = true;
  here.site = site.type === "logins" && Array.isArray(site.items) ? site : undefined;
  here.siteProblem = site.code;
  here.vault = vault.type === "vault" && Array.isArray(vault.items) ? vault : undefined;
  here.vaultProblem = vault.code;
  here.pending = tab?.id ? await pendingSave(tab.id) : undefined;
  $("foot-text").textContent = status.locked
    ? t("connectedLocked")
    : status.name
      ? t("connectedTo", status.name)
      : t("connected");
  $("foot").classList.toggle("locked", Boolean(status.locked));
  return vault;
}

async function start() {
  // The PIN form never navigates, whatever is clicked before its handler is in place.
  $("check").addEventListener("submit", (event) => event.preventDefault());
  say(t("checking"));
  $("tab-site").textContent = t("tabSite");
  $("tab-vault").textContent = t("tabVault");
  $("tab-gen").textContent = t("tabGen");
  $("tab-site").onclick = showSite;
  $("tab-vault").onclick = showVault;
  $("tab-gen").onclick = showGenerator;
  $("add-login").textContent = t("addLogin");
  $("add-login").onclick = () => showNewLogin();
  $("foot-prefs").textContent = t("prefsTitle");
  $("foot-prefs").onclick = () => showPrefs(() => (here.site?.items.length ? showSite() : showVault()));
  $("new-login").addEventListener("submit", (event) => event.preventDefault());
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  here.tab = tab;
  // Before anything else: an extension that is not connected offers to connect, whatever
  // page is in front.
  if (!(await loadKey())) return offerPairing();
  const vault = await load();
  if (!here.vault) {
    // Locked while a connection waits: the app asks after it is unlocked, so keep waiting.
    const code = vault.code === "locked" ? await waitingCode() : undefined;
    return code ? waitForApp(code) : explain(vault.code);
  }
  await stopWaiting();
  showOffer();
  // On a page with nothing to fill, the vault itself is the useful place to land.
  if (here.site?.items.length || here.pending) showSite();
  else showVault();
}

start();
