// The extension's own window.
//
// The extension keeps no passwords: it asks the desktop app through the native host. A
// password passes through here only on its way into the page the person is looking at, or
// while they asked to see it (and then for 15 seconds at most); copying is done by the app
// itself, so a copied password never reaches the browser.
//
// What it does keep is a connection key, agreed with the app when the person connects it and
// allowed there. Every request and every answer is sealed with keys derived from it; the
// browser holds it as a key object that scripts (this one included) can use but not read.
//
// The views live in popup/: the site in front (site.js), the whole vault (vault.js), one
// login (entry.js), the one-time codes (codes.js), the generator (generator.js), a new login (new-login.js), the settings
// (prefs.js), connecting (pairing.js); the rules they share and test on their own are the
// small modules beside them.

import { ask, pendingSave } from "./app.js";
import { loadKey, stopWaiting, waitingCode } from "./link.js";
import { showCodes } from "./popup/codes.js";
import { showEntry } from "./popup/entry.js";
import { showGenerator } from "./popup/generator.js";
import { drawIcons } from "./popup/icons.js";
import { showNewLogin } from "./popup/new-login.js";
import { connect, offerPairing, stopWatching, waitForApp } from "./popup/pairing.js";
import { showPrefs } from "./popup/prefs.js";
import { showSite } from "./popup/site.js";
import { here, routes } from "./popup/state.js";
import { $, explain, say, t, toast } from "./popup/ui.js";
import { showUpdate } from "./popup/update.js";
import { showVault } from "./popup/vault.js";

Object.assign(routes, {
  site: showSite,
  vault: showVault,
  codes: showCodes,
  gen: showGenerator,
  entry: showEntry,
  newLogin: showNewLogin,
  connect,
  refresh: () => open(),
  reload: () => load(),
});

/** Where the person was, to go back to from the settings. */
function backToPlace() {
  if (here.place === "gen") return showGenerator();
  if (here.place === "vault") return showVault();
  if (here.place === "codes") return showCodes();
  return here.site ? showSite() : showVault();
}

/** Asks the app for this page's logins and for the vault's list. */
async function load() {
  const tab = here.tab;
  const [site, vault, status] = await Promise.all([
    tab?.url ? ask({ type: "logins", url: tab.url }) : { type: "error", code: "not_a_website" },
    ask({ type: "vault" }),
    // Sealed like the rest: the app tells the vault's name to the connected extension only.
    ask({ type: "status" }),
  ]);
  if (status.code === "locked") status.locked = true;
  here.status = status;
  here.site = site.type === "logins" && Array.isArray(site.items) ? site : undefined;
  here.siteProblem = site.code;
  here.vault = vault.type === "vault" && Array.isArray(vault.items) ? vault : undefined;
  here.vaultProblem = vault.code;
  here.pending = tab?.id ? await pendingSave(tab.id) : undefined;
  drawFoot();
  return vault;
}

/** Who this window is connected to, and the vault's lock. */
function drawFoot() {
  const status = here.status || {};
  const locked = Boolean(status.locked);
  // Locked, a login may still be filled where the app fills with Windows Hello while locked.
  const helloFills = locked && Boolean(here.site?.hello || here.vault?.hello);
  $("foot-text").textContent = locked
    ? t(helloFills ? "connectedLockedHello" : "connectedLocked")
    : status.name
      ? t("connectedTo", status.name)
      : t("connected");
  $("foot-text").title = $("foot-text").textContent;
  $("foot").classList.toggle("locked", locked);
  $("foot-lock").hidden = locked || !here.canLock;
}

/** Locks the vault in the app, as its own "Lock now" does. */
async function lockNow() {
  const button = $("foot-lock");
  button.disabled = true;
  const reply = await ask({ type: "lock" });
  button.disabled = false;
  if (reply.type === "locked_now") {
    toast(t("lockedNowToast"));
    return open();
  }
  if (reply.code === "bad_request") {
    // An app older than this button: it goes, nothing else changes.
    here.canLock = false;
    return drawFoot();
  }
  explain(reply.code);
}

let wired = false;

/** The window's fixed words and buttons, once. */
function wire() {
  if (wired) return;
  wired = true;
  drawIcons();
  // The PIN and new-login forms never navigate, whatever is clicked before their handlers are
  // in place.
  $("check").addEventListener("submit", (event) => event.preventDefault());
  $("new-login").addEventListener("submit", (event) => event.preventDefault());
  $("tabs").setAttribute("aria-label", t("actionTitle"));
  $("tab-site").textContent = t("tabSite");
  $("tab-vault").textContent = t("tabVault");
  $("tab-codes").textContent = t("tabCodes");
  $("tab-gen").textContent = t("tabGen");
  $("tab-site").onclick = showSite;
  $("tab-vault").onclick = showVault;
  $("tab-codes").onclick = showCodes;
  $("tab-gen").onclick = showGenerator;
  $("foot-lock-text").textContent = t("lockButton");
  $("foot-lock").title = t("lockTitle");
  $("foot-lock").onclick = lockNow;
  $("foot-prefs").title = t("prefsTitle");
  $("foot-prefs").setAttribute("aria-label", t("prefsTitle"));
  $("foot-prefs").onclick = () => showPrefs(backToPlace);
}

/** Connected or not, locked or open: asks the app and shows the right place. */
async function open() {
  stopWatching();
  say(t("checking"));
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
  // On a page with nothing to fill, the vault itself is the useful place to land.
  if (here.site?.items.length || here.pending) showSite();
  else showVault();
}

async function start() {
  wire();
  showUpdate();
  const [tab, platform] = await Promise.all([
    chrome.tabs.query({ active: true, currentWindow: true }).then(([front]) => front),
    chrome.runtime.getPlatformInfo().catch(() => undefined),
  ]);
  here.tab = tab;
  here.os = platform?.os;
  await open();
}

start();
