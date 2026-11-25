// The extension's window for a page's passkey request (opened by passkey-worker.js). A page
// can't draw over it or click in it. It shows the page that asks and the site its passkeys
// belong to, the passkeys Vault has there (or the account a new one is for), and sends the
// person's choice to the background worker.
// No key or signature passes through here; a PIN typed for the item lock goes to the app, as
// in the extension's popup.

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);
const token = new URLSearchParams(location.search).get("ask") || "";

async function say(kind, extra = {}) {
  try {
    return (await chrome.runtime.sendMessage({ kind, token, ...extra })) ?? { gone: true };
  } catch {
    return { gone: true };
  }
}

/** What the worker said about the request. */
let state;
/** Whatever was being done when the item lock asked for its PIN, to do again with it. */
let again;

// The worker keeps the request while this window is open.
setInterval(() => say("passkey-ping"), 20_000);

function siteIcon(site, letter) {
  const tile = () => {
    const span = document.createElement("span");
    span.className = "tile";
    span.textContent = (letter || "?").trim().charAt(0);
    return span;
  };
  const img = document.createElement("img");
  img.className = "favicon";
  img.alt = "";
  img.src = `${chrome.runtime.getURL("/_favicon/")}?pageUrl=${encodeURIComponent(`https://${site}`)}&size=64`;
  img.addEventListener("error", () => img.replaceWith(tile()));
  return img;
}

function lockIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "lock");
  const label = document.createElementNS(ns, "title");
  label.textContent = t("passkeyLockedRow");
  const body = document.createElementNS(ns, "rect");
  for (const [name, value] of Object.entries({ x: 4, y: 10.5, width: 16, height: 10.5, rx: 2.5 })) {
    body.setAttribute(name, String(value));
  }
  const shackle = document.createElementNS(ns, "path");
  shackle.setAttribute("d", "M8 10.5V7.5a4 4 0 0 1 8 0v3");
  svg.append(label, body, shackle);
  return svg;
}

function problem(words) {
  $("problem").textContent = words || "";
}

function busy(on) {
  for (const button of document.querySelectorAll("button")) button.disabled = on;
}

function render() {
  const get = state.kind === "get";
  document.title = t(get ? "passkeyGetTitle" : "passkeyCreateTitle");
  // The page that asks, in full, and the site its passkey belongs to when that is another
  // name: a page under example.com may use example.com's passkeys, and which page it is
  // (accounts.example.com, or someone's corner of a shared domain) is the person's call.
  const page = state.host || state.site;
  $("icon").replaceChildren(siteIcon(page, page));
  $("site").textContent = page;
  $("for").hidden = page === state.site;
  $("for").textContent = page === state.site ? "" : t("passkeyForSite", state.site);
  $("title").textContent = t(get ? "passkeyGetTitle" : "passkeyCreateTitle");
  $("other").textContent = t("passkeyOther");
  $("no").textContent = t("cancelButton");
  $("yes").textContent = t("passkeySave");
  $("check").hidden = true;
  problem("");

  $("locked").hidden = !state.locked;
  $("list").hidden = state.locked || !get;
  $("make").hidden = state.locked || get;
  $("yes").hidden = state.locked || get;
  if (state.locked) {
    $("locked-text").textContent = t(get ? "passkeyLockedGet" : "passkeyLockedCreate");
    $("retry").textContent = t("passkeyRetry");
    $("retry").focus();
    return;
  }
  if (get) {
    const rows = state.items.map((entry) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "login";
      button.setAttribute("role", "listitem");
      const name = entry.userName || entry.displayName || t("noUsername");
      const title = document.createElement("span");
      title.className = "title";
      title.textContent = name;
      const detail = document.createElement("span");
      detail.className = "detail";
      detail.textContent = entry.title;
      const tile = document.createElement("span");
      tile.className = "tile";
      tile.textContent = name.trim().charAt(0) || "?";
      button.append(tile, title, detail);
      if (entry.locked) button.append(lockIcon());
      button.addEventListener("click", () => use(entry));
      return button;
    });
    $("list").replaceChildren(...rows);
    rows[0]?.focus();
  } else {
    const name = state.userName || state.displayName || t("noUsername");
    $("make-tile").textContent = name.trim().charAt(0) || "?";
    $("make-name").textContent = name;
    $("make-detail").textContent = state.displayName && state.displayName !== name ? state.displayName : state.site;
    $("make-text").textContent = t("passkeyCreateText");
    $("yes").focus();
  }
}

/**
 * The passkey is in the vault but the page was gone (or had cancelled, or passkeys were
 * turned off) before it could get it: the site doesn't know it. Said here, with only Close.
 * `replaced`: it took the place of the passkey kept before for this account, which the site
 * may still expect and which is no longer in the vault.
 */
function madeNotSent(replaced) {
  for (const id of ["list", "make", "locked", "check", "other", "yes"]) $(id).hidden = true;
  problem(t(replaced ? "passkeyMadeNotSentReplaced" : "passkeyMadeNotSent"));
  $("no").textContent = t("passkeyClose");
  $("no").focus();
}

/** What the worker answered to a choice. */
function answered(reply) {
  // The app is still at work on an earlier click: its answer comes with that one.
  if (reply?.code === "busy") return;
  busy(false);
  if (!reply || reply.gone || reply.done) {
    window.close();
    return;
  }
  if (reply.code === "made_not_sent") {
    madeNotSent(reply.replaced === true);
    return;
  }
  if (reply.code === "item_locked" || reply.code === "wrong_check") {
    askCheck(reply);
    return;
  }
  if (reply.code === "locked") {
    state.locked = true;
    render();
    return;
  }
  problem(t(reply.code === "page_changed" ? "passkeyPageChanged" : "passkeyFailed"));
}

function askCheck(reply) {
  const kind = reply.check || state.check;
  if (kind === "app") {
    problem(t("passkeyOpenInApp"));
    return;
  }
  const pin = kind === "pin";
  $("check").hidden = false;
  $("check-text").textContent = t(pin ? "passkeyPin" : "passkeyItemPassword");
  const input = $("check-input");
  input.placeholder = t(pin ? "pinLabel" : "passwordLabel");
  input.inputMode = pin ? "numeric" : "text";
  input.value = "";
  $("check-go").textContent = t("openButton");
  $("check-hello").hidden = !state.hello;
  $("check-hello").textContent = t("passkeyHello");
  if (reply.code === "wrong_check") {
    problem(reply.left === 1 ? t("wrongCheckLast") : t("wrongCheck", String(reply.left ?? "")));
  } else {
    problem("");
  }
  input.focus();
}

async function use(entry, extra = {}) {
  busy(true);
  again = (more) => use(entry, more);
  answered(await say("passkey-use", { id: entry.id, credential: entry.credential, ...extra }));
}

async function save(extra = {}) {
  busy(true);
  again = (more) => save(more);
  answered(await say("passkey-save", extra));
}

$("check").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = $("check-input");
  const check = input.value;
  input.value = "";
  if (check && again) again({ check });
});
$("check-hello").addEventListener("click", () => again?.({ hello: true }));
$("yes").addEventListener("click", () => save());
$("other").addEventListener("click", async () => answered(await say("passkey-other")));
$("no").addEventListener("click", async () => answered(await say("passkey-no")));
$("retry").addEventListener("click", async () => {
  busy(true);
  const reply = await say("passkey-retry");
  busy(false);
  if (!reply || reply.gone) {
    window.close();
    return;
  }
  state = reply;
  render();
  if (state.locked) problem(t("passkeyStillLocked"));
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") $("no").click();
});

(async () => {
  state = await say("passkey-window");
  if (!state || state.gone || !state.kind) {
    window.close();
    return;
  }
  render();
})();
