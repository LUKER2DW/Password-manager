// The small card a page shows under a sign-in field, or in its corner after a sign-in.
//
// It is the extension's own page in a frame: the web page around it can move or cover it,
// but can't read it or click inside it by script. Against being covered (clickjacking) it
// listens to the browser: a click counts only after the frame has been reported fully
// visible, with nothing drawn over it, for a moment.
//
// The frame's address says what to show and where the field is: `#logins`, `#code`, `#new`
// or `#save`, with `:up` when the card sits above the field, then `|` and the page's colour
// scheme. The content script changes only that part when the card has to move above, which
// doesn't reload this page.

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);
const say = (message) => chrome.runtime.sendMessage(message).catch(() => undefined);
const [mode = "logins"] = location.hash.slice(1).split("|")[0].split(":");
// The card under a field (logins or a new password) and the one in the corner (save).
const which = mode === "save" ? "save" : "logins";

function placement() {
  const [where, scheme = "normal"] = location.hash.slice(1).split("|");
  document.body.classList.toggle("up", where.endsWith(":up"));
  document.body.classList.toggle("corner", mode === "save");
  // The page's colour scheme, so the browser draws no opaque box behind this frame (see
  // content.js). Only known words are taken.
  let words = "normal";
  try {
    words = decodeURIComponent(scheme);
  } catch {
    // Not written by the content script: the default stays.
  }
  document.documentElement.style.colorScheme = /^(normal|only|light|dark| )+$/.test(words) ? words : "normal";
}
placement();
window.addEventListener("hashchange", placement);

// ---- only real, visible clicks ----

const VISIBLE_FOR_MS = 400;
let visibleSince = 0;
new IntersectionObserver(
  (entries) => {
    const seen = entries[entries.length - 1];
    // `isVisible` is the browser's own word that nothing covers, fades or distorts us. A
    // browser that can't tell leaves it undefined; there only the frame's size is known.
    const visible = seen.isIntersecting && seen.isVisible !== false;
    visibleSince = visible ? visibleSince || performance.now() : 0;
  },
  { threshold: 1, trackVisibility: true, delay: 100 },
).observe(document.documentElement);

// The page can move this frame. Slid under the pointer just before a click meant for the
// page, it would take that click: so a mouse click also counts only when the pointer has
// been over the card for a moment. (A tap or a key press has no pointer resting anywhere.)
const HOVERED_FOR_MS = 150;
let hoveredSince = 0;
document.addEventListener("pointermove", () => (hoveredSince ||= performance.now()), true);
document.documentElement.addEventListener("pointerleave", () => (hoveredSince = 0));

function genuine(event) {
  const now = performance.now();
  if (!event.isTrusted || visibleSince === 0 || now - visibleSince < VISIBLE_FOR_MS) return false;
  const byMouse = event.detail > 0 && (event.pointerType ?? "mouse") === "mouse";
  return !byMouse || (hoveredSince > 0 && now - hoveredSince >= HOVERED_FOR_MS);
}

// This card belongs right inside a page's own document. Inside a frame of the page (an
// advert, an embedded widget) it shows nothing: such a frame is not the site in front.
const around = location.ancestorOrigins;
const direct = !around || around.length === 1;

/** Tells the page how tall the frame must be: the card, its arrow and its shadow. */
function fit() {
  const card = document.querySelector(".card");
  const below = parseFloat(getComputedStyle(card).marginBottom) || 0;
  say({ kind: "frame-size", which, height: Math.ceil(card.getBoundingClientRect().bottom + below) });
}
window.addEventListener("hashchange", fit);

/** The site's icon as the browser already has it (nothing is fetched), or its first letter. */
function siteIcon(origin, letter) {
  const img = document.createElement("img");
  img.className = "favicon";
  img.alt = "";
  img.src = `${chrome.runtime.getURL("/_favicon/")}?pageUrl=${encodeURIComponent(origin)}&size=32`;
  img.addEventListener("error", () => {
    const tile = document.createElement("span");
    tile.className = "letter";
    tile.textContent = (letter || "?").trim().charAt(0);
    img.replaceWith(tile);
  });
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

/** Always the same number of dots: the password's length is not shown. */
const DOTS = "••••••••••••";

// ---- the logins of this site ----

async function showLogins() {
  const listed = await say({ kind: "frame-logins" });
  // Under a one-time code field: only the logins that have a code.
  const codes = mode === "code";
  if (codes && listed?.items) listed.items = listed.items.filter((entry) => entry.has_code);
  if (!listed?.items?.length) return say({ kind: "frame-dismiss", which });
  // The logins are those of the page this card sits in, or they are not shown.
  if (around && around[0] !== listed.origin) return say({ kind: "frame-dismiss", which });
  $("logins").hidden = false;
  const site = listed.origin.replace(/^https:\/\//, "");
  const typed = listed.check === "pin" || listed.check === "password";
  const asks = listed.hello
    ? t("asksHelloLong")
    : typed
      ? t(listed.check === "pin" ? "asksPinLong" : "asksPasswordLong")
      : t("lockedItem");
  const rows = listed.items.map((entry) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "row";
    row.setAttribute("role", "option");
    row.title = entry.title;
    const lines = document.createElement("span");
    lines.className = "lines";
    const name = document.createElement("span");
    name.className = "name";
    // The username is what tells the logins of one site apart; the item's own name only
    // shows when there is no username (and on hover, as the row's title).
    name.textContent = entry.username || (entry.title || "").trim() || t("noUsername");
    const dots = document.createElement("span");
    dots.className = "secret";
    dots.textContent = codes ? t("fillCodeRow") : DOTS;
    lines.append(name, dots);
    row.append(siteIcon(listed.origin, entry.title || site), lines);
    if (entry.locked) row.append(lockIcon(asks));
    row.addEventListener("click", async (event) => {
      if (!genuine(event)) return;
      for (const other of rows) other.disabled = true;
      await say({ kind: codes ? "frame-code" : "frame-fill", id: entry.id });
    });
    return row;
  });
  $("list").replaceChildren(...rows);
  $("manage-text").textContent = t("managePasswords");
  $("manage").onclick = (event) => genuine(event) && say({ kind: "frame-manage" });
  fit();
}

// ---- a strong password for a new account ----

async function showNew() {
  $("new").hidden = false;
  $("new-title").textContent = t("suggestTitle");
  $("new-again-text").textContent = t("suggestAnother");
  const draw = async () => {
    const made = await say({ kind: "frame-suggest" });
    if (!made?.password) return say({ kind: "frame-dismiss", which });
    $("new-password").textContent = made.password;
    $("new-use").title = t("suggestNote", String(made.password.length));
    fit();
  };
  $("new-again").onclick = (event) => event.isTrusted && draw();
  $("new-use").onclick = async (event) => {
    if (!genuine(event)) return;
    $("new-use").disabled = true;
    await say({ kind: "frame-use-password" });
  };
  await draw();
}

// ---- save what was typed? ----

async function showSave() {
  const info = await say({ kind: "frame-save-info" });
  if (!info?.origin) return say({ kind: "frame-dismiss", which });
  $("save").hidden = false;
  const site = info.origin.replace(/^https:\/\//, "");
  $("save-icon").replaceWith(siteIcon(info.origin, site));
  $("save-title").textContent = t(info.update ? "updateTitle" : "saveTitle");
  $("save-who").textContent = `${info.username || t("noUsername")} ${t("saveOn", site)}`;
  const yes = $("save-yes");
  const no = $("save-no");
  yes.textContent = t(info.update ? "updateYes" : "saveYes");
  no.textContent = t("saveNo");
  no.onclick = (event) => event.isTrusted && say({ kind: "frame-dismiss", which });
  yes.onclick = async (event) => {
    if (!genuine(event)) return;
    yes.disabled = true;
    const outcome = await say({ kind: "frame-save" });
    if (outcome?.queued) {
      // Locked: kept for the next unlock. Said for a moment, then the card goes.
      $("save-note").classList.add("good");
      $("save-note").textContent = t("savedQueued");
      yes.hidden = true;
      no.hidden = true;
      fit();
      setTimeout(() => say({ kind: "frame-dismiss", which }), 2600);
      return;
    }
    if (outcome?.done || outcome?.popup) return;
    yes.disabled = false;
    $("save-note").textContent = t("saveFailed");
    fit();
  };
  fit();
}

if (!direct) {
  // Nothing is shown and nothing is asked.
} else if (mode === "save") showSave();
else if (mode === "new") showNew();
else showLogins();
