// The small card a page shows under a sign-in field, or in its corner after a sign-in.
//
// It is the extension's own page in a frame: the web page around it can move or cover it,
// but can't read it or click inside it by script. Against being covered (clickjacking) it
// listens to the browser: a click counts only after the frame has been reported fully
// visible, with nothing drawn over it, for a moment.
//
// The frame's address says what to show and where the field is: `#logins`, `#code`, `#new`,
// `#cards` (the vault's cards, under a payment field: cards.js) or `#save`, with `:up` when the card sits above the field, then `|` and the page's colour
// scheme, then `|` and the offer: which field of the page the card was shown under. A login
// picked here is typed into that field's form only (fill.js). The content script changes only
// the first part when the card has to move above. The page sets this address at the browser's
// address for this session (`use_dynamic_url`), which Chrome serves from the extension's own:
// so the change loads this page again, and its click check starts over.
//
// Under a sign-in field, while the page waits for a field's suggestions (a passkey request
// with `mediation: "conditional"`), the site's passkeys in Vault come first: picking one has
// the app sign in to that page (passkey-worker.js), with the same click check.
//
// `#warn` is a warning, under a field or (`:corner`) in the corner, and the offer part names
// what it is about: `lookalike`, `pasted`, `sent`, `kit` or `kit-typed`. What it shows (names
// of sites, never a password) comes from the worker, not from this address, which the page
// can change: a page can only make it show the tab's real warnings again.

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);
const say = (message) => chrome.runtime.sendMessage(message).catch(() => undefined);
const [mode = "logins", ...flags] = location.hash.slice(1).split("|")[0].split(":");
const offer = location.hash.slice(1).split("|")[2] || "";
// The card under a field (logins, a new password, a warning) and the one in the corner (save,
// a warning).
const corner = mode === "save" || flags.includes("corner");
const which = corner ? "save" : "logins";

function placement() {
  const [where, scheme = "normal"] = location.hash.slice(1).split("|");
  document.body.classList.toggle("up", where.split(":").includes("up"));
  document.body.classList.toggle("corner", corner);
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
    // `isVisible` is the browser's own word that nothing covers, fades or distorts us; every
    // Chrome and Edge this extension runs in (127 and later) gives it. Not given, or the frame
    // not wholly inside the viewport, counts as not visible: a click then does nothing.
    // (Firefox doesn't give it, and content.js shows this frame nowhere there.)
    const visible = seen.isIntersecting && seen.intersectionRatio >= 1 && seen.isVisible === true;
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

// While an AI agent or another program drives the browser (agent.js), the content script draws
// no card; one drawn anyway (by a copy of it from before the extension was updated) takes no
// click. The worker refuses its requests too.
const driven = () => globalThis.VaultAgent?.driven() ?? true;

function genuine(event) {
  const now = performance.now();
  if (driven()) return false;
  if (!event.isTrusted || visibleSince === 0 || now - visibleSince < VISIBLE_FOR_MS) return false;
  const byMouse = event.detail > 0 && (event.pointerType ?? "mouse") === "mouse";
  return !byMouse || (hoveredSince > 0 && now - hoveredSince >= HOVERED_FOR_MS);
}

// This card belongs right inside a page's own document. Inside a frame of the page (an
// advert, an embedded widget) it shows nothing: such a frame is not the site in front. Nor
// in a sandboxed document, whose origin the browser lists as "null".
const around = location.ancestorOrigins;
const direct = !around || (around.length === 1 && around[0] !== "null");

/** Tells the page how tall the frame must be: the card, its arrow and its shadow. */
function fit() {
  const card = document.querySelector(".card");
  const below = parseFloat(getComputedStyle(card).marginBottom) || 0;
  say({ kind: "frame-size", which, height: Math.ceil(card.getBoundingClientRect().bottom + below) });
}
window.addEventListener("hashchange", fit);

/**
 * A letter tile's colour (0–7) for `key`: FNV-1a over the lowercased key, the desktop app's
 * colours for a login without an icon (apps/desktop/src/view.rs, popup/tint.js), so a site
 * looks alike everywhere.
 */
function tintOf(key) {
  let hash = 0x811c9dc5;
  for (const ch of String(key ?? "").toLowerCase()) {
    // Its UTF-8 bytes, as the app hashes them.
    const c = ch.codePointAt(0);
    const bytes =
      c < 0x80
        ? [c]
        : c < 0x800
          ? [0xc0 | (c >> 6), 0x80 | (c & 63)]
          : c < 0x10000
            ? [0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)]
            : [0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)];
    for (const byte of bytes) hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
  }
  return hash % 8;
}

/** The host a site is keyed by for its colour ("www." dropped). */
function hostKey(site) {
  return String(site ?? "")
    .replace(/^[a-z]+:\/\//i, "")
    .split(/[/?#]/)[0]
    .toLowerCase()
    .replace(/^\*\./, "")
    .replace(/^www\./, "");
}

/** The site's icon as the browser already has it (nothing is fetched), or its first letter. */
function siteIcon(origin, letter) {
  const img = document.createElement("img");
  img.className = "favicon";
  img.alt = "";
  img.src = `${chrome.runtime.getURL("/_favicon/")}?pageUrl=${encodeURIComponent(origin)}&size=32`;
  img.addEventListener("error", () => {
    const tile = document.createElement("span");
    if (img.id) tile.id = img.id;
    tile.className = `letter tint-${tintOf(hostKey(origin) || letter)}`;
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

/** A passkey (Lucide's key-round), for the rows of the site's passkeys. */
function passkeyIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const box = document.createElement("span");
  box.className = "key passkey";
  box.setAttribute("aria-hidden", "true");
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  const bow = document.createElementNS(ns, "path");
  bow.setAttribute(
    "d",
    "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z",
  );
  const hole = document.createElementNS(ns, "circle");
  for (const [name, value] of Object.entries({ cx: 16.5, cy: 7.5, r: 0.5 })) hole.setAttribute(name, String(value));
  svg.append(bow, hole);
  box.append(svg);
  return box;
}

/** What opens a locked entry, said on its lock: Windows Hello, the PIN, or the app. */
function opensWith(listing) {
  if (listing.hello) return t("asksHelloLong");
  if (listing.check === "pin") return t("asksPinLong");
  if (listing.check === "password") return t("asksPasswordLong");
  return t("lockedItem");
}

/** Always the same number of dots: the password's length is not shown. */
const DOTS = "••••••••••••";

// ---- the logins of this site ----

async function showLogins() {
  const listed = await say({ kind: "frame-logins" });
  // Under a one-time code field: only the logins that have a code, and no passkeys.
  const codes = mode === "code";
  const items = (listed?.items ?? []).filter((entry) => !codes || entry.has_code);
  const passkeys = codes ? undefined : listed?.passkeys;
  const keys = passkeys?.items ?? [];
  if (!items.length && !keys.length) return say({ kind: "frame-dismiss", which });
  // The logins are those of the page this card sits in, or they are not shown.
  if (around && around[0] !== listed.origin) return say({ kind: "frame-dismiss", which });
  $("logins").hidden = false;
  const site = listed.origin.replace(/^https:\/\//, "");
  const asks = opensWith(listed);
  const rows = [];
  for (const entry of keys) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "row";
    row.setAttribute("role", "option");
    row.title = entry.title;
    const lines = document.createElement("span");
    lines.className = "lines";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = entry.userName || entry.displayName || (entry.title || "").trim() || t("noUsername");
    const kind = document.createElement("span");
    kind.className = "kind";
    // The site the passkey belongs to, as the app checked it, when it is not this page's host
    // (a page under example.com using example.com's passkeys).
    const elsewhere = passkeys.site && passkeys.site !== site.replace(/:\d+$/, "");
    kind.textContent = elsewhere ? t("passkeyRowFor", passkeys.site) : t("passkeyRow");
    lines.append(name, kind);
    row.append(passkeyIcon(), lines);
    if (entry.locked) row.append(lockIcon(opensWith(passkeys)));
    row.addEventListener("click", async (event) => {
      if (!genuine(event)) return;
      for (const other of rows) other.disabled = true;
      await say({ kind: "frame-passkey", id: entry.id, credential: entry.credential });
    });
    rows.push(row);
  }
  for (const entry of items) {
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
      await say({ kind: codes ? "frame-code" : "frame-fill", id: entry.id, offer });
    });
    rows.push(row);
  }
  $("list").replaceChildren(...rows);
  $("manage-text").textContent = t("managePasswords");
  $("manage").onclick = (event) => genuine(event) && say({ kind: "frame-manage" });
  fit();
}

// ---- the vault's cards, under a payment field ----

/** A card (Lucide's credit-card), for the rows of the vault's cards. */
function cardIcon() {
  const ns = "http://www.w3.org/2000/svg";
  const box = document.createElement("span");
  box.className = "key";
  box.setAttribute("aria-hidden", "true");
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  const body = document.createElementNS(ns, "rect");
  for (const [name, value] of Object.entries({ x: 2, y: 5, width: 20, height: 14, rx: 2 })) {
    body.setAttribute(name, String(value));
  }
  const stripe = document.createElementNS(ns, "path");
  stripe.setAttribute("d", "M2 10h20");
  svg.append(body, stripe);
  box.append(svg);
  return box;
}

async function showCards() {
  const listed = await say({ kind: "frame-cards" });
  const items = listed?.items ?? [];
  if (!items.length) return say({ kind: "frame-dismiss", which });
  if (around && around[0] !== listed.origin) return say({ kind: "frame-dismiss", which });
  $("cards").hidden = false;
  const asks = opensWith(listed);
  const rows = items.map((entry) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "row";
    row.setAttribute("role", "option");
    row.title = entry.title;
    const lines = document.createElement("span");
    lines.className = "lines";
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = entry.hint || entry.title || t("cardRow");
    const sub = document.createElement("span");
    sub.className = "secret";
    const expiry = entry.expiry ? t(entry.expired ? "cardExpired" : "cardExpires", entry.expiry) : "";
    sub.textContent = [entry.holder, expiry].filter(Boolean).join(" · ") || entry.title;
    lines.append(name, sub);
    row.append(cardIcon(), lines);
    if (entry.locked) row.append(lockIcon(asks));
    row.addEventListener("click", async (event) => {
      if (!genuine(event)) return;
      for (const other of rows) other.disabled = true;
      const outcome = await say({ kind: "frame-card", id: entry.id });
      for (const other of rows) other.disabled = false;
      if (outcome?.waiting?.length) askApproval(outcome);
    });
    return row;
  });
  $("card-list").replaceChildren(...rows);
  fit();
}

/**
 * Payment fields in a frame of another site: fill there too? The answer is kept by the app for
 * this site and that one (Settings → Browser extension → Site rules), and the card is filled
 * again. The same click check as every click here.
 */
function askApproval(outcome) {
  const site = outcome.waiting[0];
  $("card-approve").hidden = false;
  $("card-approve-text").textContent = t(outcome.done ? "cardFramePartly" : "cardFrameAsk", site);
  const yes = $("card-approve-yes");
  const no = $("card-approve-no");
  yes.textContent = t("cardFrameYes");
  no.textContent = t("cardFrameNo");
  yes.disabled = false;
  no.onclick = (event) => event.isTrusted && say({ kind: "frame-dismiss", which });
  yes.onclick = async (event) => {
    if (!genuine(event)) return;
    yes.disabled = true;
    const again = await say({ kind: "frame-card-approve", site });
    if (again?.waiting?.length && !again.done) return askApproval(again);
    if (!again?.done) {
      $("card-approve-text").textContent = t("cardFrameFailed");
      yes.hidden = true;
      fit();
    }
  };
  // What the card shows changed under the pointer: the click check starts over.
  if (visibleSince) visibleSince = performance.now();
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
  drawSave(info);
}

/** "Not now" for the offer `info`: with a newer one waiting, the card shows that one. */
async function dismissSave(info) {
  const outcome = await say({ kind: "frame-dismiss", which, offer: info.id });
  if (outcome?.redraw) await redraw();
}

/** The card for offer `info`: its site and username, and Save and Not now for it alone. */
function drawSave(info) {
  const site = info.origin.replace(/^https:\/\//, "");
  const icon = siteIcon(info.origin, site);
  icon.id = "save-icon";
  $("save-icon").replaceWith(icon);
  $("save-title").textContent = t(info.update ? "updateTitle" : "saveTitle");
  $("save-who").textContent = `${info.username || t("noUsername")} ${t("saveOn", site)}`;
  const yes = $("save-yes");
  const no = $("save-no");
  const note = $("save-note");
  yes.textContent = t(info.update ? "updateYes" : "saveYes");
  no.textContent = t("saveNo");
  yes.hidden = false;
  no.hidden = false;
  yes.disabled = false;
  note.classList.remove("good");
  // A page that only looks like a saved site: said before Save. Then a new password that is
  // known leaked, or another login's (F18).
  const weight = weightWords(info.weighed);
  note.classList.toggle("warns", Boolean(info.lookalike || weight));
  note.textContent = info.lookalike ? t("saveLookalike", info.lookalike) : weight;
  // The breach service is still being asked: the card looks again in a moment.
  if (!info.lookalike && info.weighed?.weighing) {
    setTimeout(async () => {
      const again = await say({ kind: "frame-save-info" });
      if (again?.id === info.id && !note.classList.contains("good")) {
        const words = weightWords(again.weighed);
        note.classList.toggle("warns", Boolean(words));
        note.textContent = words;
        fit();
        if (again.weighed?.weighing) drawSave(again);
      }
    }, 1600);
  }
  no.onclick = (event) => event.isTrusted && dismissSave(info);
  yes.onclick = async (event) => {
    if (!genuine(event)) return;
    yes.disabled = true;
    // The offer this card shows: Save acts on it, not on a newer one it didn't show.
    const outcome = await say({ kind: "frame-save", offer: info.id });
    if (outcome?.queued) {
      // Locked: kept for the next unlock. Said for a moment, then the card goes.
      note.classList.remove("warns");
      note.classList.add("good");
      note.textContent = t("savedQueued");
      yes.hidden = true;
      no.hidden = true;
      fit();
      setTimeout(() => dismissSave(info), 2600);
      return;
    }
    if (outcome?.done || outcome?.popup) return;
    // No longer the offer waiting (another sign-in replaced it, or it ran out): the card
    // shows the one waiting now, or says that nothing was saved. Never closed silently.
    if (outcome?.stale) return redraw();
    if (outcome?.changed) {
      // The login was changed in Vault since the card was offered: nothing was replaced.
      note.textContent = t("updateChangedSince");
      yes.hidden = true;
      no.textContent = t("saveClose");
      fit();
      return;
    }
    yes.disabled = false;
    note.textContent = t("saveFailed");
    fit();
  };
  fit();
}

/** What the card says of a new password the app weighed: leaked first, then reused. */
function weightWords(weighed) {
  if (!weighed) return "";
  if (weighed.leaked > 0) return t("saveLeaked", String(weighed.leaked));
  if (weighed.reused === 1) return t("saveReusedOne");
  if (weighed.reused > 1) return t("saveReused", String(weighed.reused));
  return "";
}

/** Loads the offer waiting now into the card, or says there is none (nothing was saved). */
async function redraw() {
  const info = await say({ kind: "frame-save-info" });
  if (info?.origin) {
    drawSave(info);
    // What the card shows changed under the pointer: clicks count again only once the
    // browser has reported it visible for the full moment, as for a new card.
    if (visibleSince) visibleSince = performance.now();
    return;
  }
  const note = $("save-note");
  note.classList.remove("good");
  note.textContent = t("saveGone");
  $("save-yes").hidden = true;
  $("save-no").textContent = t("saveClose");
  // Closes the card, or shows an offer that came meanwhile.
  $("save-no").onclick = (event) => event.isTrusted && dismissSave({ id: "" });
  fit();
}

// ---- a warning ----

/** The words of the warning about `about`, from what the worker says of it; none for nothing. */
function warningWords(about, info) {
  if (info?.kit) {
    return { title: t("kitTitle"), text: t(about === "kit-typed" ? "kitTypedText" : "kitText") };
  }
  if (typeof info?.site !== "string" || !info.site) return undefined;
  const page = info.page || "";
  if (about === "lookalike") return { title: t("lookalikeTitle"), text: t("lookalikeText", page, info.site) };
  if (about === "pasted") {
    return {
      title: t("pastedTitle", info.site),
      text: t(info.lookalike ? "pastedLookalike" : "pastedText", page, info.site),
    };
  }
  if (about === "sent") {
    return {
      title: t("sentTitle", info.site),
      text: t(info.lookalike ? "sentLookalike" : "sentText", page, info.site),
    };
  }
  return undefined;
}

async function showWarning() {
  const about = offer;
  const info = await say({ kind: "frame-warning", about });
  const words = warningWords(about, info);
  const close = () => say({ kind: "frame-dismiss", which: corner ? "warn-corner" : "logins" });
  if (!words) return close();
  $("warn").hidden = false;
  $("warn-title").textContent = words.title;
  $("warn-text").textContent = words.text;
  // The same click check as everywhere in this frame: a page that draws over the warning can't
  // have it dismissed by a click meant for the page.
  const ok = $("warn-ok");
  ok.textContent = t(about === "pasted" ? "pastedKeep" : "warnOk");
  ok.onclick = (event) => genuine(event) && close();
  const remove = $("warn-other");
  remove.hidden = about !== "pasted";
  remove.textContent = t("pastedRemove");
  remove.onclick = (event) => genuine(event) && say({ kind: "frame-warn-clear" });
  fit();
}

if (!direct) {
  // Nothing is shown and nothing is asked.
} else if (mode === "save") showSave();
else if (mode === "new") showNew();
else if (mode === "warn") showWarning();
else if (mode === "cards") showCards();
else showLogins();
