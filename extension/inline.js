// The small card a page shows under a sign-in field, or in its corner after a sign-in.
//
// It is the extension's own page in a frame: the web page around it can move or cover it,
// but can't read it or click inside it by script. Against being covered (clickjacking) it
// listens to the browser: a click counts only after the frame has been reported fully
// visible, with nothing drawn over it, for a moment.
//
// The frame's address says what to show and where the field is: `#logins`, `#new` or
// `#save`, with `:up` when the card sits above the field. The content script changes only
// that part when the card has to move above, which doesn't reload this page.

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);
const say = (message) => chrome.runtime.sendMessage(message).catch(() => undefined);
const [mode = "logins"] = location.hash.slice(1).split(":");
// The card under a field (logins or a new password) and the one in the corner (save).
const which = mode === "save" ? "save" : "logins";

function placement() {
  document.body.classList.toggle("up", location.hash.endsWith(":up"));
  document.body.classList.toggle("corner", mode === "save");
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

function genuine(event) {
  return event.isTrusted && visibleSince > 0 && performance.now() - visibleSince >= VISIBLE_FOR_MS;
}

function fit() {
  say({ kind: "frame-size", which, height: Math.ceil(document.body.getBoundingClientRect().height) });
}

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
  if (!listed?.items?.length) return say({ kind: "frame-dismiss", which });
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
    name.textContent = entry.username || t("noUsername");
    // The item's own name, when it says more than the site does.
    const title = (entry.title || "").trim();
    if (title && !site.toLowerCase().includes(title.toLowerCase())) {
      const small = document.createElement("small");
      small.textContent = title;
      name.append(small);
    }
    const dots = document.createElement("span");
    dots.className = "secret";
    dots.textContent = DOTS;
    lines.append(name, dots);
    row.append(siteIcon(listed.origin, entry.title || site), lines);
    if (entry.locked) row.append(lockIcon(asks));
    row.addEventListener("click", async (event) => {
      if (!genuine(event)) return;
      for (const other of rows) other.disabled = true;
      await say({ kind: "frame-fill", id: entry.id });
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
  $("save-title").textContent = t("saveTitle");
  $("save-who").textContent = `${info.username || t("noUsername")} ${t("saveOn", site)}`;
  const yes = $("save-yes");
  const no = $("save-no");
  yes.textContent = t("saveYes");
  no.textContent = t("saveNo");
  no.onclick = (event) => event.isTrusted && say({ kind: "frame-dismiss", which });
  yes.onclick = async (event) => {
    if (!genuine(event)) return;
    yes.disabled = true;
    const outcome = await say({ kind: "frame-save" });
    if (outcome?.done || outcome?.popup) return;
    yes.disabled = false;
    $("save-note").textContent = t("saveFailed");
    fit();
  };
  fit();
}

if (mode === "save") showSave();
else if (mode === "new") showNew();
else showLogins();
