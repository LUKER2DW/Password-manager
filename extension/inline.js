// The small frame a page shows under a sign-in field, or in its corner after a sign-in.
//
// It is the extension's own page: the web page around it can move or cover it, but can't
// read it or click inside it by script. Against being covered (clickjacking) it listens to
// the browser: a click counts only after the frame has been reported fully visible, with
// nothing drawn over it, for a moment.

const t = (key, ...parts) => chrome.i18n.getMessage(key, parts) || key;
const $ = (id) => document.getElementById(id);
const say = (message) => chrome.runtime.sendMessage(message).catch(() => undefined);
const mode = location.hash.slice(1) || "logins";
// The frame under a field (logins or a new password) and the one in the corner (save).
const which = mode === "save" ? "save" : "logins";

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

// ---- the logins of this site ----

async function showLogins() {
  const listed = await say({ kind: "frame-logins" });
  if (!listed?.items?.length) return say({ kind: "frame-dismiss", which });
  $("logins").hidden = false;
  $("logins-title").textContent = t("inlineTitle", listed.origin.replace(/^https:\/\//, ""));
  $("logins-close").textContent = t("inlineClose");
  $("logins-close").onclick = (event) => event.isTrusted && say({ kind: "frame-dismiss", which });
  const typed = listed.check === "pin" || listed.check === "password";
  const rows = listed.items.map((entry) => {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "login";
    const tile = document.createElement("span");
    tile.className = "tile";
    tile.textContent = (entry.title || entry.username || "?").trim().charAt(0);
    const title = document.createElement("span");
    title.className = "title";
    title.textContent = entry.username || t("noUsername");
    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = entry.title;
    row.append(tile, title, detail);
    if (entry.locked) {
      const asks = document.createElement("span");
      asks.className = "asks";
      asks.textContent = listed.hello ? t("asksHello") : typed ? t(listed.check === "pin" ? "asksPin" : "asksPassword") : t("lockedItem");
      row.append(asks);
    }
    row.addEventListener("click", async (event) => {
      if (!genuine(event)) return;
      for (const other of rows) other.disabled = true;
      await say({ kind: "frame-fill", id: entry.id });
    });
    return row;
  });
  $("list").replaceChildren(...rows);
  fit();
}

// ---- save what was typed? ----

async function showSave() {
  const info = await say({ kind: "frame-save-info" });
  if (!info?.origin) return say({ kind: "frame-dismiss", which });
  $("save").hidden = false;
  $("save-title").textContent = t("saveTitle");
  const who = $("save-who");
  const name = document.createElement("strong");
  name.textContent = info.username || t("noUsername");
  who.replaceChildren(name, ` ${t("saveOn", info.origin.replace(/^https:\/\//, ""))}`);
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

// ---- a strong password for a new account ----

async function showNew() {
  $("new").hidden = false;
  $("new-title").textContent = t("suggestTitle");
  $("new-close").textContent = t("inlineClose");
  $("new-close").onclick = (event) => event.isTrusted && say({ kind: "frame-dismiss", which });
  $("new-use").textContent = t("suggestUse");
  $("new-again").textContent = t("suggestAnother");
  const draw = async () => {
    const made = await say({ kind: "frame-suggest" });
    if (!made?.password) return say({ kind: "frame-dismiss", which });
    $("new-password").textContent = made.password;
    $("new-note").textContent = t("suggestNote", String(made.password.length));
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

if (mode === "save") showSave();
else if (mode === "new") showNew();
else showLogins();
