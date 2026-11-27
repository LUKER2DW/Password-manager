// One login: who and where, its password and one-time code shown on request, copied by the
// app, or filled into the page in front. A shown password is plain text in its field, which
// can be selected, back to dots after 15 seconds; a shown code goes back to dots when it runs
// out (code-view.js). Neither comes back by itself: showing again asks again.

import { ask, originOf } from "../app.js";
import { asksFor } from "./asks.js";
import { codeControl } from "./code-view.js";
import { secondsLeft, SHOW_FOR_MS } from "./countdown.js";
import { guarded } from "./guard.js";
import { keepShown } from "./secrets.js";
import { fill, fillTheCode } from "./site.js";
import { here } from "./state.js";
import { $, asksLine, drawColoured, explainRefusal, eye, siteIcon, siteName, siteUrl, t, toast, view } from "./ui.js";

const DOTS = "••••••••••";

const ENTRY_ASK = {
  hello: "entryAsksHello",
  pin: "entryAsksPin",
  password: "entryAsksPassword",
  setup: "setupShort",
  app: "itemLockedText",
};

/** The login on screen; an answer that comes after the person moved on is dropped. */
let current;
/** Hides the shown password sooner (the eye clicked again). */
let hidePassword;

/** Still on this login: its page, or the PIN form opened for it. */
function stillOn(entry) {
  if (!$("check").hidden) return true;
  return !$("entry").hidden && current?.id === entry.id;
}

export function showEntry(entry, listing, back) {
  current = entry;
  hidePassword = undefined;
  const again = () => showEntry(entry, listing, back);
  view("entry", "foot");
  $("entry-back-text").textContent = t("backButton");
  $("entry-back").onclick = back;
  $("entry-tile").replaceChildren(siteIcon(entry.site, entry.title || entry.username, 40));
  $("entry-title").textContent = entry.title || entry.username || t("noUsername");
  $("entry-sub").textContent = siteName(entry.site);
  asksLine($("entry-asks"), asksFor(entry, listing), ENTRY_ASK);
  for (const name of ["username", "password", "code", "site"]) {
    $(`label-${name}`).textContent = t(`label_${name}`);
  }
  for (const id of ["copy-username", "copy-password", "copy-code"]) $(id).textContent = t("copyButton");

  /** Asks the app to copy; the value never comes here. */
  const copy = (what) => async () => {
    const request = { type: "copy", id: entry.id, what };
    const reply =
      what === "username" ? await ask(request) : await guarded(entry, listing, request, t("copyButton"), again);
    if (!reply || !stillOn(entry)) return;
    if (reply.type !== "copied") return explainRefusal(reply, listing);
    if ($("entry").hidden) again();
    toast(reply.seconds ? t("copiedSecret", String(reply.seconds)) : t("copied"));
  };

  // ---- username ----
  $("field-username").hidden = !entry.username;
  $("value-username").textContent = entry.username;
  $("copy-username").onclick = copy("username");

  // ---- password ----
  $("field-password").hidden = entry.has_password === false;
  resetPassword();
  const show = $("show-password");
  eye(show, false);
  show.onclick = async () => {
    if (hidePassword) return hidePassword();
    const reply = await guarded(entry, listing, { type: "reveal", id: entry.id }, t("showButton"), again);
    if (!reply || !stillOn(entry)) return;
    if (reply.type !== "reveal") return explainRefusal(reply, listing);
    if ($("entry").hidden) again();
    showPassword(reply.password);
    reply.password = "";
  };
  $("copy-password").onclick = copy("password");

  // ---- one-time code: dots and an eye, as the password ----
  $("field-code").hidden = !entry.has_code;
  codeControl(entry, listing, {
    find: () => ({ digits: $("code-digits"), clock: $("code-clock"), eye: $("show-code") }),
    again,
    isHere: () => stillOn(entry),
    shown: () => !$("entry").hidden,
  });
  $("copy-code").onclick = copy("code");

  // ---- website ----
  const url = siteUrl(entry.site);
  $("field-site").hidden = !url;
  $("value-site").textContent = siteName(entry.site);
  $("open-site-text").textContent = t("openButton");
  $("open-site").onclick = () => {
    if (originOf(url).startsWith("https://") || originOf(url).startsWith("http://")) chrome.tabs.create({ url });
  };

  // ---- fill, when this login belongs to the page in front (the app decides that) ----
  const fits = here.site?.items.some((item) => item.id === entry.id);
  const fillButton = $("entry-fill");
  fillButton.hidden = !fits;
  fillButton.disabled = false;
  fillButton.textContent = t("fillHere");
  fillButton.onclick = () => {
    fillButton.disabled = true;
    fill(entry, again);
  };
  const codeButton = $("entry-fill-code");
  codeButton.hidden = !fits || !entry.has_code;
  codeButton.textContent = t("fillCode");
  codeButton.onclick = () => fillTheCode(entry, again);
  $("entry-actions").hidden = fillButton.hidden && codeButton.hidden;
}

/** The password field without the password: dots, the eye shut. */
function resetPassword() {
  const value = $("value-password");
  value.replaceChildren(DOTS);
  value.classList.remove("shown");
  $("password-note").hidden = true;
  eye($("show-password"), false);
}

/**
 * The password as text in its field, which can be selected, for 15 seconds at most; the line
 * under it counts down.
 */
function showPassword(password) {
  const value = $("value-password");
  drawColoured(value, password);
  value.classList.add("shown");
  $("password-note").hidden = false;
  const until = Date.now() + SHOW_FOR_MS;
  const tick = () => ($("password-left").textContent = t("hidesIn", secondsLeft(until, Date.now())));
  tick();
  const timer = setInterval(tick, 1000);
  eye($("show-password"), true);
  hidePassword = keepShown(() => {
    clearInterval(timer);
    // The text goes from the page, not only from sight.
    resetPassword();
    hidePassword = undefined;
  }, SHOW_FOR_MS);
}
