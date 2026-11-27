// The site in front: its logins, to fill, and a login typed into it that isn't saved yet.

import { dropPendingSave, originOf, pendingSave, updateRequest } from "../app.js";
import { fillCode, fillLogin } from "../fill.js";
import { listAsks } from "./asks.js";
import { guarded } from "./guard.js";
import { here, routes } from "./state.js";
import {
  $,
  asksLine,
  explain,
  explainRefusal,
  loginRow,
  mark,
  outcome,
  sideButton,
  siteName,
  t,
  toast,
  view,
} from "./ui.js";

/** What the line above a list says, per kind, when every login asks the same. */
const ALL_ASK = {
  hello: "siteAsksHello",
  pin: "siteAsksPin",
  password: "siteAsksPassword",
  setup: "setupShort",
  app: "siteAsksApp",
};
/** And when only some do (those with a padlock). */
const SOME_ASK = {
  hello: "someAskHello",
  pin: "someAskPin",
  password: "someAskPassword",
  setup: "setupShort",
  app: "someAskApp",
};

export function showSite() {
  mark("site");
  const reply = here.site;
  if (!reply) return explain(here.siteProblem || "not_a_website");
  view("tabs", "site", "foot");
  $("origin").textContent = siteName(reply.origin);
  $("origin").title = reply.origin;
  showWarnings();
  showOffer();
  const empty = reply.items.length === 0;
  $("site-empty").hidden = !empty;
  $("list").hidden = empty;
  const asks = listAsks(reply.items, reply);
  asksLine($("site-asks"), asks.kind, asks.all ? ALL_ASK : SOME_ASK);
  // A page that only looks like a saved site (the app compares, from the vault's own sites):
  // said in place of "no login", naming both.
  const looks = empty && typeof reply.lookalike?.site === "string" ? reply.lookalike : undefined;
  $("site-empty").classList.toggle("warns", Boolean(looks));
  if (empty) {
    $("site-empty-title").textContent = t(looks ? "lookalikeTitle" : "noLoginsTitle");
    $("site-empty-text").textContent = looks
      ? t("lookalikeText", looks.page || siteName(reply.origin), looks.site)
      : t("noLoginsText", reply.origin);
    $("list").replaceChildren();
    return;
  }
  const rows = reply.items.map((entry) => {
    const full = { ...entry, site: reply.origin, has_password: true };
    const extra = [];
    if (entry.has_code) {
      extra.push(
        sideButton(t("fillCodeRow"), {
          text: t("codeShort"),
          onClick: () => {
            disableRows();
            fillTheCode(full, showSite);
          },
        }),
      );
    }
    extra.push(sideButton(t("detailsButton"), { glyph: "next", onClick: () => routes.entry(full, reply, showSite) }));
    return loginRow(entry, reply, {
      detail: entry.username,
      site: reply.origin,
      marks: !asks.all,
      onPick: () => {
        disableRows();
        fill(full, showSite);
      },
      extra,
    });
  });
  $("list").replaceChildren(...rows);
  if (!here.pending) $("list").querySelector("button.login:enabled")?.focus();
}

function disableRows() {
  for (const button of document.querySelectorAll("#list button")) button.disabled = true;
}

// ---- filling ----

/** Fills `entry` into the page in front; `back` shows where the person was. */
export async function fill(entry, back) {
  const tab = here.tab;
  const reply = await guarded(entry, here.site, { type: "fill", url: tab.url, id: entry.id }, t("fillButton"), back);
  if (!reply) return;
  if (reply.type !== "fill") return explainRefusal(reply, here.site);
  // The tab may have navigated while the app answered: look again, and let the page-side
  // function check once more where it really runs.
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return outcome("pageChanged");
  let result = "none";
  try {
    const [ran] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillLogin,
      args: [reply.origin, reply.username, reply.password],
    });
    result = ran?.result ?? "none";
  } catch {
    result = "failed";
  }
  reply.password = "";
  switch (result) {
    case "both":
    case "password":
      return window.close();
    case "username":
      return outcome("filledUsername");
    case "wrong_page":
      return outcome("pageChanged");
    case "choose_field":
      return outcome("chooseField");
    case "insecure_form":
      return outcome("insecureForm");
    case "none":
      return outcome("noFields");
    default:
      return outcome("failed");
  }
}

/** Types the current one-time code of `entry` into the page in front. */
export async function fillTheCode(entry, back) {
  const tab = here.tab;
  const reply = await guarded(entry, here.site, { type: "code", url: tab.url, id: entry.id }, t("fillCode"), back);
  if (!reply) return;
  if (reply.type !== "code") return explainRefusal(reply, here.site);
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return outcome("pageChanged");
  let result = "none";
  try {
    const [ran] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillCode,
      args: [reply.origin, reply.code],
    });
    result = ran?.result ?? "none";
  } catch {
    result = "failed";
  }
  reply.code = "";
  if (result === "filled") return window.close();
  if (result === "wrong_page") return outcome("pageChanged");
  if (result === "choose_field") return outcome("chooseCodeField");
  if (result === "insecure_form") return outcome("insecureForm");
  return outcome(result === "none" ? "noCodeField" : "failed");
}

// ---- what the page was warned about ----

/**
 * The words of the warning to show for `warnings` (the worker's `tab-warnings`): a key of the
 * kit first, then a password sent, then one pasted; none for nothing.
 */
export function warningWords(warnings) {
  if (warnings?.kit) return { title: t("kitTitle"), text: t(warnings.kit.typed ? "kitTypedText" : "kitText") };
  for (const about of ["sent", "pasted"]) {
    const found = warnings?.[about];
    if (typeof found?.site !== "string" || !found.site) continue;
    const page = found.page || "";
    const text = about === "sent" ? (found.lookalike ? "sentLookalike" : "sentText") : found.lookalike ? "pastedLookalike" : "pastedText";
    return { title: t(`${about}Title`, found.site), text: t(text, page, found.site) };
  }
  return undefined;
}

function showWarnings() {
  const words = warningWords(here.warnings);
  $("site-warn").hidden = !words;
  if (!words) return;
  $("site-warn-title").textContent = words.title;
  $("site-warn-text").textContent = words.text;
}

// ---- a login typed into this page and not saved yet ----

function showOffer() {
  const pending = here.pending;
  $("offer").hidden = !pending;
  if (!pending) return;
  const update = pending.update;
  $("offer-title").textContent = t(update ? "updateTitle" : "saveTitle");
  $("offer-text").textContent = t(update ? "offerUpdateText" : "offerText", pending.username || t("noUsername"));
  const yes = $("offer-yes");
  const no = $("offer-no");
  yes.textContent = t(update ? "updateYes" : "saveYes");
  yes.disabled = false;
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
    const title = siteName(originOf(pending.url));
    if (update) {
      // Changing a locked login's password opens it first, as a fill does.
      const entry = { title, username: pending.username, locked: update.locked, site: pending.url };
      const listing = here.site || { hello: false };
      // For the version of the login the app compared, and its username (`updateRequest`).
      const request = updateRequest(pending);
      const reply = await guarded(entry, listing, request, t("updateYes"), showSite);
      yes.disabled = false;
      if (!reply) return;
      // Changed since: nothing was replaced, and this offer can't be taken again.
      if (reply.code === "changed_since") await done();
      if (reply.type !== "updated") return explainRefusal(reply, listing);
      await done();
      toast(t(reply.changed ? "updatedToast" : "alreadySavedToast"));
      await routes.reload();
      showSite();
      return;
    }
    // A new login asks for nothing unless the item lock covers new items; then as a fill.
    const entry = { title, username: pending.username, locked: false, site: pending.url };
    const listing = here.site || { hello: true };
    const request = { type: "save", url: pending.url, username: pending.username, password: pending.password };
    const reply = await guarded(entry, { ...listing, hello: true }, request, t("saveYes"), showSite);
    yes.disabled = false;
    if (!reply) return;
    if (reply.type !== "saved") return explainRefusal(reply, listing);
    await done();
    toast(t(reply.queued ? "savedQueued" : "savedToast"));
    await routes.reload();
    showSite();
  };
  yes.focus();
}
