// The vault's cards and identities, offered for the payment and address fields of the page in
// front (F5). Identities go into the page's own document only (address-fill.js). Cards are filled by
// cards.js: the page's own fields, and those in frames of another site only once the person
// allowed that site's frames for this one (kept by the app with the site's rules).

import { ask, originOf } from "../app.js";
import { fillAddress } from "../address-fill.js";
import { approveCardFrame, fillCardInTab } from "../cards.js";
import { guarded } from "./guard.js";
import { ruleOf } from "./site-rule.js";
import { here } from "./state.js";
import { $, explainRefusal, loginRow, outcome, t } from "./ui.js";

/** Asks the app for the cards and identities, and lists them under the site's logins. */
export async function showCardsHere(back) {
  const box = $("site-cards");
  if (!box || !here.site || !here.tab?.url) return;
  const [listed, people] = await Promise.all([
    ask({ type: "cards", url: here.tab.url }),
    ask({ type: "identities", url: here.tab.url }),
  ]);
  const items = listed?.type === "cards" && Array.isArray(listed.items) ? listed.items : [];
  const identities = people?.type === "identities" && Array.isArray(people.items) ? people.items : [];
  box.hidden = items.length === 0 && identities.length === 0;
  if (box.hidden) return;
  $("site-cards-title").textContent = t(items.length && identities.length ? "cardsAndAddressesTitle" : items.length ? "cardsTitle" : "identitiesTitle");
  const who = identities.map((entry) => {
    const shown = { ...entry, title: entry.name || entry.title, username: entry.summary, site: "" };
    return loginRow(shown, people, {
      detail: entry.summary || entry.title,
      site: "",
      onPick: () => fillTheIdentity(shown, people, back),
    });
  });
  const rows = items.map((entry) => {
    const shown = { ...entry, title: entry.hint || entry.title, username: entry.holder, site: "" };
    const expiry = entry.expiry ? t(entry.expired ? "cardExpired" : "cardExpires", entry.expiry) : "";
    return loginRow(shown, listed, {
      detail: [entry.holder, expiry].filter(Boolean).join(" · ") || entry.title,
      site: "",
      onPick: () => fillTheCard(shown, listed, back),
    });
  });
  $("site-cards-list").replaceChildren(...rows, ...who);
}

/** Types identity `entry` into the address fields of the page in front (its own origin only). */
async function fillTheIdentity(entry, listed, back) {
  const tab = here.tab;
  const reply = await guarded(entry, listed, { type: "identity_fill", url: tab.url, id: entry.id }, t("fillAddressButton"), back);
  if (!reply) return;
  if (reply.type !== "identity_fill") return explainRefusal(reply, listed);
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return outcome("pageChanged");
  let result = "none";
  try {
    const [ran] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillAddress,
      args: [reply.origin, reply],
    });
    result = ran?.result ?? "none";
  } catch {
    result = "failed";
  }
  if (result === "filled") return window.close();
  if (result === "wrong_page") return outcome("pageChanged");
  if (result === "insecure_form") return outcome("insecureForm");
  return outcome(result === "none" ? "addressNoFields" : "failed");
}

async function fillTheCard(entry, listed, back) {
  const tab = here.tab;
  const send = (request) => guarded(entry, listed, request, t("fillCardButton"), back);
  const done = await fillCardInTab(tab, entry.id, ruleOf(here.site), send);
  if (done.done && !done.waiting?.length) return window.close();
  if (done.reply && done.reply.type !== "card_fill") return explainRefusal(done.reply, listed);
  if (done.changed) return outcome("pageChanged");
  if (done.waiting?.length) return askApproval(entry, listed, back, done.waiting[0]);
  if (done.done) return window.close();
  return outcome(done.none ? "cardNoFields" : "failed");
}

/** Payment fields in a frame of another site: allow that site's frames here, then fill again. */
function askApproval(entry, listed, back, site) {
  const box = $("site-cards-approve");
  box.hidden = false;
  $("site-cards-approve-text").textContent = t("cardFrameWindowAsk", site);
  const yes = $("site-cards-approve-yes");
  yes.textContent = t("cardFrameWindowYes");
  yes.disabled = false;
  yes.onclick = async () => {
    yes.disabled = true;
    const rule = await approveCardFrame(here.tab, site);
    box.hidden = true;
    if (!rule) return outcome("failed");
    here.site = { ...here.site, rule };
    await fillTheCard(entry, listed, back);
  };
}
