// The vault's cards, offered for the payment fields of the page in front (F5). Filled by
// cards.js: the page's own fields, and those in frames of another site only once the person
// allowed that site's frames for this one (kept by the app with the site's rules).

import { ask } from "../app.js";
import { approveCardFrame, fillCardInTab } from "../cards.js";
import { guarded } from "./guard.js";
import { ruleOf } from "./site-rule.js";
import { here } from "./state.js";
import { $, explainRefusal, loginRow, outcome, t } from "./ui.js";

/** Asks the app for the cards and lists them under the site's logins (none: nothing shown). */
export async function showCardsHere(back) {
  const box = $("site-cards");
  if (!box || !here.site || !here.tab?.url) return;
  const listed = await ask({ type: "cards", url: here.tab.url });
  const items = listed?.type === "cards" && Array.isArray(listed.items) ? listed.items : [];
  box.hidden = items.length === 0;
  if (!items.length) return;
  $("site-cards-title").textContent = t("cardsTitle");
  const rows = items.map((entry) => {
    const shown = { ...entry, title: entry.hint || entry.title, username: entry.holder, site: "" };
    const expiry = entry.expiry ? t(entry.expired ? "cardExpired" : "cardExpires", entry.expiry) : "";
    return loginRow(shown, listed, {
      detail: [entry.holder, expiry].filter(Boolean).join(" · ") || entry.title,
      site: "",
      onPick: () => fillTheCard(shown, listed, back),
    });
  });
  $("site-cards-list").replaceChildren(...rows);
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
