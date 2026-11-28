// The person's rules for the site in front (F16): never offer to save, no card under its
// fields, never fill, no passkeys. The app keeps them (on this computer, Settings → Browser
// extension → Site rules) and enforces them; this window only shows them and asks the app to
// change one. The app tells of each change in its own window.

import { ask } from "../app.js";
import { here } from "./state.js";
import { SWITCHES, ruleOf, ruleRequest } from "./site-rule.js";
import { $, t, toast } from "./ui.js";

/** Draws the site's rules under its logins; a change goes to the app at once. */
export function showRules() {
  const box = $("site-rules");
  if (!box) return;
  const listing = here.site;
  box.hidden = !listing;
  if (!listing) return;
  const rule = ruleOf(listing);
  $("site-rules-title").textContent = t("rulesTitle");
  const rows = SWITCHES.map(([key, words]) => {
    const label = document.createElement("label");
    label.className = "rule";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = rule[key];
    input.addEventListener("change", async () => {
      input.disabled = true;
      const reply = await ask(ruleRequest(here.tab.url, key, input.checked));
      input.disabled = false;
      if (reply?.type !== "site_rule") {
        input.checked = !input.checked;
        toast(t("ruleNotChanged"));
        return;
      }
      here.site = { ...here.site, rule: reply.rule ?? undefined };
      toast(t("ruleChanged", reply.site || ""));
    });
    const text = document.createElement("span");
    text.textContent = t(words);
    label.append(input, text);
    return label;
  });
  $("site-rules-list").replaceChildren(...rows);
  box.open = SWITCHES.some(([key]) => rule[key]);
}
