// The authenticator: every login with a one-time code, as the phone's Codes and the desktop
// app's Authenticator list them. Each code sits behind dots and an eye, as a password does:
// showing one asks the app (the PIN, or Windows Hello where it offers it, each time), and it
// goes back to dots when it runs out. Copy is done by the app; Fill types it into the page in
// front when the login belongs there.

import { listAsks } from "./asks.js";
import { codeClockElement, codeControl, eyeElement } from "./code-view.js";
import { guarded } from "./guard.js";
import { fillTheCode } from "./site.js";
import { here } from "./state.js";
import { $, asksLine, explain, explainRefusal, mark, siteIcon, siteName, t, toast, view } from "./ui.js";

const ALL_ASK = {
  hello: "codesAsksHello",
  pin: "codesAsksPin",
  password: "codesAsksPassword",
  setup: "setupShort",
  app: "codesAsksApp",
};
const SOME_ASK = {
  hello: "someAskHello",
  pin: "someAskPin",
  password: "someAskPassword",
  setup: "setupShort",
  app: "someAskApp",
};

/** The row of login `id` in the list as it is now. */
function rowOf(id) {
  return [...document.querySelectorAll("#codes-list .code-row")].find((row) => row.dataset.id === id);
}

function partsOf(id) {
  const row = rowOf(id);
  if (!row) return undefined;
  return { digits: row.querySelector(".code-digits"), clock: row.querySelector(".code-clock"), eye: row.querySelector("button.eye") };
}

function codeRow(entry, listing) {
  const row = document.createElement("div");
  row.className = "code-row";
  row.dataset.id = entry.id;

  const tile = document.createElement("span");
  tile.className = "code-tile";
  tile.append(siteIcon(entry.site, entry.title || entry.username));

  const name = document.createElement("span");
  name.className = "title";
  name.textContent = entry.title || entry.username || t("noUsername");
  const who = document.createElement("span");
  who.className = "detail";
  who.textContent = entry.username || siteName(entry.site);

  const line = document.createElement("div");
  line.className = "code-line";
  const digits = document.createElement("span");
  digits.className = "code-digits";
  const acts = document.createElement("div");
  acts.className = "acts";
  const eye = eyeElement();
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "plain small";
  copy.textContent = t("copyButton");
  copy.addEventListener("click", async () => {
    const reply = await guarded(entry, listing, { type: "copy", id: entry.id, what: "code" }, t("copyButton"), showCodes);
    if (!reply) return;
    if (reply.type !== "copied") return explainRefusal(reply, listing);
    if ($("codes").hidden) showCodes();
    toast(reply.seconds ? t("copiedSecret", String(reply.seconds)) : t("copied"));
  });
  acts.append(codeClockElement(), eye, copy);
  // Fill, when this login belongs to the page in front (the app decides that).
  if (here.site?.items.some((item) => item.id === entry.id)) {
    const fill = document.createElement("button");
    fill.type = "button";
    fill.className = "plain small";
    fill.textContent = t("fillButton");
    fill.title = t("fillCodeRow");
    fill.addEventListener("click", () => fillTheCode(entry, showCodes));
    acts.append(fill);
  }
  line.append(digits, acts);
  row.append(tile, name, who, line);
  return row;
}

export function showCodes() {
  mark("codes");
  const reply = here.vault;
  if (!reply) return explain(here.vaultProblem || "failed");
  view("tabs", "codes", "foot");
  const items = reply.items.filter((entry) => entry.has_code);
  const asks = listAsks(items, reply);
  asksLine($("codes-asks"), asks.kind, asks.all ? ALL_ASK : SOME_ASK);
  $("codes-empty").hidden = items.length > 0;
  $("codes-empty-title").textContent = t("codesEmptyTitle");
  $("codes-empty-text").textContent = t("codesEmptyText");
  $("codes-list").replaceChildren(...items.map((entry) => codeRow(entry, reply)));
  for (const entry of items) {
    codeControl(entry, reply, {
      find: () => partsOf(entry.id),
      again: showCodes,
      isHere: () => !$("check").hidden || !$("codes").hidden,
      shown: () => !$("codes").hidden,
    });
  }
  $("codes-list").querySelector("button")?.focus();
}
