// Every login in the vault, to search and open; and the way to add one by hand.

import { listAsks } from "./asks.js";
import { here, routes } from "./state.js";
import { $, asksLine, explain, loginRow, mark, siteName, t, view } from "./ui.js";

const ALL_ASK = {
  hello: "vaultAsksHello",
  pin: "vaultAsksPin",
  password: "vaultAsksPassword",
  setup: "setupShort",
  app: "vaultAsksApp",
};
const SOME_ASK = {
  hello: "someAskHello",
  pin: "someAskPin",
  password: "someAskPassword",
  setup: "setupShort",
  app: "someAskApp",
};

/** What was typed in the search, kept while the window is open (back from a login). */
let searched = "";

export function showVault() {
  mark("vault");
  const reply = here.vault;
  if (!reply) return explain(here.vaultProblem || "failed");
  view("tabs", "vault", "foot");
  const search = $("search");
  search.placeholder = t("searchLabel");
  search.setAttribute("aria-label", t("searchLabel"));
  search.value = searched;
  $("add-login-text").textContent = t("addLogin");
  $("add-login").onclick = () => routes.newLogin();
  const asks = listAsks(reply.items, reply);
  asksLine($("vault-asks"), asks.kind, asks.all ? ALL_ASK : SOME_ASK);
  const draw = () => {
    searched = search.value;
    const words = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    const found = reply.items.filter((entry) => {
      const text = `${entry.title} ${entry.username} ${entry.site}`.toLowerCase();
      return words.every((word) => text.includes(word));
    });
    $("vault-list").replaceChildren(
      ...found.map((entry) =>
        loginRow(entry, reply, {
          detail: entry.username || siteName(entry.site),
          marks: !asks.all,
          onPick: (picked) => routes.entry(picked, reply, showVault),
        }),
      ),
    );
    const empty = $("vault-empty");
    empty.hidden = found.length > 0;
    empty.textContent = reply.items.length === 0 ? t("vaultEmpty") : t("searchEmpty");
  };
  search.oninput = draw;
  search.onkeydown = (event) => {
    // Enter opens the first login found.
    if (event.key === "Enter") $("vault-list").querySelector("button.login")?.click();
  };
  draw();
  search.focus();
}
