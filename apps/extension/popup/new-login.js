// A new login, made in this window and saved by the app.

import { ask, originOf } from "../app.js";
import { currentRequest, generate } from "./generator.js";
import { guarded } from "./guard.js";
import { here, routes } from "./state.js";
import { $, explainRefusal, eye, siteName, t, toast, view } from "./ui.js";

/** `generated`: a password the generator made (`{ id, password }`), to start with. */
export function showNewLogin(generated) {
  view("new-login", "foot");
  $("new-title").textContent = t("newLoginTitle");
  $("new-back-text").textContent = t("backButton");
  $("new-site-label").textContent = t("label_site");
  $("new-name-label").textContent = t("nameLabel");
  $("new-user-label").textContent = t("label_username");
  $("new-pass-label").textContent = t("label_password");
  eye($("new-show"), false);
  $("new-generate").title = t("generateButton");
  $("new-generate").setAttribute("aria-label", t("generateButton"));
  $("new-save").textContent = t("saveYes");
  $("new-save").disabled = false;
  $("new-cancel").textContent = t("cancelButton");
  $("new-error").textContent = "";
  const site = $("new-site");
  const page = originOf(here.tab?.url || "");
  site.value = page.startsWith("https://") ? siteName(page) : "";
  site.placeholder = "example.com";
  $("new-name").value = "";
  $("new-name").placeholder = t("nameHint");
  $("new-user").value = "";
  const pass = $("new-pass");
  pass.type = "password";
  pass.value = generated?.password || "";
  let kept = generated;
  const leave = () => (here.place === "gen" ? routes.gen() : routes.vault());
  $("new-back").onclick = leave;
  $("new-cancel").onclick = leave;
  $("new-show").onclick = () => {
    pass.type = pass.type === "password" ? "text" : "password";
    eye($("new-show"), pass.type === "text");
  };
  $("new-generate").onclick = async () => {
    const made = await generate(await currentRequest());
    if (made.error) return;
    kept = made;
    pass.value = made.password;
    pass.type = "text";
    eye($("new-show"), true);
  };
  (site.value ? $("new-user") : site).focus();
  $("new-login").onsubmit = async (event) => {
    event.preventDefault();
    const address = site.value.trim();
    const url = /^https?:\/\//i.test(address) ? address : `https://${address}`;
    if (!address || !originOf(url).startsWith("https://")) {
      $("new-error").textContent = t("newSiteError");
      return site.focus();
    }
    if (!pass.value) return pass.focus();
    $("new-error").textContent = "";
    $("new-save").disabled = true;
    const entry = { title: $("new-name").value || address, username: $("new-user").value, locked: false, site: url };
    const listing = here.vault || here.site || { hello: false };
    const request = {
      type: "save",
      url,
      title: $("new-name").value.trim() || undefined,
      username: $("new-user").value.trim(),
      password: pass.value,
    };
    const reply = await guarded(entry, listing, request, t("saveYes"), () => showNewLogin(kept));
    $("new-save").disabled = false;
    if (!reply) return;
    if (reply.type !== "saved") return explainRefusal(reply, listing);
    if (reply.existing) {
      $("new-error").textContent = t("newExists");
      return;
    }
    if (kept && kept.password === request.password) await ask({ type: "keep", id: kept.id });
    pass.value = "";
    toast(t(reply.queued ? "savedQueued" : "savedToast"));
    await routes.reload();
    routes.vault();
  };
}
