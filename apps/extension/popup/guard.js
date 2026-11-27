// The item lock, as the browser meets it. A login the app marks `locked` is opened for one
// request at a time: by Windows Hello (the system's own prompt) when the app offers it, else
// by the item lock's PIN or password typed here. What is typed goes to the app with that one
// request and is kept nowhere; the next request asks again.

import { ask } from "../app.js";
import { refusal } from "./asks.js";
import { $, siteIcon, t, view } from "./ui.js";

/**
 * Sends `request` for a login that may be locked. Windows Hello first when the app offers it;
 * otherwise, or when Hello is closed and the app asks for the PIN, the PIN or item password
 * typed here. Resolves with the app's final reply, or `undefined` when the person turned
 * back (`back` has shown where they were).
 */
export async function guarded(entry, listing, request, goLabel, back) {
  const reply = await ask({ ...request, hello: Boolean(entry.locked && listing?.hello) });
  if (refusal(reply, listing) !== "prompt") return reply;
  return new Promise((resolve) => {
    const pin = reply.check === "pin";
    view("check", "foot");
    $("check-tile").replaceChildren(siteIcon(entry.site, entry.title || entry.username, 32));
    $("check-title").textContent = entry.title || entry.username || t("noUsername");
    $("check-username").textContent = entry.title ? entry.username : "";
    $("check-text").textContent = t(pin ? "pinText" : "passwordText");
    $("check-error").textContent = "";
    $("check-go").textContent = goLabel;
    $("check-go").disabled = false;
    $("check-back-text").textContent = t("backButton");
    const input = $("check-input");
    input.value = "";
    input.placeholder = t(pin ? "pinLabel" : "passwordLabel");
    input.setAttribute("aria-label", t(pin ? "pinLabel" : "passwordLabel"));
    input.inputMode = pin ? "numeric" : "text";
    input.maxLength = pin ? 8 : 256;
    input.classList.toggle("pin", pin);
    input.focus();
    $("check-back").onclick = () => {
      input.value = "";
      back();
      resolve(undefined);
    };
    $("check").onsubmit = async (event) => {
      event.preventDefault();
      const typed = input.value;
      if (!typed) return;
      input.value = "";
      $("check-go").disabled = true;
      const answer = await ask({ ...request, check: typed });
      $("check-go").disabled = false;
      if (answer.code === "wrong_check") {
        $("check-error").textContent =
          answer.left === 1 ? t("wrongCheckLast") : t("wrongCheck", String(answer.left));
        return input.focus();
      }
      resolve(answer);
    };
  });
}
