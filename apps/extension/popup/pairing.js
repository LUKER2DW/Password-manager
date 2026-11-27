// Connecting to the app. The extension and the app agree on a connection key without sending
// it (link.js `agree`); both show a code drawn from it, and the person allows the connection
// in the app, with the master password, only if the two codes match. Nothing secret is typed
// in the browser.

import { ask, send } from "../app.js";
import { agree, dropKey, loadKey, saveKey, startWaiting, stopWaiting, waitingCode } from "../link.js";
import { routes } from "./state.js";
import { $, drawCode, explain, t, view } from "./ui.js";

/** Counts the waits started, so an older one stops when a newer view takes over. */
let watching = 0;

/** Not connected: carry on with a connection the app is still asking about, or offer one. */
export async function connect() {
  const code = await waitingCode();
  return code ? waitForApp(code) : offerPairing();
}

/**
 * First use, or the app no longer knows this extension (disconnected there, or another vault
 * is open): one button that sends the person to the app. The old connection key is dropped
 * only when they choose to connect again, never by itself.
 */
export async function offerPairing() {
  watching = 0;
  const known = Boolean(await loadKey());
  view("pair");
  $("pair").classList.remove("waiting");
  $("pair-title").textContent = t(known ? "pairAgainTitle" : "pairTitle");
  $("pair-text").textContent = t(known ? "pairAgainText" : "pairText");
  $("pair-code").hidden = true;
  $("pair-restart").hidden = true;
  const button = $("pair-button");
  button.hidden = false;
  button.textContent = t(known ? "pairAgainButton" : "pairButton");
  button.disabled = false;
  button.onclick = async () => {
    button.disabled = true;
    await dropKey();
    // The key and the code are kept before the app comes forward (which may close this
    // window); a connection the app then refuses leaves neither behind.
    const agreed = await agree(send, async (key, code) => {
      await saveKey(key);
      await startWaiting(code);
    });
    if (agreed.error) {
      await dropKey();
      return explain(agreed.error === "not_paired" ? "failed" : agreed.error);
    }
    waitForApp(agreed.code);
  };
  button.focus();
}

/**
 * The app has come forward and shows the same code, asking for the master password. Nothing
 * more to do here: this window asks again every second and carries on by itself once the app
 * has connected it.
 */
export function waitForApp(code) {
  view("pair");
  $("pair").classList.add("waiting");
  $("pair-title").textContent = t("pairWaitTitle");
  $("pair-text").textContent = t("pairWaitText");
  drawCode($("pair-code"), code);
  $("pair-code").hidden = false;
  $("pair-button").hidden = true;
  const restart = $("pair-restart");
  restart.textContent = t("pairRestart");
  restart.hidden = false;
  restart.onclick = () => offerPairing();
  const mine = ++watching;
  const look = async () => {
    if (mine !== watching) return;
    const reply = await ask({ type: "vault" });
    if (mine !== watching) return;
    if (reply.code === "not_paired" || reply.code === "locked") {
      return setTimeout(look, 1000);
    }
    watching = 0;
    await stopWaiting();
    routes.refresh();
  };
  setTimeout(look, 1000);
}

/** Stops waiting for the app (another view took over). */
export function stopWatching() {
  watching = 0;
}
