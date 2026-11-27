// The extension's own settings: whether Vault offers to save passwords instead of the browser
// (the browser's "Offer to save passwords and passkeys" is then off, and its settings say
// this extension controls it; turned off, Vault keeps and offers nothing typed into sign-in
// forms, see app.js), and whether Vault keeps passkeys. Back goes to where the person was.

import { dropPendingSaves, vaultSaves } from "../app.js";
import { here } from "./state.js";
import { $, t, view } from "./ui.js";

export async function showPrefs(back) {
  view("prefs", "foot");
  $("prefs-title").textContent = t("prefsTitle");
  $("prefs-back-text").textContent = t("backButton");
  $("prefs-back").onclick = back;
  $("prefs-saving-label").textContent = t("prefsSaving");
  $("prefs-saving-hint").textContent = t("prefsSavingHint");
  $("prefs-passkeys-label").textContent = t("prefsPasskeys");
  $("prefs-passkeys-hint").textContent = t("prefsPasskeysHint");
  $("prefs-app").textContent = t("prefsInApp");
  $("prefs-version").textContent = t("prefsVersion", chrome.runtime.getManifest().version);
  const passkeys = $("prefs-passkeys");
  chrome.storage.local.get("vaultPasskeys").then(({ vaultPasskeys = true }) => {
    passkeys.checked = vaultPasskeys;
  });
  passkeys.onchange = () => chrome.storage.local.set({ vaultPasskeys: passkeys.checked });
  const box = $("prefs-saving");
  const state = $("prefs-saving-state");
  const saving = chrome.privacy.services.passwordSavingEnabled;
  const mine = (details) =>
    ["controllable_by_this_extension", "controlled_by_this_extension"].includes(details.levelOfControl);
  // The box is what Vault does with what is typed into sign-in forms, whoever holds the
  // browser's own setting; the line under it says when that one isn't Vault's to turn off.
  const refresh = async () => {
    const details = await saving.get({});
    box.checked = await vaultSaves();
    state.textContent = mine(details)
      ? ""
      : t(details.levelOfControl === "not_controllable" ? "prefsSavingPolicy" : "prefsSavingOther");
  };
  box.onchange = async () => {
    await chrome.storage.local.set({ vaultSaves: box.checked });
    if (!box.checked) {
      // Off: an offer still waiting goes, here and in the page.
      here.pending = undefined;
      await dropPendingSaves();
    }
    if (mine(await saving.get({}))) {
      if (box.checked) await saving.set({ value: false });
      else await saving.clear({});
    }
    await refresh();
  };
  await refresh();
}
