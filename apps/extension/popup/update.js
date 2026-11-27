// A newer version of this extension. The background worker learns of it and keeps
// `extensionUpdate: { version, manual }` in `chrome.storage.local`; this window says so at
// the top. Where the worker can put it in place itself (`manual: false`), one button asks it
// to; otherwise the steps are in Vault.

import { $, t } from "./ui.js";
import { updateNotice } from "./version.js";

export async function showUpdate() {
  const banner = $("update");
  let notice;
  try {
    const { extensionUpdate } = await chrome.storage.local.get("extensionUpdate");
    notice = updateNotice(extensionUpdate, chrome.runtime.getManifest().version);
  } catch {
    notice = undefined;
  }
  banner.hidden = !notice;
  if (!notice) return;
  $("update-text").textContent = t(notice.manual ? "updateManual" : "updateText", notice.version);
  const button = $("update-now");
  button.hidden = notice.manual;
  button.disabled = false;
  button.textContent = t("updateNow");
  button.onclick = async () => {
    button.disabled = true;
    button.textContent = t("updating");
    try {
      await chrome.runtime.sendMessage({ kind: "apply-update" });
    } catch {
      // The worker restarts the extension, which closes this window; nothing to wait for.
    }
  };
}
