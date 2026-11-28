// A site's word about its passkeys through the WebAuthn Signal API (F23), as the worker passes
// it to the app: checked and bounded here, on its own so it can be tested apart. The app notes
// it on the passkeys concerned; the person decides on the item's page.

/**
 * The page's word about its passkeys (the Signal API, F23), checked and bounded, for the app:
 * it notes it on the passkeys concerned for the person to decide, and changes nothing itself.
 */
export function signalRequest(url, signal) {
  const str = (value, max) => (typeof value === "string" && value.length <= max ? value : "");
  const kinds = { unknown: "unknown", accepted: "accepted", details: "details" };
  const kind = kinds[signal?.kind];
  if (!kind) return undefined;
  const request = { type: "passkey_signal", url, rp_id: str(signal.rpId, 253), signal: kind };
  if (kind === "unknown") {
    request.credential = str(signal.credentialId, 1400);
    if (!request.credential) return undefined;
  } else {
    request.user_id = str(signal.userId, 100);
    if (!request.user_id) return undefined;
  }
  if (kind === "accepted") {
    if (!Array.isArray(signal.accepted)) return undefined;
    request.accepted = signal.accepted.slice(0, 65).map((id) => str(id, 1400)).filter(Boolean);
  }
  if (kind === "details") {
    request.name = str(signal.name, 256);
    request.display_name = str(signal.displayName, 256);
  }
  return request;
}
