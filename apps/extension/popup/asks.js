// What the app asks before it gives a login's secret to the browser, said before the person
// acts. A listing from the app (`logins`, `vault`) says what opens the logins it marks
// `locked`: Windows Hello (`hello`), else the item lock's PIN or password (`check`). With
// `always_asks`, the app asks for every password, code, fill and passkey the browser wants,
// each time; when it has nothing the browser may ask for (`check: "app"` and no Hello), it
// can't, and the person sets one up in Vault.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

/**
 * What giving out `entry`'s secret asks for: "none", "hello", "pin", "password", "setup"
 * (nothing the browser may ask for is set up in Vault) or "app" (only the master password
 * opens it, typed in the app).
 */
export function asksFor(entry, listing = {}) {
  if (!entry?.locked) return "none";
  if (listing?.hello) return "hello";
  if (listing?.check === "pin") return "pin";
  if (listing?.check === "password") return "password";
  return listing?.always_asks ? "setup" : "app";
}

/**
 * What a list of logins asks, for one line above it: the kind when every login asks the
 * same (`all`), or the kind the locked ones ask when only some do. `kind` is "none" when
 * none asks.
 */
export function listAsks(entries, listing = {}) {
  const kinds = (entries ?? []).map((entry) => asksFor(entry, listing));
  const locked = kinds.filter((kind) => kind !== "none");
  if (locked.length === 0) return { kind: "none", all: false };
  return { kind: locked[0], all: locked.length === kinds.length };
}

/**
 * What a refusal as `item_locked` means for the window: "prompt" (the PIN or item password
 * may be typed here), "setup" (the app asks before the browser gets anything and nothing is
 * set up for it), "hello" (Windows Hello was offered and didn't confirm) or "app" (only the
 * master password opens it). `undefined` for any other answer.
 */
export function refusal(reply, listing = {}) {
  if (reply?.code !== "item_locked") return undefined;
  if (reply.check === "pin" || reply.check === "password") return "prompt";
  if (listing?.hello) return "hello";
  return listing?.always_asks ? "setup" : "app";
}
