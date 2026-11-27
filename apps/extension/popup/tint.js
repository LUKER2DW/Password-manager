// The letter tile in front of a login without an icon: its initial on a colour hashed from
// its site, the same colour the desktop app gives it (apps/desktop/src/view.rs `tint`: FNV-1a
// over the lowercased key, eight colours), so a service looks alike in every app.
// inline.js and passkey.js carry the same few lines (they run without imports).
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

export const TINTS = 8;

/** Which of the eight colours (0–7) belongs to `key`. */
export function tintOf(key) {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(String(key ?? "").toLowerCase())) {
    hash = Math.imul(hash ^ byte, 0x01000193) >>> 0;
  }
  return hash % TINTS;
}

/** The host a saved website stands for, as the desktop app keys its colour ("www." dropped). */
export function hostKey(site) {
  let rest = String(site ?? "").trim();
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(rest);
  if (scheme) {
    if (!/^https?$/i.test(scheme[1])) return "";
    rest = rest.slice(scheme[0].length);
  }
  rest = rest.split(/[/?#]/)[0];
  rest = rest.slice(rest.lastIndexOf("@") + 1).toLowerCase();
  return rest.replace(/^\*\./, "").replace(/^www\./, "");
}

/** The tile's letter: the title's first letter or digit, upper-cased ("•" when none). */
export function initial(title) {
  const found = Array.from(String(title ?? "")).find((ch) => /[\p{L}\p{N}]/u.test(ch));
  return found ? found.toUpperCase() : "•";
}
