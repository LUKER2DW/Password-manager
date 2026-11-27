// The emergency kit's keys, refused in every page.
//
// The Secret Key and the recovery parts are typed into the app, never into a website: a page
// that asks for one is phishing for the second factor, the one thing that keeps a stolen
// master password from opening a copied vault file. They are recognised by their printed
// shape alone, with no secret here: a prefix (`S0` the Secret Key, `A0`, `B0` and `C0` the
// recovery parts, `R0` the Recovery Key of older kits), then Crockford Base32 characters in
// groups. The rule is the app's (crates/browser/src/kit.rs), so both refuse the same text:
// lower case, Crockford's aliases (`O` for `0`, `I` and `L` for `1`), spaces or no separators
// are the same key; the prefix and the end must stand apart; the bits that fill the key's last
// character are zero. No site is an exception.
//
// A classic script, loaded at document_start into the extension's isolated world of every
// https document (frames too), before any of the page's own scripts: its listeners on the
// window come first, so a key pasted or dropped is stopped before the page hears of it. A key
// typed by hand is taken out of the field as its last character comes (the page may have
// heard each key press before: typing it is the rarer way in, pasting it the usual one). Then
// the worker is told, and the extension's own frame in the page says why (content.js).

(() => {
  // How many data characters follow each prefix, and how many low bits of the last character
  // before the two of checksum are padding (always zero in a printed key).
  const SHAPES = { S0: [28, 2], A0: [28, 2], B0: [28, 2], C0: [28, 2], R0: [54, 4] };
  const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  // At most this many separators (dashes, spaces) between two characters of a key.
  const MAX_GAP = 3;
  // Only the first this many characters of a text are looked at: what a field holds.
  const MAX_SCANNED = 4096;

  // ASCII only, as the app's checks are (`is_ascii_alphanumeric`, `is_ascii_whitespace`).
  const alnum = (ch) => ch !== undefined && /^[0-9A-Za-z]$/.test(ch);
  const separator = (ch) => ch !== undefined && /^[- \t\n\f\r]$/.test(ch);
  /** A Crockford Base32 character's value, as the app reads it; `undefined` for any other. */
  function symbol(ch) {
    if (!alnum(ch)) return undefined;
    const upper = ch.toUpperCase();
    if (upper === "O") return 0;
    if (upper === "I" || upper === "L") return 1;
    const at = ALPHABET.indexOf(upper);
    return at >= 0 ? at : undefined;
  }

  /** Whether exactly `count` key characters follow `from`, padded as a printed key's are. */
  function fits(text, from, count, padding) {
    let at = from;
    const values = [];
    while (values.length < count) {
      const gapStart = at;
      while (at < text.length && separator(text[at])) at++;
      if (at - gapStart > MAX_GAP) return false;
      const value = symbol(text[at]);
      if (value === undefined) return false;
      values.push(value);
      at++;
    }
    // Not followed by another character of a key, right after or after one dash.
    if (alnum(text[at]) || (text[at] === "-" && alnum(text[at + 1]))) return false;
    return (values[count - 3] & ((1 << padding) - 1)) === 0;
  }

  /** Whether `text` holds one of the emergency kit's keys in its printed shape. */
  function holdsKitKey(text) {
    if (typeof text !== "string") return false;
    const scanned = text.slice(0, MAX_SCANNED);
    for (let start = 0; start + 1 < scanned.length; start++) {
      if (start > 0 && alnum(scanned[start - 1])) continue;
      const first = scanned[start];
      const shape = SHAPES[(first >= "a" && first <= "z" ? first.toUpperCase() : first) + scanned[start + 1]];
      if (shape && fits(scanned, start + 2, shape[0], shape[1])) return true;
    }
    return false;
  }

  globalThis.VaultKit = Object.freeze({ holdsKitKey });

  // ---- in the page ----

  if (typeof window === "undefined" || typeof chrome === "undefined") return;

  // Whether the browser can vouch for the extension's frame in a page (content.js): where it
  // can't (Firefox), the worker marks the toolbar button instead.
  const framed = typeof IntersectionObserverEntry === "function" && "isVisible" in IntersectionObserverEntry.prototype;
  /** Tells the worker, which has the page's own frame say why (at most once a second). */
  let toldAt = -Infinity;
  function refused(how) {
    const now = performance.now();
    if (now - toldAt < 1000) return;
    toldAt = now;
    try {
      chrome.runtime.sendMessage({ kind: "kit-refused", how, framed }).catch(() => {});
    } catch {
      // The extension was reloaded or updated: the key was refused all the same.
    }
  }

  const stop = (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
  };
  const textField = (el) => el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT");
  /** Empties a field as typing would, so the page's own copy of its value follows. */
  function empty(field) {
    const proto = field.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(field, "");
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
  }
  /** What a field would hold once `data` is typed over its selection. */
  function after(field, data) {
    const value = field.value ?? "";
    try {
      const start = field.selectionStart ?? value.length;
      const end = field.selectionEnd ?? start;
      return value.slice(0, start) + data + value.slice(end);
    } catch {
      // Fields without a selection (email, number): typed at the end.
      return value + data;
    }
  }

  const options = { capture: true };
  window.addEventListener(
    "paste",
    (event) => {
      if (event.isTrusted && holdsKitKey(event.clipboardData?.getData("text/plain"))) {
        stop(event);
        refused("pasted");
      }
    },
    options,
  );
  window.addEventListener(
    "drop",
    (event) => {
      if (event.isTrusted && holdsKitKey(event.dataTransfer?.getData("text/plain"))) {
        stop(event);
        refused("pasted");
      }
    },
    options,
  );
  window.addEventListener(
    "beforeinput",
    (event) => {
      if (!event.isTrusted) return;
      const field = event.target;
      const data = typeof event.data === "string" ? event.data : event.dataTransfer?.getData("text/plain");
      if (typeof data !== "string" || !data) return;
      const whole = textField(field) ? after(field, data) : data;
      if (!holdsKitKey(whole)) return;
      stop(event);
      if (textField(field)) empty(field);
      refused(event.inputType === "insertText" ? "typed" : "pasted");
    },
    options,
  );
  // Whatever got a key into a field another way (an input method, another extension).
  window.addEventListener(
    "input",
    (event) => {
      const field = event.target;
      if (!event.isTrusted || !textField(field) || !holdsKitKey(field.value)) return;
      event.stopImmediatePropagation();
      empty(field);
      refused("typed");
    },
    options,
  );
})();
