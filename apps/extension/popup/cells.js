// Secrets shown as data: a shown or generated password with its digits and symbols in colours
// of their own, so it can be read out or typed on another device; the connection code one
// character to a box, in its two groups, as the emergency kit prints a key; a one-time code
// in two halves.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

/** What kind of character `ch` is: "upper", "lower", "digit", "space" or "symbol". */
export function kindOf(ch) {
  if (/^[0-9]$/.test(ch)) return "digit";
  if (ch === " ") return "space";
  if (/^\p{Lu}$/u.test(ch)) return "upper";
  if (/^\p{L}$/u.test(ch)) return "lower";
  if (/^\p{N}$/u.test(ch)) return "digit";
  return "symbol";
}

/** The characters of `text` (not UTF-16 units), each with its kind, numbered from 1. */
export function cellsOf(text) {
  return Array.from(String(text ?? ""), (char, i) => ({ char, kind: kindOf(char), number: i + 1 }));
}

/**
 * The connection code's groups, one box per character: "74At LSYM" → [["7","4","A","t"],
 * ["L","S","Y","M"]]. Split on spaces, as the app writes it.
 */
export function codeGroups(code) {
  return String(code ?? "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((group) => Array.from(group));
}

/** A one-time code in two halves, as the apps show it: "932663" → "932 663". */
export function spacedCode(code) {
  const digits = Array.from(String(code ?? "").replace(/\s+/g, ""));
  if (digits.length < 6) return digits.join("");
  const half = Math.ceil(digits.length / 2);
  return `${digits.slice(0, half).join("")} ${digits.slice(half).join("")}`;
}
