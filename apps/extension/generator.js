// What a site's password field allows, turned into options for the app's generator.
//
// The passwords themselves are made by the desktop app (one generator, the one the app
// uses everywhere, and a history of the ones used). This file only reads the field —
// `maxlength`, `minlength`, `pattern` and the `passwordrules` attribute some sites publish
// for password managers — so the app's suggestion fits the site the first time, and checks
// the result against the field's pattern.

export const DEFAULT_LENGTH = 20;
const MIN_LENGTH = 4;
const MAX_LENGTH = 128;

/** Parses a `passwordrules` value: `minlength: 8; maxlength: 16; required: lower, upper; allowed: [-_]`. */
export function parsePasswordRules(text) {
  const rules = { required: new Set(), allowed: new Set(), extra: "" };
  if (typeof text !== "string") return rules;
  for (const part of text.split(";")) {
    const at = part.indexOf(":");
    if (at < 0) continue;
    const name = part.slice(0, at).trim().toLowerCase();
    const value = part.slice(at + 1).trim();
    if (name === "minlength" || name === "maxlength") {
      const n = parseInt(value, 10);
      if (n > 0) rules[name] = n;
    } else if (name === "required" || name === "allowed") {
      for (const token of value.match(/\[[^\]]*\]|[a-z-]+/gi) || []) {
        if (token.startsWith("[")) {
          rules.extra += token.slice(1, -1);
          rules[name].add("special");
        } else {
          rules[name].add(token.toLowerCase());
        }
      }
    }
  }
  return rules;
}

/**
 * Options for the app's generator (`{ length, lower, upper, digits, symbols }`, where
 * `symbols` is true, false or the symbols allowed) that fit a field described as
 * `{ maxLength, minLength, passwordRules }`. Unknown rules fall back to the defaults.
 */
export function rulesFor(field = {}) {
  const rules = parsePasswordRules(field.passwordRules);
  const kinds = new Set([...rules.required, ...rules.allowed]);
  const options = { lower: true, upper: true, digits: true, symbols: true };
  if (kinds.size > 0 && !kinds.has("ascii-printable") && !kinds.has("unicode")) {
    options.lower = kinds.has("lower");
    options.upper = kinds.has("upper");
    options.digits = kinds.has("digit");
    const listed = [...new Set(rules.extra)].filter((c) => /[!-/:-@[-`{-~]/.test(c)).join("");
    options.symbols = kinds.has("special") ? listed || true : false;
  }
  let max = MAX_LENGTH;
  let min = MIN_LENGTH;
  for (const value of [field.maxLength, rules.maxlength]) if (value > 0) max = Math.min(max, value);
  for (const value of [field.minLength, rules.minlength]) if (value > 0) min = Math.max(min, value);
  options.length = Math.max(MIN_LENGTH, Math.min(max, Math.max(min, DEFAULT_LENGTH)));
  return options;
}

/** The field's `pattern` as a test, or `undefined` when it has none or it doesn't compile. */
export function patternTest(pattern) {
  if (typeof pattern !== "string" || !pattern || pattern.length > 256) return undefined;
  // The pattern is the page's: one built to take forever (a repeated group that itself
  // repeats, a back-reference) is not run, it would stall the extension. The suggestion is
  // then made from the field's other rules alone.
  if (/[+*}]\??\)[+*{]|\\[1-9]|\\k</.test(pattern)) return undefined;
  try {
    const regex = new RegExp(`^(?:${pattern})$`, "v");
    return (password) => regex.test(password);
  } catch {
    return undefined;
  }
}

/**
 * Narrower and narrower options, for a field whose pattern the first suggestion missed:
 * without symbols, then letters and digits, then digits only.
 */
export function fallbacks(options) {
  return [
    options,
    { ...options, symbols: false },
    { ...options, lower: true, upper: true, digits: true, symbols: false },
    { ...options, lower: false, upper: false, digits: true, symbols: false },
  ];
}
