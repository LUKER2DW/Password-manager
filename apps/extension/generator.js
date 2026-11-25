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

// How much backtracking a page's pattern may cause, judged before it is run. The browser's
// regular expressions backtrack without limit: a group that repeats (`(a+)+`), a
// back-reference, or many repeats in a row (`.*.*.*…x`, whose cost grows with the password's
// length to the power of their number) would stall the extension's worker, and every tab with
// it. So a pattern is run only when it is plainly cheap:
// - no group that repeats or is optional (`(…)+`, `(…)*`, `(…){2,}`, `(…)?`), no
//   back-reference;
// - in each part, at most two repeats of variable length (`*`, `+`, `?`, `{2,}`, `{2,8}`)
//   and at most three `|` choices. A part is each alternative of the whole pattern, and each
//   look-ahead it starts with (`(?=.*\d)(?=.*[a-z]).{8,}` is three parts of one repeat
//   each): those are tried once, one after the other, so their costs add up instead of
//   multiplying.
// What sits in a character class (`[()+*]`) or is escaped (`\*`, `\p{L}`) is no repeat.
const REPEATS_PER_PART = 2;
const CHOICES_PER_PART = 3;
/** The longest password tested against a page's pattern (the generator's own limit). */
const TESTED_LENGTH = 128;

/** Whether `pattern` is cheap enough to run (see above). */
export function tame(pattern) {
  const parts = [];
  const part = () => parts.push({ repeats: 0, choices: 0 }) - 1;
  let body = part();
  // Still at the start of an alternative of the whole pattern: a look-ahead there is a part.
  let leading = true;
  const open = [];
  const counted = () => (open.length > 0 ? open[open.length - 1] : body);
  /** The repeat that starts at `at`: its length and whether it varies, or `undefined`. */
  const repeat = (at) => {
    let length;
    let varies = true;
    if ("*+?".includes(pattern[at])) length = 1;
    else if (pattern[at] === "{") {
      const bounds = /^\{(\d+)(,(\d*))?\}/.exec(pattern.slice(at));
      if (!bounds) return undefined;
      length = bounds[0].length;
      varies = bounds[2] !== undefined && bounds[3] !== bounds[1];
    } else return undefined;
    if (pattern[at + length] === "?") length++;
    return { length, varies };
  };
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "\\") {
      const next = pattern[i + 1];
      // A back-reference (`\1`, `\k<name>`), or a pattern that ends in the middle of one.
      if (next === undefined || /[1-9k]/.test(next)) return false;
      if ("pPu".includes(next) && pattern[i + 2] === "{") {
        const end = pattern.indexOf("}", i + 2);
        if (end < 0) return false;
        i = end + 1;
      } else i += 2;
      if (open.length === 0) leading = false;
      continue;
    }
    if (c === "[") {
      // A class, maybe with classes inside it (`[[a-z]--[aeiou]]`): one character.
      let depth = 0;
      for (; i < pattern.length; i++) {
        if (pattern[i] === "\\") i++;
        else if (pattern[i] === "[") depth++;
        else if (pattern[i] === "]" && --depth === 0) break;
      }
      if (depth !== 0) return false;
      i++;
      if (open.length === 0) leading = false;
      continue;
    }
    if (c === "(") {
      const ahead = pattern.startsWith("(?=", i) || pattern.startsWith("(?!", i);
      let owner = counted();
      if (open.length === 0) {
        if (ahead && leading) owner = part();
        else leading = false;
      }
      open.push(owner);
      // Past what names the group: `(`, `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, `(?<name>`, `(?i:`.
      if (pattern[i + 1] !== "?") i += 1;
      else if (pattern.startsWith("(?<=", i) || pattern.startsWith("(?<!", i)) i += 4;
      else if (pattern[i + 2] === "<") {
        const end = pattern.indexOf(">", i);
        if (end < 0) return false;
        i = end + 1;
      } else if (":=!".includes(pattern[i + 2])) i += 3;
      else {
        const end = pattern.indexOf(":", i);
        if (end < 0) return false;
        i = end + 1;
      }
      continue;
    }
    if (c === ")") {
      if (open.length === 0) return false;
      open.pop();
      i++;
      // A group that repeats, or may be left out: each try of it multiplies the others.
      if (repeat(i)) return false;
      continue;
    }
    if (c === "|") {
      if (open.length === 0) {
        body = part();
        leading = true;
      } else parts[counted()].choices++;
      i++;
      continue;
    }
    const repeats = repeat(i);
    if (repeats) {
      if (repeats.varies) parts[counted()].repeats++;
      i += repeats.length;
      continue;
    }
    // An anchor keeps the start of the alternative; any other character ends it.
    if (open.length === 0 && c !== "^" && c !== "$") leading = false;
    i++;
  }
  return open.length === 0 && parts.every((one) => one.repeats <= REPEATS_PER_PART && one.choices <= CHOICES_PER_PART);
}

/** The field's `pattern` as a test, or `undefined` when it has none or it doesn't compile. */
export function patternTest(pattern) {
  if (typeof pattern !== "string" || !pattern || pattern.length > 256) return undefined;
  // The pattern is the page's: one that could take long (see `tame`) is not run. The
  // suggestion is then made from the field's other rules alone.
  if (!tame(pattern)) return undefined;
  try {
    const regex = new RegExp(`^(?:${pattern})$`, "v");
    return (password) => typeof password === "string" && password.length <= TESTED_LENGTH && regex.test(password);
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
