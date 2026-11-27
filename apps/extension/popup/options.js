// The generator's choices, as the app takes them in a `generate` request. The app clamps
// them too (length 4–128, words 3–20, a separator of at most 3 characters); the window keeps
// its controls inside the same bounds so what it shows is what the app makes.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

export const LENGTH = { min: 4, max: 128, start: 20 };
export const WORDS = { min: 3, max: 20, start: 6 };
export const SEPARATOR_MAX = 3;

const clamp = (value, { min, max, start }) => {
  const n = Math.round(Number(value));
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : start;
};

/** The choices a window starts with. */
export function startOptions() {
  return {
    words: false,
    length: LENGTH.start,
    count: WORDS.start,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
    avoid_ambiguous: false,
    separator: "-",
    capitalize: false,
    number: false,
  };
}

/** Choices kept from an earlier window, made safe: anything unknown or out of bounds is reset. */
export function keptOptions(kept) {
  const options = startOptions();
  if (!kept || typeof kept !== "object") return options;
  for (const name of ["words", "upper", "lower", "digits", "symbols", "avoid_ambiguous", "capitalize", "number"]) {
    if (typeof kept[name] === "boolean") options[name] = kept[name];
  }
  if (kept.length !== undefined) options.length = clamp(kept.length, LENGTH);
  if (kept.count !== undefined) options.count = clamp(kept.count, WORDS);
  if (typeof kept.separator === "string") options.separator = separatorOf(kept.separator);
  return options;
}

/** At most three characters (not UTF-16 units); line breaks and tabs are left out. */
export function separatorOf(text) {
  return Array.from(String(text ?? "").replace(/[\r\n\t]/g, ""))
    .slice(0, SEPARATOR_MAX)
    .join("");
}

/** Whether these choices can make anything: at least one kind of character, in that mode. */
export function canMake(options) {
  return options.words || options.upper || options.lower || options.digits || options.symbols;
}

/** The `generate` request's fields for these choices. */
export function generateRequest(options) {
  if (options.words) {
    return {
      words: clamp(options.count, WORDS),
      separator: separatorOf(options.separator),
      capitalize: Boolean(options.capitalize),
      number: Boolean(options.number),
    };
  }
  return {
    length: clamp(options.length, LENGTH),
    upper: Boolean(options.upper),
    lower: Boolean(options.lower),
    digits: Boolean(options.digits),
    symbols: Boolean(options.symbols),
    avoid_ambiguous: Boolean(options.avoid_ambiguous),
  };
}
