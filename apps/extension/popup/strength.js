// The strength of a generated password, in a word, as the desktop app colours its meter:
// red below 50 bits, yellow below 70, green above. The app says how many bits; nothing is
// measured here.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

/** `level` (1–4 segments of the meter), the message key of its word, and its tone. */
export function strengthOf(bits) {
  const b = Number(bits) || 0;
  if (b < 50) return { level: 1, key: "strengthWeak", tone: "weak" };
  if (b < 70) return { level: 2, key: "strengthFair", tone: "fair" };
  if (b < 100) return { level: 3, key: "strengthStrong", tone: "good" };
  return { level: 4, key: "strengthVeryStrong", tone: "good" };
}
