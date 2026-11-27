// How long a secret stays on screen. A shown password goes back to dots after SHOW_FOR_MS (15
// seconds, as in the desktop app); a one-time code goes when it runs out, and never later
// than SHOW_FOR_MS either. Neither comes back by itself: showing again asks again (the PIN, or
// Windows Hello where the app offers it), so it is the person's click.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

export const SHOW_FOR_MS = 15_000;

/** Whole seconds left until `until` (rounded up, never below zero). */
export function secondsLeft(until, now) {
  return Math.max(0, Math.ceil((until - now) / 1000));
}

/**
 * The clock of a code the app answered with `{ left, period }` at `shownAt` (milliseconds):
 * when it goes back to dots (`until`: when it runs out, 15 seconds at most), and at any time
 * `now` the seconds until then, that time as a part of the code's period (1 → 0, for the
 * ring) and whether it is hidden by now.
 */
export function codeClock({ left, period }, shownAt) {
  const validFor = Math.max(0, Number(left) || 0) * 1000;
  const span = Math.max(1, Number(period) || 30) * 1000;
  const until = shownAt + Math.min(validFor, SHOW_FOR_MS);
  return {
    until,
    at(now) {
      const shownFor = Math.max(0, until - now);
      return {
        seconds: Math.ceil(shownFor / 1000),
        fraction: Math.min(1, shownFor / span),
        expired: now >= until,
      };
    },
  };
}
