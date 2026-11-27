// Live updates from a control that moves fast (the generator's length slider): the app is
// asked at most once every `interval` milliseconds, always for the newest value, and the last
// value given is always asked for in the end. Answers can come back out of order; one older
// than the answer already shown is dropped, so what is shown never goes back.
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

/**
 * `run(value)` asks (and may return a promise); `apply(result, value)` shows an answer.
 * `now`, `later` and `cancel` are the clock and timers (stand-ins in tests).
 * Returns `push(value)`, to call on every move, and `cancel()` to drop what is still waiting.
 */
export function throttleLatest({
  interval,
  run,
  apply,
  now = () => Date.now(),
  later = (fn, ms) => setTimeout(fn, ms),
  cancel = (id) => clearTimeout(id),
}) {
  let lastRun = -Infinity;
  let timer;
  let waiting = false;
  let value;
  let asked = 0;
  let shown = 0;

  const fire = () => {
    timer = undefined;
    if (!waiting) return;
    waiting = false;
    const mine = ++asked;
    const given = value;
    lastRun = now();
    Promise.resolve()
      .then(() => run(given))
      .then(
        (result) => {
          // An answer to an older value, after a newer one was shown: dropped.
          if (mine <= shown) return;
          shown = mine;
          apply(result, given);
        },
        () => {},
      );
  };

  return {
    push(next) {
      value = next;
      waiting = true;
      if (timer !== undefined) return;
      const wait = lastRun + interval - now();
      if (wait <= 0) fire();
      else timer = later(fire, wait);
    },
    cancel() {
      if (timer !== undefined) cancel(timer);
      timer = undefined;
      waiting = false;
      // Answers still on their way are not shown either.
      shown = asked;
    },
  };
}
