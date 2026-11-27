// The extension window's own rules, apart from the page: the generator's live updates, how
// long a secret stays, how a shown secret is drawn, what a login will ask for, the
// strength word, the update notice, the tile colours and where a site's icon is looked for. Run: node --test apps/extension/test/popup.test.mjs

import assert from "node:assert/strict";
import test from "node:test";

import { listAsks, asksFor, refusal } from "../popup/asks.js";
import { cellsOf, codeGroups, kindOf, spacedCode } from "../popup/cells.js";
import { codeClock, secondsLeft, SHOW_FOR_MS } from "../popup/countdown.js";
import { canMake, generateRequest, keptOptions, separatorOf, startOptions } from "../popup/options.js";
import { strengthOf } from "../popup/strength.js";
import { throttleLatest } from "../popup/throttle.js";
import { iconPages } from "../popup/icon-pages.js";
import { hostKey, initial, tintOf } from "../popup/tint.js";
import { compareVersions, updateNotice } from "../popup/version.js";

const settle = () => new Promise((done) => setImmediate(done));

/** A clock and timers that only move when told. */
function fakeTime() {
  let now = 0;
  let timers = [];
  return {
    now: () => now,
    later: (fn, ms) => {
      const timer = { at: now + ms, fn };
      timers.push(timer);
      return timer;
    },
    cancel: (timer) => (timers = timers.filter((other) => other !== timer)),
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        const next = timers.filter((timer) => timer.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!next) break;
        timers = timers.filter((timer) => timer !== next);
        now = next.at;
        next.fn();
        await settle();
      }
      now = end;
      await settle();
    },
  };
}

// ---- the generator's live updates ----

test("a slider dragged fast asks at most once per interval, and always for its last value", async () => {
  const time = fakeTime();
  const asked = [];
  const shown = [];
  const live = throttleLatest({
    interval: 120,
    run: (value) => (asked.push(value), `password-${value}`),
    apply: (result) => shown.push(result),
    ...time,
  });
  // The first move asks at once.
  live.push(10);
  await settle();
  assert.deepEqual(asked, [10]);
  // Moves within the interval wait; only the newest is asked for when it ends.
  for (const value of [11, 12, 13, 14]) {
    await time.advance(20);
    live.push(value);
  }
  assert.deepEqual(asked, [10]);
  await time.advance(120);
  assert.deepEqual(asked, [10, 14]);
  // Released on a value: it is the last one asked for and the last one shown.
  live.push(15);
  await time.advance(200);
  assert.deepEqual(asked, [10, 14, 15]);
  assert.equal(shown.at(-1), "password-15");
  // About 8 a second at most, however many moves.
  const before = asked.length;
  for (let i = 0; i < 100; i++) {
    live.push(20 + i);
    await time.advance(10);
  }
  await time.advance(200);
  assert.ok(asked.length - before <= Math.ceil(1000 / 120) + 1, `asked ${asked.length - before} times`);
  assert.equal(asked.at(-1), 119);
  assert.equal(shown.at(-1), "password-119");
});

test("an answer that comes back after a newer one is dropped", async () => {
  const time = fakeTime();
  const answers = new Map();
  const shown = [];
  const live = throttleLatest({
    interval: 100,
    run: (value) => new Promise((resolve) => answers.set(value, resolve)),
    apply: (result) => shown.push(result),
    ...time,
  });
  live.push("a");
  await time.advance(100);
  live.push("b");
  await time.advance(100);
  // The newer answer first, the older one late.
  answers.get("b")("B");
  await settle();
  answers.get("a")("A");
  await settle();
  assert.deepEqual(shown, ["B"]);
});

test("a cancelled live update asks nothing more and shows nothing late", async () => {
  const time = fakeTime();
  let resolve;
  const asked = [];
  const shown = [];
  const live = throttleLatest({
    interval: 100,
    run: (value) => (asked.push(value), new Promise((done) => (resolve = done))),
    apply: (result) => shown.push(result),
    ...time,
  });
  live.push(1);
  await settle();
  live.push(2);
  live.cancel();
  await time.advance(500);
  resolve("late");
  await settle();
  assert.deepEqual(asked, [1]);
  assert.deepEqual(shown, []);
});

test("the generator's choices stay inside what the app accepts", () => {
  const options = startOptions();
  assert.deepEqual(generateRequest(options), {
    length: 20,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
    avoid_ambiguous: false,
  });
  assert.equal(generateRequest({ ...options, length: 500 }).length, 128);
  assert.equal(generateRequest({ ...options, length: 1 }).length, 4);
  assert.equal(generateRequest({ ...options, length: "abc" }).length, 20);
  const words = generateRequest({ ...options, words: true, count: 40, separator: "--==", capitalize: true });
  assert.deepEqual(words, { words: 20, separator: "--=", capitalize: true, number: false });
  assert.equal(generateRequest({ ...options, words: true, count: 1 }).words, 3);
  // Three characters, not three UTF-16 units; no line breaks.
  assert.equal(separatorOf("🔑🔑🔑🔑"), "🔑🔑🔑");
  assert.equal(separatorOf("a\nb"), "ab");
  assert.equal(canMake({ ...options, upper: false, lower: false, digits: false, symbols: false }), false);
  assert.equal(canMake({ ...options, words: true, upper: false, lower: false, digits: false, symbols: false }), true);
  // Kept choices from an earlier window: anything odd falls back.
  assert.deepEqual(keptOptions(undefined), options);
  const kept = keptOptions({ words: true, length: 999, count: "x", separator: 5, upper: "yes", symbols: false });
  assert.equal(kept.words, true);
  assert.equal(kept.length, 128);
  assert.equal(kept.count, 6);
  assert.equal(kept.separator, "-");
  assert.equal(kept.upper, true);
  assert.equal(kept.symbols, false);
});

// ---- how long a secret stays ----

test("a code goes back to dots when it runs out, and a secret never stays past 15 seconds", () => {
  assert.equal(SHOW_FOR_MS, 15_000);
  const clock = codeClock({ left: 9, period: 30 }, 1000);
  assert.equal(clock.until, 1000 + 9_000);
  assert.deepEqual(clock.at(1000), { seconds: 9, fraction: 9 / 30, expired: false });
  assert.deepEqual(clock.at(1000 + 8_500), { seconds: 1, fraction: 0.5 / 30, expired: false });
  assert.equal(clock.at(1000 + 9_000).expired, true);
  assert.equal(clock.at(1000 + 9_000).seconds, 0);
  // A code good for longer goes back to dots after 15 seconds all the same, and its clock
  // counts down to that.
  const long = codeClock({ left: 17, period: 30 }, 0);
  assert.equal(long.until, SHOW_FOR_MS);
  assert.equal(long.at(SHOW_FOR_MS).expired, true);
  assert.equal(long.at(0).seconds, 15);
  assert.equal(long.at(SHOW_FOR_MS - 1).seconds, 1);
  assert.equal(long.at(0).fraction, 15 / 30);
  // Nonsense from the app shows nothing for long.
  assert.equal(codeClock({ left: -5, period: 0 }, 0).at(0).expired, true);
  assert.equal(codeClock({}, 0).until, 0);
  assert.equal(secondsLeft(10_001, 0), 11);
  assert.equal(secondsLeft(0, 50), 0);
});

// ---- secrets as data ----

test("a shown password tells digits and symbols apart, character by character", () => {
  const cells = cellsOf("aZ3$ é🔑");
  assert.deepEqual(
    cells.map((cell) => [cell.char, cell.kind, cell.number]),
    [
      ["a", "lower", 1],
      ["Z", "upper", 2],
      ["3", "digit", 3],
      ["$", "symbol", 4],
      [" ", "space", 5],
      ["é", "lower", 6],
      ["🔑", "symbol", 7],
    ],
  );
  assert.equal(kindOf("-"), "symbol");
  assert.equal(cellsOf("x".repeat(128)).length, 128);
  assert.deepEqual(cellsOf(""), []);
});

test("the connection code is two groups of boxes, and a one-time code two halves", () => {
  assert.deepEqual(codeGroups("74At LSYM"), [
    ["7", "4", "A", "t"],
    ["L", "S", "Y", "M"],
  ]);
  assert.deepEqual(codeGroups("  74At   LSYM "), codeGroups("74At LSYM"));
  assert.deepEqual(codeGroups(""), []);
  assert.equal(spacedCode("932663"), "932 663");
  assert.equal(spacedCode("12345678"), "1234 5678");
  assert.equal(spacedCode("1234567"), "1234 567");
  assert.equal(spacedCode("1234"), "1234");
});

// ---- what a login asks ----

test("each login says what it will ask for before anything is done", () => {
  const open = { locked: false };
  const locked = { locked: true };
  assert.equal(asksFor(open, { hello: true }), "none");
  assert.equal(asksFor(locked, { hello: true, check: "pin" }), "hello");
  assert.equal(asksFor(locked, { hello: false, check: "pin" }), "pin");
  assert.equal(asksFor(locked, { hello: false, check: "password" }), "password");
  assert.equal(asksFor(locked, { hello: false, check: "app" }), "app");
  // The app asks before the browser gets anything, and nothing is set up for it.
  assert.equal(asksFor(locked, { hello: false, check: "app", always_asks: true }), "setup");
  assert.equal(asksFor(locked, undefined), "app");

  assert.deepEqual(listAsks([locked, locked], { hello: true }), { kind: "hello", all: true });
  assert.deepEqual(listAsks([open, locked], { check: "pin" }), { kind: "pin", all: false });
  assert.deepEqual(listAsks([open], { check: "pin" }), { kind: "none", all: false });
  assert.deepEqual(listAsks([], {}), { kind: "none", all: false });
});

test("a refusal says whether to ask for the PIN here, or what to do in Vault", () => {
  assert.equal(refusal({ code: "item_locked", check: "pin" }, {}), "prompt");
  assert.equal(refusal({ code: "item_locked", check: "password" }, {}), "prompt");
  assert.equal(refusal({ code: "item_locked", check: "app" }, { always_asks: true }), "setup");
  assert.equal(refusal({ code: "item_locked", check: "app" }, { always_asks: false }), "app");
  // Windows Hello was offered: it didn't confirm, which is not "nothing is set up".
  assert.equal(refusal({ code: "item_locked", check: "app" }, { always_asks: true, hello: true }), "hello");
  assert.equal(refusal({ code: "locked" }, {}), undefined);
  assert.equal(refusal(undefined, {}), undefined);
});

// ---- strength, update notice, tiles ----

test("strength in a word follows the desktop app's meter", () => {
  assert.deepEqual(strengthOf(30), { level: 1, key: "strengthWeak", tone: "weak" });
  assert.equal(strengthOf(49).level, 1);
  assert.equal(strengthOf(50).key, "strengthFair");
  assert.equal(strengthOf(70).key, "strengthStrong");
  assert.equal(strengthOf(129).key, "strengthVeryStrong");
  assert.equal(strengthOf(undefined).level, 1);
});

test("the update notice shows only for a newer version", () => {
  assert.equal(compareVersions("0.4.10", "0.4.9"), 1);
  assert.equal(compareVersions("0.4.7", "0.4.7"), 0);
  assert.equal(compareVersions("0.4", "0.4.1"), -1);
  assert.deepEqual(updateNotice({ version: "0.5.0", manual: false }, "0.4.7"), { version: "0.5.0", manual: false });
  assert.deepEqual(updateNotice({ version: "0.5.0", manual: true }, "0.4.7"), { version: "0.5.0", manual: true });
  // Without an explicit `manual: false`, no button that updates by itself.
  assert.deepEqual(updateNotice({ version: "0.5.0" }, "0.4.7"), { version: "0.5.0", manual: true });
  assert.equal(updateNotice({ version: "0.4.7", manual: false }, "0.4.7"), undefined);
  assert.equal(updateNotice({ version: "0.4.6" }, "0.4.7"), undefined);
  assert.equal(updateNotice({ version: "1.0.0-evil<script>" }, "0.4.7"), undefined);
  assert.equal(updateNotice(undefined, "0.4.7"), undefined);
  assert.equal(updateNotice({ version: 5 }, "0.4.7"), undefined);
});

test("a site's tile has the colour the desktop app gives it", () => {
  // FNV-1a, as apps/desktop/src/view.rs: the same key gives the same colour in any case.
  assert.equal(tintOf("github.com"), tintOf("GitHub.com"));
  // Known answers: FNV-1a 32-bit of "" and of "a".
  assert.equal(tintOf(""), 0x811c9dc5 % 8);
  assert.equal(tintOf("a"), 0xe40c292c % 8);
  for (const key of ["bank.example", "mail.example", "x", "ünïcode.example"]) {
    assert.ok(tintOf(key) >= 0 && tintOf(key) < 8);
  }
  assert.equal(hostKey("https://www.GitHub.com/login"), "github.com");
  assert.equal(hostKey("*.shop.example"), "shop.example");
  assert.equal(hostKey("user@mail.example/inbox"), "mail.example");
  assert.equal(hostKey("ftp://files.example"), "");
  assert.equal(initial("  github"), "G");
  assert.equal(initial("#1 bank"), "1");
  assert.equal(initial("éclair"), "É");
  assert.equal(initial("!!"), "•");
});

test("the in-page card and the passkey window colour a site as the window does", async () => {
  const { readFileSync } = await import("node:fs");
  for (const file of ["../inline.js", "../passkey.js"]) {
    const source = readFileSync(new URL(file, import.meta.url), "utf8").replaceAll("\r\n", "\n");
    const body = source.match(/function tintOf\(key\) \{[\s\S]*?\n\}/)[0];
    const copy = new Function(`${body}; return tintOf;`)();
    for (const key of ["github.com", "bank.example", "ünïcode.example", "日本.example", "🔑.example", ""]) {
      assert.equal(copy(key), tintOf(key), `${file}: ${key}`);
    }
  }
});

test("a site's icon is looked for under the pages the browser has most likely shown", () => {
  assert.deepEqual(iconPages("github.com", "https://github.com/login?return=1#top"), [
    "https://github.com/login",
    "https://github.com/",
    "https://www.github.com/",
  ]);
  // Another site in front is not asked about.
  assert.deepEqual(iconPages("github.com", "https://news.example/"), ["https://github.com/", "https://www.github.com/"]);
  assert.deepEqual(iconPages("https://www.bank.example/login", undefined), [
    "https://www.bank.example/login",
    "https://www.bank.example/",
    "https://bank.example/",
  ]);
  assert.deepEqual(iconPages("*.shop.example", ""), ["https://shop.example/", "https://www.shop.example/"]);
  assert.deepEqual(iconPages("localhost:8443", ""), ["https://localhost:8443/"]);
  assert.deepEqual(iconPages("ftp://files.example", ""), []);
  assert.deepEqual(iconPages("", "https://github.com/"), []);
  assert.ok(iconPages("a.example/x", "https://a.example/y").length <= 4);
});
