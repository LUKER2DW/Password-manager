// Tests for reading a site's password rules: `node --test apps/extension/test/generator.test.mjs`.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fallbacks, parsePasswordRules, patternTest, rulesFor, tame } from "../generator.js";

test("keeps within the field's length limits", () => {
  assert.equal(rulesFor({ maxLength: 12 }).length, 12);
  assert.equal(rulesFor({ minLength: 32 }).length, 32);
  assert.equal(rulesFor({ maxLength: 524288 }).length, 20);
  assert.equal(rulesFor({}).length, 20);
  assert.equal(rulesFor({ maxLength: 2 }).length, 4, "never below the generator's floor");
});

test("reads passwordrules", () => {
  const rules = parsePasswordRules("minlength: 10; maxlength: 14; required: lower; required: upper; required: digit; allowed: [-_.];");
  assert.equal(rules.minlength, 10);
  assert.equal(rules.maxlength, 14);
  assert.ok(rules.required.has("digit"));
  const options = rulesFor({ passwordRules: "minlength: 10; maxlength: 14; required: lower; required: upper; required: digit; allowed: [-_.];" });
  assert.deepEqual(options, { lower: true, upper: true, digits: true, symbols: "-_.", length: 14 });
  const noSymbols = rulesFor({ passwordRules: "required: lower; required: digit" });
  assert.equal(noSymbols.symbols, false);
  assert.equal(noSymbols.upper, false);
  assert.equal(rulesFor({ passwordRules: "required: special" }).symbols, true);
  assert.equal(rulesFor({ passwordRules: "allowed: ascii-printable" }).symbols, true);
});

test("checks the field's pattern, and ignores one that doesn't compile", () => {
  const test6 = patternTest("\\d{6}");
  assert.ok(test6("123456"));
  assert.ok(!test6("12345a"));
  assert.ok(!test6("1234567"), "the whole value must match");
  assert.equal(patternTest("(["), undefined);
  assert.equal(patternTest(""), undefined);
});

test("doesn't run a pattern that could take forever", () => {
  assert.equal(patternTest("(a+)+b"), undefined);
  assert.equal(patternTest("([a-z]*)*\\d"), undefined);
  assert.equal(patternTest("(?:\\w{2,})+!"), undefined);
  assert.equal(patternTest("(.)\\1"), undefined);
  assert.equal(patternTest("a".repeat(300)), undefined);
  assert.equal(patternTest("(a|a)+$"), undefined, "overlapping choices, repeated");
  assert.equal(patternTest("(.|.)*x"), undefined);
  assert.equal(patternTest("(?:ab){3,}"), undefined);
  assert.ok(patternTest("(?=.*\\d)(?=.*[a-z]).{8,}")("abc12345"), "an ordinary one still runs");
});

test("doesn't run many repeats in a row, and runs what only looks like them", () => {
  // No group at all, but the cost grows with the length to the power of the repeats.
  assert.equal(patternTest(`${".*".repeat(20)}é`), undefined);
  assert.equal(patternTest(`${"a*".repeat(30)}b`), undefined);
  assert.equal(patternTest(`${"a?".repeat(25)}${"a".repeat(25)}`), undefined, "optional ones count too");
  assert.equal(patternTest(`${".{0,40}".repeat(10)}x`), undefined, "bounded ones too");
  assert.equal(patternTest("(?=.*.*.*x).{8,}"), undefined, "inside a look-ahead as well");
  assert.equal(patternTest("(a|b)(c|d)(e|f)(g|h)x"), undefined, "choices multiply");
  assert.equal(patternTest("(abc)?d"), undefined, "an optional group");
  assert.equal(patternTest("\\k<x>(?<x>a)"), undefined);
  // Characters in a class or escaped are no repeat, and an exact count doesn't vary.
  assert.ok(tame("[()+*]{8,}"), "a class of symbols");
  // (The browser reads a pattern with the `v` flag, where `(` and `)` in a class are escaped.)
  const symbols = patternTest("[\\(\\)+*]{8,}");
  assert.ok(symbols);
  assert.ok(symbols("()+*()+*"));
  assert.ok(patternTest("\\*\\+\\?[a-z]{8}")("*+?abcdefgh"));
  assert.ok(patternTest("[\\p{L}\\d]{8,64}")("abcdefgh1"));
  // The usual ones: look-aheads each tried once, then one repeat.
  const usual = patternTest("(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9]).{8,64}");
  assert.ok(usual("aB3!aB3!"));
  assert.ok(!usual("abcdefgh"));
  assert.ok(patternTest("^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d@$!%*#?&]{8,}$")("abcd1234"));
  assert.ok(patternTest(".*[A-Z].*|\\d{6}")("123456"), "each alternative is a part of its own");
  // Never run on a password longer than the generator makes.
  assert.equal(patternTest(".*")("a".repeat(129)), false);
});

test("a pattern of many repeats is judged at once, without running it", () => {
  const started = performance.now();
  for (const pattern of [`${".*".repeat(20)}é`, `${"\\w*".repeat(40)}!`, `(?=${".*".repeat(10)}x)`]) {
    assert.equal(patternTest(pattern), undefined);
  }
  assert.ok(performance.now() - started < 50);
});

test("narrows step by step", () => {
  const steps = fallbacks({ length: 8, lower: true, upper: true, digits: true, symbols: true });
  assert.equal(steps.length, 4);
  assert.equal(steps[1].symbols, false);
  assert.deepEqual(steps[3], { length: 8, lower: false, upper: false, digits: true, symbols: false });
});
