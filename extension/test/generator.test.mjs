// Tests for reading a site's password rules: `node --test extension/test/generator.test.mjs`.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fallbacks, parsePasswordRules, patternTest, rulesFor } from "../generator.js";

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
  assert.ok(patternTest("(?=.*\\d)(?=.*[a-z]).{8,}")("abc12345"), "an ordinary one still runs");
});

test("narrows step by step", () => {
  const steps = fallbacks({ length: 8, lower: true, upper: true, digits: true, symbols: true });
  assert.equal(steps.length, 4);
  assert.equal(steps[1].symbols, false);
  assert.deepEqual(steps[3], { length: 8, lower: false, upper: false, digits: true, symbols: false });
});
