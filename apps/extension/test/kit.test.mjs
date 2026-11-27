// Tests for the emergency kit's keys refused in pages (kit.js): `node --test apps/extension/test`.
// kit.js runs in a sandbox with a stand-in window and fields; no browser and no packages are
// needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const SCRIPT = readFileSync(new URL("../kit.js", import.meta.url), "utf8");

// Keys made for these tests from obvious test bytes (0x00, 0x01, …), with real checksums: the
// same list as crates/browser/tests/kit.rs, which checks that vault_core reads each one and that
// the app's own check (vault_browser::kit) recognises it.
const KEYS = [
  "S0-000G40R-40M30E2-09185GR-38E1WMT",
  "S0-MPHAQC5-SGT7S97-CTWFMF3-ZP7SGX4",
  "A0-208H44R-M2MB1E6-0S38DHR-78Y3WKG",
  "B0-40GJ48S-44MK2EA-1958NJR-B9E5W0M",
  "C0-60RK4CS-M6MV3EE-1S78XKR-F9Y7WEV",
  "R0-001GC2-8C1W91-A60V3R-GJ89SA-5MR36D-HS7GZM-4HA89D-752N2Q-B9EGYV",
];

/** A field of the stand-in page: its value behind the prototype's setter, as in a browser. */
class HTMLInputElement {
  constructor(props = {}) {
    Object.assign(this, { tagName: "INPUT", type: "text", events: [], ...props });
    this.stored = props.value ?? "";
    if (this.selectionStart === undefined) this.selectionStart = this.stored.length;
    if (this.selectionEnd === undefined) this.selectionEnd = this.selectionStart;
  }
  get value() {
    return this.stored;
  }
  set value(text) {
    this.stored = text;
  }
  dispatchEvent(event) {
    this.events.push(event.type);
  }
}
// A browser's text area has a `value` of its own prototype's, as here.
class HTMLTextAreaElement extends HTMLInputElement {
  get value() {
    return this.stored;
  }
  set value(text) {
    this.stored = text;
  }
}

/** kit.js in a fresh sandbox: its listeners on the window, and what it told the worker. */
function load({ page = true } = {}) {
  const listeners = {};
  const told = [];
  let now = 5000;
  const sandbox = {
    performance: { now: () => now },
    Event: class {
      constructor(type) {
        this.type = type;
      }
    },
    HTMLInputElement,
    HTMLTextAreaElement,
  };
  if (page) {
    sandbox.window = { addEventListener: (type, listener, options) => (listeners[type] ||= []).push({ listener, options }) };
    sandbox.chrome = { runtime: { sendMessage: async (message) => told.push(message) } };
  }
  vm.createContext(sandbox);
  vm.runInContext(SCRIPT, sandbox);
  /** Sends a trusted event to kit.js; returns what it did with it. */
  const fire = (type, details) => {
    const event = { type, isTrusted: true, prevented: false, stopped: false, ...details };
    event.preventDefault = () => (event.prevented = true);
    event.stopImmediatePropagation = () => (event.stopped = true);
    for (const { listener } of listeners[type] ?? []) listener(event);
    return event;
  };
  // What was told, as plain objects of this realm.
  const heard = () => told.map((message) => ({ ...message }));
  return { holdsKitKey: sandbox.VaultKit.holdsKitKey, listeners, heard, told, fire, later: (ms) => (now += ms) };
}

const clipboard = (text) => ({ getData: (kind) => (kind === "text/plain" ? text : "") });

test("every key of the kit is recognised, however it is written", () => {
  const { holdsKitKey } = load({ page: false });
  for (const key of KEYS) {
    for (const written of [
      key,
      key.toLowerCase(),
      key.replaceAll("-", " "),
      key.replaceAll("-", ""),
      key.replaceAll("-", " - "),
      `My Secret Key is ${key}, please check`,
      `${key}\n`,
      `("${key}")`,
      // Crockford's aliases: O for 0 (not in the prefix), I or L for 1.
      key.slice(0, 2) + key.slice(2).replaceAll("0", "O").replaceAll("1", "l"),
    ]) {
      assert.ok(holdsKitKey(written), written);
    }
  }
});

test("other text is not a key of the kit", () => {
  const { holdsKitKey } = load({ page: false });
  const key = KEYS[0];
  const groups = key.slice(2);
  for (const text of [
    "",
    "S0",
    "hunter2",
    "correct horse battery staple",
    // A TOTP secret and a token, which look a little alike.
    "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    `tok_9f8s${key.replaceAll("-", "")}`,
    // Another prefix, a letter for its zero, or glued to what is before.
    `D0${groups}`,
    `SO${groups}`,
    `XS0${groups}`,
    `1${key}`,
    // A character short, or one more after it.
    key.slice(0, -1),
    `${key}A`,
    `${key}-A`,
    // U is not a Crockford character; a non-ASCII letter is none either.
    `S0-UUUUUUU${groups.slice(8)}`,
    `S0-ııııııı${groups.slice(8)}`,
    // Too many separators between two characters.
    key.replace("-", "----"),
    // A long-s for the S of the prefix.
    `ſ0${groups}`,
  ]) {
    assert.ok(!holdsKitKey(text), text);
  }
  // The bits that fill a key's last character are zero in every printed key.
  const bare = key.replaceAll("-", "");
  assert.ok(!holdsKitKey(`${bare.slice(0, 27)}Z${bare.slice(28)}`));
  assert.ok(!holdsKitKey(42));
});

test("a key pasted or dropped anywhere in a page is stopped before the page hears of it", () => {
  const kit = load();
  // Listened to on the window, in the capture phase: before any of the page's listeners.
  for (const type of ["paste", "drop", "beforeinput", "input"]) {
    assert.equal(kit.listeners[type]?.[0]?.options?.capture, true, type);
  }
  const field = new HTMLInputElement({ type: "password" });
  const pasted = kit.fire("paste", { target: field, clipboardData: clipboard(`key: ${KEYS[2]}`) });
  assert.ok(pasted.prevented && pasted.stopped);
  assert.deepEqual(kit.heard(), [{ kind: "kit-refused", how: "pasted", framed: false }], "nothing of the key is told");
  kit.later(2000);
  const dropped = kit.fire("drop", { target: field, dataTransfer: clipboard(KEYS[5]) });
  assert.ok(dropped.prevented && dropped.stopped);
  assert.equal(kit.told.length, 2);
  // Anything else is left alone, and so is what a page script made up.
  const other = kit.fire("paste", { target: field, clipboardData: clipboard("an ordinary password") });
  assert.ok(!other.prevented && !other.stopped);
  const madeUp = kit.fire("paste", { target: field, isTrusted: false, clipboardData: clipboard(KEYS[0]) });
  assert.ok(!madeUp.prevented);
  assert.equal(kit.told.length, 2);
});

test("a key typed by hand is taken out of the field as its last character comes", () => {
  const kit = load();
  const key = KEYS[0];
  const field = new HTMLInputElement({ value: key.slice(0, -2) });
  // Typing an earlier character is nothing (the browser then puts it in).
  const early = kit.fire("beforeinput", { target: field, inputType: "insertText", data: key.at(-2) });
  assert.ok(!early.prevented);
  field.value = key.slice(0, -1);
  field.selectionStart = field.selectionEnd = field.value.length;
  const last = kit.fire("beforeinput", { target: field, inputType: "insertText", data: key.slice(-1) });
  assert.ok(last.prevented && last.stopped);
  assert.equal(field.value, "", "emptied");
  assert.deepEqual(field.events, ["input", "change"], "as the page's own copy needs to hear");
  assert.deepEqual(kit.heard(), [{ kind: "kit-refused", how: "typed", framed: false }]);
  // Typed in the middle: what the field would hold counts.
  kit.later(2000);
  const middle = new HTMLTextAreaElement({ tagName: "TEXTAREA", value: `${key.slice(0, 10)}${key.slice(11)}`, selectionStart: 10 });
  assert.ok(kit.fire("beforeinput", { target: middle, inputType: "insertText", data: key[10] }).prevented);
  assert.equal(middle.value, "");
  // Got there another way (an input method, another extension): taken out all the same.
  kit.later(2000);
  const other = new HTMLInputElement({ value: key });
  assert.ok(kit.fire("input", { target: other }).stopped);
  assert.equal(other.value, "");
  assert.equal(kit.told.length, 3);
  // Told at most once a second, however often it happens.
  kit.fire("input", { target: new HTMLInputElement({ value: key }) });
  assert.equal(kit.told.length, 3);
});
