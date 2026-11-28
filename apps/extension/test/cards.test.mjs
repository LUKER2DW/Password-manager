// Tests for cards in pages (F5), the site's rules as the window reads them (F16) and a site's
// word about its passkeys (F23): `node --test apps/extension/test/cards.test.mjs`. A few plain
// objects stand in for the page; no browser and no packages are needed.

import assert from "node:assert/strict";
import { test } from "node:test";

// app.js reaches the browser only when asked: nothing here asks.
globalThis.chrome = { runtime: { getManifest: () => ({ version: "0.4.8" }) } };

const { cardFieldsHere, fillCard } = await import("../card-fill.js");
const { cardTargets, siteKey } = await import("../cards.js");
const { ruleOf, ruleRequest } = await import("../popup/site-rule.js");
const { signalRequest } = await import("../signals.js");

class Event {
  constructor(type) {
    this.type = type;
  }
}

class Field {
  constructor({ tag = "INPUT", type = "text", attributes = {}, options, form = null, shown = true, name = "", id = "" }) {
    Object.assign(this, { tagName: tag, type, attributes, form, shown, name, id, disabled: false, readOnly: false });
    this.text = "";
    this.events = [];
    if (options) this.options = options.map((value) => ({ value, textContent: value }));
  }
  get value() {
    return this.text;
  }
  set value(text) {
    this.text = text;
  }
  getAttribute(name) {
    return this.attributes[name] ?? null;
  }
  getBoundingClientRect() {
    return this.shown ? { width: 200, height: 30 } : { width: 0, height: 0 };
  }
  focus() {}
  dispatchEvent(event) {
    this.events.push(event.type);
  }
}

/** A fake document of `origin` with `fields`; `sandboxed`: its own origin is "null". */
function page(fields, { origin = "https://pay.example", sandboxed = false } = {}) {
  const made = fields.map((field) => new Field(field));
  const window = {
    location: { origin, href: `${origin}/checkout` },
    origin: sandboxed ? "null" : origin,
    HTMLInputElement: Field,
    Element: { prototype: { getAttribute(name) { return this.getAttribute(name); } } },
    getComputedStyle: () => ({ display: "block", visibility: "visible" }),
  };
  Object.assign(globalThis, {
    window,
    document: { baseURI: window.location.href, querySelectorAll: () => made },
    Event,
  });
  return made;
}

const CARD = { holder: "Test Person", number: "4242424242424242", month: 3, year: 2031, security_code: "123" };

test("payment fields are found by their autofill marks and their names", () => {
  page([
    { attributes: { autocomplete: "cc-number" } },
    { attributes: { autocomplete: "cc-exp" } },
    { attributes: { autocomplete: "cc-csc" } },
    { name: "cardholder" },
    { name: "email" },
    { name: "search", attributes: { placeholder: "Search" } },
    { name: "cardnumber", shown: false },
  ]);
  const found = cardFieldsHere();
  assert.deepEqual(found.kinds, { number: 1, exp: 1, csc: 1, name: 1 });
  assert.equal(found.origin, "https://pay.example");
  assert.equal(found.sandboxed, false);
});

test("a card is typed into the payment fields of an allowed document only", () => {
  const [number, exp, csc, name, email] = page([
    { attributes: { autocomplete: "cc-number" } },
    { attributes: { autocomplete: "cc-exp", placeholder: "MM / YY" } },
    { name: "cvc" },
    { attributes: { autocomplete: "cc-name" } },
    { name: "email" },
  ]);
  assert.equal(fillCard(["https://pay.example"], CARD), "filled");
  assert.equal(number.value, "4242424242424242");
  assert.equal(exp.value, "03 / 31");
  assert.equal(csc.value, "123");
  assert.equal(name.value, "Test Person");
  assert.equal(email.value, "");
  assert.ok(number.events.includes("input") && number.events.includes("change"));

  // Another origin than those allowed, or a sandboxed document: nothing.
  const [other] = page([{ attributes: { autocomplete: "cc-number" } }], { origin: "https://evil.example" });
  assert.equal(fillCard(["https://pay.example"], CARD), "wrong_page");
  assert.equal(other.value, "");
  const [boxed] = page([{ attributes: { autocomplete: "cc-number" } }], { sandboxed: true });
  assert.equal(fillCard(["https://pay.example"], CARD), "wrong_page");
  assert.equal(boxed.value, "");
});

test("the expiry follows the field: month and year apart, four digits when it shows them", () => {
  const [month, year, joined] = page([
    { tag: "SELECT", attributes: { autocomplete: "cc-exp-month" }, options: ["01", "02", "03", "04"] },
    { tag: "SELECT", attributes: { autocomplete: "cc-exp-year" }, options: ["2030", "2031", "2032"] },
    { attributes: { autocomplete: "cc-exp", maxlength: "4" } },
  ]);
  assert.equal(fillCard(["https://pay.example"], CARD), "filled");
  assert.equal(month.value, "03");
  assert.equal(year.value, "2031");
  assert.equal(joined.value, "0331");
});

test("a form that sends over plain http gets no card", () => {
  const form = { attributes: { action: "http://pay.example/charge" } };
  form.querySelectorAll = () => [];
  page([{ attributes: { autocomplete: "cc-number" }, form }]);
  globalThis.window.Element.prototype.getAttribute = function (name) {
    return this.attributes?.[name] ?? null;
  };
  assert.equal(fillCard(["https://pay.example"], CARD), "insecure_form");
});

test("a frame of another site gets a card only once approved for this site", () => {
  const frames = [
    { frameId: 0, origin: "https://shop.example", kinds: { name: 1 } },
    { frameId: 3, origin: "https://js.payments.example", kinds: { number: 1 } },
    { frameId: 4, origin: "https://shop.example", kinds: { csc: 1 } },
    { frameId: 5, origin: "https://ads.example", sandboxed: true, kinds: { number: 1 } },
    { frameId: 6, origin: "http://plain.example", kinds: { number: 1 } },
  ];
  const before = cardTargets(frames, "https://shop.example", []);
  assert.deepEqual(
    before.allowed.map((frame) => frame.frameId),
    [0, 4],
  );
  assert.deepEqual(before.waiting, ["js.payments.example"]);
  const after = cardTargets(frames, "https://shop.example", ["js.payments.example"]);
  assert.deepEqual(
    after.allowed.map((frame) => frame.frameId),
    [0, 3, 4],
  );
  assert.deepEqual(after.waiting, []);
  // The tab's own document must still be the tab's origin.
  const moved = cardTargets([{ frameId: 0, origin: "https://elsewhere.example", kinds: { number: 1 } }], "https://shop.example", []);
  assert.deepEqual(moved, { allowed: [], waiting: [] });
});

test("a site is kept as the app keeps it", () => {
  assert.equal(siteKey("https://www.Shop.example"), "shop.example");
  assert.equal(siteKey("https://pay.example:8443"), "pay.example:8443");
  assert.equal(siteKey("not a site"), "");
});

test("the window reads the site's rule strictly and asks for one switch at a time", () => {
  assert.deepEqual(ruleOf({ rule: { site: "example.com", never_save: true, no_card: "yes", card_frames: ["a", 2] } }), {
    site: "example.com",
    card_frames: ["a"],
    never_save: true,
    no_card: false,
    never_fill: false,
    no_passkeys: false,
  });
  assert.equal(ruleOf(undefined).never_fill, false);
  assert.deepEqual(ruleRequest("https://example.com/x", "no_passkeys", 1), {
    type: "site_rule",
    url: "https://example.com/x",
    rule: { no_passkeys: true },
  });
});

test("a site's word about its passkeys is passed on checked and bounded", () => {
  const url = "https://example.com/";
  assert.deepEqual(signalRequest(url, { kind: "unknown", rpId: "example.com", credentialId: "AAEC" }), {
    type: "passkey_signal",
    url,
    rp_id: "example.com",
    signal: "unknown",
    credential: "AAEC",
  });
  assert.deepEqual(
    signalRequest(url, { kind: "details", rpId: "example.com", userId: "dXNlcg", name: "new@example.com", displayName: "New" }),
    {
      type: "passkey_signal",
      url,
      rp_id: "example.com",
      signal: "details",
      user_id: "dXNlcg",
      name: "new@example.com",
      display_name: "New",
    },
  );
  const accepted = signalRequest(url, { kind: "accepted", userId: "dXNlcg", accepted: Array(100).fill("AAEC") });
  assert.equal(accepted.accepted.length, 65, "a list longer than the app reads is cut, and the app then notes nothing");
  // Missing what it is about, or of an unknown kind: nothing is sent.
  assert.equal(signalRequest(url, { kind: "unknown" }), undefined);
  assert.equal(signalRequest(url, { kind: "accepted", userId: "dXNlcg" }), undefined);
  assert.equal(signalRequest(url, { kind: "delete", credentialId: "AAEC" }), undefined);
});
