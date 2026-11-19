// Tests for the function that types a login into a page: `node --test extension/test`.
// A few plain objects stand in for the page; no browser and no packages are needed.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fillCode, fillLogin } from "../fill.js";

class Event {
  constructor(type) {
    this.type = type;
  }
}

class HTMLInputElement {
  constructor({ type = "text", name = "", id = "", autocomplete = "", form = null, shown = true, ...rest }) {
    Object.assign(this, { type, name, id, form, shown, disabled: false, readOnly: false, ...rest });
    this.autocomplete = autocomplete;
    this.text = "";
    this.events = [];
  }
  get value() {
    return this.text;
  }
  set value(text) {
    this.text = text;
  }
  getAttribute(name) {
    return name === "autocomplete" ? this.autocomplete : null;
  }
  getBoundingClientRect() {
    return this.shown ? { width: 200, height: 30 } : { width: 0, height: 0 };
  }
  focus() {}
  dispatchEvent(event) {
    this.events.push(event.type);
  }
}

/** Puts a fake page in place and returns its inputs. */
function page(fields, { origin = "https://github.com", framed = false } = {}) {
  const inputs = fields.map((field) => new HTMLInputElement(field));
  const window = {
    location: { origin },
    HTMLInputElement,
    getComputedStyle: (el) => ({ display: el.display ?? "block", visibility: el.visibility ?? "visible" }),
  };
  window.top = framed ? {} : window;
  Object.assign(globalThis, {
    window,
    document: { querySelectorAll: () => inputs },
    Event,
  });
  return inputs;
}

const fill = () => fillLogin("https://github.com", "octocat", "s3cret");

test("fills the username and the password of a sign-in form", () => {
  const form = {};
  const [search, user, password] = page([
    { name: "q" },
    { name: "login", autocomplete: "username", form },
    { type: "password", name: "password", form },
  ]);
  assert.equal(fill(), "both");
  assert.equal(search.value, "", "a field of another form is left alone");
  assert.equal(user.value, "octocat");
  assert.equal(password.value, "s3cret");
  assert.deepEqual(password.events, ["input", "change"], "frameworks hear about it");
});

test("types nothing on another site or inside a frame", () => {
  let inputs = page([{ name: "login" }, { type: "password" }], { origin: "https://github.com.evil.example" });
  assert.equal(fill(), "wrong_page");
  assert.ok(inputs.every((input) => input.value === ""));
  inputs = page([{ name: "login" }, { type: "password" }], { framed: true });
  assert.equal(fill(), "wrong_page");
  assert.ok(inputs.every((input) => input.value === ""));
});

test("skips fields that are hidden, disabled or read-only", () => {
  const [hidden, off, gone, user, password] = page([
    { type: "password", shown: false },
    { type: "password", disabled: true },
    { type: "password", display: "none" },
    { type: "email" },
    { type: "password" },
  ]);
  assert.equal(fill(), "both");
  assert.deepEqual([hidden.value, off.value, gone.value], ["", "", ""]);
  assert.equal(user.value, "octocat");
  assert.equal(password.value, "s3cret");
});

test("does not put the password into a new-password field", () => {
  const [user, fresh] = page([
    { type: "email", name: "email" },
    { type: "password", autocomplete: "new-password" },
  ]);
  assert.equal(fill(), "username");
  assert.equal(user.value, "octocat");
  assert.equal(fresh.value, "");
});

test("handles a password alone, a username alone, and nothing at all", () => {
  let [password] = page([{ type: "password" }]);
  assert.equal(fill(), "password");
  assert.equal(password.value, "s3cret");

  const [first, user] = page([{ name: "q" }, { name: "identifier" }]);
  assert.equal(fill(), "username");
  assert.deepEqual([first.value, user.value], ["", "octocat"]);

  const [search] = page([{ name: "q" }]);
  assert.equal(fill(), "none");
  assert.equal(search.value, "");
});

test("prefers the field that looks like a username, else the first text field of the form", () => {
  const form = {};
  let [code, user, password] = page([
    { name: "company", form },
    { name: "user_email", form },
    { type: "password", form },
  ]);
  assert.equal(fill(), "both");
  assert.deepEqual([code.value, user.value, password.value], ["", "octocat", "s3cret"]);

  const [only, secret] = page([{ name: "field1", form }, { type: "password", form }]);
  assert.equal(fill(), "both");
  assert.deepEqual([only.value, secret.value], ["octocat", "s3cret"]);
});

test("a one-time code goes into the field marked for it, never elsewhere", () => {
  const form = {};
  const [search, code] = page([
    { name: "q" },
    { name: "otp_attempt", autocomplete: "one-time-code", form },
  ]);
  assert.equal(fillCode("https://github.com", "123456"), "filled");
  assert.equal(search.value, "");
  assert.equal(code.value, "123456");
  assert.deepEqual(code.events, ["input", "change"]);

  const [named] = page([{ name: "totp" }]);
  assert.equal(fillCode("https://github.com", "654321"), "filled");
  assert.equal(named.value, "654321");

  page([{ name: "q" }, { type: "password" }]);
  assert.equal(fillCode("https://github.com", "123456"), "none");
  const elsewhere = page([{ name: "otp" }], { origin: "https://github.com.evil.example" });
  assert.equal(fillCode("https://github.com", "123456"), "wrong_page");
  assert.equal(elsewhere[0].value, "");
});

test("a code split over one box per digit is spread over the boxes", () => {
  const form = {};
  const boxes = page(
    Array.from({ length: 6 }, (_, i) => ({ name: `otp-${i}`, maxLength: 1, form })),
  );
  assert.equal(fillCode("https://github.com", "908172"), "filled");
  assert.deepEqual(
    boxes.map((box) => box.value),
    ["9", "0", "8", "1", "7", "2"],
  );
  page(Array.from({ length: 4 }, (_, i) => ({ name: `otp-${i}`, maxLength: 1, form })));
  assert.equal(fillCode("https://github.com", "908172"), "none", "too few boxes: nothing half-typed");
});
