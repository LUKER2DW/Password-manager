// Tests for the function that types a login into a page: `node --test apps/extension/test`.
// A few plain objects stand in for the page; no browser and no packages are needed.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fillCode, fillLogin } from "../fill.js";

class Event {
  constructor(type) {
    this.type = type;
  }
}

class Element {
  constructor(tagName = "DIV", parentElement = null) {
    Object.assign(this, { tagName, parentElement });
  }
  getAttribute(name) {
    return this.attributes?.[name] ?? null;
  }
  contains(other) {
    for (let node = other; node; node = node.parentElement) if (node === this) return true;
    return false;
  }
}

/** A form; `action` is its attribute as written in the page. */
function form(action = null) {
  const made = new Element("FORM");
  made.attributes = { action };
  return made;
}

/** A submit button of `owner` (a form), with a `formaction` when given. */
function submitButton(owner, formaction) {
  const made = new Element("BUTTON");
  Object.assign(made, { type: "submit", form: owner, attributes: formaction === undefined ? {} : { formaction } });
  return made;
}

/** A box of the page that fields outside a form sit in. */
function box() {
  return new Element("DIV");
}

class HTMLInputElement {
  constructor({ type = "text", name = "", id = "", autocomplete = "", form = null, shown = true, ...rest }) {
    Object.assign(this, { tagName: "INPUT", isConnected: true, type, name, id, form, shown, disabled: false, readOnly: false, ...rest });
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

/**
 * Puts a fake page in place and returns its inputs. A field sits in its `box` when given,
 * else in its form, else in one box with the page's other fields outside forms. `buttons`
 * are the page's submit buttons, `base` its base URL (a `<base>` element).
 */
function page(fields, { origin = "https://github.com", framed = false, focused, buttons = [], base } = {}) {
  const html = new Element("HTML");
  const body = new Element("BODY", html);
  const loose = new Element("DIV", body);
  const inputs = fields.map(({ box: inside, ...field }) => {
    const input = new HTMLInputElement(field);
    input.parentElement = inside ?? field.form ?? loose;
    return input;
  });
  for (const node of [...inputs, ...buttons]) {
    for (let at = node; at; at = at.parentElement) {
      if (!at.parentElement && at !== html) at.parentElement = body;
    }
  }
  const window = {
    location: { origin, href: `${origin}/login` },
    Element,
    HTMLInputElement,
    getComputedStyle: (el) => ({ display: el.display ?? "block", visibility: el.visibility ?? "visible" }),
  };
  window.top = framed ? {} : window;
  Object.assign(globalThis, {
    window,
    document: {
      baseURI: base ?? window.location.href,
      querySelectorAll: (selector) => (selector === "input" ? inputs : [...buttons, ...inputs]),
      activeElement: focused === undefined ? undefined : inputs[focused],
    },
    Event,
  });
  delete globalThis.VaultOffer;
  return inputs;
}

/** Where a form sends, as content.js computes it when the card is shown (fields.js). */
function destination(owner) {
  const resolved = (raw) => (raw ? new URL(raw, document.baseURI).href : window.location.href);
  const places = [resolved(owner.attributes.action)];
  for (const el of document.querySelectorAll("button, input")) {
    if (el.form === owner && el.tagName === "BUTTON" && el.type === "submit" && el.attributes.formaction !== undefined) {
      places.push(resolved(el.attributes.formaction));
    }
  }
  return places.join("\n");
}

/** The card's offer, as content.js keeps it for the field `field`. */
function offerFor(field, id = "offer-1") {
  const action = field.form ? destination(field.form) : "";
  globalThis.VaultOffer = Object.freeze({ id, field, form: field.form, action });
  return id;
}

const fill = () => fillLogin("https://github.com", "octocat", "s3cret");

test("fills the username and the password of a sign-in form", () => {
  const signIn = form();
  const [search, user, password] = page([
    { name: "q" },
    { name: "login", autocomplete: "username", form: signIn },
    { type: "password", name: "password", form: signIn },
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
  const signIn = form();
  let [code, user, password] = page([
    { name: "company", form: signIn },
    { name: "user_email", form: signIn },
    { type: "password", form: signIn },
  ]);
  assert.equal(fill(), "both");
  assert.deepEqual([code.value, user.value, password.value], ["", "octocat", "s3cret"]);

  const [only, secret] = page([{ name: "field1", form: signIn }, { type: "password", form: signIn }]);
  assert.equal(fill(), "both");
  assert.deepEqual([only.value, secret.value], ["octocat", "s3cret"]);
});

test("a one-time code goes into the field marked for it, never elsewhere", () => {
  const signIn = form();
  const [search, code] = page([
    { name: "q" },
    { name: "otp_attempt", autocomplete: "one-time-code", form: signIn },
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
  const signIn = form();
  const boxes = page(
    Array.from({ length: 6 }, (_, i) => ({ name: `otp-${i}`, maxLength: 1, form: signIn })),
  );
  assert.equal(fillCode("https://github.com", "908172"), "filled");
  assert.deepEqual(
    boxes.map((box) => box.value),
    ["9", "0", "8", "1", "7", "2"],
  );
  page(Array.from({ length: 4 }, (_, i) => ({ name: `otp-${i}`, maxLength: 1, form: signIn })));
  assert.equal(fillCode("https://github.com", "908172"), "none", "too few boxes: nothing half-typed");
});

// ---- the form the card was shown for ----

/** Two sign-in forms on one page, of two accounts. */
function twoForms(options) {
  const first = form();
  const second = form();
  const fields = page(
    [
      { name: "login", form: first },
      { type: "password", form: first },
      { name: "login", form: second },
      { type: "password", form: second },
    ],
    options,
  );
  return { first, second, fields };
}

test("a login picked in the card goes into the form of the field it was shown under", () => {
  const { fields } = twoForms();
  const [user1, pass1, user2, pass2] = fields;
  const offer = offerFor(pass2);
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "both");
  assert.deepEqual([user1.value, pass1.value], ["", ""], "the other form is left alone");
  assert.deepEqual([user2.value, pass2.value], ["octocat", "s3cret"]);
});

test("under a username field, the password goes into the same form, after it", () => {
  const { fields } = twoForms();
  const [user1, pass1, user2, pass2] = fields;
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offerFor(user2)), "both");
  assert.deepEqual([user1.value, pass1.value, user2.value, pass2.value], ["", "", "octocat", "s3cret"]);
});

test("nothing is typed when the card's offer is not the page's current one", () => {
  const { fields } = twoForms();
  offerFor(fields[3], "offer-2");
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", "offer-1"), "wrong_page");
  delete globalThis.VaultOffer;
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", "offer-1"), "wrong_page", "no offer at all");
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", ""), "wrong_page", "a card without an offer");
  assert.ok(fields.every((input) => input.value === ""));
});

test("nothing is typed when the page replaced the field, moved it or changed where its form sends", () => {
  let { second, fields } = twoForms();
  let offer = offerFor(fields[3]);
  fields[3].isConnected = false;
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "wrong_page", "the field was replaced");

  ({ second, fields } = twoForms());
  offer = offerFor(fields[3]);
  fields[3].form = fields[0].form;
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "wrong_page", "moved into another form");

  ({ second, fields } = twoForms());
  offer = offerFor(fields[3]);
  second.attributes.action = "https://collector.example/steal";
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "wrong_page", "the form sends elsewhere now");
  assert.ok(fields.every((input) => input.value === ""));
});

test("a form that sends over plain http gets nothing", () => {
  const signIn = form("http://github.com/session");
  const fields = page([
    { name: "login", form: signIn },
    { type: "password", form: signIn },
  ]);
  assert.equal(fill(), "insecure_form");
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offerFor(fields[1])), "insecure_form");
  assert.ok(fields.every((input) => input.value === ""));
});

test("from the extension's window: the focused field's form, and no guess between two forms", () => {
  let { fields } = twoForms({ focused: 2 });
  assert.equal(fill(), "both");
  assert.deepEqual(
    fields.map((input) => input.value),
    ["", "", "octocat", "s3cret"],
  );
  ({ fields } = twoForms());
  assert.equal(fill(), "choose_field");
  assert.ok(fields.every((input) => input.value === ""));
});

test("a one-time code picked in the card goes into that field's form only", () => {
  const first = form();
  const second = form();
  const boxes = page([
    { name: "otp", autocomplete: "one-time-code", form: first },
    { name: "otp", autocomplete: "one-time-code", form: second },
  ]);
  assert.equal(fillCode("https://github.com", "123456", offerFor(boxes[1])), "filled");
  assert.deepEqual(
    boxes.map((box) => box.value),
    ["", "123456"],
  );
  assert.equal(fillCode("https://github.com", "123456", "stale"), "wrong_page");
});

// ---- the extension's window: which field is focused ----

test("from the extension's window, a focused field that is no sign-in field is passed over", () => {
  const signIn = form();
  let [search, user, password] = page(
    [{ name: "q" }, { name: "login", form: signIn }, { type: "password", form: signIn }],
    { focused: 0 },
  );
  assert.equal(fill(), "both", "a focused search box takes nothing");
  assert.deepEqual([search.value, user.value, password.value], ["", "octocat", "s3cret"]);

  for (const other of [{ name: "otp", autocomplete: "one-time-code" }, { name: "quantity" }, { type: "number", name: "qty" }]) {
    const fields = page([other, { name: "login", form: signIn }, { type: "password", form: signIn }], { focused: 0 });
    assert.equal(fill(), "both", other.name);
    assert.equal(fields[0].value, "", other.name);
  }
  // A focused field of the sign-in form is where it goes.
  [user, password] = page([{ name: "login", form: signIn }, { type: "password", form: signIn }], { focused: 1 });
  assert.equal(fill(), "both");
  assert.deepEqual([user.value, password.value], ["octocat", "s3cret"]);
});

// ---- fields outside any form ----

test("outside a form, the password goes only next to the field picked, never before it into another box", () => {
  // Box A: a sign-in. Box B: the username of another account, alone (the first of two steps).
  const a = box();
  const b = box();
  let [userA, passA, userB] = page([
    { name: "login", box: a },
    { type: "password", box: a },
    { name: "login", box: b },
  ]);
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offerFor(userB)), "username");
  assert.deepEqual([userA.value, passA.value, userB.value], ["", "", "octocat"]);

  // From the extension's window with B's field focused: the same.
  [userA, passA, userB] = page(
    [
      { name: "login", box: a },
      { type: "password", box: a },
      { name: "login", box: b },
    ],
    { focused: 2 },
  );
  assert.equal(fill(), "username");
  assert.deepEqual([userA.value, passA.value, userB.value], ["", "", "octocat"]);
});

test("outside a form, a newsletter box above the sign-in gets nothing", () => {
  const news = box();
  const login = box();
  const [newsletter, user, password] = page([
    { type: "email", name: "email", box: news },
    { name: "username", box: login },
    { type: "password", box: login },
  ]);
  assert.equal(fill(), "both");
  assert.deepEqual([newsletter.value, user.value, password.value], ["", "octocat", "s3cret"]);
  // Two sign-ins outside forms, and none focused: nothing is guessed.
  const other = box();
  page([
    { name: "username", box: login },
    { type: "password", box: login },
    { name: "username", box: other },
    { type: "password", box: other },
  ]);
  assert.equal(fill(), "choose_field");
});

// ---- where a form sends ----

test("a form sends where the page's base URL and its buttons say, as the browser reads them", () => {
  // <base href="http://…"> makes a relative action plain http.
  let signIn = form("/session");
  page([{ name: "login", form: signIn }, { type: "password", form: signIn }], { base: "http://github.example/" });
  assert.equal(fill(), "insecure_form");

  // A submit button's formaction overrides the action.
  signIn = form("/session");
  let fields = page([{ name: "login", form: signIn }, { type: "password", form: signIn }], {
    buttons: [submitButton(signIn, "http://github.com/session")],
  });
  assert.equal(fill(), "insecure_form");
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offerFor(fields[1])), "insecure_form");
  assert.ok(fields.every((input) => input.value === ""));

  // Changed after the card was shown: a <base> put in, or a button's formaction.
  signIn = form("/session");
  const button = submitButton(signIn, "/session");
  fields = page([{ name: "login", form: signIn }, { type: "password", form: signIn }], { buttons: [button] });
  let offer = offerFor(fields[1]);
  button.attributes.formaction = "https://collector.example/steal";
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "wrong_page");
  button.attributes.formaction = "/session";
  offer = offerFor(fields[1]);
  document.baseURI = "https://collector.example/";
  assert.equal(fillLogin("https://github.com", "octocat", "s3cret", offer), "wrong_page");
  assert.ok(fields.every((input) => input.value === ""));
});

// ---- one-time codes: the same checks ----

test("a one-time code gets the same checks: where its form sends, and which form", () => {
  let signIn = form();
  let boxes = page([{ name: "otp", autocomplete: "one-time-code", form: signIn }]);
  const offer = offerFor(boxes[0]);
  signIn.attributes.action = "https://collector.example/steal";
  assert.equal(fillCode("https://github.com", "123456", offer), "wrong_page");
  assert.equal(boxes[0].value, "");

  signIn = form("http://github.com/two-factor");
  boxes = page([{ name: "otp", autocomplete: "one-time-code", form: signIn }]);
  assert.equal(fillCode("https://github.com", "123456"), "insecure_form");
  assert.equal(fillCode("https://github.com", "123456", offerFor(boxes[0])), "insecure_form");
  assert.equal(boxes[0].value, "");

  // From the extension's window: the focused code field, and no guess between two forms.
  const first = form();
  const second = form();
  const codes = [
    { name: "otp", autocomplete: "one-time-code", form: first },
    { name: "otp", autocomplete: "one-time-code", form: second },
  ];
  boxes = page(codes, { focused: 1 });
  assert.equal(fillCode("https://github.com", "123456"), "filled");
  assert.deepEqual(
    boxes.map((one) => one.value),
    ["", "123456"],
  );
  boxes = page(codes);
  assert.equal(fillCode("https://github.com", "123456"), "choose_field");
  assert.ok(boxes.every((one) => one.value === ""));
});

test("the first step of two in several forms, none focused: nothing is guessed", () => {
  const news = form();
  const signIn = form();
  let fields = page([
    { type: "email", name: "email", form: news },
    { name: "username", form: signIn },
  ]);
  assert.equal(fill(), "choose_field");
  assert.ok(fields.every((input) => input.value === ""));
  // Focused, it is that one.
  fields = page(
    [
      { type: "email", name: "email", form: news },
      { name: "username", form: signIn },
    ],
    { focused: 1 },
  );
  assert.equal(fill(), "username");
  assert.deepEqual(
    fields.map((input) => input.value),
    ["", "octocat"],
  );
});
