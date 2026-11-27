// Tests for what the content script reads from a page when a sign-in is sent:
// `node --test apps/extension/test`. fields.js runs in a sandbox with a few plain objects
// standing in for the page; no browser and no packages are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const SCRIPT = readFileSync(new URL("../fields.js", import.meta.url), "utf8");

/** An element of the fake page: a tag, attributes, a parent, text. */
class Element {
  constructor(tagName, { parent = null, attributes = {}, text = "", ...rest } = {}) {
    Object.assign(this, { tagName, parentElement: parent, attributes, textContent: text, ...rest });
    this.disabled = false;
    this.readOnly = false;
    this.isConnected = true;
  }
  getAttribute(name) {
    return this.attributes[name] ?? null;
  }
  getBoundingClientRect() {
    return { width: 200, height: 30 };
  }
  contains(other) {
    for (let node = other; node; node = node.parentElement) if (node === this) return true;
    return false;
  }
  matches(selector) {
    return selector.split(",").some((part) => {
      const one = part.trim();
      if (one === "[role=button]") return this.attributes.role === "button";
      return this.tagName === one.toUpperCase();
    });
  }
  closest(selector) {
    for (let node = this; node; node = node.parentElement) if (node.matches(selector)) return node;
    return null;
  }
}

/** fields.js loaded into a fresh sandbox; returns its functions. */
function load() {
  const sandbox = { Element, URL, location: { href: "https://login.example.com/" } };
  vm.createContext(sandbox);
  vm.runInContext(SCRIPT, sandbox);
  return sandbox.VaultFields;
}
const { typedLogin, sentScope } = load();

/** A page with a body; `el(tag, parent, props)` adds an element to it. */
function page() {
  const html = new Element("HTML");
  const body = new Element("BODY", { parent: html });
  const inputs = [];
  const el = (tag, parent, props = {}) => {
    const made = new Element(tag, { parent, ...props });
    if (tag === "INPUT") {
      made.type = props.type ?? "text";
      made.value = props.value ?? "";
      made.name = props.name ?? "";
      made.id = props.id ?? "";
      made.form = props.form ?? null;
      inputs.push(made);
    }
    if (tag === "BUTTON") {
      made.type = props.type ?? (props.form ? "submit" : "submit");
      made.form = props.form ?? null;
      if (props.type) made.attributes.type = props.type;
    }
    return made;
  };
  return { body, inputs, el };
}

/** A sign-in form with what was typed in it, and a help button outside it. */
function signInForm() {
  const { body, inputs, el } = page();
  const form = el("FORM", body);
  const user = el("INPUT", form, { name: "username", value: "octocat", form });
  const password = el("INPUT", form, { type: "password", value: "s3cret", form });
  const eye = el("BUTTON", form, { type: "button", form, attributes: { "aria-label": "Show password" } });
  const send = el("BUTTON", form, { form, text: "Sign in" });
  const help = el("BUTTON", body, { text: "Help" });
  const link = el("A", body, { text: "Forgot password?" });
  return { body, form, inputs, user, password, eye, send, help, link, el };
}

test("a click on Help, an eye button or a link reads nothing that was typed", () => {
  const { inputs, help, eye, link } = signInForm();
  for (const target of [help, eye, link]) {
    const scope = sentScope("click", target, inputs);
    assert.equal(scope, undefined);
    assert.equal(typedLogin(inputs, scope), undefined);
  }
});

test("the form's own submit button and its submit event send it", () => {
  const { form, inputs, send } = signInForm();
  assert.equal(sentScope("click", send, inputs), form);
  assert.equal(sentScope("submit", form, inputs), form);
  assert.deepEqual({ ...typedLogin(inputs, form) }, { username: "octocat", password: "s3cret" });
});

test("a submit button of another form sends that form only", () => {
  const { body, inputs, el } = signInForm();
  const search = el("FORM", body);
  el("INPUT", search, { name: "q", value: "cats", form: search });
  const go = el("BUTTON", search, { form: search, text: "Search" });
  // Its click reads nothing (it doesn't read like signing in); the search form's own submit
  // is read, and holds no login.
  assert.equal(sentScope("click", go, inputs), undefined);
  const scope = sentScope("submit", search, inputs);
  assert.equal(scope, search);
  assert.equal(typedLogin(inputs, scope), undefined, "no password and no username in that form");
});

test("a form's other buttons read nothing by their click, even those that would submit it", () => {
  const { form, inputs, el } = signInForm();
  // A button without a type submits its form, but a click on it may be cancelled (a Help
  // that opens a box, an eye that calls preventDefault): only the submit itself counts.
  for (const label of ["Help", "Show password", "Forgot password?", "Cancel"]) {
    const button = el("BUTTON", form, { form, text: label });
    assert.equal(sentScope("click", button, inputs), undefined, label);
  }
  const reset = el("INPUT", form, { type: "reset", value: "Clear", form });
  assert.equal(sentScope("click", reset, inputs), undefined);
});

test("Enter on a button, a file or a reset control of the form sends nothing", () => {
  const { form, inputs, el } = signInForm();
  for (const type of ["button", "submit", "reset", "file", "image", "color", "range"]) {
    const control = el("INPUT", form, { type, value: "Show password", form });
    assert.equal(sentScope("enter", control, inputs), undefined, type);
  }
  for (const type of ["text", "email", "password", "search", "url", "tel", "number", "checkbox"]) {
    const field = el("INPUT", form, { type, form });
    assert.equal(sentScope("enter", field, inputs), form, type);
  }
});

test("a sign-in button of the form counts when it is no submit button (pages that sign in by script)", () => {
  const { form, inputs, el } = signInForm();
  for (const label of ["Entrar", "Sign in", "Sign-in", "Log in →", "Next", "Continuar"]) {
    const button = el("BUTTON", form, { type: "button", form, text: label });
    assert.equal(sentScope("click", button, inputs), form, label);
  }
  const value = el("INPUT", form, { type: "button", value: "Login", form });
  assert.equal(sentScope("click", value, inputs), form);
  assert.deepEqual({ ...typedLogin(inputs, form) }, { username: "octocat", password: "s3cret" });
});

test("help, another way in or another account reads like no sign-in, wherever it is", () => {
  const { body, inputs, el } = page();
  const box = el("DIV", body);
  el("INPUT", box, { name: "email", type: "email", value: "octocat@example.com" });
  el("INPUT", box, { type: "password", value: "s3cret" });
  const labels = [
    "Can't log in?",
    "Login help",
    "Log in with Google",
    "Continue with Google",
    "Entrar com Google",
    "Problemas para entrar?",
    "Não consigo acessar minha conta",
    "Esqueceu a senha?",
    "Sign in with a passkey",
    "Sign in to another account",
    "Help",
    "Sign in to keep your cart and see your orders from any device you use",
  ];
  for (const label of labels) {
    const asRole = el("DIV", box, { attributes: { role: "button" }, text: label });
    assert.equal(sentScope("click", asRole, inputs), undefined, label);
    const asSubmit = el("BUTTON", box, { type: "submit", text: label });
    assert.equal(sentScope("click", asSubmit, inputs), undefined, `${label} (type=submit)`);
    const named = el("BUTTON", box, { type: "submit", attributes: { "aria-label": label }, text: "Sign in" });
    assert.equal(sentScope("click", named, inputs), undefined, `${label} (aria-label)`);
  }
  // Without a label that reads like signing in, a formless submit button sends nothing.
  assert.equal(sentScope("click", el("BUTTON", box, { type: "submit" }), inputs), undefined);
  assert.equal(sentScope("click", el("BUTTON", box, { type: "submit", text: "Sign in" }), inputs), null);
});

test("Enter sends the form of the field it was pressed in", () => {
  const { body, form, inputs, password, el } = signInForm();
  assert.equal(sentScope("enter", password, inputs), form);
  const other = el("FORM", body);
  const q = el("INPUT", other, { name: "q", value: "x", form: other });
  assert.equal(typedLogin(inputs, sentScope("enter", q, inputs)), undefined);
});

test("outside any form, only a sign-in button next to the fields sends them", () => {
  const { body, inputs, el } = page();
  const box = el("DIV", body);
  const row = el("DIV", box);
  el("INPUT", row, { name: "email", type: "email", value: "octocat@example.com" });
  const password = el("INPUT", row, { type: "password", value: "s3cret" });
  const send = el("DIV", box, { attributes: { role: "button" }, text: "Log in" });
  const eye = el("BUTTON", row, { type: "button", attributes: { "aria-label": "Show password" } });
  const help = el("BUTTON", body, { text: "Help" });
  const farAway = el("BUTTON", body, { text: "Continue" });

  assert.equal(sentScope("click", send, inputs), null);
  assert.deepEqual({ ...typedLogin(inputs, null) }, { username: "octocat@example.com", password: "s3cret" });
  assert.equal(sentScope("click", eye, inputs), undefined, "the eye shows the password, it sends nothing");
  assert.equal(sentScope("click", help, inputs), undefined);
  assert.equal(sentScope("click", farAway, inputs), undefined, "not next to the fields");
  assert.equal(sentScope("enter", password, inputs), null, "Enter in the password field");
});

test("fields outside a form are not read for a form's submit, nor a form's for a formless button", () => {
  const { body, inputs, el } = signInForm();
  const signIn = el("BUTTON", body, { text: "Sign in" });
  assert.equal(sentScope("click", signIn, inputs), undefined, "the typed fields sit in a form it does not send");
});

test("a role=button inside a form sends that form when it reads like a sign-in", () => {
  const { form, inputs, el } = signInForm();
  const div = el("DIV", form, { attributes: { role: "button" }, text: "Entrar" });
  assert.equal(sentScope("click", div, inputs), form);
  const menu = el("DIV", form, { attributes: { role: "button" }, text: "More options" });
  assert.equal(sentScope("click", menu, inputs), undefined);
});

// ---- content.js: when what was typed is read at all ----

const CONTENT = readFileSync(new URL("../content.js", import.meta.url), "utf8");

/** IntersectionObserverEntry as a browser that reports a frame's visibility has it (v2). */
class VouchingEntry {
  get isVisible() {
    return false;
  }
}

/**
 * content.js (with fields.js) on the stand-in page `inputs`: `fire` sends an event to its
 * listeners, `submitted` is what reached the worker. `saves` is the extension's setting, as
 * stored (`held`: not read yet until `release()`). `vouches`: the browser reports whether the
 * frame is fully visible (Firefox doesn't). `waiting`: the request for a field's suggestions
 * that passkeys.js holds, if any.
 */
async function contentScript(inputs, { saves = true, held = false, vouches = true, waiting } = {}) {
  const listeners = {};
  const toWorker = [];
  const fromWorker = [];
  const storage = [];
  const appended = [];
  let now = 10_000;
  let ids = 0;
  let release;
  const read = new Promise((done) => (release = done));
  if (!held) release();
  const frame = () => ({
    tagName: "IFRAME",
    style: {
      setProperty(name, value) {
        this[name] = value;
      },
    },
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    removed: false,
    remove() {
      this.removed = true;
    },
  });
  const sandbox = {
    Element,
    URL,
    location: { href: "https://login.example.com/" },
    document: {
      baseURI: "https://login.example.com/",
      addEventListener: (type, listener) => (listeners[type] ||= []).push(listener),
      querySelectorAll: (selector) => (selector === "input" ? inputs : []),
      querySelector: () => null,
      createElement: frame,
      documentElement: { append: (made) => appended.push(made) },
      activeElement: null,
    },
    window: { addEventListener() {}, innerHeight: 800, innerWidth: 1200 },
    getComputedStyle: () => ({ colorScheme: "normal", borderBottomWidth: "0", boxShadow: "none", backgroundColor: "transparent" }),
    IntersectionObserverEntry: vouches ? VouchingEntry : class {},
    VaultPasskeys: { waiting: () => waiting },
    performance: { now: () => now },
    crypto: { randomUUID: () => `offer-${++ids}` },
    chrome: {
      runtime: {
        id: "vault",
        getURL: (path) => `chrome-extension://vault/${path}`,
        sendMessage: async (message) => {
          toWorker.push(message);
          return message.kind === "field-focused" ? { show: true } : undefined;
        },
        onMessage: { addListener: (listener) => fromWorker.push(listener) },
      },
      storage: {
        local: { get: async (key) => read.then(() => ({ [key]: saves })) },
        onChanged: { addListener: (listener) => storage.push(listener) },
      },
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(SCRIPT, sandbox);
  vm.runInContext(CONTENT, sandbox);
  await settle();
  return {
    sandbox,
    appended,
    fire(type, event) {
      for (const listener of listeners[type] ?? []) listener({ type, isTrusted: true, ...event });
    },
    tell: (message) => fromWorker.forEach((listener) => listener(message)),
    turn: (on) => storage.forEach((listener) => listener({ vaultSaves: { newValue: on } }, "local")),
    release: async () => {
      release();
      await settle();
    },
    later: (ms) => (now += ms),
    submitted: () => toWorker.filter((message) => message.kind === "submitted"),
    toWorker,
  };
}
const settle = () => new Promise((done) => setTimeout(done, 1));

test("a submit is read only right after the person's own act in that very form", async () => {
  const { body, form, inputs, password, eye, el } = signInForm();
  const search = el("FORM", body);
  const go = el("BUTTON", search, { form: search, text: "Search" });
  const page = await contentScript(inputs);

  // A page script's requestSubmit(): the browser fires a trusted submit, with no act before it.
  page.fire("submit", { target: form });
  assert.deepEqual(page.submitted(), [], "nothing read without the person");
  // A made-up click is no act; nor is a click in another form.
  page.fire("click", { target: eye, isTrusted: false });
  page.fire("submit", { target: form });
  page.fire("click", { target: go });
  page.fire("submit", { target: form });
  assert.deepEqual(page.submitted(), []);

  // The person clicks in the form (here its eye button, which reads nothing itself), then the
  // form is submitted: read once.
  page.fire("click", { target: eye });
  assert.deepEqual(page.submitted(), []);
  page.fire("submit", { target: form });
  assert.equal(page.submitted().length, 1);
  assert.equal(page.submitted()[0].password, "s3cret");
  // One act counts for one submit: a guess the script submits next is not read.
  password.value = "guess-2";
  page.fire("submit", { target: form });
  assert.equal(page.submitted().length, 1);
  // Nor long after the act.
  page.fire("click", { target: eye });
  page.later(5000);
  page.fire("submit", { target: form });
  assert.equal(page.submitted().length, 1);
  // Enter in one of its fields is an act too.
  page.fire("keydown", { key: "Enter", target: password });
  assert.equal(page.submitted().length, 2);
  assert.equal(page.submitted()[1].password, "guess-2");
  // A div the page signs in from counts as the person's act in its form.
  password.value = "third";
  const div = el("DIV", form, { text: "Go" });
  page.fire("click", { target: div });
  page.fire("submit", { target: form });
  assert.equal(page.submitted().length, 3);
});

test("with saving left to the browser, content.js reads nothing typed at all", async () => {
  const { form, inputs, send } = signInForm();
  const off = await contentScript(inputs, { saves: false });
  off.fire("click", { target: send });
  off.fire("submit", { target: form });
  assert.deepEqual(off.submitted(), [], "nothing left the page's script, not even to the worker");
  // Turned on: read again.
  off.turn(true);
  off.fire("click", { target: send });
  assert.equal(off.submitted().length, 1);
  off.turn(false);
  off.fire("click", { target: send });
  assert.equal(off.submitted().length, 1);

  // Not known yet counts as off.
  const early = await contentScript(inputs, { held: true });
  early.fire("click", { target: send });
  assert.deepEqual(early.submitted(), []);
  await early.release();
  early.fire("click", { target: send });
  assert.equal(early.submitted().length, 1);
});

test("a newer offer replaces the save card on screen, so the card shows the offer that waits", async () => {
  const { inputs } = signInForm();
  const page = await contentScript(inputs);
  page.tell({ kind: "offer-save" });
  assert.equal(page.appended.length, 1);
  page.tell({ kind: "offer-save" });
  assert.equal(page.appended.length, 2);
  assert.equal(page.appended[0].removed, true, "the card of the older offer is gone");
  assert.equal(page.appended[1].removed, false);
});

test("the card's offer is kept out of the page's reach; its id is no secret", async () => {
  const { inputs, user } = signInForm();
  const page = await contentScript(inputs);
  page.sandbox.document.activeElement = user;
  page.fire("focusin", { target: user });
  await settle();
  const frame = page.appended.at(-1);
  assert.ok(frame, "the card is shown");
  assert.deepEqual(frame.attributes, { scrolling: "no" }, "nothing about the offer on the frame element");
  const offer = vm.runInContext("VaultOffer", page.sandbox);
  assert.equal(offer.field, user);
  assert.ok(frame.src.endsWith(`|${offer.id}`), "the frame learns its offer from its address");
  assert.ok(Object.isFrozen(offer));
});

test("where a form sends is read as the browser reads it: the base URL, and each button's formaction", () => {
  const { body, el } = page();
  const form = el("FORM", body, { attributes: { action: "/session" } });
  const send = el("BUTTON", form, { form, attributes: { formaction: "http://login.example.com/plain" } });
  const sandbox = {
    Element,
    URL,
    location: { href: "https://login.example.com/sign-in" },
    document: { baseURI: "https://cdn.example.net/", querySelectorAll: () => [send] },
  };
  vm.createContext(sandbox);
  vm.runInContext(SCRIPT, sandbox);
  assert.equal(
    sandbox.VaultFields.destinationOf(form),
    "https://cdn.example.net/session\nhttp://login.example.com/plain",
  );
  // A field named "action" stands in for nothing: the attribute is read from the element.
  form.action = { value: "https://login.example.com/session" };
  assert.ok(sandbox.VaultFields.destinationOf(form).startsWith("https://cdn.example.net/session"));
  assert.equal(sandbox.VaultFields.destinationOf(null), "");
});

test("a browser that can't vouch for the frame shows none in pages; a waiting login marks the button", async () => {
  const { inputs, user } = signInForm();
  const page = await contentScript(inputs, { vouches: false });
  page.sandbox.document.activeElement = user;
  page.fire("focusin", { target: user });
  await settle();
  assert.equal(page.appended.length, 0, "no frame under the field");
  assert.ok(!page.toWorker.some((message) => message.kind === "field-focused"));
  page.tell({ kind: "offer-save" });
  assert.equal(page.appended.length, 0, "no save card either");
  assert.ok(page.toWorker.some((message) => message.kind === "offer-waiting"), "the toolbar button says so");
});

test("while the page waits for a field's suggestions, a sign-in or passkey field lists the site's passkeys", async () => {
  const waiting = { id: "r1", request: { kind: "get", rpId: "example.com", challenge: "AQ", allow: [], conditional: true } };
  const { body, el, inputs } = page();
  // No sign-in field by its looks, but marked for the browser's passkey suggestions.
  const handle = el("INPUT", body, { name: "handle", attributes: { autocomplete: "webauthn" } });
  const code = el("INPUT", body, { name: "otp", attributes: { autocomplete: "one-time-code" } });
  const form = el("FORM", body);
  const password = el("INPUT", form, { type: "password", form });

  const asked = async (field, options) => {
    const content = await contentScript(inputs, options);
    content.sandbox.document.activeElement = field;
    content.fire("focusin", { target: field });
    await settle();
    return content.toWorker.find((message) => message.kind === "field-focused");
  };
  assert.deepEqual((await asked(handle, { waiting })).passkey, waiting);
  assert.deepEqual((await asked(password, { waiting })).passkey, waiting);
  // Nothing waits: the marked field is no sign-in field, and nothing is offered under it.
  assert.equal(await asked(handle, {}), undefined);
  // A one-time code field never lists passkeys.
  assert.equal((await asked(code, { waiting })).passkey, undefined);
  const { isPasskeyField } = load();
  assert.ok(isPasskeyField(el("INPUT", body, { attributes: { autocomplete: "username webauthn" } })));
  assert.ok(!isPasskeyField(el("INPUT", body, { attributes: { autocomplete: "username" } })));
  assert.ok(!isPasskeyField(el("INPUT", body, { type: "checkbox", attributes: { autocomplete: "webauthn" } })));
});
