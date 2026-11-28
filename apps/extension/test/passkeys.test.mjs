// Tests for Vault's place in front of a page's passkey requests: `node --test apps/extension/test`.
// The page script runs in a sandbox standing in for a page: its own navigator.credentials (the
// "browser"), window messages, and the WebAuthn types; no browser and no packages are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

import { openRequest, sealed } from "./sealed.mjs";

const PAGE_SCRIPT = readFileSync(new URL("../passkeys-page.js", import.meta.url), "utf8");
const ORIGIN = "https://login.example.com";

/**
 * A page with passkeys-page.js loaded; `posted` is what it sent to the content script.
 * `documentOrigin`: the document's own origin ("null" when the site sandboxed it).
 */
function page({ documentOrigin = ORIGIN } = {}) {
  const listeners = [];
  const posted = [];
  const browserCalls = [];
  const win = {
    location: { origin: ORIGIN },
    origin: documentOrigin,
    crypto: { randomUUID: (() => { let n = 0; return () => `id-${++n}`; })() },
    btoa,
    atob,
    DOMException,
    ArrayBuffer,
    Uint8Array,
    Object,
    Array,
    Number,
    String,
    Promise,
    addEventListener: (type, listener) => type === "message" && listeners.push(listener),
    postMessage: (data, origin) => {
      assert.equal(origin, ORIGIN, "only to the page's own origin");
      posted.push(data);
    },
  };
  win.globalThis = win;
  class PublicKeyCredential {}
  class AuthenticatorAssertionResponse {}
  class AuthenticatorAttestationResponse {}
  Object.assign(win, { PublicKeyCredential, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse });
  win.navigator = {
    credentials: {
      get: async (options) => {
        browserCalls.push(["get", options]);
        return "from the browser";
      },
      create: async (options) => {
        browserCalls.push(["create", options]);
        return "from the browser";
      },
    },
  };
  vm.createContext(win);
  vm.runInContext(PAGE_SCRIPT, win);
  // The page's own global, as its scripts see it (not the sandbox object itself).
  const inner = vm.runInContext("globalThis", win);
  /** The content script's answer to the last request. */
  const answer = (reply, { source = inner, origin = ORIGIN } = {}) => {
    const last = posted.at(-1);
    for (const listener of listeners) {
      listener({ source, origin, data: { channel: "vault-passkeys", direction: "answer", id: last.id, answer: reply } });
    }
  };
  return { win, posted, browserCalls, answer };
}

const tick = () => new Promise((done) => setImmediate(done));
/** What postMessage hands the content script: a structured copy, here as plain data. */
const plain = (value) => JSON.parse(JSON.stringify(value));
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

test("a sandboxed document keeps the browser's own passkeys", async () => {
  // `Content-Security-Policy: sandbox` at the site's address: the browser answers (and refuses
  // the opaque origin); nothing goes to Vault, and the page doesn't wait forever.
  const { win, posted, browserCalls } = page({ documentOrigin: "null" });
  assert.equal(await win.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) } }), "from the browser");
  assert.equal(await win.navigator.credentials.create({ publicKey: { challenge: new Uint8Array([1]) } }), "from the browser");
  assert.deepEqual(browserCalls.map(([kind]) => kind), ["get", "create"]);
  assert.equal(posted.length, 0);
});

test("what the site asks about verifying the person goes along with its request", () => {
  const { win, posted } = page();
  win.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]), userVerification: "required" } });
  win.navigator.credentials.create({
    publicKey: {
      challenge: new Uint8Array([1]),
      rp: { id: "example.com", name: "Example" },
      user: { id: new Uint8Array([5]), name: "me", displayName: "Me" },
      authenticatorSelection: { userVerification: "discouraged" },
    },
  });
  win.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([2]) } });
  assert.equal(posted[0].request.userVerification, "required");
  assert.equal(posted[1].request.userVerification, "discouraged");
  assert.equal(posted[2].request.userVerification, undefined, "not given: the worker reads preferred");
});

test("a sign-in goes to Vault, and the page gets a credential it can read", async () => {
  const { win, posted, answer, browserCalls } = page();
  const pending = win.navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array([1, 2, 3, 250]).buffer,
      rpId: "example.com",
      allowCredentials: [{ type: "public-key", id: new Uint8Array([9, 9]) }],
    },
  });
  await tick();
  assert.deepEqual(plain(posted[0].request), {
    kind: "get",
    rpId: "example.com",
    challenge: b64u([1, 2, 3, 250]),
    allow: [b64u([9, 9])],
  });
  assert.equal(posted[0].direction, "ask");
  const signed = {
    origin: ORIGIN,
    credential: b64u([7, 7, 7]),
    client_data: b64u(Buffer.from('{"type":"webauthn.get"}')),
    authenticator_data: b64u([5, 5]),
    signature: b64u([4, 4, 4, 4]),
    user_handle: b64u(Buffer.from("user-42")),
  };
  // Another frame, or another origin, can't answer for Vault.
  answer({ assertion: { ...signed, signature: b64u([0]) } }, { source: {} });
  answer({ assertion: { ...signed, signature: b64u([0]) } }, { origin: "https://evil.example" });
  answer({ assertion: signed });
  const credential = await pending;
  assert.ok(credential instanceof win.PublicKeyCredential);
  assert.ok(credential.response instanceof win.AuthenticatorAssertionResponse);
  assert.equal(credential.id, signed.credential);
  assert.equal(credential.type, "public-key");
  assert.deepEqual([...new Uint8Array(credential.rawId)], [7, 7, 7]);
  assert.deepEqual([...new Uint8Array(credential.response.signature)], [4, 4, 4, 4]);
  assert.equal(Buffer.from(credential.response.userHandle).toString(), "user-42");
  assert.equal(Buffer.from(credential.response.clientDataJSON).toString(), '{"type":"webauthn.get"}');
  assert.deepEqual(plain(credential.getClientExtensionResults()), {});
  const json = credential.toJSON();
  assert.equal(json.response.signature, signed.signature);
  assert.equal(json.rawId, signed.credential);
  assert.equal(browserCalls.length, 0, "the browser's handler wasn't asked");
});

test("a passkey made in Vault comes back as the browser would make it", async () => {
  const { win, posted, answer } = page();
  const pending = win.navigator.credentials.create({
    publicKey: {
      rp: { id: "example.com", name: "Example" },
      user: { id: new Uint8Array([42]), name: "me@example.com", displayName: "Me" },
      challenge: new Uint8Array([8, 8]),
      pubKeyCredParams: [
        { type: "public-key", alg: -8 },
        { type: "public-key", alg: -7 },
        { type: "other", alg: -999 },
      ],
      excludeCredentials: [{ type: "public-key", id: new Uint8Array([1]) }],
      extensions: { credProps: true },
    },
  });
  await tick();
  assert.deepEqual(plain(posted[0].request), {
    kind: "create",
    rpId: "example.com",
    rpName: "Example",
    userId: b64u([42]),
    userName: "me@example.com",
    displayName: "Me",
    challenge: b64u([8, 8]),
    algorithms: [-8, -7],
    exclude: [b64u([1])],
  });
  answer({
    attestation: {
      origin: ORIGIN,
      credential: b64u([3, 3]),
      client_data: b64u(Buffer.from('{"type":"webauthn.create"}')),
      attestation_object: b64u([0xa3]),
      authenticator_data: b64u([1, 2]),
      public_key: b64u([0x30, 0x59]),
      algorithm: -7,
    },
  });
  const credential = await pending;
  assert.ok(credential.response instanceof win.AuthenticatorAttestationResponse);
  assert.deepEqual([...new Uint8Array(credential.response.attestationObject)], [0xa3]);
  assert.deepEqual([...new Uint8Array(credential.response.getPublicKey())], [0x30, 0x59]);
  assert.deepEqual([...new Uint8Array(credential.response.getAuthenticatorData())], [1, 2]);
  assert.equal(credential.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual(plain(credential.response.getTransports()), ["hybrid", "internal"]);
  assert.deepEqual(plain(credential.getClientExtensionResults()), { credProps: { rk: true } });
  assert.equal(credential.toJSON().response.publicKeyAlgorithm, -7);
});

test("without Vault's passkey the browser's own handler answers, unchanged", async () => {
  const { win, posted, answer, browserCalls } = page();
  const options = { publicKey: { challenge: new Uint8Array([1]) } };
  const pending = win.navigator.credentials.get(options);
  await tick();
  answer({ fallback: true });
  assert.equal(await pending, "from the browser");
  assert.equal(browserCalls[0][1], options, "the very same options");
  // A field's suggestions Vault has nothing for: the browser's own, with the same options.
  const conditional = { mediation: "conditional", publicKey: { challenge: new Uint8Array([1]) } };
  const suggested = win.navigator.credentials.get(conditional);
  await tick();
  assert.equal(posted[1].request.conditional, true);
  answer({ fallback: true });
  assert.equal(await suggested, "from the browser");
  assert.equal(browserCalls[1][1], conditional);
  // A security key, and anything without publicKey: never asked.
  const key = {
    publicKey: {
      challenge: new Uint8Array([1]),
      user: { id: new Uint8Array([1]), name: "me" },
      authenticatorSelection: { authenticatorAttachment: "cross-platform" },
    },
  };
  assert.equal(await win.navigator.credentials.create(key), "from the browser");
  assert.equal(await win.navigator.credentials.get({ password: true }), "from the browser");
  assert.equal(posted.length, 2);
});

test("a field's suggestions wait for a pick; a later request or an abort ends them", async () => {
  const { win, posted, answer } = page();
  const suggestions = () => ({ mediation: "conditional", publicKey: { challenge: new Uint8Array([1]) } });
  const first = win.navigator.credentials.get(suggestions());
  await tick();
  assert.deepEqual(plain(posted[0].request), { kind: "get", rpId: "", challenge: b64u([1]), allow: [], conditional: true });
  // A later request, of any kind, ends the one waiting, and Vault hears so first.
  const later = win.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([2]) } });
  await assert.rejects(first, (error) => error.name === "AbortError");
  assert.deepEqual(plain(posted.slice(1).map(({ direction, id }) => [direction, id])), [
    ["cancel", posted[0].id],
    ["ask", posted[2].id],
  ]);
  answer({ error: "NotAllowedError" });
  await assert.rejects(later, (error) => error.name === "NotAllowedError");

  // A pick under the field answers it, much later.
  const picked = win.navigator.credentials.get(suggestions());
  await tick();
  answer({
    assertion: {
      origin: ORIGIN,
      credential: b64u([7]),
      client_data: b64u(Buffer.from("{}")),
      authenticator_data: b64u([5]),
      signature: b64u([4]),
      user_handle: "",
    },
  });
  assert.equal((await picked).id, b64u([7]));

  // The page's own abort.
  const controller = new AbortController();
  const aborted = win.navigator.credentials.get({ ...suggestions(), signal: controller.signal });
  await tick();
  controller.abort();
  await assert.rejects(aborted, (error) => error.name === "AbortError");
  assert.equal(posted.at(-1).direction, "cancel");
  // Nothing waits any more: the next request ends nothing.
  win.navigator.credentials.get({ publicKey: { challenge: new Uint8Array([3]) } });
  await tick();
  assert.equal(posted.at(-1).direction, "ask");
  assert.equal(posted.at(-2).direction, "cancel");
});

test("a refusal is the WebAuthn error the page expects, and an abort is told to Vault", async () => {
  const { win, posted, answer } = page();
  const options = { publicKey: { challenge: new Uint8Array([1]) } };
  const refused = win.navigator.credentials.get(options);
  await tick();
  answer({ error: "NotAllowedError" });
  await assert.rejects(refused, (error) => error.name === "NotAllowedError");
  const exists = win.navigator.credentials.create({
    publicKey: { challenge: new Uint8Array([1]), user: { id: new Uint8Array([1]), name: "me" } },
  });
  await tick();
  answer({ error: "InvalidStateError" });
  await assert.rejects(exists, (error) => error.name === "InvalidStateError");
  // Something else named: still only "not allowed".
  const odd = win.navigator.credentials.get(options);
  await tick();
  answer({ error: "toString" });
  await assert.rejects(odd, (error) => error.name === "NotAllowedError");

  const controller = new AbortController();
  const aborted = win.navigator.credentials.get({ ...options, signal: controller.signal });
  await tick();
  controller.abort();
  await assert.rejects(aborted, (error) => error.name === "AbortError");
  assert.equal(posted.at(-1).direction, "cancel");
  assert.equal(posted.at(-1).id, posted.at(-2).id);
});

// ---- the worker, between pages, its window and the app ----
//
// A stand-in browser (tabs, windows, settings, messages to one document by its id) and a
// stand-in app answer the worker. Each page's document runs the real relay (passkeys.js) in
// a sandbox of its own, so "does this document still wait for that request?" is answered by
// the relay itself.

const RELAY = readFileSync(new URL("../passkeys.js", import.meta.url), "utf8");
const AGENT = readFileSync(new URL("../agent.js", import.meta.url), "utf8");
const WINDOW_SCRIPT = readFileSync(new URL("../passkey.js", import.meta.url), "utf8");
const MESSAGES = JSON.parse(readFileSync(new URL("../_locales/en/messages.json", import.meta.url), "utf8"));

const hmacKey = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, [
  "sign",
]);
const soon = (work) => setTimeout(work, 0);
// The connection key in IndexedDB (link.js), here a test key.
globalThis.indexedDB = {
  open() {
    const opening = {};
    soon(() => {
      opening.result = {
        transaction: () => ({
          objectStore: () => ({
            get: () => {
              const getting = {};
              soon(() => {
                getting.result = hmacKey;
                getting.onsuccess();
              });
              return getting;
            },
          }),
        }),
        close() {},
      };
      opening.onsuccess();
    });
    return opening;
  },
};

const browser = {
  tabs: new Map(),
  /** Documents by the browser's id: the tab they are in, and their relay's message listener. */
  documents: new Map(),
  windows: [],
  removed: [],
  asked: [],
  answers: {},
  local: {},
  heard: { windowRemoved: [], tabRemoved: [], tabUpdated: [], storage: [] },
};
let nextWindow = 100;
globalThis.chrome = {
  runtime: {
    getURL: (path) => `chrome-extension://vault/${path.replace(/^\//, "")}`,
    // The app: the sealed request opened, answered from `browser.answers` by its type, sealed
    // to the request as the app does.
    sendNativeMessage: async (_host, envelope) => {
      const request = openRequest(envelope);
      browser.asked.push(request);
      const answer = browser.answers[request.type];
      return sealed(envelope, typeof answer === "function" ? await answer(request) : (answer ?? { type: "error", code: "bad_request" }));
    },
  },
  windows: {
    get: async () => ({ left: 0, top: 0, width: 1200 }),
    create: async ({ url }) => {
      const opened = { id: nextWindow++, url };
      browser.windows.push(opened);
      return opened;
    },
    remove: async (id) => {
      browser.removed.push(id);
    },
    onRemoved: { addListener: (listener) => browser.heard.windowRemoved.push(listener) },
  },
  tabs: {
    get: async (id) => {
      const tab = browser.tabs.get(id);
      if (!tab) throw new Error("No tab with id");
      return { ...tab };
    },
    // Only to a document still there, in that tab, as the browser does with `documentId`.
    sendMessage: async (tabId, message, options) => {
      const doc = browser.documents.get(options?.documentId);
      if (!doc || doc.tabId !== tabId) throw new Error("Could not establish connection. Receiving end does not exist.");
      return new Promise((resolve) => {
        doc.onMessage?.(message, {}, resolve);
        setImmediate(() => resolve(undefined));
      });
    },
    onRemoved: { addListener: (listener) => browser.heard.tabRemoved.push(listener) },
    onUpdated: { addListener: (listener) => browser.heard.tabUpdated.push(listener) },
  },
  storage: {
    local: {
      get: async (key) => ({ [key]: browser.local[key] }),
      set: async (values) => {
        const changes = {};
        for (const [key, value] of Object.entries(values)) {
          changes[key] = { oldValue: browser.local[key], newValue: value };
          browser.local[key] = value;
        }
        for (const listener of browser.heard.storage) listener(changes, "local");
      },
    },
    onChanged: { addListener: (listener) => browser.heard.storage.push(listener) },
  },
};

const worker = await import("../passkey-worker.js");

/** Waits (a few hundred turns at most) until `check()` holds. */
async function until(check, what = "it") {
  for (let i = 0; i < 400; i++) {
    if (check()) return;
    await new Promise((done) => setTimeout(done, 1));
  }
  throw new Error(`never happened: ${what}`);
}

/** A test's app answers, with nothing asked yet. */
function reset(answers) {
  browser.answers = answers;
  browser.asked.length = 0;
}

/** An answer the app gives only when `open()` is called. */
function held(answer) {
  let open;
  const gate = new Promise((done) => {
    open = done;
  });
  return { answer: () => gate.then(() => answer), open };
}

let nextTab = 1;
let nextDocument = 1;

/** IntersectionObserverEntry as a browser that reports a frame's visibility has it (v2). */
class VouchingEntry {
  get isVisible() {
    return false;
  }
}

/**
 * One document of a tab, with the relay (passkeys.js) in it. `restarted`: the worker answers
 * a field's suggestions with "waits" and then forgets them, as one the browser stopped since.
 * `vouches`: the browser reports a frame's visibility (Firefox doesn't). `webdriver`: the
 * browser says a program drives it; `agent`: the person said an agent uses it (agent.js).
 */
function load(tabId, url, { restarted = false, vouches = true, documentOrigin, webdriver = false, agent = false } = {}) {
  const documentId = `doc-${nextDocument++}`;
  const origin = new URL(url).origin;
  const heard = { message: [], pagehide: [] };
  const answers = new Map();
  const win = {
    location: { origin },
    origin: documentOrigin ?? origin,
    IntersectionObserverEntry: vouches ? VouchingEntry : class {},
    navigator: { webdriver },
    addEventListener: (type, listener) => heard[type]?.push(listener),
    postMessage: (data) => answers.set(data.id, data.answer),
    chrome: {
      storage: {
        local: { get: async (key) => ({ [key]: key === "vaultAgent" ? agent : browser.local[key] }) },
        onChanged: { addListener: (listener) => browser.heard.storage.push(listener) },
      },
      runtime: {
        // To the background worker, a moment later, as the browser relays it.
        sendMessage: async (message) => {
          await new Promise((done) => setImmediate(done));
          const tab = await chrome.tabs.get(tabId);
          if (message.kind === "passkey" && restarted && message.request.conditional) return { waits: true };
          if (message.kind === "passkey") {
            return worker.passkeyFromPage(tab, String(message.id), message.request, documentId);
          }
          if (message.kind === "passkey-cancel") worker.passkeyCancelled(tabId, String(message.id));
          return undefined;
        },
        onMessage: {
          addListener: (listener) => {
            browser.documents.get(documentId).onMessage = listener;
          },
        },
      },
    },
  };
  win.window = win;
  browser.documents.set(documentId, { tabId });
  vm.createContext(win);
  vm.runInContext(AGENT, win);
  vm.runInContext(RELAY, win);
  // The page's own global, as the relay sees it (`window`).
  const inner = vm.runInContext("globalThis", win);
  const post = (data) => {
    for (const listener of heard.message) listener({ source: inner, origin, data: { channel: "vault-passkeys", ...data } });
  };
  return {
    documentId,
    ask: (id, request) => post({ direction: "ask", id, request }),
    cancel: (id) => post({ direction: "cancel", id }),
    /** What passkeys.js tells content.js: the request for a field's suggestions that waits. */
    waiting: () => vm.runInContext("VaultPasskeys", win).waiting(),
    /** The page goes away. `quietly`: its last word (the relay's cancel) never arrives. */
    leave: ({ quietly = false } = {}) => {
      if (!quietly) for (const listener of heard.pagehide) listener({});
      browser.documents.delete(documentId);
    },
    answer: (id) => answers.get(id),
  };
}

/** A tab on `url`; `navigate` loads another document in it. */
function openTab(url, options) {
  const id = nextTab++;
  browser.tabs.set(id, { id, url, windowId: 1 });
  const tab = { id, doc: load(id, url, options), now: () => chrome.tabs.get(id) };
  tab.navigate = (next, how) => {
    tab.doc.leave(how);
    browser.tabs.get(id).url = next;
    for (const listener of browser.heard.tabUpdated) listener(id, { url: next });
    tab.doc = load(id, next);
  };
  return tab;
}

/** The passkey window opened after `count` others; `say` is a message from it. */
async function windowAfter(count) {
  await until(() => browser.windows.length > count, "the window opens");
  const opened = browser.windows[count];
  const token = new URL(opened.url).searchParams.get("ask");
  const say = (kind, extra = {}, from = opened.url) =>
    worker.passkeyFromWindow({ kind, token, ...extra }, { url: from });
  return { ...opened, token, say };
}

const PAGE_URL = "https://accounts.example.com/sign-in";
const PAGE_ORIGIN = "https://accounts.example.com";
const CREATE = { kind: "create", rpId: "example.com", challenge: "AQ", userId: "Kg", userName: "me@example.com" };
const GET = { kind: "get", rpId: "example.com", challenge: "AQ" };
const LISTED = {
  type: "passkeys",
  origin: PAGE_ORIGIN,
  rp_id: "example.com",
  check: "app",
  hello: false,
  items: [{ id: "item-1", credential: "Y3JlZA", title: "Example", user_name: "me@example.com", display_name: "", locked: false }],
};
const ATTESTATION = {
  type: "attestation",
  origin: PAGE_ORIGIN,
  credential: "bmV3",
  client_data: "e30",
  attestation_object: "oA",
  authenticator_data: "AQ",
  public_key: "MFk",
  algorithm: -7,
};
const ASSERTION = {
  type: "assertion",
  origin: PAGE_ORIGIN,
  credential: "Y3JlZA",
  client_data: "e30",
  authenticator_data: "AQ",
  signature: "c2ln",
  user_handle: "dQ",
};
const madeAny = () => browser.asked.some((request) => request.type === "passkey_create" || request.type === "passkey_get");

test("a sandboxed document relays nothing to Vault", async () => {
  const asked = browser.asked.length;
  const windows = browser.windows.length;
  const tab = openTab(PAGE_URL, { documentOrigin: "null" });
  tab.doc.ask("1", GET);
  for (let i = 0; i < 5; i++) await new Promise((done) => setImmediate(done));
  assert.equal(tab.doc.answer("1"), undefined, "no relay listens there");
  assert.equal(browser.asked.length, asked, "the app is asked nothing");
  assert.equal(browser.windows.length, windows, "no window opens");
});

test("the worker takes only plain, bounded requests", async () => {
  const { cleaned, fromPasskeyWindow } = worker;
  assert.deepEqual(cleaned({ kind: "get", challenge: "AQ", rpId: "example.com", allow: ["a", 5, "b"] }), {
    kind: "get",
    rpId: "example.com",
    challenge: "AQ",
    allow: ["a", "b"],
    userVerification: "preferred",
  });
  // What the site asks about verifying the person: kept when known, "preferred" otherwise.
  for (const [asked, kept] of [["required", "required"], ["discouraged", "discouraged"], ["sometimes", "preferred"], [7, "preferred"]]) {
    assert.equal(cleaned({ kind: "get", challenge: "AQ", userVerification: asked }).userVerification, kept);
  }
  assert.equal(cleaned({ kind: "get", challenge: "" }), null);
  assert.equal(cleaned({ kind: "get", challenge: "x".repeat(1401) }), null);
  assert.equal(cleaned({ kind: "sign", challenge: "AQ" }), null);
  assert.equal(cleaned({ kind: "create", challenge: "AQ", userName: "me" }), null, "no user id");
  const made = cleaned({
    kind: "create",
    challenge: "AQ",
    userId: "Kg",
    userName: "me",
    algorithms: [-7, "x", 1.5, -257],
  });
  assert.deepEqual(made.algorithms, [-7, -257]);
  assert.equal(made.rpId, "");
  assert.equal(made.userVerification, "preferred");
  assert.equal(cleaned({ kind: "get", challenge: "AQ", conditional: true }).conditional, true);
  assert.equal(cleaned({ kind: "get", challenge: "AQ", conditional: "yes" }).conditional, undefined);
  assert.equal(cleaned({ ...made, kind: "create", conditional: true }).conditional, undefined);
  assert.ok(fromPasskeyWindow({ url: "chrome-extension://vault/passkey.html?ask=1" }));
  assert.ok(!fromPasskeyWindow({ url: "https://example.com/passkey.html" }));
  assert.ok(!fromPasskeyWindow({}));
});

test("a request is taken before the app is asked: a second one is refused, a cancel ends it", async () => {
  const lookup = held(LISTED);
  reset({ passkeys: lookup.answer });
  const windows = browser.windows.length;
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  await until(() => browser.asked.some((request) => request.type === "passkeys"), "the app is asked");
  // While the app looks, the same tab asks again: one request per tab, from the start.
  tab.doc.ask("r2", CREATE);
  await until(() => tab.doc.answer("r2"), "the second request is answered");
  assert.equal(tab.doc.answer("r2").error, "NotAllowedError");
  // The page cancels while the app still looks: no window opens for it afterwards.
  tab.doc.cancel("r1");
  await until(() => tab.doc.answer("r1"), "the cancel is answered");
  assert.equal(tab.doc.answer("r1").error, "AbortError");
  lookup.open();
  await new Promise((done) => setTimeout(done, 20));
  assert.equal(browser.windows.length, windows, "no window for a cancelled request");
});

test("nothing is made for a document that is gone, even at the same address", async () => {
  reset({ passkeys: LISTED, passkey_create: ATTESTATION });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  // Another document of the same site (a reload, a form post), and the old one's last word lost.
  tab.navigate(`${PAGE_ORIGIN}/sign-in?step=2`, { quietly: true });
  browser.asked.length = 0;
  assert.deepEqual(await win.say("passkey-save"), { code: "page_changed" });
  assert.ok(!madeAny(), "the app made nothing");
  assert.ok(browser.removed.includes(win.id), "the window closes");
});

test("a request the page cancelled gets nothing made, even with the cancel still on its way", async () => {
  reset({ passkeys: LISTED, passkey_create: ATTESTATION });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  browser.asked.length = 0;
  // The page aborts; the relay passes that on a moment later, after the click is in.
  tab.doc.cancel("r1");
  const reply = await win.say("passkey-save");
  assert.ok(!madeAny(), "the app made nothing");
  assert.ok(reply.code === "page_changed" || reply.gone, "nothing was sent");
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.ok(["AbortError", "NotAllowedError"].includes(tab.doc.answer("r1").error));
});

test("a passkey made after the page went away is told in the window, not lost", async () => {
  const making = held(ATTESTATION);
  reset({ passkeys: LISTED, passkey_create: making.answer });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  const old = tab.doc;
  const saving = win.say("passkey-save");
  await until(() => browser.asked.some((request) => request.type === "passkey_create"), "the app is making it");
  tab.navigate("https://other.example/");
  making.open();
  assert.deepEqual(await saving, { code: "made_not_sent" });
  assert.ok(!browser.removed.includes(win.id), "the window stays to say so");
  assert.ok(!old.answer("r1")?.attestation, "the page never got it");
  // Close, and it is gone.
  assert.deepEqual(await win.say("passkey-no"), { gone: true });
});

test("passkeys turned off while the window is open: the browser takes the request, nothing is made", async () => {
  reset({ passkeys: LISTED, passkey_create: ATTESTATION });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  browser.asked.length = 0;
  await chrome.storage.local.set({ vaultPasskeys: false });
  try {
    await until(() => tab.doc.answer("r1"), "the page is answered");
    assert.deepEqual(tab.doc.answer("r1"), { fallback: true });
    assert.ok(browser.removed.includes(win.id));
    assert.deepEqual(await win.say("passkey-save"), { gone: true });
    assert.ok(!madeAny());
  } finally {
    await chrome.storage.local.set({ vaultPasskeys: true });
  }

  // Turned off while the app is at work: what it made isn't sent, and the window says so.
  const making = held(ATTESTATION);
  browser.answers.passkey_create = making.answer;
  tab.doc.ask("r2", CREATE);
  const second = await windowAfter(browser.windows.length);
  const saving = second.say("passkey-save");
  await until(() => browser.asked.some((request) => request.type === "passkey_create"), "the app is making it");
  await chrome.storage.local.set({ vaultPasskeys: false });
  try {
    making.open();
    assert.deepEqual(await saving, { code: "made_not_sent" });
    await until(() => tab.doc.answer("r2"), "the page is answered");
    assert.equal(tab.doc.answer("r2").error, "NotAllowedError");
  } finally {
    await chrome.storage.local.set({ vaultPasskeys: true });
  }
});

test("only the window opened for a request speaks for it", async () => {
  reset({ passkeys: LISTED, passkey_create: ATTESTATION });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  browser.asked.length = 0;
  const elsewhere = "chrome-extension://vault/passkey.html?ask=another-request";
  assert.deepEqual(await win.say("passkey-save", {}, elsewhere), { gone: true });
  assert.deepEqual(await win.say("passkey-window", {}, "chrome-extension://vault/popup.html"), { gone: true });
  assert.ok(!madeAny());
  assert.deepEqual(await win.say("passkey-no"), { gone: true });
});

test("a choice made stands if the window is closed while the app works: the page gets its passkey", async () => {
  const making = held(ATTESTATION);
  reset({ passkeys: LISTED, passkey_create: making.answer });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  const saving = win.say("passkey-save");
  await until(() => browser.asked.some((request) => request.type === "passkey_create"), "the app is making it");
  for (const listener of browser.heard.windowRemoved) listener(win.id);
  making.open();
  assert.deepEqual(await saving, { done: true });
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.equal(tab.doc.answer("r1").attestation.credential, ATTESTATION.credential);
});

test("the window names the page that asks and the site; a sign-in goes to that page", async () => {
  reset({ passkeys: LISTED, passkey_get: ASSERTION });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", GET);
  const win = await windowAfter(browser.windows.length);
  const shown = await win.say("passkey-window");
  assert.equal(shown.host, "accounts.example.com");
  assert.equal(shown.site, "example.com");
  assert.deepEqual(await win.say("passkey-use", { id: "item-1", credential: "Y3JlZA" }), { done: true });
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.equal(tab.doc.answer("r1").assertion.signature, ASSERTION.signature);
  assert.ok(browser.removed.includes(win.id));
});

test("while the vault is locked the window names the page alone, never the site the page wrote", async () => {
  reset({ passkeys: { type: "error", code: "locked" } });
  const tab = openTab("https://evil.example/sign-in");
  tab.doc.ask("r1", { ...GET, rpId: "bank.example" });
  const win = await windowAfter(browser.windows.length);
  const shown = await win.say("passkey-window");
  assert.equal(shown.locked, true);
  assert.equal(shown.host, "evil.example");
  assert.equal(shown.site, "evil.example", "the app hasn't checked bank.example");
  assert.ok(!JSON.stringify(shown).includes("bank.example"));
  // Words of the page's choosing don't reach the window either.
  assert.deepEqual(await win.say("passkey-no"), { gone: true });
  tab.doc.ask("r2", { ...GET, rpId: "Your bank asks you to confirm" });
  const second = await windowAfter(browser.windows.length);
  assert.equal((await second.say("passkey-window")).site, "evil.example");
  // Unlocked, the site is named as the app checked it.
  assert.deepEqual(await second.say("passkey-no"), { gone: true });
  browser.answers.passkeys = LISTED;
  const other = openTab(PAGE_URL);
  other.doc.ask("r3", GET);
  const third = await windowAfter(browser.windows.length);
  assert.equal((await third.say("passkey-window")).site, "example.com");
  assert.deepEqual(await third.say("passkey-no"), { gone: true });
});

test("a passkey that replaced the one kept before, but never reached the page, is said so", async () => {
  const making = held({ ...ATTESTATION, replaced: true });
  reset({ passkeys: LISTED, passkey_create: making.answer });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", CREATE);
  const win = await windowAfter(browser.windows.length);
  const saving = win.say("passkey-save");
  await until(() => browser.asked.some((request) => request.type === "passkey_create"), "the app is making it");
  tab.navigate("https://other.example/");
  making.open();
  assert.deepEqual(await saving, { code: "made_not_sent", replaced: true });
  assert.deepEqual(await win.say("passkey-no"), { gone: true });
});

// ---- a field's suggestions (`mediation: "conditional"`) ----

const SUGGEST = { ...GET, conditional: true };
const PICK = { id: "item-1", credential: "Y3JlZA" };
const pause = (ms = 10) => new Promise((done) => setTimeout(done, ms));

test("a field's suggestions wait in the page until a passkey is picked under a field", async () => {
  reset({ passkeys: LISTED, passkey_get: ASSERTION });
  const windows = browser.windows.length;
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", SUGGEST);
  await until(() => tab.doc.waiting(), "the request waits in the page");
  assert.equal(tab.doc.answer("r1"), undefined, "the page is not answered");
  assert.equal(browser.windows.length, windows, "no window opens");
  assert.ok(!madeAny());
  // A sign-in field is focused: the frame under it lists the site's passkeys, never a key.
  assert.equal(await worker.passkeysForField(await tab.now(), tab.doc.documentId, tab.doc.waiting()), 1);
  const shown = worker.passkeySuggestions(await tab.now());
  assert.equal(shown.site, "example.com");
  assert.equal(shown.origin, PAGE_ORIGIN);
  assert.deepEqual(Object.keys(shown.items[0]).sort(), ["credential", "displayName", "id", "locked", "title", "userName"]);
  assert.equal(shown.items[0].userName, "me@example.com");
  // Only a passkey the frame listed is signed.
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), { ...PICK, credential: "other" }), { done: false });
  assert.ok(!madeAny());
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: true });
  const signed = browser.asked.find((request) => request.type === "passkey_get");
  assert.equal(signed.url, PAGE_URL, "for the tab's own address");
  assert.equal(signed.challenge, "AQ");
  assert.equal(signed.hello, false);
  // What the site asked about verifying the person goes to the app (nothing: "preferred").
  assert.equal(signed.user_verification, "preferred");
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.equal(tab.doc.answer("r1").assertion.signature, ASSERTION.signature);
  assert.equal(tab.doc.waiting(), undefined);
  assert.equal(worker.passkeySuggestions(await tab.now()), undefined, "nothing is left to pick");
  assert.equal(browser.windows.length, windows);
});

test("no passkey for the site, a locked vault, or a browser with no frame: the browser's own suggestions", async () => {
  for (const passkeys of [{ ...LISTED, items: [] }, { type: "error", code: "locked" }, { type: "error", code: "not_running" }]) {
    reset({ passkeys });
    const tab = openTab(PAGE_URL);
    tab.doc.ask("r1", SUGGEST);
    await until(() => tab.doc.answer("r1"), "the page is answered");
    assert.deepEqual(plain(tab.doc.answer("r1")), { fallback: true });
    assert.equal(tab.doc.waiting(), undefined);
  }
  // Firefox can't vouch for a frame in a page: Vault isn't even asked.
  reset({ passkeys: LISTED });
  const tab = openTab(PAGE_URL, { vouches: false });
  tab.doc.ask("r1", SUGGEST);
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.deepEqual(plain(tab.doc.answer("r1")), { fallback: true });
  assert.equal(browser.asked.length, 0);
});

test("while an agent or a program drives the browser, a field's suggestions are the browser's; Vault's window still answers", async () => {
  for (const driven of [{ webdriver: true }, { agent: true }]) {
    reset({ passkeys: LISTED, passkey_get: ASSERTION });
    const windows = browser.windows.length;
    const tab = openTab(PAGE_URL, driven);
    tab.doc.ask("r1", SUGGEST);
    await until(() => tab.doc.answer("r1"), "the page is answered");
    assert.deepEqual(plain(tab.doc.answer("r1")), { fallback: true }, JSON.stringify(driven));
    assert.equal(tab.doc.waiting(), undefined, "nothing waits for a card in the page");
    assert.equal(browser.asked.length, 0, "Vault isn't even asked");
    // A request that opens Vault's own window is still Vault's, with its usual checks.
    tab.doc.ask("r2", GET);
    await until(() => browser.windows.length > windows, "Vault's window opens");
    tab.doc.cancel("r2");
    await pause();
  }
  // Turned off again: Vault's suggestions are back.
  reset({ passkeys: LISTED });
  const tab = openTab(PAGE_URL, { agent: false });
  tab.doc.ask("r1", SUGGEST);
  await until(() => tab.doc.waiting(), "the request waits in the page");
});

test("a field's suggestions end with an abort, a later request, a navigation or passkeys turned off", async () => {
  reset({ passkeys: LISTED, passkey_get: ASSERTION });
  const tab = openTab(PAGE_URL);
  const waits = async (id) => {
    tab.doc.ask(id, SUGGEST);
    await until(() => tab.doc.waiting()?.id === id, "the request waits in the page");
    assert.equal(await worker.passkeysForField(await tab.now(), tab.doc.documentId, tab.doc.waiting()), 1);
  };

  // The page aborts: nothing is left to pick, and nothing is signed.
  await waits("r1");
  tab.doc.cancel("r1");
  await pause();
  assert.equal(tab.doc.waiting(), undefined);
  assert.equal(worker.passkeySuggestions(await tab.now()), undefined);
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false });
  assert.ok(!madeAny());

  // A later request of the page ends it (AbortError), and is taken as usual.
  await waits("r2");
  const windows = browser.windows.length;
  tab.doc.ask("r3", GET);
  await until(() => tab.doc.answer("r2"), "the waiting request is answered");
  assert.equal(tab.doc.answer("r2").error, "AbortError");
  const win = await windowAfter(windows);
  assert.equal(worker.passkeySuggestions(await tab.now()), undefined);
  assert.deepEqual(await win.say("passkey-no"), { gone: true });
  await until(() => tab.doc.answer("r3"), "the window's request is answered");

  // Passkeys turned off: the browser's own handler takes it.
  await waits("r4");
  await chrome.storage.local.set({ vaultPasskeys: false });
  try {
    await until(() => tab.doc.answer("r4"), "the page is answered");
    assert.deepEqual(plain(tab.doc.answer("r4")), { fallback: true });
    assert.equal(worker.passkeySuggestions(await tab.now()), undefined);
  } finally {
    await chrome.storage.local.set({ vaultPasskeys: true });
  }

  // The tab goes to another site: nothing is left to pick there.
  await waits("r5");
  tab.navigate("https://other.example/");
  assert.equal(worker.passkeySuggestions(await tab.now()), undefined);
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false });
  assert.ok(!madeAny());
});

test("a worker stopped meanwhile hears the request again from the page; only a page that waits is answered", async () => {
  reset({ passkeys: LISTED, passkey_get: ASSERTION });
  const tab = openTab(PAGE_URL, { restarted: true });
  tab.doc.ask("r1", SUGGEST);
  await until(() => tab.doc.waiting(), "the request waits in the page");
  assert.equal(worker.passkeySuggestions(await tab.now()), undefined, "the worker knows nothing of it");
  // A request the page doesn't hold, told by someone else: listed, but never signed.
  const made = { id: "made-up", request: SUGGEST };
  assert.equal(await worker.passkeysForField(await tab.now(), tab.doc.documentId, made), 1);
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false });
  assert.ok(!madeAny(), "nothing signed for a request no page waits for");
  // The field focused again: the page tells the request it holds.
  assert.equal(await worker.passkeysForField(await tab.now(), tab.doc.documentId, tab.doc.waiting()), 1);
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: true });
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.equal(tab.doc.answer("r1").assertion.credential, ASSERTION.credential);
  // Another document's request is no request of this one.
  tab.doc.ask("r2", SUGGEST);
  await until(() => tab.doc.waiting(), "the request waits in the page");
  assert.equal(await worker.passkeysForField(await tab.now(), "doc-elsewhere", tab.doc.waiting()), 1);
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false });
  assert.equal(tab.doc.answer("r2"), undefined);
});

test("a locked login takes the person to the window for its PIN; closing it leaves the request waiting", async () => {
  const locked = { ...LISTED, check: "pin", items: [{ ...LISTED.items[0], locked: true }] };
  let pin;
  reset({
    passkeys: locked,
    passkey_get: (request) => {
      pin = request.check;
      return request.check === "1234" ? ASSERTION : { type: "error", code: "item_locked", check: "pin" };
    },
  });
  const tab = openTab(PAGE_URL);
  tab.doc.ask("r1", SUGGEST);
  await until(() => tab.doc.waiting(), "the request waits in the page");
  await worker.passkeysForField(await tab.now(), tab.doc.documentId, tab.doc.waiting());
  const windows = browser.windows.length;
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false, popup: true });
  assert.equal(pin, undefined, "nothing typed in the page");
  const first = await windowAfter(windows);
  assert.equal((await first.say("passkey-window")).items[0].locked, true);
  // Closed (Cancel, or the window's own close): the page still waits, the frame still lists it.
  assert.deepEqual(await first.say("passkey-no"), { gone: true });
  assert.ok(browser.removed.includes(first.id));
  for (const listener of browser.heard.windowRemoved) listener(first.id);
  assert.equal(tab.doc.answer("r1"), undefined);
  assert.ok(tab.doc.waiting());
  assert.equal(worker.passkeySuggestions(await tab.now()).items.length, 1);
  // Picked again: the PIN typed in the window signs in.
  assert.deepEqual(await worker.passkeyFromFrame(await tab.now(), PICK), { done: false, popup: true });
  const second = await windowAfter(windows + 1);
  assert.deepEqual(await second.say("passkey-use", { ...PICK, check: "1234" }), { done: true });
  await until(() => tab.doc.answer("r1"), "the page is answered");
  assert.equal(tab.doc.answer("r1").assertion.signature, ASSERTION.signature);
  assert.ok(browser.removed.includes(second.id));
});

// ---- the window itself (passkey.js), on a stand-in page ----

/** passkey.js on a page of stand-in elements; the worker's replies come from `replies`. */
async function windowPage(state, replies = {}) {
  const elements = new Map();
  const element = (tag = "div") => ({
    tag,
    hidden: false,
    disabled: false,
    textContent: "",
    value: "",
    className: "",
    children: [],
    listeners: {},
    replaceChildren(...children) {
      this.children = children;
    },
    append(...children) {
      this.children.push(...children);
    },
    replaceWith() {},
    setAttribute() {},
    addEventListener(type, listener) {
      this.listeners[type] = listener;
    },
    focus() {},
    click() {
      this.listeners.click?.({});
    },
  });
  const getMessage = (key, parts = []) => {
    const entry = MESSAGES[key];
    let text = entry?.message ?? "";
    for (const [name, holder] of Object.entries(entry?.placeholders ?? {})) {
      text = text.replaceAll(`$${name.toUpperCase()}$`, parts[Number(holder.content.slice(1)) - 1] ?? "");
    }
    return text;
  };
  const sandbox = {
    document: {
      title: "",
      getElementById: (id) => {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
      },
      querySelectorAll: () => [],
      createElement: (tag) => element(tag),
      createElementNS: (_ns, tag) => element(tag),
      addEventListener() {},
    },
    location: { search: "?ask=tok" },
    URLSearchParams,
    setInterval: () => 0,
    closed: false,
    chrome: {
      i18n: { getMessage },
      runtime: {
        getURL: (path) => `chrome-extension://vault/${path.replace(/^\//, "")}`,
        sendMessage: async (message) => (message.kind === "passkey-window" ? state : (replies[message.kind] ?? {})),
      },
    },
  };
  sandbox.window = { close: () => (sandbox.closed = true) };
  vm.createContext(sandbox);
  vm.runInContext(WINDOW_SCRIPT, sandbox);
  await new Promise((done) => setTimeout(done, 5));
  return { $: (id) => sandbox.document.getElementById(id), sandbox, getMessage };
}

const WINDOW_STATE = {
  kind: "get",
  site: "example.com",
  host: "accounts.example.com",
  origin: PAGE_ORIGIN,
  locked: false,
  check: "app",
  hello: false,
  items: [{ id: "item-1", credential: "Y3JlZA", title: "Example", userName: "me@example.com", displayName: "", locked: false }],
  userName: "",
  displayName: "",
};

test("the window shows the page that asks, and the site when that is another name", async () => {
  const sub = await windowPage(WINDOW_STATE);
  assert.equal(sub.$("site").textContent, "accounts.example.com");
  assert.equal(sub.$("for").hidden, false);
  assert.equal(sub.$("for").textContent, "for example.com");
  const same = await windowPage({ ...WINDOW_STATE, host: "example.com" });
  assert.equal(same.$("site").textContent, "example.com");
  assert.equal(same.$("for").hidden, true);
  // A port is part of the page's name.
  const port = await windowPage({ ...WINDOW_STATE, host: "example.com:8443" });
  assert.equal(port.$("site").textContent, "example.com:8443");
  assert.equal(port.$("for").textContent, "for example.com");
});

test("a passkey made but not sent is said in the window, with only Close", async () => {
  const page = await windowPage(
    { ...WINDOW_STATE, kind: "create", items: [], userName: "me@example.com" },
    { "passkey-save": { code: "made_not_sent" }, "passkey-no": { gone: true } },
  );
  page.$("yes").click();
  await new Promise((done) => setTimeout(done, 5));
  assert.equal(page.$("problem").textContent, page.getMessage("passkeyMadeNotSent"));
  assert.equal(page.$("yes").hidden, true);
  assert.equal(page.$("other").hidden, true);
  assert.equal(page.$("no").textContent, page.getMessage("passkeyClose"));
  assert.equal(page.sandbox.closed, false, "it waits for the person");
  page.$("no").click();
  await new Promise((done) => setTimeout(done, 5));
  assert.equal(page.sandbox.closed, true);

  // It took the place of the passkey kept before: that one is gone too, and the window says so.
  const replaced = await windowPage(
    { ...WINDOW_STATE, kind: "create", items: [], userName: "me@example.com" },
    { "passkey-save": { code: "made_not_sent", replaced: true } },
  );
  replaced.$("yes").click();
  await new Promise((done) => setTimeout(done, 5));
  assert.equal(replaced.$("problem").textContent, replaced.getMessage("passkeyMadeNotSentReplaced"));
});
