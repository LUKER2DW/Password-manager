// Tests for Vault's place in front of a page's passkey requests: `node --test apps/extension/test`.
// The page script runs in a sandbox standing in for a page: its own navigator.credentials (the
// "browser"), window messages, and the WebAuthn types; no browser and no packages are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const PAGE_SCRIPT = readFileSync(new URL("../passkeys-page.js", import.meta.url), "utf8");
const ORIGIN = "https://login.example.com";

/** A page with passkeys-page.js loaded; `posted` is what it sent to the content script. */
function page() {
  const listeners = [];
  const posted = [];
  const browserCalls = [];
  const win = {
    location: { origin: ORIGIN },
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
  // The autofill list of a field, a security key, and anything without publicKey: never asked.
  const conditional = { mediation: "conditional", publicKey: { challenge: new Uint8Array([1]) } };
  assert.equal(await win.navigator.credentials.get(conditional), "from the browser");
  const key = {
    publicKey: {
      challenge: new Uint8Array([1]),
      user: { id: new Uint8Array([1]), name: "me" },
      authenticatorSelection: { authenticatorAttachment: "cross-platform" },
    },
  };
  assert.equal(await win.navigator.credentials.create(key), "from the browser");
  assert.equal(await win.navigator.credentials.get({ password: true }), "from the browser");
  assert.equal(posted.length, 1);
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

test("the worker takes only plain, bounded requests", async () => {
  globalThis.chrome = {
    runtime: { getURL: (path) => `chrome-extension://vault/${path.replace(/^\//, "")}` },
    windows: { onRemoved: { addListener() {} } },
    tabs: { onRemoved: { addListener() {} }, onUpdated: { addListener() {} } },
  };
  const { cleaned, fromPasskeyWindow } = await import("../passkey-worker.js");
  assert.deepEqual(cleaned({ kind: "get", challenge: "AQ", rpId: "example.com", allow: ["a", 5, "b"] }), {
    kind: "get",
    rpId: "example.com",
    challenge: "AQ",
    allow: ["a", "b"],
  });
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
  assert.ok(fromPasskeyWindow({ url: "chrome-extension://vault/passkey.html?ask=1" }));
  assert.ok(!fromPasskeyWindow({ url: "https://example.com/passkey.html" }));
  assert.ok(!fromPasskeyWindow({}));
});
