// Tests for the sealed link to the app and the key agreement: `node --test apps/extension/test`.

import assert from "node:assert/strict";
import { createECDH, createHash, createHmac, hkdfSync, webcrypto } from "node:crypto";
import { test } from "node:test";

import { agree, freshCounter, opened, seal } from "../link.js";
import { openRequest, sealed } from "./sealed.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const hmacKey = (raw) => webcrypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

// The vectors of crates/browser/src/pairing.rs, computed apart with Node's `crypto` (OpenSSL).
const RAW = Buffer.alloc(32, 7);
const COUNTER = 1_800_000_000_123;
const NONCE = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
const ANSWER_NONCE = Buffer.from(Array.from({ length: 12 }, (_, i) => i + 0x21));
const REQUEST_DATA =
  "AQIDBAUGBwgJCgsMHtP2/rQqZUHHS+svo50x6RGFhF5yN20hcEMv/K9x2HiZiTpKgUmu+dECSD6oT/oj2BS+bMkb0SZ2T252VA==";
const ANSWER_DATA = "ISIjJCUmJygpKissm6LbrMi/r6elsr/MgqvvVY5ATBtOVbI6FYJcbhUi3IqbMwXbdel3kYt6GF0=";

test("counters follow the clock and differ when made at once", () => {
  const before = Date.now() * 1000;
  const counters = Array.from({ length: 200 }, freshCounter);
  for (const counter of counters) {
    assert.ok(Number.isSafeInteger(counter));
    assert.ok(counter >= before && counter < (Date.now() + 1) * 1000);
  }
  assert.ok(new Set(counters).size > 150, "random part");
});

test("a request is sealed with its counter, and nothing of it is readable", async () => {
  const key = await hmacKey(RAW);
  const request = { type: "logins", url: "https://github.com/" };
  const sent = await seal(key, request, COUNTER, NONCE);
  assert.deepEqual(sent.message, { type: "sealed", counter: COUNTER, data: REQUEST_DATA });
  assert.equal(sent.counter, COUNTER);
  assert.deepEqual([...sent.nonce], [...NONCE]);
  assert.deepEqual(openRequest(sent.message, RAW), request);

  const fresh = await seal(key, request);
  assert.ok(!JSON.stringify(fresh.message).includes("github"));
  assert.notEqual(fresh.message.data, (await seal(key, request, fresh.counter)).message.data, "fresh nonces");
  assert.throws(() => openRequest({ ...fresh.message, counter: fresh.counter + 1 }, RAW), "the counter is bound");
  assert.throws(() => openRequest(fresh.message, Buffer.alloc(32, 8)), "another connection");
});

test("an answer is read only when sealed to its own request", async () => {
  const key = await hmacKey(RAW);
  const sent = { counter: COUNTER, nonce: NONCE, message: { counter: COUNTER, data: REQUEST_DATA } };
  const answer = { type: "logins", items: [] };
  assert.deepEqual(await opened(key, sent, { type: "sealed", data: ANSWER_DATA }), answer);
  assert.deepEqual(sealed(sent.message, answer, RAW, ANSWER_NONCE), { type: "sealed", data: ANSWER_DATA });

  const bad = { type: "error", code: "bad_answer" };
  const changed = Buffer.from(ANSWER_DATA, "base64");
  changed[20] ^= 1;
  // Changed, answering another request, unsealed, cut short, or not base64.
  assert.deepEqual(await opened(key, sent, { type: "sealed", data: changed.toString("base64") }), bad);
  assert.deepEqual(await opened(key, { ...sent, counter: COUNTER + 1 }, { type: "sealed", data: ANSWER_DATA }), bad);
  assert.deepEqual(await opened(key, { ...sent, nonce: new Uint8Array(12) }, { type: "sealed", data: ANSWER_DATA }), bad);
  assert.deepEqual(await opened(key, sent, answer), bad, "a plain answer");
  assert.deepEqual(await opened(key, sent, { type: "error", code: "item_locked" }), bad, "only a few errors come plain");
  assert.deepEqual(await opened(key, sent, { type: "sealed", data: "AAEC" }), bad);
  assert.deepEqual(await opened(key, sent, { type: "sealed", data: "%%%" }), bad);
  assert.deepEqual(await opened(key, sent, undefined), bad);
  // A request sent back as if it were the answer.
  assert.deepEqual(await opened(key, sent, { type: "sealed", data: REQUEST_DATA }), bad);
  assert.deepEqual(await opened(await hmacKey(Buffer.alloc(32, 8)), sent, { type: "sealed", data: ANSWER_DATA }), bad);
  // What comes before any trust passes plain, and nothing more of it is kept.
  for (const code of ["not_paired", "not_running", "bad_request"]) {
    assert.deepEqual(await opened(key, sent, { type: "error", code, extra: "x" }), { type: "error", code });
  }
  // A real round trip, with text that needs escaping and a long answer.
  const request = await seal(key, { type: "logins", url: "https://github.com/" });
  const long = { type: "logins", items: Array.from({ length: 3000 }, (_, i) => ({ id: `${i}`, title: 'Quote "and" \\ é' })) };
  assert.deepEqual(await opened(key, request, sealed(request.message, long, RAW)), long);
});

/** A P-256 key pair from a fixed secret (all bytes `byte`), as WebCrypto keys. */
async function fixedPair(byte) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.alloc(32, byte));
  const point = ecdh.getPublicKey(null, "uncompressed");
  const jwk = {
    kty: "EC",
    crv: "P-256",
    d: Buffer.alloc(32, byte).toString("base64url"),
    x: point.subarray(1, 33).toString("base64url"),
    y: point.subarray(33).toString("base64url"),
  };
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  return {
    privateKey: await webcrypto.subtle.importKey("jwk", jwk, algorithm, false, ["deriveBits"]),
    publicKey: await webcrypto.subtle.importKey("raw", point, algorithm, true, []),
  };
}

/** The app's side of the key agreement (secret 22×32), with Node's own ECDH and HKDF. */
function standInApp() {
  const app = createECDH("prime256v1");
  app.setPrivateKey(Buffer.alloc(32, 0x22));
  const ours = app.getPublicKey(null, "uncompressed");
  const heard = [];
  let commit;
  return {
    heard,
    send: async (message) => {
      heard.push(message);
      if (message.type === "pair") {
        commit = message.commit;
        return { type: "pair_offer", key: ours.toString("hex") };
      }
      const theirs = Buffer.from(message.key, "hex");
      const expected = createHash("sha256").update("vault-browser/pairing-commit").update(theirs).digest("hex");
      if (message.type !== "pair_key" || expected !== commit) return { type: "error", code: "bad_request" };
      const key = Buffer.from(hkdfSync("sha256", app.computeSecret(theirs), Buffer.concat([theirs, ours]), "vault-browser/pairing", 32));
      heard.key = key;
      return { type: "pair_wait" };
    },
  };
}

test("connecting agrees on a key that never travels, and on the code", async () => {
  const app = standInApp();
  let kept;
  const agreed = await agree(app.send, async (key, code) => (kept = { key, code, revealed: app.heard.length > 1 }), await fixedPair(0x11));
  assert.deepEqual(agreed, { code: "74At LSYM" });
  assert.equal(kept.code, "74At LSYM");
  assert.equal(kept.revealed, false, "kept before ours is revealed");
  // The vectors of pairing.rs: the commitment, our public key, the key both sides hold.
  assert.deepEqual(app.heard[0], { type: "pair", commit: "56135d400b11486d786cc15da678e0498718808a61cd417e7bc3b40405d108e8" });
  assert.deepEqual(app.heard[1], {
    type: "pair_key",
    key: "040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794",
  });
  assert.equal(app.heard.key.toString("hex"), "ea6aae30def35019834e7828de518d6037a7c2d4cd2e1ef596215828f5e0e3ed");
  for (const message of app.heard) assert.ok(!JSON.stringify(message).includes(app.heard.key.toString("hex")));
  // The key kept is that key, as a key object no script can read.
  const data = Buffer.from("vault-browser/answers\u0001");
  assert.equal(
    Buffer.from(await webcrypto.subtle.sign("HMAC", kept.key, data)).toString("hex"),
    createHmac("sha256", app.heard.key).update(data).digest("hex"),
  );
  assert.equal(kept.key.extractable, false);
  await assert.rejects(webcrypto.subtle.exportKey("raw", kept.key));
  // A fresh run makes a fresh key pair and another code.
  const again = standInApp();
  assert.ok((await agree(again.send, async () => {})).code);
  assert.notEqual(again.heard[1].key, app.heard[1].key);
});

test("connecting stops at an app that refuses or answers something else", async () => {
  const keepNothing = async () => assert.fail("nothing to keep");
  // An app older than the key agreement doesn't understand it.
  assert.deepEqual(await agree(async () => ({ type: "error", code: "bad_request" }), keepNothing), { error: "bad_request" });
  // Something that isn't the app's public key.
  for (const key of ["04", "zz".repeat(65), "05" + "00".repeat(64), "04" + "00".repeat(64)]) {
    assert.deepEqual(await agree(async () => ({ type: "pair_offer", key }), keepNothing), { error: "bad_answer" });
  }
  // A key handed over whole, as an older app does: not taken.
  assert.deepEqual(await agree(async () => ({ type: "pairing", key: "ab".repeat(32), code: "123 456" }), keepNothing), {
    error: "bad_answer",
  });
  // The app refuses the key revealed.
  const app = standInApp();
  const refusing = async (message) => (message.type === "pair_key" ? { type: "error", code: "bad_request" } : app.send(message));
  assert.deepEqual(await agree(refusing, async () => {}), { error: "bad_request" });
});
