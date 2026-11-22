// Tests for the proof put on every request: `node --test apps/extension/test`.

import assert from "node:assert/strict";
import { createHmac, webcrypto } from "node:crypto";
import { test } from "node:test";

import { freshCounter, sign } from "../link.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

test("counters follow the clock and differ when made at once", () => {
  const before = Date.now() * 1000;
  const counters = Array.from({ length: 200 }, freshCounter);
  for (const counter of counters) {
    assert.ok(Number.isSafeInteger(counter));
    assert.ok(counter >= before && counter < (Date.now() + 1) * 1000);
  }
  assert.ok(new Set(counters).size > 150, "random part");
});

test("a request is signed over its counter and its exact text", async () => {
  const raw = Buffer.alloc(32, 7);
  const key = await webcrypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const request = { type: "logins", url: "https://github.com/" };
  const signed = await sign(key, request, 1_800_000_000_123);

  assert.equal(signed.type, "signed");
  assert.equal(signed.counter, 1_800_000_000_123);
  assert.deepEqual(JSON.parse(signed.body), request);

  // The same bytes the app checks: counter as 8 bytes little-endian, then the text.
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64LE(1_800_000_000_123n);
  const expected = createHmac("sha256", raw).update(counter).update(signed.body).digest("hex");
  assert.equal(signed.mac, expected);

  const later = await sign(key, request, 1_800_000_000_124);
  assert.notEqual(later.mac, signed.mac, "another counter, another proof");
});
