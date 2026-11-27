// The app's side of the sealed link, for the tests' stand-in app: opening a request and sealing
// its answer as crates/browser/src/pairing.rs does, with Node's own crypto (apart from link.js,
// which uses WebCrypto).

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

/** Answers the app gives before any trust: they travel plain. */
const PLAIN = new Set(["not_paired", "not_running", "bad_request"]);

/** One block of HKDF-SHA-256-Expand: HMAC(key, info ‖ 0x01). */
const expand = (key, info) => createHmac("sha256", key).update(info).update(Buffer.from([1])).digest();

function littleEndian(counter) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(counter));
  return bytes;
}

/** The request inside `envelope` (what link.js `seal` sends); throws when it doesn't open. */
export function openRequest(envelope, key = Buffer.alloc(32)) {
  const data = Buffer.from(envelope.data, "base64");
  const decipher = createDecipheriv("aes-256-gcm", expand(key, "vault-browser/requests"), data.subarray(0, 12));
  decipher.setAAD(Buffer.concat([Buffer.from("vault-browser/request"), littleEndian(envelope.counter)]));
  decipher.setAuthTag(data.subarray(data.length - 16));
  const text = Buffer.concat([decipher.update(data.subarray(12, data.length - 16)), decipher.final()]);
  return JSON.parse(text.toString("utf8"));
}

/** `answer` as the app sends it back for `envelope`, under `nonce` (fresh unless given). */
export function sealed(envelope, answer, key = Buffer.alloc(32), nonce = randomBytes(12)) {
  if (answer?.type === "error" && PLAIN.has(answer.code)) return answer;
  const requestNonce = Buffer.from(envelope.data, "base64").subarray(0, 12);
  const cipher = createCipheriv("aes-256-gcm", expand(key, "vault-browser/answers"), nonce);
  cipher.setAAD(Buffer.concat([Buffer.from("vault-browser/answer"), littleEndian(envelope.counter), requestNonce]));
  const body = Buffer.concat([cipher.update(JSON.stringify(answer), "utf8"), cipher.final(), cipher.getAuthTag()]);
  return { type: "sealed", data: Buffer.concat([nonce, body]).toString("base64") };
}
