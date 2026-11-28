// The connection key shared with the desktop app, the sealing of every request, and the
// opening of every answer (crates/browser/src/pairing.rs, docs/spec/CRYPTO.md §3.9).
//
// The key is agreed with the app when the person connects the extension (`agree`: ECDH, so it
// never travels) and allowed there with the code this window shows. It is a non-extractable
// HMAC key kept in the browser's IndexedDB: scripts can use it but can't read it back. Every
// request is sealed with a key derived from it, and every answer opened with another, so a
// program put between the browser and the app reads nothing and can't forge an answer. The
// master password is never here.
//
// Connecting and every sealed request name this extension's version (its manifest's): the app
// connects and answers only an extension of the version it accepts or later
// (crates/browser/src/protocol.rs `MIN_EXTENSION_VERSION`), and refuses an older one with
// `outdated_extension`.

/** This extension's version, as its manifest says ("" where there is none: a test). */
export function extensionVersion() {
  try {
    return String(chrome.runtime.getManifest().version ?? "");
  } catch {
    return "";
  }
}

const DB = "vault-link";
const STORE = "keys";
const NAME = "connection";

function open() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function store(mode, work) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const request = work(db.transaction(STORE, mode).objectStore(STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

/** The connection key, or `undefined` when the extension is not connected. */
export async function loadKey() {
  try {
    return await store("readonly", (keys) => keys.get(NAME));
  } catch {
    return undefined;
  }
}

/** Keeps the connection key (the key object `agree` made). */
export async function saveKey(key) {
  await store("readwrite", (keys) => keys.put(key, NAME));
}

export async function dropKey() {
  try {
    await store("readwrite", (keys) => keys.delete(NAME));
    await store("readwrite", (keys) => keys.delete(WAITING));
  } catch {
    // Nothing to forget.
  }
}

// A connection the app has not confirmed yet: its code, and when it was asked for. The
// browser closes this window when the app comes forward, so the wait must survive that.

const WAITING = "waiting";
const WAIT_FOR_MS = 5 * 60 * 1000;

export async function startWaiting(code) {
  await store("readwrite", (keys) => keys.put({ code, since: Date.now() }, WAITING));
}

/** The code of a connection still waiting for the app, or `undefined`. */
export async function waitingCode() {
  try {
    const waiting = await store("readonly", (keys) => keys.get(WAITING));
    return waiting && Date.now() - waiting.since < WAIT_FOR_MS ? waiting.code : undefined;
  } catch {
    return undefined;
  }
}

export async function stopWaiting() {
  try {
    await store("readwrite", (keys) => keys.delete(WAITING));
  } catch {
    // Nothing to forget.
  }
}

/**
 * A counter for a request: this clock in milliseconds × 1000, plus a random part below 1000,
 * so requests sent at the same moment (this window and the background worker ask in
 * parallel) still differ. The app accepts each counter once, and only near its own clock.
 */
export function freshCounter() {
  const random = new Uint16Array(1);
  crypto.getRandomValues(random);
  return Date.now() * 1000 + (random[0] % 1000);
}

const TEXT = new TextEncoder();
/** The labels of pairing.rs, byte for byte. */
const REQUEST_KEY_INFO = TEXT.encode("vault-browser/requests");
const ANSWER_KEY_INFO = TEXT.encode("vault-browser/answers");
const REQUEST_LABEL = TEXT.encode("vault-browser/request");
const ANSWER_LABEL = TEXT.encode("vault-browser/answer");
const PAIRING_INFO = TEXT.encode("vault-browser/pairing");
const COMMIT_LABEL = TEXT.encode("vault-browser/pairing-commit");
const CODE_LABEL = TEXT.encode("vault-browser/pairing-code");
/** The code's characters: letters and digits, without the ones read for one another. */
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
const CODE_LENGTH = 8;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
/** Answers given before any trust, which come plain: they tell nothing. */
const PLAIN = new Set(["not_paired", "not_running", "bad_request"]);
/** What a changed, forged or misplaced answer becomes. */
const BAD_ANSWER = Object.freeze({ type: "error", code: "bad_answer" });

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A counter as 8 bytes, little-endian. */
function littleEndian(counter) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(counter), true);
  return bytes;
}

const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** Exactly `length` bytes written as hex, or null. */
function fromHex(text, length) {
  if (typeof text !== "string" || text.length !== 2 * length || !/^[0-9a-f]*$/.test(text)) return null;
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

function toBase64(bytes) {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(text) {
  try {
    return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

/**
 * One block of HKDF-SHA-256-Expand with the connection key, HMAC(key, info ‖ 0x01), made with
 * the key object itself and kept as a non-extractable AES-GCM key for `usage` only.
 */
async function derived(key, info, usage) {
  const raw = new Uint8Array(await crypto.subtle.sign("HMAC", key, concat(info, Uint8Array.of(1))));
  try {
    return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, [usage]);
  } finally {
    raw.fill(0);
  }
}

/**
 * Seals a request for the app: AES-256-GCM with the requests' key, a fresh 96-bit nonce, and
 * the counter (8 bytes, little-endian) after the requests' label as associated data. Returns
 * what is sent (`message`) and what its answer is bound to (`counter`, `nonce`).
 */
export async function seal(key, request, counter = freshCounter(), nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH))) {
  const text = TEXT.encode(JSON.stringify(request));
  try {
    const sealed = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: concat(REQUEST_LABEL, littleEndian(counter)) },
      await derived(key, REQUEST_KEY_INFO, "encrypt"),
      text,
    );
    return {
      message: { type: "sealed", counter, data: toBase64(concat(nonce, new Uint8Array(sealed))) },
      counter,
      nonce,
    };
  } finally {
    text.fill(0);
  }
}

/**
 * The app's answer to `sent` (what `seal` made), once it opens with the answers' key and the
 * request's counter and nonce as associated data. A plain "not connected", "not running" or
 * "not understood" passes as it is; anything else unsealed, sealed to another request or
 * changed is `bad_answer`.
 */
export async function opened(key, sent, reply) {
  if (reply?.type === "error" && PLAIN.has(reply.code)) return { type: "error", code: reply.code };
  if (reply?.type !== "sealed" || typeof reply.data !== "string") return BAD_ANSWER;
  const sealed = fromBase64(reply.data);
  if (!sealed || sealed.length < NONCE_LENGTH + TAG_LENGTH) return BAD_ANSWER;
  let plain;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: sealed.subarray(0, NONCE_LENGTH),
          additionalData: concat(ANSWER_LABEL, littleEndian(sent.counter), sent.nonce),
        },
        await derived(key, ANSWER_KEY_INFO, "decrypt"),
        sealed.subarray(NONCE_LENGTH),
      ),
    );
  } catch {
    return BAD_ANSWER;
  }
  try {
    const answer = JSON.parse(new TextDecoder().decode(plain));
    return answer && typeof answer === "object" && typeof answer.type === "string" ? answer : BAD_ANSWER;
  } catch {
    return BAD_ANSWER;
  } finally {
    plain.fill(0);
  }
}

/**
 * The code both sides show ("74At LSYM"): eight characters of the alphabet, each byte of
 * SHA-256(label ‖ ours ‖ theirs ‖ block) below 224 taken as `byte mod 56` (pairing.rs).
 */
async function agreedCode(ours, theirs) {
  let code = "";
  for (let block = 0; code.length < CODE_LENGTH && block < 256; block++) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(CODE_LABEL, ours, theirs, Uint8Array.of(block))));
    for (const byte of digest) {
      if (code.length === CODE_LENGTH) break;
      if (byte < 224) code += CODE_ALPHABET[byte % CODE_ALPHABET.length];
    }
  }
  return `${code.slice(0, CODE_LENGTH / 2)} ${code.slice(CODE_LENGTH / 2)}`;
}

/**
 * Connects to the app with a key that never travels (pairing.rs): a fresh ECDH P-256 key pair
 * made here (its private half not extractable), a commitment to its public half (with this
 * extension's version), the app's public key in return, then ours revealed. Both sides then hold
 * `K = HKDF-SHA-256(ECDH secret, salt = ours ‖ theirs, info = "vault-browser/pairing")` and
 * show the same eight-character code, which the person compares before connecting in the app.
 *
 * `send` sends one message to the app (app.js `send`). `keep(key, code)` is called before ours
 * is revealed, when the app may come forward and close this window: the key and the code are
 * kept by then. Returns `{ code }`, or `{ error }` with the app's refusal (or `bad_answer`).
 * `pair` is a key pair to use instead of a fresh one (tests).
 */
export async function agree(send, keep, pair) {
  const keys = pair ?? (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]));
  const ours = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const commit = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", concat(COMMIT_LABEL, ours))));
  const offer = await send({ type: "pair", commit, version: extensionVersion() });
  if (offer?.type !== "pair_offer") return { error: offer?.type === "error" ? offer.code : "bad_answer" };
  const theirs = fromHex(offer.key, 65);
  if (!theirs || theirs[0] !== 4) return { error: "bad_answer" };
  let shared;
  try {
    const app = await crypto.subtle.importKey("raw", theirs, { name: "ECDH", namedCurve: "P-256" }, false, []);
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: app }, keys.privateKey, 256));
  } catch {
    return { error: "bad_answer" };
  }
  let key;
  try {
    const secret = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: concat(ours, theirs), info: PAIRING_INFO },
      secret,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign"],
    );
  } finally {
    shared.fill(0);
  }
  const code = await agreedCode(ours, theirs);
  await keep(key, code);
  const waiting = await send({ type: "pair_key", key: hex(ours) });
  if (waiting?.type !== "pair_wait") return { error: waiting?.type === "error" ? waiting.code : "bad_answer" };
  return { code };
}
