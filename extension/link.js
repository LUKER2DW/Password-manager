// The connection key shared with the desktop app, and the proof put on every request.
//
// The key arrives once, when the person connects the extension and allows it in the app. It
// is imported as a non-extractable HMAC key and kept in the browser's IndexedDB: scripts can
// sign with it but can't read it back. The master password is never here.

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

/** Keeps the key the app handed over (64 hex characters) as a key object. */
export async function saveKey(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("bad key");
  const raw = Uint8Array.from(hex.match(/../g), (byte) => parseInt(byte, 16));
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  raw.fill(0);
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

/**
 * Wraps a request for the app: the request as text, a counter (see `freshCounter`) and
 * HMAC-SHA-256 over counter (8 bytes, little-endian) followed by the text.
 */
export async function sign(key, request, counter = freshCounter()) {
  const body = JSON.stringify(request);
  const text = new TextEncoder().encode(body);
  const data = new Uint8Array(8 + text.length);
  new DataView(data.buffer).setBigUint64(0, BigInt(counter), true);
  data.set(text, 8);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  return {
    type: "signed",
    counter,
    body,
    mac: Array.from(mac, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}
