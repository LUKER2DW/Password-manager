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
  } catch {
    // Nothing to forget.
  }
}

/**
 * Wraps a request for the app: the request as text, a counter (this clock, in milliseconds,
 * so an old request can't be sent again) and HMAC-SHA-256 over counter (8 bytes,
 * little-endian) followed by the text.
 */
export async function sign(key, request, counter = Date.now()) {
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
