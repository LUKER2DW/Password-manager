// Runs in every https page's own world (top frame only), before the page's scripts. It puts
// Vault in front of the page's passkey requests: navigator.credentials.create() and .get()
// with `publicKey`.
//
// It holds nothing of the vault. A request goes, as plain data, to the extension's content
// script (passkeys.js) and on to its background worker, which asks the person in the
// extension's own window and the app for the answer. The page gets back only what WebAuthn
// would give it: a credential for its own origin, written and signed by the app.
//
// A request for the suggestions of a field (`mediation: "conditional"`) waits, as in the
// browser, until the person picks one of Vault's passkeys in the frame under a sign-in field
// (content.js, inline.html), the page aborts it, or a later request of the page ends it.
//
// When Vault has no passkey for the site, isn't running, or the person picks another device,
// the request goes to the browser's own handler, as if Vault weren't there. So do requests
// for a security key (`authenticatorAttachment: "cross-platform"`), and a field's suggestions
// while the vault is locked or in a browser that can't show the frame in pages (passkeys.js).

(() => {
  const credentials = globalThis.navigator?.credentials;
  if (!credentials || typeof credentials.get !== "function" || typeof credentials.create !== "function") return;
  const CHANNEL = "vault-passkeys";
  const origin = globalThis.location.origin;
  const browser = { get: credentials.get.bind(credentials), create: credentials.create.bind(credentials) };
  const waiting = new Map();
  /** The request for a field's suggestions that waits, if any: `{ id }`. */
  let suggesting = null;

  globalThis.addEventListener("message", (event) => {
    if (event.source !== globalThis || event.origin !== origin) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL || data.direction !== "answer") return;
    const done = waiting.get(data.id);
    if (!done) return;
    waiting.delete(data.id);
    if (suggesting?.id === data.id) suggesting = null;
    done(data.answer && typeof data.answer === "object" ? data.answer : { fallback: true });
  });

  /** Ends request `id` before its answer: Vault is told, the page gets AbortError. */
  function drop(id) {
    const done = waiting.get(id);
    if (!done) return;
    waiting.delete(id);
    if (suggesting?.id === id) suggesting = null;
    globalThis.postMessage({ channel: CHANNEL, direction: "cancel", id }, origin);
    done({ error: "AbortError" });
  }

  /** One request to the extension; resolves with its answer (or AbortError when aborted). */
  function ask(request, signal) {
    // A later request ends the one waiting for a field's suggestions, as in the browser.
    if (suggesting) drop(suggesting.id);
    return new Promise((resolve) => {
      if (signal?.aborted) {
        resolve({ error: "AbortError" });
        return;
      }
      const id = globalThis.crypto.randomUUID();
      waiting.set(id, resolve);
      if (request.conditional) suggesting = { id };
      signal?.addEventListener("abort", () => drop(id), { once: true });
      globalThis.postMessage({ channel: CHANNEL, direction: "ask", id, request }, origin);
    });
  }

  // ---- bytes ----

  function bytesOf(source) {
    if (Object.prototype.toString.call(source) === "[object ArrayBuffer]") return new Uint8Array(source);
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    return null;
  }

  /** base64url without padding, or "" when `source` holds no bytes. */
  function b64u(source) {
    const bytes = bytesOf(source);
    if (!bytes) return "";
    let text = "";
    for (const byte of bytes) text += String.fromCharCode(byte);
    return globalThis.btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function buffer(text) {
    const plain = globalThis.atob(String(text).replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(plain.length);
    for (let i = 0; i < plain.length; i++) bytes[i] = plain.charCodeAt(i);
    return bytes.buffer;
  }

  const ids = (list) => {
    try {
      return Array.from(list ?? [], (entry) => b64u(entry?.id)).filter(Boolean).slice(0, 64);
    } catch {
      return [];
    }
  };
  const text = (value, max = 1024) => (typeof value === "string" ? value.slice(0, max) : "");

  // ---- what the page gets ----

  /** An object with the given own values over `proto` (WebAuthn's own type, when there). */
  function made(proto, values) {
    const object = proto ? Object.create(proto) : {};
    for (const [name, value] of Object.entries(values)) {
      Object.defineProperty(object, name, { value, enumerable: typeof value !== "function", configurable: true });
    }
    return object;
  }

  function credential(answer, response, json, extensions) {
    return made(globalThis.PublicKeyCredential?.prototype, {
      id: answer.credential,
      rawId: buffer(answer.credential),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({ ...extensions }),
      toJSON: () => ({
        id: answer.credential,
        rawId: answer.credential,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: { ...extensions },
        response: json,
      }),
    });
  }

  function assertion(answer) {
    const response = made(globalThis.AuthenticatorAssertionResponse?.prototype, {
      clientDataJSON: buffer(answer.client_data),
      authenticatorData: buffer(answer.authenticator_data),
      signature: buffer(answer.signature),
      userHandle: answer.user_handle ? buffer(answer.user_handle) : null,
    });
    return credential(answer, response, {
      clientDataJSON: answer.client_data,
      authenticatorData: answer.authenticator_data,
      signature: answer.signature,
      userHandle: answer.user_handle || undefined,
    }, {});
  }

  function attestation(answer, extensions) {
    const transports = ["hybrid", "internal"];
    const response = made(globalThis.AuthenticatorAttestationResponse?.prototype, {
      clientDataJSON: buffer(answer.client_data),
      attestationObject: buffer(answer.attestation_object),
      getTransports: () => [...transports],
      getAuthenticatorData: () => buffer(answer.authenticator_data),
      getPublicKey: () => buffer(answer.public_key),
      getPublicKeyAlgorithm: () => answer.algorithm,
    });
    return credential(answer, response, {
      clientDataJSON: answer.client_data,
      attestationObject: answer.attestation_object,
      authenticatorData: answer.authenticator_data,
      transports,
      publicKey: answer.public_key,
      publicKeyAlgorithm: answer.algorithm,
    }, extensions);
  }

  const WORDS = {
    NotAllowedError: "The request was not allowed: it was cancelled or timed out.",
    InvalidStateError: "A passkey for this account is already saved.",
    SecurityError: "This page may not use passkeys for that site.",
    AbortError: "The request was aborted.",
  };

  function failure(name) {
    const known = Object.hasOwn(WORDS, name) ? name : "NotAllowedError";
    return new DOMException(WORDS[known], known);
  }

  // ---- in front of the browser's handler ----

  async function get(options) {
    const key = options?.publicKey;
    const challenge = b64u(key?.challenge);
    if (!key || !challenge) return browser.get(options);
    const request = { kind: "get", rpId: text(key.rpId, 253), challenge, allow: ids(key.allowCredentials) };
    // The suggestions of a field: answered only when the person picks a passkey under one.
    if (options.mediation === "conditional") request.conditional = true;
    const answer = await ask(request, options.signal);
    if (answer.assertion) return assertion(answer.assertion);
    if (answer.error) throw failure(answer.error);
    return browser.get(options);
  }

  async function create(options) {
    const key = options?.publicKey;
    const challenge = b64u(key?.challenge);
    const userId = b64u(key?.user?.id);
    if (!key || !challenge || !userId || key.authenticatorSelection?.authenticatorAttachment === "cross-platform") {
      return browser.create(options);
    }
    let algorithms = [];
    try {
      algorithms = Array.from(key.pubKeyCredParams ?? [])
        .filter((param) => param?.type === "public-key")
        .map((param) => Number(param.alg))
        .filter(Number.isSafeInteger)
        .slice(0, 16);
    } catch {
      return browser.create(options);
    }
    const answer = await ask(
      {
        kind: "create",
        rpId: text(key.rp?.id, 253),
        rpName: text(key.rp?.name, 256),
        userId,
        userName: text(key.user?.name, 256),
        displayName: text(key.user?.displayName, 256),
        challenge,
        algorithms,
        exclude: ids(key.excludeCredentials),
      },
      options.signal,
    );
    if (answer.attestation) {
      const extensions = key.extensions?.credProps ? { credProps: { rk: true } } : {};
      return attestation(answer.attestation, extensions);
    }
    if (answer.error) throw failure(answer.error);
    return browser.create(options);
  }

  for (const [name, handler] of Object.entries({ get, create })) {
    Object.defineProperty(credentials, name, {
      value: function (options) {
        return handler(options);
      },
      writable: true,
      configurable: true,
    });
  }
})();
