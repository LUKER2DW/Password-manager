// Tests for the extension updating itself (update.js): `node --test apps/extension/test`.
// A stand-in `chrome` (manifest, reload, storage, native messaging) and a stand-in app that
// says which version it carries; no browser and no packages are needed.

import assert from "node:assert/strict";
import { test } from "node:test";

import { openRequest, sealed } from "./sealed.mjs";

// ---- the stand-ins, in place before update.js loads ----

const hmacKey = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, [
  "sign",
]);
const later = (work) => setTimeout(work, 0);
let paired = true;
globalThis.indexedDB = {
  open() {
    const opening = {};
    later(() => {
      opening.result = {
        transaction: () => ({
          objectStore: () => ({
            get: () => {
              const getting = {};
              later(() => {
                getting.result = paired ? hmacKey : undefined;
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

/** What the browser has loaded, what the app carries, and what reloading does. */
const world = {
  version: "0.4.7",
  // What a reload brings: the app's folder holds a newer version, or the extension was loaded
  // from elsewhere and stays as it is.
  folder: "0.4.8",
  status: { type: "status", locked: false, name: "", extension_version: "0.4.8" },
  reloads: 0,
  asked: 0,
  open: [],
};
let local = {};
let session = {};

/** Waits for the reload update.js asks for a moment after its answer. */
const settle = () => new Promise((done) => setTimeout(done, 300));

globalThis.chrome = {
  runtime: {
    id: "vault-extension",
    getManifest: () => ({ version: world.version }),
    getContexts: async ({ contextTypes }) => world.open.filter((context) => contextTypes.includes(context)),
    reload: () => {
      world.reloads++;
      world.version = world.folder;
      // A reload forgets what this browser session kept.
      session = {};
    },
    sendNativeMessage: async (_host, envelope) => {
      const request = openRequest(envelope);
      if (request.type === "status") world.asked++;
      return sealed(envelope, request.type === "status" ? world.status : world.logins);
    },
  },
  storage: {
    local: {
      get: async (key) => ({ [key]: structuredClone(local[key]) }),
      set: async (values) => Object.assign(local, structuredClone(values)),
      remove: async (keys) => {
        for (const key of [keys].flat()) delete local[key];
      },
    },
    session: {
      get: async (key) => ({ [key]: structuredClone(session[key]) }),
      set: async (values) => Object.assign(session, structuredClone(values)),
    },
  },
};

const { ask } = await import("../app.js");

/** A start of the worker (the first, or the one a reload makes): update.js as it loads then. */
let runs = 0;
const run = () => import(`../update.js?run=${runs++}`);

/** A fresh start: the browser runs `version`, the app has `offered` in use. */
function start({ version = "0.4.7", offered = "0.4.8", folder = offered } = {}) {
  Object.assign(world, { version, folder, reloads: 0, asked: 0, open: [] });
  world.status = { type: "status", locked: false, name: "", extension_version: offered };
  world.logins = { type: "logins", origin: "https://login.example", items: [], extension_version: offered };
  local = {};
  session = {};
  paired = true;
  return run();
}

const { newer, versionParts } = await run();

test("versions are compared as numbers, and anything else is no version", () => {
  assert.equal(newer("0.4.10", "0.4.9"), true);
  assert.equal(newer("0.5", "0.4.9"), true);
  assert.equal(newer("0.4.8", "0.4.8"), false);
  assert.equal(newer("0.4.8.0", "0.4.8"), false);
  assert.equal(newer("0.4.7", "0.4.8"), false, "an older app changes nothing");
  for (const bad of [undefined, "", "1.2.3-beta", "1..2", "v1.2", "1.2.3.4.5", 4, "99999999999"]) {
    assert.equal(versionParts(bad), undefined, String(bad));
    assert.equal(newer(bad, "0.0.1"), false, String(bad));
  }
});

test("a newer version in the app's folder is taken by reloading once", async () => {
  const { checkForUpdate } = await start();
  assert.equal(await checkForUpdate(), "reloading");
  await settle();
  assert.equal(world.reloads, 1);
  assert.equal(world.version, "0.4.8");
  // The new version's first start: up to date, nothing waits.
  assert.equal(await (await run()).checkForUpdate(), "current");
  assert.equal(local.extensionUpdate, undefined);
  assert.equal(local.extensionUpdateTried, undefined);
  assert.equal(world.reloads, 1);
});

test("loaded from elsewhere, a reload doesn't bring it: the person is told, once", async () => {
  const first = await start({ folder: "0.4.7" });
  assert.equal(await first.checkForUpdate(), "reloading");
  await settle();
  assert.equal(world.reloads, 1);
  const { applyUpdate, checkForUpdate } = await run();
  assert.equal(await checkForUpdate(), "manual");
  assert.deepEqual(local.extensionUpdate, { version: "0.4.8", manual: true });
  // Never again for this version, and the window can't make it try either.
  assert.equal(await checkForUpdate({ force: true }), "manual");
  assert.deepEqual(await applyUpdate(), { reloading: false });
  await settle();
  assert.equal(world.reloads, 1);
  // Updated by hand (or the app went back to this version): the notice goes.
  world.version = "0.4.8";
  assert.equal(await checkForUpdate({ force: true }), "current");
  assert.equal(local.extensionUpdate, undefined);
  // A later version is tried again.
  world.status.extension_version = "0.4.9";
  world.folder = "0.4.9";
  assert.equal(await checkForUpdate({ force: true }), "reloading");
  await settle();
  assert.equal(world.version, "0.4.9");
});

test("the app's answer about a page's logins is enough: noticed at the next request", async () => {
  await start();
  // A sign-in field asks for the page's logins; the answer names the newer version.
  const reply = await ask({ type: "logins", url: "https://login.example/" });
  assert.equal(reply.type, "logins");
  await settle();
  assert.equal(world.reloads, 1, "reloaded without a status of its own");
  assert.equal(world.asked, 0);
  assert.equal(world.version, "0.4.8");
  // Heard again before the reload came: still one reload.
  await start();
  await ask({ type: "logins", url: "https://login.example/" });
  await ask({ type: "logins", url: "https://login.example/" });
  await settle();
  assert.equal(world.reloads, 1);
});

test("while something is under way it waits for the person, who takes it from the window", async () => {
  const { applyUpdate, checkForUpdate } = await start();
  session.pendingSaves = { 7: { id: "offer", at: Date.now() } };
  assert.equal(await checkForUpdate(), "waiting");
  assert.deepEqual(local.extensionUpdate, { version: "0.4.8", manual: false });
  assert.equal(world.reloads, 0, "a login waiting to be saved would be lost");
  // The extension's window (or the passkey window) open: the same.
  session = {};
  world.open = ["POPUP"];
  assert.equal(await checkForUpdate({ force: true }), "waiting");
  assert.equal(world.reloads, 0);
  // "Update now".
  assert.deepEqual(await applyUpdate(), { reloading: true });
  await settle();
  assert.equal(world.reloads, 1);
  assert.equal(world.version, "0.4.8");
  world.open = [];
  const after = await run();
  assert.equal(await after.checkForUpdate(), "current");
  assert.equal(local.extensionUpdate, undefined);
  // Nothing waits: nothing to apply.
  assert.deepEqual(await after.applyUpdate(), { reloading: false });
});

test("no answer to go by changes nothing", async () => {
  // An app that doesn't say which version it carries (older than this), or says nonsense.
  for (const extension_version of [undefined, "", "latest"]) {
    const { checkForUpdate } = await start();
    world.status = { type: "status", locked: true, name: "", extension_version };
    assert.equal(await checkForUpdate(), "unknown");
  }
  // Not connected, or the app isn't running.
  let { checkForUpdate } = await start();
  paired = false;
  assert.equal(await checkForUpdate(), "unknown");
  assert.equal(world.asked, 0, "nothing is asked without a connection");
  ({ checkForUpdate } = await start());
  world.status = { type: "error", code: "not_running" };
  assert.equal(await checkForUpdate(), "unknown");
  assert.equal(world.reloads, 0);
  assert.deepEqual(local, {});
});

test("the worker starts often: the app is asked at most every few minutes", async () => {
  const { checkForUpdate } = await start({ offered: "0.4.7" });
  assert.equal(await checkForUpdate(), "current");
  assert.equal(await checkForUpdate(), "checked");
  assert.equal(world.asked, 1);
  session.extensionUpdateChecked = Date.now() - 11 * 60 * 1000;
  assert.equal(await checkForUpdate(), "current");
  assert.equal(world.asked, 2);
});
