// Tests for the background worker's part in filling and saving: `node --test apps/extension/test`.
// A stand-in `chrome` (tabs, storage, scripting, native messaging) and a stand-in app answer
// it; no browser and no packages are needed.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

import { openRequest, sealed, versionOf } from "./sealed.mjs";

// ---- the stand-ins, in place before the worker loads ----

const hmacKey = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, [
  "sign",
]);
const later = (work) => setTimeout(work, 0);
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

const tabs = new Map();
const scripted = [];
const asked = [];
let answers = {};
const session = {};
const local = {};
const told = [];
const badges = [];
const storageListeners = [];
const versions = [];
// The address `chrome.runtime.getURL` gives the frame: the extension's own, or (Chrome with
// `use_dynamic_url`) one for this session only.
let frameHost = "vault-extension";
let onMessage;
const ignored = { addListener() {} };

globalThis.chrome = {
  runtime: {
    id: "vault-extension",
    getURL: (path) => {
      const file = path.replace(/^\//, "");
      return `chrome-extension://${file.startsWith("inline.html") ? frameHost : "vault-extension"}/${file}`;
    },
    getManifest: () => ({ version: "0.4.8" }),
    onInstalled: ignored,
    onStartup: ignored,
    onMessage: { addListener: (listener) => (onMessage = listener) },
    // The app: the sealed request opened, answered from `answers` by its type, sealed to the
    // request as the app does.
    sendNativeMessage: async (_host, envelope) => {
      const request = openRequest(envelope);
      versions.push(versionOf(envelope));
      asked.push(request);
      const answer = answers[request.type];
      return sealed(envelope, typeof answer === "function" ? await answer(request) : (answer ?? { type: "error", code: "bad_request" }));
    },
  },
  tabs: {
    get: async (id) => tabs.get(id),
    sendMessage: async (tabId, message) => {
      told.push({ tabId, message });
    },
    onRemoved: ignored,
    onUpdated: ignored,
  },
  windows: { onRemoved: ignored },
  storage: {
    session: {
      get: async (key) => ({ [key]: session[key] }),
      set: async (values) => Object.assign(session, structuredClone(values)),
    },
    // The extension's settings; a change is told to the listeners, as the browser does.
    local: {
      get: async (key) => ({ [key]: local[key] }),
      set: async (values) => {
        const changes = {};
        for (const [key, value] of Object.entries(values)) {
          changes[key] = { oldValue: local[key], newValue: value };
          local[key] = value;
        }
        for (const listener of storageListeners) listener(changes, "local");
      },
    },
    onChanged: { addListener: (listener) => storageListeners.push(listener) },
  },
  scripting: {
    executeScript: async (details) => {
      scripted.push(details);
      return [{ result: "both" }];
    },
  },
  action: {
    openPopup: async () => {},
    setBadgeText: async (details) => {
      badges.push(details);
    },
  },
  privacy: { services: { passwordSavingEnabled: { get: async () => ({}), set: async () => {}, clear: async () => {} } } },
};

const { isFrameUrl } = await import("../background.js");

const ORIGIN = "https://login.example";
let nextTab = 1;

/** A tab on the sign-in page; messages from its page and from the extension's frame in it. */
function tab() {
  const id = nextTab++;
  tabs.set(id, { id, url: `${ORIGIN}/sign-in` });
  const send = (message, sender) =>
    new Promise((resolve) => {
      onMessage(message, { id: "vault-extension", tab: tabs.get(id), ...sender }, resolve);
    });
  return {
    id,
    page: (message) => send(message, { frameId: 0, url: tabs.get(id).url, documentId: `doc-${id}` }),
    /** The same address, in a document the site sandboxed: the browser gives its origin as "null". */
    sandboxed: (message) => send(message, { frameId: 0, url: tabs.get(id).url, documentId: `doc-${id}`, origin: "null" }),
    frame: (message) => send(message, { frameId: 7, url: chrome.runtime.getURL("inline.html#logins|normal|x") }),
    /** A document in a frame of the page (an advert, a widget), one the site may have sandboxed. */
    sub: (message) => send(message, { frameId: 3, url: "https://widget.example/frame", documentId: `sub-${id}`, origin: "null" }),
  };
}

const LOGINS = {
  type: "logins",
  origin: ORIGIN,
  hello: false,
  items: [{ id: "item-1", title: "Login", username: "me", locked: false, has_code: false }],
};

test("a login picked in the card is filled into the card's own field and form only", async () => {
  answers = {
    logins: LOGINS,
    fill: { type: "fill", origin: ORIGIN, username: "me", password: "s3cret" },
  };
  scripted.length = 0;
  const t = tab();
  const outcome = await t.frame({ kind: "frame-fill", id: "item-1", offer: "offer-42" });
  assert.equal(outcome.done, true);
  assert.equal(scripted.length, 1);
  assert.deepEqual(scripted[0].target, { tabId: t.id, frameIds: [0] });
  assert.deepEqual(scripted[0].args, [ORIGIN, "me", "s3cret", "offer-42"], "the offer goes with the password");
  // A card without an offer still names one (""), which matches no field: nothing is guessed.
  await t.frame({ kind: "frame-fill", id: "item-1" });
  assert.equal(scripted.at(-1).args[3], "");
});

test("a sandboxed document at the site's address is not the site", async () => {
  answers = { logins: LOGINS, save: { type: "saved", existing: false, queued: false } };
  const t = tab();
  asked.length = 0;
  assert.equal(await t.sandboxed({ kind: "field-focused", fresh: true, rules: {} }), undefined);
  assert.equal(await t.sandboxed({ kind: "submitted", username: "me", password: "typed-pw" }), undefined);
  assert.equal(asked.length, 0, "the app is asked nothing");
  const offer = await t.frame({ kind: "frame-save-info" });
  assert.ok(!offer?.username, "nothing waits to be saved");
});

test("Save acts on the offer the card shows, never on a newer one", async () => {
  answers = { logins: LOGINS, save: { type: "saved", existing: false, queued: false } };
  const t = tab();
  await t.page({ kind: "submitted", username: "first", password: "first-pw" });
  const shown = await t.frame({ kind: "frame-save-info" });
  assert.equal(shown.username, "first");
  assert.ok(shown.id);
  // Another sign-in on the tab replaces the offer before Save is clicked on the first card.
  await t.page({ kind: "submitted", username: "second", password: "second-pw" });
  asked.length = 0;
  const stale = await t.frame({ kind: "frame-save", offer: shown.id });
  assert.deepEqual(stale, { done: false, stale: true });
  assert.ok(!asked.some((request) => request.type === "save"), "nothing was saved");
  // The card for the second one saves the second one.
  const current = await t.frame({ kind: "frame-save-info" });
  assert.equal(current.username, "second");
  const saved = await t.frame({ kind: "frame-save", offer: current.id });
  assert.equal(saved.done, true);
  const save = asked.find((request) => request.type === "save");
  assert.equal(save.username, "second");
  assert.equal(save.password, "second-pw");
});

test("a save the app could not write is not done, and can be tried again", async () => {
  answers = { logins: LOGINS, save: { type: "error", code: "not_saved" } };
  const t = tab();
  await t.page({ kind: "submitted", username: "me2", password: "pw2" });
  const shown = await t.frame({ kind: "frame-save-info" });
  const failed = await t.frame({ kind: "frame-save", offer: shown.id });
  assert.equal(failed.done, false);
  assert.ok(!failed.stale);
  assert.ok((await t.frame({ kind: "frame-save-info" })).id, "still offered");
  answers.save = { type: "saved", existing: false, queued: false };
  assert.equal((await t.frame({ kind: "frame-save", offer: shown.id })).done, true);
});

/** Lets the listeners' own work (dropping what waits) finish. */
const settle = () => new Promise((done) => setTimeout(done, 5));

test("with saving left to the browser, nothing typed is kept or offered; compared only for the warnings", async () => {
  answers = {
    logins: LOGINS,
    changed: { type: "changed", id: "item-1", changed: true },
    save: { type: "saved", existing: false, queued: false },
    elsewhere: { type: "elsewhere", page: "login.example" },
  };
  await chrome.storage.local.set({ vaultSaves: false });
  try {
    const t = tab();
    asked.length = 0;
    await t.page({ kind: "username-step", username: "first-step" });
    await t.page({ kind: "submitted", username: "new-one", password: "typed-pw" });
    // The app's warnings about other sites are on: what was sent is compared there (and only
    // that: nothing to save, update or keep).
    assert.deepEqual(
      asked.map((request) => request.type),
      ["elsewhere"],
    );
    // Turned off in the app (its answers say so): nothing typed goes to the app at all.
    await chrome.storage.local.set({ vaultWarns: false });
    asked.length = 0;
    await t.page({ kind: "submitted", username: "me", password: "other-pw" });
    await t.page({ kind: "submitted", username: "", password: "after-step" });
    assert.deepEqual(asked, [], "nothing typed went to the app, not even to compare");
    await chrome.storage.local.set({ vaultWarns: true });
    assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {});
    assert.deepEqual(await t.page({ kind: "pending" }), { offer: false });
    assert.equal(Object.keys(session.pendingSaves ?? {}).length, 0, "nothing kept");
    // Turned back on: the username typed while off wasn't kept for the next step either.
    await chrome.storage.local.set({ vaultSaves: true });
    await t.page({ kind: "submitted", username: "", password: "pw-after" });
    assert.equal((await t.frame({ kind: "frame-save-info" })).username, "");
  } finally {
    await chrome.storage.local.set({ vaultSaves: true, vaultWarns: true });
  }
});

test("an offer waiting when saving is turned off is dropped, and Save refuses it", async () => {
  answers = { logins: LOGINS, save: { type: "saved", existing: false, queued: false } };
  const t = tab();
  await t.page({ kind: "submitted", username: "waiting", password: "waiting-pw" });
  const shown = await t.frame({ kind: "frame-save-info" });
  assert.ok(shown.id);
  told.length = 0;
  await chrome.storage.local.set({ vaultSaves: false });
  await settle();
  try {
    assert.equal(session.pendingSaves?.[t.id], undefined, "dropped, not only hidden");
    assert.ok(
      told.some(({ tabId, message }) => tabId === t.id && message.kind === "close" && message.which === "save"),
      "the card in the page closes",
    );
    asked.length = 0;
    assert.deepEqual(await t.frame({ kind: "frame-save", offer: shown.id }), { done: false, stale: true });
    assert.ok(!asked.some((request) => request.type === "save"), "nothing was saved");
  } finally {
    await chrome.storage.local.set({ vaultSaves: true });
  }
  // On again, the dropped offer stays gone.
  assert.deepEqual(await t.frame({ kind: "frame-save", offer: shown.id }), { done: false, stale: true });
});

test("Save refuses while saving is off, even if the offer is still stored", async () => {
  answers = { logins: LOGINS, save: { type: "saved", existing: false, queued: false } };
  const t = tab();
  await t.page({ kind: "submitted", username: "kept", password: "kept-pw" });
  const shown = await t.frame({ kind: "frame-save-info" });
  // Off without any listener told (the worker was asleep when it changed, say).
  local.vaultSaves = false;
  try {
    asked.length = 0;
    assert.deepEqual(await t.frame({ kind: "frame-save", offer: shown.id }), { done: false, stale: true });
    assert.ok(!asked.some((request) => request.type === "save"));
    assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {}, "nor offered");
  } finally {
    local.vaultSaves = true;
  }
});

test("a sign-in that leads to another host is saved for the address it was typed on", async () => {
  answers = { logins: LOGINS, save: { type: "saved", existing: false, queued: false } };
  const t = tab();
  await t.page({ kind: "submitted", username: "me3", password: "pw3" });
  // Signed in on the identity host, sent on to the app's own (SSO): the card comes along.
  tabs.get(t.id).url = "https://app.example/home";
  const shown = await t.frame({ kind: "frame-save-info" });
  assert.equal(shown.origin, ORIGIN, "the card names the site it was typed on");
  asked.length = 0;
  assert.deepEqual(await t.frame({ kind: "frame-save", offer: shown.id }), { done: true, queued: false });
  const save = asked.find((request) => request.type === "save");
  assert.equal(save.url, `${ORIGIN}/sign-in`, "for the address it was typed on, not the tab's");
  assert.equal(save.password, "pw3");
});

test("an update is for the version of the login the app compared, and its username", async () => {
  answers = {
    logins: LOGINS,
    changed: { type: "changed", id: "item-1", changed: true, stamp: "stamp-1" },
    update: { type: "updated", changed: true },
  };
  const t = tab();
  await t.page({ kind: "submitted", username: "me", password: "new-pw" });
  const shown = await t.frame({ kind: "frame-save-info" });
  assert.equal(shown.update, true);
  asked.length = 0;
  assert.equal((await t.frame({ kind: "frame-save", offer: shown.id })).done, true);
  const update = asked.find((request) => request.type === "update");
  assert.deepEqual(
    { id: update.id, password: update.password, username: update.username, stamp: update.stamp },
    { id: "item-1", password: "new-pw", username: "me", stamp: "stamp-1" },
  );

  // Changed in the app since (an edit, a sync): nothing replaced, and the card says so.
  answers.update = { type: "error", code: "changed_since" };
  await t.page({ kind: "submitted", username: "me", password: "newer-pw" });
  const again = await t.frame({ kind: "frame-save-info" });
  assert.deepEqual(await t.frame({ kind: "frame-save", offer: again.id }), { done: false, changed: true });
  assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {}, "that offer is done with");

  // An older app gives no stamp: the request it knows, without the new fields.
  answers.changed = { type: "changed", id: "item-1", changed: true };
  answers.update = { type: "updated", changed: true };
  await t.page({ kind: "submitted", username: "me", password: "third-pw" });
  const old = await t.frame({ kind: "frame-save-info" });
  asked.length = 0;
  assert.equal((await t.frame({ kind: "frame-save", offer: old.id })).done, true);
  const plain = asked.find((request) => request.type === "update");
  assert.equal("stamp" in plain || "username" in plain, false);
});

test("Save and Not now drop only the offer they were for, never a newer one", async () => {
  // The app answers the save only once a second sign-in has stored a newer offer.
  let answer;
  answers = { logins: LOGINS, save: () => new Promise((done) => (answer = done)) };
  const t = tab();
  await t.page({ kind: "submitted", username: "first", password: "first-pw" });
  const first = await t.frame({ kind: "frame-save-info" });
  const saving = t.frame({ kind: "frame-save", offer: first.id });
  await settle();
  await t.page({ kind: "submitted", username: "second", password: "second-pw" });
  answer({ type: "saved", existing: false, queued: false });
  assert.equal((await saving).done, true);
  const waiting = await t.frame({ kind: "frame-save-info" });
  assert.equal(waiting.username, "second", "the newer offer is still there");

  // "Not now" on a card that still shows the first offer: the card redraws with the newer one.
  assert.deepEqual(await t.frame({ kind: "frame-dismiss", which: "save", offer: first.id }), { redraw: true });
  assert.equal((await t.frame({ kind: "frame-save-info" })).username, "second");
  // On the newer one's own card it goes.
  await t.frame({ kind: "frame-dismiss", which: "save", offer: waiting.id });
  assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {});
});

test("offers of two tabs stored at once are both kept, and none outlives saving turned off", async () => {
  answers = { logins: LOGINS };
  const one = tab();
  const two = tab();
  await Promise.all([
    one.page({ kind: "submitted", username: "one", password: "one-pw" }),
    two.page({ kind: "submitted", username: "two", password: "two-pw" }),
  ]);
  assert.equal((await one.frame({ kind: "frame-save-info" })).username, "one");
  assert.equal((await two.frame({ kind: "frame-save-info" })).username, "two");

  // Turned off while a third offer is being stored: nothing typed stays.
  const three = tab();
  const storing = three.page({ kind: "submitted", username: "three", password: "three-pw" });
  await chrome.storage.local.set({ vaultSaves: false });
  try {
    await storing;
    await settle();
    assert.deepEqual(session.pendingSaves ?? {}, {});
  } finally {
    await chrome.storage.local.set({ vaultSaves: true });
  }
});

// ---- the save card itself (inline.js), on a stand-in page ----

const INLINE_SCRIPT = readFileSync(new URL("../inline.js", import.meta.url), "utf8");

const AGENT_SCRIPT = readFileSync(new URL("../agent.js", import.meta.url), "utf8");

/**
 * inline.js as the save card, with the worker's replies from `replies` (by message kind).
 * `webdriver`: the browser says a program drives it; `agent`: the person said so (agent.js).
 */
async function saveCard(replies, { webdriver = false, agent = false } = {}) {
  const elements = new Map();
  const element = () => ({
    hidden: false,
    disabled: false,
    textContent: "",
    classList: { add() {}, remove() {}, toggle() {} },
    style: {},
    replaceWith() {},
    replaceChildren() {},
    append() {},
    addEventListener() {},
    setAttribute() {},
    getBoundingClientRect: () => ({ bottom: 120 }),
  });
  const sent = [];
  let observe;
  let now = 1000;
  const sandbox = {
    location: { hash: "#save|normal|", ancestorOrigins: [ORIGIN] },
    document: {
      getElementById: (id) => {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
      },
      querySelector: () => element(),
      body: element(),
      documentElement: element(),
      addEventListener() {},
      createElement: element,
      createElementNS: element,
    },
    window: { addEventListener() {} },
    IntersectionObserver: class {
      constructor(callback) {
        observe = callback;
      }
      observe() {}
    },
    getComputedStyle: () => ({ marginBottom: "0" }),
    performance: { now: () => now },
    setTimeout,
    navigator: { webdriver },
    chrome: {
      i18n: { getMessage: (key) => key },
      storage: {
        local: { get: async (key) => ({ [key]: key === "vaultAgent" ? agent : undefined }) },
        onChanged: { addListener() {} },
      },
      runtime: {
        getURL: (path) => `chrome-extension://vault-extension/${path}`,
        sendMessage: async (message) => {
          sent.push(message);
          const reply = replies[message.kind];
          return typeof reply === "function" ? reply(message) : reply;
        },
      },
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(AGENT_SCRIPT, sandbox);
  vm.runInContext(INLINE_SCRIPT, sandbox);
  await settle();
  const $ = (id) => sandbox.document.getElementById(id);
  // Seen whole by the browser, for long enough; the click is a key press (no pointer).
  const seen = () => {
    observe([{ isIntersecting: true, intersectionRatio: 1, isVisible: true }]);
    now += 500;
  };
  const press = async (id) => {
    await $(id).onclick({ isTrusted: true, detail: 0 });
    await settle();
  };
  return { $, sent, seen, press, later: (ms) => (now += ms) };
}

test("the card never closes silently on an offer that is gone: it shows the one waiting, or says so", async () => {
  let waiting = { id: "offer-1", origin: ORIGIN, username: "first", update: false };
  const replies = {
    "frame-save-info": () => waiting,
    "frame-save": (message) => (message.offer === waiting.id ? { done: true, queued: false } : { done: false, stale: true }),
  };
  const card = await saveCard(replies);
  assert.equal(card.$("save-who").textContent.startsWith("first"), true);
  card.seen();
  // Another sign-in replaced the offer: Save on the old card loads the newer one.
  waiting = { id: "offer-2", origin: ORIGIN, username: "second", update: false };
  await card.press("save-yes");
  assert.ok(card.$("save-who").textContent.startsWith("second"), "the card shows the offer waiting now");
  assert.equal(card.$("save-yes").hidden, false);
  assert.ok(!card.sent.some((message) => message.kind === "frame-dismiss"), "not closed");
  // What it shows changed: a click counts again only once it has been seen anew.
  const saves = () => card.sent.filter((message) => message.kind === "frame-save");
  await card.press("save-yes");
  assert.equal(saves().length, 1);
  card.later(500);
  await card.press("save-yes");
  assert.deepEqual({ ...saves().at(-1) }, { kind: "frame-save", offer: "offer-2" });

  // Nothing waits any more: the card says nothing was saved, and Close closes it.
  const gone = await saveCard({ "frame-save-info": () => waiting, "frame-save": { done: false, stale: true } });
  gone.seen();
  waiting = {};
  await gone.press("save-yes");
  assert.equal(gone.$("save-note").textContent, "saveGone");
  assert.equal(gone.$("save-yes").hidden, true);
  assert.equal(gone.$("save-no").textContent, "saveClose");
  await gone.press("save-no");
  assert.ok(gone.sent.some((message) => message.kind === "frame-dismiss"));
});

test("while an agent or a program drives the browser, a card drawn anyway takes no click", async () => {
  const replies = { "frame-save-info": { id: "offer-1", origin: ORIGIN, username: "me", update: false }, "frame-save": { done: true } };
  for (const driven of [{ webdriver: true }, { agent: true }]) {
    const card = await saveCard(replies, driven);
    card.seen();
    card.later(500);
    await card.press("save-yes");
    assert.ok(!card.sent.some((message) => message.kind === "frame-save"), JSON.stringify(driven));
  }
  // Neither: the same click counts.
  const card = await saveCard(replies);
  card.seen();
  await card.press("save-yes");
  assert.ok(card.sent.some((message) => message.kind === "frame-save"));
});

test("the card says when the login was changed in Vault since the update was offered", async () => {
  const card = await saveCard({
    "frame-save-info": { id: "offer-1", origin: ORIGIN, username: "me", update: true },
    "frame-save": { done: false, changed: true },
  });
  card.seen();
  await card.press("save-yes");
  assert.equal(card.$("save-note").textContent, "updateChangedSince");
  assert.equal(card.$("save-yes").hidden, true);
});

test("where the browser shows no card in pages, a login waiting to be saved marks the toolbar button", async () => {
  answers = { logins: LOGINS };
  const t = tab();
  badges.length = 0;
  // Asked with nothing waiting: no mark.
  await t.page({ kind: "offer-waiting" });
  assert.deepEqual(badges, []);
  await t.page({ kind: "submitted", username: "new-one", password: "new-pw" });
  await t.page({ kind: "offer-waiting" });
  assert.deepEqual(badges.at(-1), { tabId: t.id, text: "1" });
  // The offer answered (here "Not now"): the mark goes with it.
  const shown = await t.frame({ kind: "frame-save-info" });
  await t.frame({ kind: "frame-dismiss", which: "save", offer: shown.id });
  assert.deepEqual(badges.at(-1), { tabId: t.id, text: "" });
});

test("under a sign-in field, the page's request for a field's suggestions lists the site's passkeys", async () => {
  answers = {
    logins: { ...LOGINS, items: [] },
    passkeys: {
      type: "passkeys",
      origin: ORIGIN,
      rp_id: "login.example",
      check: "app",
      hello: false,
      items: [{ id: "item-9", credential: "Y3JlZA", title: "Login", user_name: "me", display_name: "", locked: false }],
    },
  };
  const waiting = { id: "r1", request: { kind: "get", rpId: "", challenge: "AQ", allow: [], conditional: true } };
  const t = tab();
  assert.deepEqual(await t.page({ kind: "field-focused", fresh: false, code: false, passkey: waiting }), { show: true });
  const lookup = asked.findLast((request) => request.type === "passkeys");
  assert.equal(lookup.url, `${ORIGIN}/sign-in`, "for the tab's own address");
  const listed = await t.frame({ kind: "frame-logins" });
  assert.equal(listed.origin, ORIGIN);
  assert.deepEqual(listed.items, []);
  assert.deepEqual(listed.passkeys.items, [
    { id: "item-9", credential: "Y3JlZA", title: "Login", userName: "me", displayName: "", locked: false },
  ]);
  // Without the page's request, a field lists no passkey (and has no login to list here).
  const other = tab();
  assert.deepEqual(await other.page({ kind: "field-focused", fresh: false, code: false }), { show: false });
  assert.equal((await other.frame({ kind: "frame-logins" })).passkeys, undefined);
});

// ---- warnings: another site's password, a page that only looks like a saved site, the kit ----

const LOOKALIKE = {
  type: "logins",
  origin: ORIGIN,
  hello: false,
  items: [],
  lookalike: { site: "example.com", page: "login.example" },
};

test("a password pasted on a page that isn't its site is compared by the app, and named by its site only", async () => {
  answers = {
    logins: LOGINS,
    elsewhere: (request) =>
      request.password === "bank-pw"
        ? { type: "elsewhere", page: "login.example", site: "bank.example" }
        : { type: "elsewhere", page: "login.example" },
  };
  const t = tab();
  asked.length = 0;
  assert.deepEqual(await t.page({ kind: "pasted", password: "own-pw" }), { warn: false });
  assert.deepEqual(await t.page({ kind: "pasted", password: "bank-pw" }), { warn: true });
  assert.deepEqual(
    asked.map((request) => [request.type, request.url, request.password]),
    [
      ["elsewhere", `${ORIGIN}/sign-in`, "own-pw"],
      ["elsewhere", `${ORIGIN}/sign-in`, "bank-pw"],
    ],
    "the tab's own address, and only to compare",
  );
  const shown = await t.frame({ kind: "frame-warning", about: "pasted" });
  assert.deepEqual(shown, { site: "bank.example", page: "login.example", lookalike: false });
  assert.ok(!JSON.stringify(shown).includes("bank-pw"), "the frame gets no password");
  assert.equal(Object.keys(session.pendingSaves ?? {}).length, 0, "nothing kept");
  // "Remove it" in the frame empties the field: the page's script is told.
  told.length = 0;
  await t.frame({ kind: "frame-warn-clear" });
  assert.deepEqual(told, [{ tabId: t.id, message: { kind: "clear-pasted" } }]);
  // Once the tab is on another site, that warning is no longer shown.
  tabs.get(t.id).url = "https://other.example/";
  assert.deepEqual(await t.frame({ kind: "frame-warning", about: "pasted" }), {});
  // Off in the app: nothing goes there to compare.
  await chrome.storage.local.set({ vaultWarns: false });
  try {
    asked.length = 0;
    assert.deepEqual(await t.page({ kind: "pasted", password: "bank-pw" }), { warn: false });
    assert.deepEqual(asked, []);
  } finally {
    await chrome.storage.local.set({ vaultWarns: true });
  }
});

test("another site's password sent from a sign-in form is told in the corner, and not offered to save", async () => {
  answers = {
    logins: { ...LOGINS, items: [] },
    elsewhere: { type: "elsewhere", page: "login.example", site: "bank.example", lookalike: true },
    save: { type: "saved", existing: false, queued: false },
  };
  const t = tab();
  told.length = 0;
  await t.page({ kind: "submitted", username: "me", password: "bank-pw" });
  assert.deepEqual(
    told.map((sent) => sent.message),
    [{ kind: "warn", about: "sent" }],
  );
  assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {}, "nothing waits to be saved");
  assert.deepEqual(await t.frame({ kind: "frame-warning", about: "sent" }), {
    site: "bank.example",
    page: "login.example",
    lookalike: true,
  });
  // Closing it touches no offer: it only closes the corner.
  told.length = 0;
  assert.equal(await t.frame({ kind: "frame-dismiss", which: "warn-corner" }), undefined);
  assert.deepEqual(
    told.map((sent) => sent.message),
    [{ kind: "close", which: "save" }],
  );
});

test("a key of the emergency kit refused in any frame of the tab is said in the corner; the app finds one sent too", async () => {
  answers = { logins: LOGINS, elsewhere: { type: "elsewhere", page: "login.example", kit: true } };
  const t = tab();
  told.length = 0;
  // kit.js in a frame of the page, even one the site sandboxed: nothing of the key comes.
  await t.sub({ kind: "kit-refused", how: "pasted" });
  await t.sub({ kind: "kit-refused", how: "typed" });
  assert.deepEqual(
    told.map((sent) => [sent.tabId, sent.message]),
    [
      [t.id, { kind: "warn", about: "kit" }],
      [t.id, { kind: "warn", about: "kit-typed" }],
    ],
  );
  assert.deepEqual(await t.frame({ kind: "frame-warning", about: "kit" }), { kit: true });
  // Sent from a form all the same (kit.js missed it): the app says so, and nothing is offered.
  told.length = 0;
  await t.page({ kind: "submitted", username: "me", password: "looks-like-a-key" });
  assert.deepEqual(
    told.map((sent) => sent.message),
    [{ kind: "warn", about: "kit" }],
  );
  assert.deepEqual(await t.frame({ kind: "frame-save-info" }), {});
  told.length = 0;
  assert.deepEqual(await t.page({ kind: "pasted", password: "looks-like-a-key" }), { warn: false });
  assert.deepEqual(
    told.map((sent) => sent.message),
    [{ kind: "warn", about: "kit" }],
  );
});

test("on a page that only looks like a saved site, a sign-in field gets a warning instead of nothing", async () => {
  answers = {
    logins: LOOKALIKE,
    elsewhere: { type: "elsewhere", page: "login.example" },
    save: { type: "saved", existing: false, queued: false },
  };
  const t = tab();
  assert.deepEqual(await t.page({ kind: "field-focused", fresh: false, code: false }), { show: "lookalike" });
  // Where no card can be clicked, the same question only.
  assert.deepEqual(await t.page({ kind: "field-focused", framed: false }), { show: "lookalike" });
  assert.deepEqual(await t.frame({ kind: "frame-warning", about: "lookalike" }), {
    site: "example.com",
    page: "login.example",
    lookalike: true,
  });
  // A login typed there and offered to save: the card says what the page looks like.
  await t.page({ kind: "submitted", username: "me", password: "typed-here" });
  assert.equal((await t.frame({ kind: "frame-save-info" })).lookalike, "example.com");
  // A page with logins of its own: no warning.
  answers.logins = { ...LOGINS, lookalike: { site: "example.com", page: "login.example" } };
  const other = tab();
  assert.deepEqual(await other.page({ kind: "field-focused", framed: false }), { show: false });
  assert.deepEqual(await other.frame({ kind: "frame-warning", about: "lookalike" }), {});
});

test("the app's answers say whether its warnings are on, and the extension follows them", async () => {
  answers = { logins: { ...LOGINS, warns: false } };
  await tab().page({ kind: "field-focused", fresh: false, code: false });
  await settle();
  assert.equal(local.vaultWarns, false);
  answers = { logins: LOGINS };
  await tab().page({ kind: "field-focused", fresh: false, code: false });
  await settle();
  assert.equal(local.vaultWarns, true, "not said: on, as the app's default");
});

test("where the browser draws no warning in pages, the button is marked and the window says it, once", async () => {
  answers = {
    logins: LOOKALIKE,
    elsewhere: { type: "elsewhere", page: "login.example", site: "bank.example" },
  };
  const t = tab();
  badges.length = 0;
  const fromWindow = (message) =>
    new Promise((resolve) => onMessage(message, { id: "vault-extension", url: chrome.runtime.getURL("popup.html") }, resolve));
  await t.page({ kind: "field-focused", framed: false });
  await t.page({ kind: "pasted", password: "bank-pw", framed: false });
  await t.sub({ kind: "kit-refused", how: "typed", framed: false });
  assert.ok(badges.length >= 3 && badges.every((badge) => badge.tabId === t.id && badge.text === "!"));
  // Where the frame is drawn (Chrome), nothing marks the button.
  const chrome2 = tab();
  badges.length = 0;
  await chrome2.page({ kind: "pasted", password: "bank-pw", framed: true });
  assert.deepEqual(badges, []);
  // The extension's window hears what this page was warned about, by site names, and only once;
  // the mark goes with it.
  badges.length = 0;
  assert.deepEqual(await fromWindow({ kind: "tab-warnings", tabId: t.id }), {
    pasted: { site: "bank.example", page: "login.example", lookalike: false },
    kit: { kit: true, typed: true },
  });
  assert.deepEqual(badges, [{ tabId: t.id, text: "" }]);
  assert.deepEqual(await fromWindow({ kind: "tab-warnings", tabId: t.id }), {});
  // Asked by anything but the extension's window: nothing.
  assert.equal(await t.page({ kind: "tab-warnings", tabId: chrome2.id }), undefined);
});

// ---- S24: the frame's address of this session; S25: the version named; S28: agents ----

test("the frame is known at this session's address and at the extension's own, and nothing else is", async () => {
  frameHost = "0b5c2f4e-9d31-4a7e-8c6b-2f1d3e4a5b6c";
  try {
    // What the content script puts in the page: this session's address, not the fixed id.
    const placed = chrome.runtime.getURL("inline.html#logins|normal|x");
    assert.ok(!placed.includes("vault-extension"), placed);
    assert.ok(isFrameUrl(placed));
    // What Chrome reports for the frame: it serves that address from the extension's own.
    assert.ok(isFrameUrl("chrome-extension://vault-extension/inline.html#logins|normal|x"));
    for (const other of [
      "https://login.example/inline.html",
      "chrome-extension://another-extension/inline.html",
      "chrome-extension://vault-extension/popup.html",
      "chrome-extension://vault-extension/inline.html.evil",
      "not a url",
      undefined,
    ]) {
      assert.ok(!isFrameUrl(other), String(other));
    }
    // The worker answers the frame at either address.
    answers = { logins: LOGINS };
    const t = tab();
    for (const url of [placed, "chrome-extension://vault-extension/inline.html#logins|normal|x"]) {
      const listed = await new Promise((resolve) =>
        onMessage({ kind: "frame-logins" }, { id: "vault-extension", tab: tabs.get(t.id), frameId: 7, url }, resolve),
      );
      assert.equal(listed.items.length, 1, url);
    }
    // A page that claims to be the frame is the page.
    const claimed = await new Promise((resolve) =>
      onMessage(
        { kind: "frame-logins" },
        { id: "vault-extension", tab: tabs.get(t.id), frameId: 0, url: `${ORIGIN}/inline.html` },
        resolve,
      ),
    );
    assert.equal(claimed, undefined);
  } finally {
    frameHost = "vault-extension";
  }
});

test("every request names the extension's version, from its manifest", async () => {
  answers = { logins: LOGINS };
  versions.length = 0;
  const t = tab();
  await t.page({ kind: "field-focused" });
  assert.ok(versions.length > 0);
  assert.ok(versions.every((version) => version === "0.4.8"), versions.join());
});

test("while the person says an agent uses the browser, the frame gets nothing and the page is answered as frameless", async () => {
  answers = { logins: LOGINS, fill: { type: "fill", origin: ORIGIN, username: "me", password: "s3cret" } };
  const t = tab();
  await chrome.storage.local.set({ vaultAgent: true });
  try {
    scripted.length = 0;
    asked.length = 0;
    told.length = 0;
    assert.equal(await t.frame({ kind: "frame-fill", id: "item-1", offer: "offer-1" }), undefined);
    assert.equal(await t.frame({ kind: "frame-logins" }), undefined);
    assert.equal(await t.frame({ kind: "frame-save", offer: "offer-1" }), undefined);
    assert.equal(scripted.length, 0, "nothing is filled");
    assert.equal(asked.filter((request) => request.type === "fill").length, 0, "the app is asked for no password");
    // How it sits is still heard (a card from an older content script can be closed).
    await t.frame({ kind: "frame-size", which: "logins", height: 120 });
    assert.ok(told.some(({ message }) => message.kind === "size"));
    // A sign-in field: only whether the page looks like a saved site, as where no card is drawn.
    assert.deepEqual(await t.page({ kind: "field-focused" }), { show: false });
  } finally {
    await chrome.storage.local.set({ vaultAgent: false });
  }
  assert.deepEqual(await t.page({ kind: "field-focused" }), { show: true }, "turned off: cards again");
});
