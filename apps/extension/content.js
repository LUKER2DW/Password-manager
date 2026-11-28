// Runs in every https page (top frame only), in the extension's isolated world.
//
// It does two small things and holds no secret of the vault:
// - when a sign-in field is focused and the app has a login for this site (or a passkey, when
//   the page waits for a field's suggestions: passkeys.js), it places a small frame under the
//   field. The frame is the extension's own page (inline.html): this script and the web page
//   can position it but can't read or script what is inside;
// - when a sign-in form is sent, it tells the background worker what was typed, so the
//   person can be asked whether to save it.
//
// A page can cover or move the frame. The frame defends itself (it ignores clicks unless the
// browser reports it fully visible), and a click there can only ever fill a login into the
// site that login is saved for, or answer this page's own passkey request.
//
// A browser that can't report the frame fully visible (IntersectionObserver v2's `isVisible`:
// Firefox) gets no card to act on in pages, since every click in it would be refused: the
// extension's window fills there, and offers a login waiting to be saved, which the toolbar
// button then marks. The warnings below are not drawn there either: the toolbar button shows
// "!" and the extension's window says what it is about (background.js, popup/site.js).
//
// The same holds, in every browser, while an AI agent or another program drives the browser
// (agent.js: the browser says so, or the person did in the extension's window): nothing is
// drawn in pages, and the extension's window does it all. Turned on with cards on screen, they
// go at once.
//
// The frame's address is the browser's own for this session (`use_dynamic_url` in the
// manifest, built with `chrome.runtime.getURL`): it doesn't carry the extension's fixed id, and
// a page can't load `inline.html` at that id to learn that Vault is installed.
//
// It also warns, in the same frame, and names no secret to the page:
// - when a sign-in field is focused on a page that only looks like a site of the vault
//   (`paypa1.com` for `paypal.com`; the app compares, from the vault's own sites);
// - when a password pasted into a password field, or sent from a sign-in form, is the password
//   of a login saved for another site (the app compares and forgets it);
// - when one of the emergency kit's keys was refused in the page (kit.js).

(() => {
  // A document the site isolated in a sandbox (a `sandbox` frame, a `Content-Security-Policy:
  // sandbox` header, or a pop-up that inherited one) has an opaque origin, "null", while its
  // address still names the site: it is not the site, and nothing is offered, read or filled
  // in it. The isolated world reads the document's real origin; the page can't change it.
  if (globalThis.origin !== location.origin) return;
  const {
    isSignInField,
    isNewPasswordField,
    isCodeField,
    isPasskeyField,
    fieldRules,
    destinationOf,
    putNewPassword,
    typedLogin,
    sentScope,
  } = globalThis.VaultFields;
  // Whether a card may be drawn in this page: the browser vouches for the frame's visibility,
  // and no program drives the browser (unknown counts as one: agent.js).
  const vouches = typeof IntersectionObserverEntry === "function" && "isVisible" in IntersectionObserverEntry.prototype;
  const driven = () => globalThis.VaultAgent?.driven() ?? true;
  let framed = vouches && !driven();
  const inputs = () => Array.from(document.querySelectorAll("input"));
  const frames = { logins: null, save: null };
  // What each frame shows and which offer it is, kept here: the page can read and change a
  // frame element's attributes, not this isolated world's variables.
  const about = new WeakMap();
  // After the extension is reloaded or updated, this copy of the script keeps running in
  // pages already open, but it can no longer reach the extension: it then removes what it
  // drew and does nothing more.
  let retired = false;
  const alive = () => {
    try {
      return Boolean(chrome.runtime?.id);
    } catch {
      return false;
    }
  };
  function retire() {
    if (retired) return;
    retired = true;
    for (const which of Object.keys(frames)) {
      frames[which]?.remove();
      frames[which] = null;
    }
  }
  const say = (message) => {
    if (retired || !alive()) {
      retire();
      return Promise.resolve(undefined);
    }
    try {
      return chrome.runtime.sendMessage(message).catch(() => undefined);
    } catch {
      retire();
      return Promise.resolve(undefined);
    }
  };

  let anchor = null;
  const dismissed = new WeakSet();
  // The lookalike warning comes once per page, under the first sign-in field focused.
  let lookalikeShown = false;
  /** Whether the frame under a field is a warning: it stays until dismissed. */
  const warning = () => about.get(frames.logins)?.which === "warn";

  // The card under a field is one offer: an id, the field, its form and where that form
  // sends. A login picked in the card is typed into that field and its form only (fill.js
  // reads the offer here, in this isolated world the page can't reach), and not at all when
  // the page has changed them since. The id itself is no secret (it is in the frame's
  // address, which the page can read): what it stands for is kept here.
  const newId = () => crypto.randomUUID();
  function setOffer(offer) {
    globalThis.VaultOffer = offer ? Object.freeze({ ...offer }) : undefined;
  }

  // The page's colour scheme (`dark`, `light dark`…, or `normal`). The frame element and the
  // frame's page both take it: when the frame's scheme differs from the page's, the browser
  // paints an opaque box (white or dark) behind the whole frame.
  function pageScheme() {
    const declared = getComputedStyle(document.documentElement).colorScheme;
    if (declared && declared !== "normal") return declared;
    const meta = document.querySelector('meta[name="color-scheme" i]')?.content?.trim();
    return meta && /^[a-z ]+$/i.test(meta) ? meta : "normal";
  }

  /** The frame's address: what to show, `:up` above the field, the page's scheme, the offer. */
  // (`chrome.runtime.getURL` gives this session's address in Chrome, `use_dynamic_url`. Chrome
  // then serves the page from the extension's own address, so a change of the part after "#"
  // loads the frame again there, and its click check starts over.)
  function frameUrl(which, up = false, offer = "") {
    return chrome.runtime.getURL(`inline.html#${which}${up ? ":up" : ""}|${encodeURIComponent(pageScheme())}|${offer}`);
  }

  // The box the person sees around a field: often a bordered wrapper taller than the input
  // inside it (a field with a show-password button, for one). Up to three levels of parents
  // that hug the input and draw a border, background or shadow.
  function visibleBox(field) {
    let box = field.getBoundingClientRect();
    let node = field.parentElement;
    for (let level = 0; level < 3 && node && node !== document.body; level++, node = node.parentElement) {
      const outer = node.getBoundingClientRect();
      const hugs =
        outer.left <= box.left + 1 &&
        outer.right >= box.right - 1 &&
        outer.top <= box.top + 1 &&
        outer.bottom >= box.bottom - 1 &&
        outer.height - box.height <= 24 &&
        outer.width - box.width <= 120;
      if (!hugs) break;
      const style = getComputedStyle(node);
      const drawn =
        parseFloat(style.borderBottomWidth) > 0 ||
        style.boxShadow !== "none" ||
        !/rgba\(0, 0, 0, 0\)|transparent/.test(style.backgroundColor);
      if (drawn) box = outer;
    }
    return box;
  }

  function makeFrame(which, offer = "") {
    const frame = document.createElement("iframe");
    frame.src = frameUrl(which, false, offer);
    about.set(frame, { which, offer });
    frame.title = "Vault";
    frame.setAttribute("scrolling", "no");
    const set = (name, value) => frame.style.setProperty(name, value, "important");
    set("all", "initial");
    set("position", "fixed");
    set("z-index", "2147483647");
    // The card inside is 280 px wide; the rest is room for its arrow and shadow.
    set("width", "300px");
    set("height", "80px");
    set("border", "0");
    set("color-scheme", pageScheme());
    set("background", "transparent");
    // No filter, blur, clip or opacity on the frame itself: with one, the browser no longer
    // vouches that the frame is fully visible, and every click in it would be refused. The
    // card inside is a little see-through instead.
    return frame;
  }

  function show(frame) {
    document.documentElement.append(frame);
  }

  function place() {
    const frame = frames.logins;
    if (!frame || !anchor) return;
    if (!anchor.isConnected) return close("logins");
    const box = visibleBox(anchor);
    const height = parseFloat(frame.style.height) || 80;
    // The card's arrow points at the field from just below it (or above, when there is no
    // room below); the card lines up with the field's start.
    const below = box.bottom - 2;
    const fits = below + height <= window.innerHeight;
    const top = fits ? below : Math.max(0, box.top - height + 2);
    const left = Math.max(0, Math.min(box.left - 10, window.innerWidth - 300));
    frame.style.setProperty("top", `${top}px`, "important");
    frame.style.setProperty("left", `${left}px`, "important");
    // Only the part after "#" changes: the frame learns where to draw its arrow.
    const { which, offer } = about.get(frame) ?? {};
    const url = frameUrl(which, !fits, offer);
    if (frame.src !== url) frame.src = url;
  }

  function close(which) {
    frames[which]?.remove();
    frames[which] = null;
    if (which === "logins") {
      anchor = null;
      setOffer(undefined);
    }
  }

  async function offer(field) {
    if (retired) return;
    if (frames.logins && anchor === field) return;
    if (dismissed.has(field)) return;
    if (!framed) return warnOnly(field);
    const all = inputs();
    // A new password (sign-up, change of password) gets a strong suggestion instead.
    const fresh = isNewPasswordField(field, all);
    // A one-time code field (the second step of a sign-in) gets the logins that have a code.
    const code = !fresh && isCodeField(field);
    const signIn = !fresh && !code && isSignInField(field, all);
    // The page waits for a field's suggestions: a sign-in field, or one marked for passkeys,
    // lists the site's passkeys too. The worker is told the request again (it may have been
    // stopped since the page asked).
    const waiting = !fresh && !code ? globalThis.VaultPasskeys?.waiting() : undefined;
    const passkey = waiting && (signIn || isPasskeyField(field)) ? waiting : undefined;
    if (!fresh && !code && !signIn && !passkey) return;
    const id = newId();
    const answer = await say({
      kind: "field-focused",
      fresh,
      code,
      offer: id,
      rules: fresh ? fieldRules(field) : undefined,
      passkey,
    });
    if (!answer?.show || document.activeElement !== field) return;
    if (answer.show === "lookalike") return showLookalike(field);
    close("logins");
    anchor = field;
    setOffer({ id, field, form: field.form, action: destinationOf(field.form) });
    frames.logins = makeFrame(fresh ? "new" : code ? "code" : "logins", id);
    show(frames.logins);
    place();
  }

  // ---- warnings ----

  /**
   * Where no card can be clicked (Firefox): a sign-in field only asks whether the page looks
   * like a saved site; the worker then marks the toolbar button, and the window says so.
   */
  async function warnOnly(field) {
    if (lookalikeShown || !isSignInField(field, inputs()) || isNewPasswordField(field, inputs())) return;
    lookalikeShown = true;
    await say({ kind: "field-focused", framed: false });
  }

  /** Under `field`: the page only looks like a site of the vault (once per page). */
  function showLookalike(field) {
    if (lookalikeShown) return;
    lookalikeShown = true;
    warnUnder(field, "lookalike");
  }

  /** A warning (`what` it is about) in the frame under `field`, in place of any card there. */
  function warnUnder(field, what) {
    close("logins");
    anchor = field;
    frames.logins = makeFrame("warn", what);
    show(frames.logins);
    place();
  }

  /** A warning in the page's corner, in place of a save card there. */
  function warnInCorner(what) {
    close("save");
    const frame = makeFrame("warn:corner", what);
    frame.style.setProperty("top", "8px", "important");
    frame.style.setProperty("right", "8px", "important");
    frame.style.setProperty("height", "140px", "important");
    frames.save = frame;
    show(frame);
  }

  // A password pasted into a password field: is it the password of another site's login? The
  // app compares and forgets it (the worker keeps nothing either); the answer is that site's
  // name at most, shown in the frame, which the page can't read. A key of the emergency kit
  // never gets here: kit.js stopped that paste first.
  document.addEventListener(
    "paste",
    (event) => {
      const field = event.target;
      if (!event.isTrusted || retired || !warns || field?.tagName !== "INPUT" || kindOf(field) !== "password") return;
      const text = event.clipboardData?.getData("text/plain") ?? "";
      if (!text || text.length > 1024) return;
      say({ kind: "pasted", password: text, framed }).then((answer) => {
        if (answer?.warn && framed && field.isConnected) warnUnder(field, "pasted");
      });
    },
    true,
  );

  // A newer offer (another sign-in on this page) replaces the card on screen: a new frame
  // loads the offer that waits now, and counts clicks only once it has been seen anew.
  function offerSave() {
    if (!framed) {
      say({ kind: "offer-waiting" });
      return;
    }
    close("save");
    const frame = makeFrame("save");
    frame.style.setProperty("top", "8px", "important");
    frame.style.setProperty("right", "8px", "important");
    frame.style.setProperty("height", "140px", "important");
    frames.save = frame;
    show(frame);
  }

  document.addEventListener("focusin", (event) => offer(event.target), true);
  document.addEventListener(
    "pointerdown",
    (event) => {
      if (event.target === anchor) return;
      // A warning stays until it is dismissed (Got it, or Escape).
      if (frames.logins && !warning()) close("logins");
      if (event.target?.tagName === "INPUT" && document.activeElement === event.target) offer(event.target);
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape" && frames.logins) {
        if (anchor) dismissed.add(anchor);
        close("logins");
      }
      // Enter while a word is still being composed (an input method) sends nothing.
      if (event.key === "Enter" && event.isTrusted && !event.isComposing) {
        const form = event.target?.tagName === "INPUT" ? event.target.form : null;
        if (form) acted(form);
        report(sentScope("enter", event.target, inputs()));
      }
    },
    true,
  );
  // Typing in the field means the person is not picking a saved login.
  document.addEventListener(
    "input",
    (event) => event.isTrusted && event.target === anchor && !warning() && close("logins"),
    true,
  );
  window.addEventListener("scroll", place, { capture: true, passive: true });
  window.addEventListener("resize", place, { passive: true });

  // ---- what was typed, when the form is sent ----

  // Only what the person did counts: a page script that fills the fields and sends the form
  // by itself would otherwise get "Save this login?" or "Update the saved password?" offered
  // for a password it chose, and could tell from the card whether a guess was the saved
  // password. A click or a key press a script makes up is not trusted, but a `submit` event
  // is trusted even when a page script asks for it (`requestSubmit()`, or `click()` on its
  // button): the browser fires it either way. So a submit counts only right after the
  // person's own act in that very form (a click in it that is not into a field, such as on one
  // of its buttons, or Enter in one of its fields), within a few seconds, and one act counts
  // for one submit. And only the form the person sent is read:
  // a click on a help link, an eye button or a button of another form reads nothing
  // (`sentScope` in fields.js).
  const ACT_FOR_MS = 3000;
  let act = null;
  function acted(form) {
    act = form ? { form, at: performance.now() } : null;
  }
  function actedIn(form) {
    if (!act || act.form !== form || performance.now() - act.at > ACT_FOR_MS) return false;
    act = null;
    return true;
  }
  const kindOf = (el) => (el.type || "").toLowerCase();
  /**
   * The form a person's click on `target` acts in: one of its buttons (also one outside it,
   * tied by `form="…"`), or anything else in it a page may sign in from (a `div` it listens
   * to), but not a field the person clicks into to type.
   */
  function clickedForm(target) {
    if (!target?.closest) return null;
    const field = target.closest("input, select, textarea");
    if (field && !(field.tagName === "INPUT" && ["submit", "image", "button", "reset"].includes(kindOf(field)))) {
      return null;
    }
    const button = field || target.closest("button");
    return (button ? button.form : target.closest("form")) ?? null;
  }

  let reported = "";
  // Saving left to the browser (the extension's setting) and the app's warnings about other
  // sites turned off (Settings → Browser extension, which the worker writes down as
  // `vaultWarns` from the app's answers): nothing typed is read at all, not even to hand it to
  // the worker. With saving left to the browser but the warnings on, a login sent is handed to
  // the worker only for the app to compare (background.js `submitted`), never kept. Not known
  // yet counts as off.
  let saving = false;
  let warns = false;
  function setSaving(value) {
    const on = (value ?? true) === true;
    if (on && !saving) reported = "";
    saving = on;
  }
  function setWarns(value) {
    const on = (value ?? true) === true;
    if (on && !warns) reported = "";
    warns = on;
  }
  try {
    chrome.storage.local.get("vaultSaves").then(
      (stored) => setSaving(stored?.vaultSaves),
      () => {},
    );
    chrome.storage.local.get("vaultWarns").then(
      (stored) => setWarns(stored?.vaultWarns),
      () => {},
    );
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if ("vaultSaves" in changes) setSaving(changes.vaultSaves.newValue);
      if ("vaultWarns" in changes) setWarns(changes.vaultWarns.newValue);
    });
  } catch {
    // The extension is gone (reloaded or updated): nothing is read.
  }

  function report(scope) {
    if (retired || !(saving || warns) || scope === undefined) return;
    const typed = typedLogin(inputs(), scope);
    if (!typed) return;
    const mark = `${typed.username}\n${typed.password}`;
    if (mark === reported) return;
    reported = mark;
    if (typed.password) say({ kind: "submitted", username: typed.username, password: typed.password, framed });
    else if (typed.username && saving) say({ kind: "username-step", username: typed.username });
  }
  document.addEventListener(
    "submit",
    (event) => event.isTrusted && actedIn(event.target) && report(sentScope("submit", event.target, inputs())),
    true,
  );
  document.addEventListener(
    "click",
    (event) => {
      if (!event.isTrusted) return;
      const form = clickedForm(event.target);
      if (form) acted(form);
      report(sentScope("click", event.target, inputs()));
    },
    true,
  );

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.kind === "close") close(message.which === "save" ? "save" : "logins");
    if (message?.kind === "offer-save") offerSave();
    if (message?.kind === "put-password" && anchor && typeof message.password === "string") {
      const field = anchor;
      close("logins");
      dismissed.add(field);
      putNewPassword(field, inputs(), message.password);
    }
    if (message?.kind === "size") {
      const frame = frames[message.which === "save" ? "save" : "logins"];
      frame?.style.setProperty("height", `${message.height}px`, "important");
      place();
    }
    // A login sent to the wrong site, or a key of the kit refused: said in the corner.
    if (message?.kind === "warn" && framed && ["sent", "kit", "kit-typed"].includes(message.about)) {
      warnInCorner(message.about);
    }
    // "Remove it" in the warning about a pasted password: the field it is under is emptied.
    if (message?.kind === "clear-pasted" && anchor && warning() && kindOf(anchor) === "password") {
      const field = anchor;
      close("logins");
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(field, "");
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
      field.focus();
    }
  });

  // An agent or a program takes over the browser (or the person says so): the cards on screen
  // go, and none is drawn until that ends.
  globalThis.VaultAgent?.watch((now) => {
    framed = vouches && !now;
    if (now) {
      close("logins");
      close("save");
    }
  });

  // A login sent on the page before this one may still be waiting for an answer (asked once
  // whether an agent drives the browser is known, so its card isn't drawn for one).
  Promise.resolve(globalThis.VaultAgent?.ready)
    .then(() => say({ kind: "pending" }))
    .then((answer) => answer?.offer && offerSave());
})();
