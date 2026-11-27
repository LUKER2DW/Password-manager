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
// Firefox) gets no frame in pages at all, since every click in it would be refused: the
// extension's window fills there, and offers a login waiting to be saved, which the toolbar
// button then marks.

(() => {
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
  const framed = typeof IntersectionObserverEntry === "function" && "isVisible" in IntersectionObserverEntry.prototype;
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
    // Only the part after "#" changes: the frame learns where to draw its arrow, unreloaded.
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
    if (retired || !framed) return;
    if (frames.logins && anchor === field) return;
    if (dismissed.has(field)) return;
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
    close("logins");
    anchor = field;
    setOffer({ id, field, form: field.form, action: destinationOf(field.form) });
    frames.logins = makeFrame(fresh ? "new" : code ? "code" : "logins", id);
    show(frames.logins);
    place();
  }

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
      if (frames.logins) close("logins");
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
  document.addEventListener("input", (event) => event.isTrusted && event.target === anchor && close("logins"), true);
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
  // Saving left to the browser (the extension's setting): nothing typed is read at all, not
  // even to hand it to the worker. Not known yet counts as off.
  let saving = false;
  function setSaving(value) {
    const on = (value ?? true) === true;
    if (on && !saving) reported = "";
    saving = on;
  }
  try {
    chrome.storage.local.get("vaultSaves").then(
      (stored) => setSaving(stored?.vaultSaves),
      () => {},
    );
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && "vaultSaves" in changes) setSaving(changes.vaultSaves.newValue);
    });
  } catch {
    // The extension is gone (reloaded or updated): nothing is read.
  }

  function report(scope) {
    if (retired || !saving || scope === undefined) return;
    const typed = typedLogin(inputs(), scope);
    if (!typed) return;
    const mark = `${typed.username}\n${typed.password}`;
    if (mark === reported) return;
    reported = mark;
    if (typed.password) say({ kind: "submitted", username: typed.username, password: typed.password });
    else if (typed.username) say({ kind: "username-step", username: typed.username });
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
  });

  // A login sent on the page before this one may still be waiting for an answer.
  say({ kind: "pending" }).then((answer) => answer?.offer && offerSave());
})();
