// Runs in every https page (top frame only), in the extension's isolated world.
//
// It does two small things and holds no secret of the vault:
// - when a sign-in field is focused and the app has a login for this site, it places a small
//   frame under the field. The frame is the extension's own page (inline.html): this script
//   and the web page can position it but can't read or script what is inside;
// - when a sign-in form is sent, it tells the background worker what was typed, so the
//   person can be asked whether to save it.
//
// A page can cover or move the frame. The frame defends itself (it ignores clicks unless the
// browser reports it fully visible), and a click there can only ever fill a login into the
// site that login is saved for.

(() => {
  const { isSignInField, isNewPasswordField, isCodeField, fieldRules, putNewPassword, typedLogin } =
    globalThis.VaultFields;
  const inputs = () => Array.from(document.querySelectorAll("input"));
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
    for (const frame of document.querySelectorAll("iframe")) {
      if (frame.dataset.which) frame.remove();
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

  const frames = { logins: null, save: null };
  let anchor = null;
  const dismissed = new WeakSet();

  // The page's colour scheme (`dark`, `light dark`…, or `normal`). The frame element and the
  // frame's page both take it: when the frame's scheme differs from the page's, the browser
  // paints an opaque box (white or dark) behind the whole frame.
  function pageScheme() {
    const declared = getComputedStyle(document.documentElement).colorScheme;
    if (declared && declared !== "normal") return declared;
    const meta = document.querySelector('meta[name="color-scheme" i]')?.content?.trim();
    return meta && /^[a-z ]+$/i.test(meta) ? meta : "normal";
  }

  /** The frame's address: what to show, `:up` above the field, and the page's scheme. */
  function frameUrl(which, up = false) {
    return chrome.runtime.getURL(`inline.html#${which}${up ? ":up" : ""}|${encodeURIComponent(pageScheme())}`);
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

  function makeFrame(which) {
    const frame = document.createElement("iframe");
    frame.src = frameUrl(which);
    frame.dataset.which = which;
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
    const url = frameUrl(frame.dataset.which, !fits);
    if (frame.src !== url) frame.src = url;
  }

  function close(which) {
    frames[which]?.remove();
    frames[which] = null;
    if (which === "logins") anchor = null;
  }

  async function offer(field) {
    if (retired) return;
    if (frames.logins && anchor === field) return;
    if (dismissed.has(field)) return;
    const all = inputs();
    // A new password (sign-up, change of password) gets a strong suggestion instead.
    const fresh = isNewPasswordField(field, all);
    // A one-time code field (the second step of a sign-in) gets the logins that have a code.
    const code = !fresh && isCodeField(field);
    if (!fresh && !code && !isSignInField(field, all)) return;
    const answer = await say({ kind: "field-focused", fresh, code, rules: fresh ? fieldRules(field) : undefined });
    if (!answer?.show || document.activeElement !== field) return;
    close("logins");
    anchor = field;
    frames.logins = makeFrame(fresh ? "new" : code ? "code" : "logins");
    show(frames.logins);
    place();
  }

  function offerSave() {
    if (frames.save) return;
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
      if (event.key === "Enter" && event.isTrusted && event.target?.tagName === "INPUT") report();
    },
    true,
  );
  // Typing in the field means the person is not picking a saved login.
  document.addEventListener("input", (event) => event.isTrusted && event.target === anchor && close("logins"), true);
  window.addEventListener("scroll", place, { capture: true, passive: true });
  window.addEventListener("resize", place, { passive: true });

  // ---- what was typed, when the form is sent ----

  // Only what the person did counts: a page script that fills the fields and dispatches a
  // click or a submit of its own would otherwise get "Save this login?" or "Update the saved
  // password?" offered for a password it chose.
  let reported = "";
  function report() {
    if (retired) return;
    const typed = typedLogin(inputs());
    if (!typed) return;
    const mark = `${typed.username}\n${typed.password}`;
    if (mark === reported) return;
    reported = mark;
    if (typed.password) say({ kind: "submitted", username: typed.username, password: typed.password });
    else if (typed.username) say({ kind: "username-step", username: typed.username });
  }
  document.addEventListener("submit", (event) => event.isTrusted && report(), true);
  document.addEventListener(
    "click",
    (event) => {
      if (!event.isTrusted) return;
      const button = event.target?.closest?.("button, input[type=submit], [role=button]");
      if (button) report();
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
