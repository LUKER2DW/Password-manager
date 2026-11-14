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
  const { isSignInField, isNewPasswordField, fieldRules, putNewPassword, typedLogin } = globalThis.VaultFields;
  const inputs = () => Array.from(document.querySelectorAll("input"));
  const say = (message) => chrome.runtime.sendMessage(message).catch(() => undefined);

  const frames = { logins: null, save: null };
  let anchor = null;
  const dismissed = new WeakSet();

  function makeFrame(which) {
    const frame = document.createElement("iframe");
    frame.src = chrome.runtime.getURL(`inline.html#${which}`);
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
    set("color-scheme", "normal");
    set("background", "transparent");
    // The frosted glass behind the card. It is a separate element under the frame, never an
    // effect on the frame itself: with a blur, filter, clip or opacity on the frame the
    // browser no longer vouches that it is fully visible, and every click there would be
    // refused. This layer only blurs the page behind; it takes no clicks.
    const glass = document.createElement("div");
    const paint = (name, value) => glass.style.setProperty(name, value, "important");
    paint("all", "initial");
    paint("position", "fixed");
    paint("z-index", "2147483646");
    paint("border-radius", "14px");
    paint("pointer-events", "none");
    paint("backdrop-filter", "blur(20px) saturate(1.7)");
    frame.glass = glass;
    return frame;
  }

  /** Puts the glass exactly under the card: the frame minus the card's margins. */
  function fitGlass(frame, up) {
    const glass = frame.glass;
    if (!glass) return;
    const box = frame.getBoundingClientRect();
    const corner = frame.dataset.which === "save";
    const [top, bottom] = corner ? [10, 10] : up ? [14, 9] : [9, 14];
    glass.style.setProperty("left", `${box.left + 10}px`, "important");
    glass.style.setProperty("top", `${box.top + top}px`, "important");
    glass.style.setProperty("width", `${Math.max(0, box.width - 20)}px`, "important");
    glass.style.setProperty("height", `${Math.max(0, box.height - top - bottom)}px`, "important");
  }

  function show(frame) {
    document.documentElement.append(frame.glass, frame);
  }

  function place() {
    const frame = frames.logins;
    if (!frame || !anchor) return;
    if (!anchor.isConnected) return close("logins");
    const box = anchor.getBoundingClientRect();
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
    const hash = `#${frame.dataset.which}${fits ? "" : ":up"}`;
    if (!frame.src.endsWith(hash)) frame.src = chrome.runtime.getURL(`inline.html${hash}`);
    fitGlass(frame, !fits);
  }

  function close(which) {
    frames[which]?.glass?.remove();
    frames[which]?.remove();
    frames[which] = null;
    if (which === "logins") anchor = null;
  }

  async function offer(field) {
    if (frames.logins && anchor === field) return;
    if (dismissed.has(field)) return;
    const all = inputs();
    // A new password (sign-up, change of password) gets a strong suggestion instead.
    const fresh = isNewPasswordField(field, all);
    if (!fresh && !isSignInField(field, all)) return;
    const answer = await say({ kind: "field-focused", fresh, rules: fresh ? fieldRules(field) : undefined });
    if (!answer?.show || document.activeElement !== field) return;
    close("logins");
    anchor = field;
    frames.logins = makeFrame(fresh ? "new" : "logins");
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
    fitGlass(frame, false);
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
      if (event.key === "Enter" && event.target?.tagName === "INPUT") report();
    },
    true,
  );
  // Typing in the field means the person is not picking a saved login.
  document.addEventListener("input", (event) => event.isTrusted && event.target === anchor && close("logins"), true);
  window.addEventListener("scroll", place, { capture: true, passive: true });
  window.addEventListener("resize", place, { passive: true });

  // ---- what was typed, when the form is sent ----

  let reported = "";
  function report() {
    const typed = typedLogin(inputs());
    if (!typed) return;
    const mark = `${typed.username}\n${typed.password}`;
    if (mark === reported) return;
    reported = mark;
    if (typed.password) say({ kind: "submitted", username: typed.username, password: typed.password });
    else if (typed.username) say({ kind: "username-step", username: typed.username });
  }
  document.addEventListener("submit", report, true);
  document.addEventListener(
    "click",
    (event) => {
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
      if (frame && frame === frames.save) fitGlass(frame, false);
    }
  });

  // A login sent on the page before this one may still be waiting for an answer.
  say({ kind: "pending" }).then((answer) => answer?.offer && offerSave());
})();
