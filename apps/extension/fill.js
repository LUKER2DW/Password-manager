// Runs inside the page, once, after the person picked a login in the extension's window.
//
// It is handed to chrome.scripting.executeScript as a function, so it must stand on its own:
// nothing outside its body exists where it runs. It runs in the extension's isolated world
// (the page's scripts can't see its variables) and only in the top frame.

/**
 * Types a login into the page's sign-in fields.
 *
 * Where: with `offerId` (a login picked in the card under a field), into that field and its
 * own form only. content.js keeps the offer in this isolated world (`VaultOffer`), where the
 * page can't reach it; when the card's offer is not the one there, or the page has since
 * removed the field, moved it into another form or changed where its form sends (its
 * `action`, a submit button's `formaction`, or the page's `<base>`), nothing is typed.
 * Without `offerId` (the extension's window), into the focused field's form when the focused
 * field is a sign-in field (a search box or a code field is not), else the page's one
 * sign-in form; with several and none of them focused, nothing is guessed.
 *
 * Fields outside any `<form>` belong together only when they sit next to each other (in one
 * of the field's few nearest containers): the password never goes into a box of another
 * sign-in, nor before the field picked.
 *
 * A form that may send over plain `http:` (its action or a submit button's) gets nothing.
 *
 * @param {string} expectedOrigin the origin the login belongs to
 * @param {string} username
 * @param {string} password
 * @param {string} [offerId] the offer of the card the login was picked in
 * @returns {"both" | "password" | "username" | "none" | "wrong_page" | "choose_field" | "insecure_form"}
 */
export function fillLogin(expectedOrigin, username, password, offerId) {
  // The tab may have moved on between the click and now: never type into another site,
  // and never into a frame.
  if (window.top !== window || window.location.origin !== expectedOrigin) {
    return "wrong_page";
  }

  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  };
  const put = (el, value) => {
    // Through the element's own setter, with the events frameworks listen to.
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const type = (el) => (el.type || "").toLowerCase();
  const hint = (el) => `${el.getAttribute("autocomplete") || ""} ${el.name || ""} ${el.id || ""}`.toLowerCase();
  const textLike = (el) => ["text", "email", "tel", ""].includes(type(el));
  const looksLikeUser = (el) => type(el) === "email" || /user|email|e-mail|login|account|identifier/.test(hint(el));
  // A field for choosing a new password (sign-up, change password) is not a sign-in field.
  const isPassword = (el) => type(el) === "password" && !hint(el).includes("new-password");
  const CODE = /one-time-code|otp|totp|2fa|mfa|two-?factor|one-?time|verif|authenticat|security.?code|auth.?code/;
  const words = (el) =>
    `${hint(el)} ${el.getAttribute("placeholder") || ""} ${el.getAttribute("aria-label") || ""}`.toLowerCase();
  const isCode = (el) =>
    (el.getAttribute("autocomplete") || "").toLowerCase().includes("one-time-code") ||
    (!looksLikeUser(el) && CODE.test(words(el)));
  // Where a form sends, as fields.js computes it: its action and each submit button's
  // formaction, resolved against the page's base URL, read through Element.prototype (a
  // field named "action" can't stand in).
  const attribute = (el, name) => window.Element.prototype.getAttribute.call(el, name);
  const resolved = (raw) => {
    try {
      return raw ? new URL(raw, document.baseURI || window.location.href).href : window.location.href;
    } catch {
      return "";
    }
  };
  const submits = (el) =>
    el.tagName === "BUTTON" ? type(el) === "submit" : el.tagName === "INPUT" && ["submit", "image"].includes(type(el));
  const destinationOf = (form) => {
    if (!form) return "";
    const places = [resolved(attribute(form, "action"))];
    for (const el of document.querySelectorAll("button, input")) {
      if (el.form !== form || !submits(el)) continue;
      const raw = attribute(el, "formaction");
      if (raw !== null) places.push(resolved(raw));
    }
    return places.join("\n");
  };
  const insecure = (form) => destinationOf(form).split("\n").some((place) => /^http:/i.test(place));
  const scopeOf = (el) => el.form ?? null;
  // Outside any form, the fields that belong together: in one of the field's few nearest
  // containers, as fields.js reads them.
  const near = (field, other) => {
    let node = field.parentElement;
    for (let level = 0; level < 4 && node && !["BODY", "HTML"].includes(node.tagName); level++) {
      if (node.contains(other)) return true;
      node = node.parentElement;
    }
    return false;
  };

  const inputs = Array.from(document.querySelectorAll("input")).filter(usable);
  let target;
  if (offerId !== undefined) {
    const offer = globalThis.VaultOffer;
    if (!offer || typeof offerId !== "string" || offer.id !== offerId) return "wrong_page";
    target = offer.field;
    if (!target?.isConnected || !usable(target) || target.form !== offer.form || destinationOf(target.form) !== offer.action) {
      return "wrong_page";
    }
  } else {
    // The focused field counts only when it is a sign-in field (where content.js offers the
    // card): a password field, a text field that reads like a username, or one with a password
    // in its form (outside a form: next to it). A search box, a code or a quantity is not.
    const active = document.activeElement;
    if (active?.tagName === "INPUT" && usable(active)) {
      if (isPassword(active)) target = active;
      else if (textLike(active) && !isCode(active)) {
        const partner = inputs.some(
          (el) => isPassword(el) && (active.form ? el.form === active.form : !el.form && near(active, el)),
        );
        if (partner || looksLikeUser(active)) target = active;
      }
    }
  }

  // Fields in several forms, or outside forms but not next to each other: several sign-ins.
  const apart = (fields) => {
    if (new Set(fields.map(scopeOf)).size > 1) return true;
    const loose = fields.filter((el) => !el.form);
    return loose.some((el) => el !== loose[0] && !near(loose[0], el));
  };
  let scope;
  if (target) {
    scope = scopeOf(target);
  } else {
    const passwords = inputs.filter(isPassword);
    if (apart(passwords)) return "choose_field";
    // No password on the page (the first step of two): its username fields, likewise.
    if (passwords.length === 0 && apart(inputs.filter((el) => textLike(el) && looksLikeUser(el) && !isCode(el)))) {
      return "choose_field";
    }
    scope = passwords.length > 0 ? scopeOf(passwords[0]) : undefined;
  }
  if (scope && insecure(scope)) return "insecure_form";
  let mine;
  if (scope === undefined) mine = inputs;
  else if (scope !== null) mine = inputs.filter((el) => scopeOf(el) === scope);
  else {
    // Outside any form: the fields next to the one picked (or to the page's one password).
    const center = target || inputs.find(isPassword);
    mine = inputs.filter((el) => !el.form && (el === center || near(center, el)));
  }

  const after = target ? mine.slice(mine.indexOf(target) + 1) : [];
  // In a form, its password field wherever it is; outside one, only one after the field.
  const passwordField =
    target && isPassword(target)
      ? target
      : after.find(isPassword) || (target && scope === null ? undefined : mine.find(isPassword));

  if (passwordField) {
    // The username: the field picked, else the closest text field before the password.
    const before = mine.slice(0, mine.indexOf(passwordField)).filter(textLike);
    const userField =
      target && target !== passwordField && textLike(target) ? target : before.reverse().find(looksLikeUser) || before[0];
    if (userField && username) put(userField, username);
    put(passwordField, password);
    return userField && username ? "both" : "password";
  }

  // Sign-in in two steps: only the username is asked on this page.
  const userField = target && textLike(target) ? target : mine.find((el) => textLike(el) && looksLikeUser(el));
  if (userField && username) {
    put(userField, username);
    return "username";
  }
  return "none";
}

/**
 * Types a one-time code into the page's code field: the one marked `one-time-code`, else one
 * named like a code. A code split over one box per digit is spread over the boxes.
 *
 * With `offerId`, only into the field the card was shown under (as `fillLogin`), and the
 * boxes of its own form, and not when the page has changed where that form sends. Without
 * (the extension's window), into the focused code field, else the page's one; with code
 * fields in several forms and none of them focused, nothing is guessed. A form that may send
 * over plain `http:` gets nothing.
 *
 * Handed to chrome.scripting.executeScript like `fillLogin`, so it stands on its own.
 *
 * @param {string} expectedOrigin the origin the login belongs to
 * @param {string} code
 * @param {string} [offerId] the offer of the card the login was picked in
 * @returns {"filled" | "none" | "wrong_page" | "choose_field" | "insecure_form"}
 */
export function fillCode(expectedOrigin, code, offerId) {
  if (window.top !== window || window.location.origin !== expectedOrigin) {
    return "wrong_page";
  }
  const type = (el) => (el.type || "").toLowerCase();
  // As fillLogin computes it.
  const attribute = (el, name) => window.Element.prototype.getAttribute.call(el, name);
  const resolved = (raw) => {
    try {
      return raw ? new URL(raw, document.baseURI || window.location.href).href : window.location.href;
    } catch {
      return "";
    }
  };
  const submits = (el) =>
    el.tagName === "BUTTON" ? type(el) === "submit" : el.tagName === "INPUT" && ["submit", "image"].includes(type(el));
  const destinationOf = (form) => {
    if (!form) return "";
    const places = [resolved(attribute(form, "action"))];
    for (const el of document.querySelectorAll("button, input")) {
      if (el.form !== form || !submits(el)) continue;
      const raw = attribute(el, "formaction");
      if (raw !== null) places.push(resolved(raw));
    }
    return places.join("\n");
  };
  const insecure = (form) => destinationOf(form).split("\n").some((place) => /^http:/i.test(place));
  let target;
  if (offerId !== undefined) {
    const offer = globalThis.VaultOffer;
    if (!offer || typeof offerId !== "string" || offer.id !== offerId) return "wrong_page";
    target = offer.field;
    if (!target?.isConnected || target.form !== offer.form || destinationOf(target.form) !== offer.action) {
      return "wrong_page";
    }
  }
  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  };
  const put = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const words = (el) =>
    [el.getAttribute("autocomplete"), el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label")]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  const CODE = /one-time-code|otp|totp|2fa|mfa|two-?factor|one-?time|verif|authenticat|security.?code|auth.?code/;
  const boxes = Array.from(document.querySelectorAll("input")).filter(
    (el) => ["text", "tel", "number", ""].includes(type(el)) && usable(el),
  );
  if (target && !boxes.includes(target)) return "none";
  const isMarked = (el) => (el.getAttribute("autocomplete") || "").toLowerCase().includes("one-time-code");
  const isCodeBox = (el) => isMarked(el) || CODE.test(words(el));
  if (!target) {
    const active = document.activeElement;
    if (active && boxes.includes(active) && isCodeBox(active)) {
      target = active;
    } else {
      const codes = boxes.filter(isCodeBox);
      if (new Set(codes.map((el) => el.form ?? null)).size > 1) return "choose_field";
      target = codes.find(isMarked) || codes[0];
    }
    // One box per digit: the code starts in the row's first box, wherever the focus is.
    if (target?.maxLength === 1) {
      target = boxes.find((el) => el.maxLength === 1 && el.form === target.form && isCodeBox(el)) || target;
    }
  }
  if (!target) return "none";
  if (target.form && insecure(target.form)) return "insecure_form";
  if (target.maxLength === 1) {
    // One box per digit: the boxes that follow it in the same form, as many as there are digits.
    const row = boxes.filter((el) => el.maxLength === 1 && el.form === target.form);
    const start = row.indexOf(target);
    const digits = row.slice(start, start + code.length);
    if (digits.length !== code.length) return "none";
    digits.forEach((el, i) => put(el, code[i]));
    return "filled";
  }
  put(target, code);
  return "filled";
}
