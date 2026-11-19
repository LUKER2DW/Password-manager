// Which fields of a page are sign-in fields, and what was typed in them.
//
// A classic script (content scripts cannot be modules), loaded before content.js into the
// same isolated world: page scripts can't see or change these functions.

(() => {
  const type = (el) => (el.type || "").toLowerCase();
  const hint = (el) => `${el.getAttribute("autocomplete") || ""} ${el.name || ""} ${el.id || ""}`.toLowerCase();
  const textLike = (el) => ["text", "email", "tel", ""].includes(type(el));
  const looksLikeUser = (el) =>
    type(el) === "email" || /user|email|e-mail|login|account|identifier/.test(hint(el));

  function usable(el) {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  }

  /** Whether focusing `el` should offer the saved logins. */
  function isSignInField(el, inputs) {
    if (!el || el.tagName !== "INPUT" || !usable(el)) return false;
    if (type(el) === "password") return !hint(el).includes("new-password");
    if (!textLike(el)) return false;
    // A text field counts when it reads like a username, or sits in a form with a password.
    if (looksLikeUser(el)) return true;
    return inputs.some((other) => type(other) === "password" && other.form && other.form === el.form);
  }

  /**
   * Whether `el` is where a new password is chosen (sign-up, change of password): marked
   * `new-password`, named like it, or one of two password fields in a form.
   */
  function isNewPasswordField(el, inputs) {
    if (!el || el.tagName !== "INPUT" || type(el) !== "password" || !usable(el)) return false;
    const marks = hint(el);
    if (marks.includes("current-password")) return false;
    if (marks.includes("new-password") || /new|confirm|repeat|again|register|signup|sign-up/.test(marks)) return true;
    const scope = inputs.filter((other) => type(other) === "password" && usable(other) && other.form === el.form);
    return scope.length >= 2;
  }

  const CODE = /one-time-code|otp|totp|2fa|mfa|two-?factor|one-?time|verif|authenticat|security.?code|auth.?code/;
  const words = (el) =>
    `${hint(el)} ${el.getAttribute("placeholder") || ""} ${el.getAttribute("aria-label") || ""}`.toLowerCase();

  /** Whether `el` asks for a one-time code (two-step sign-in). */
  function isCodeField(el) {
    if (!el || el.tagName !== "INPUT" || !usable(el)) return false;
    if (!["text", "tel", "number", ""].includes(type(el))) return false;
    if ((el.getAttribute("autocomplete") || "").toLowerCase().includes("one-time-code")) return true;
    return !looksLikeUser(el) && CODE.test(words(el));
  }

  /** What the site allows in a new password, as the field says it. */
  function fieldRules(el) {
    const text = (value) => (typeof value === "string" && value.length <= 512 ? value : undefined);
    return {
      maxLength: el.maxLength > 0 ? el.maxLength : undefined,
      minLength: el.minLength > 0 ? el.minLength : undefined,
      pattern: text(el.getAttribute("pattern")),
      passwordRules: text(el.getAttribute("passwordrules")),
    };
  }

  /** Puts a chosen password into the new-password fields next to `el` (and their repeats). */
  function putNewPassword(el, inputs, password) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    const targets = inputs.filter(
      (other) =>
        type(other) === "password" &&
        usable(other) &&
        (other === el || (other.form === el.form && !hint(other).includes("current-password"))),
    );
    for (const field of targets) {
      field.focus();
      setter.call(field, password);
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
    }
    return targets.length;
  }

  /**
   * What was typed: the first filled password field and the username before it. With no
   * password on the page, the username alone (the first step of a two-step sign-in).
   */
  function typedLogin(inputs) {
    const shown = inputs.filter(usable);
    const password = shown.find((el) => type(el) === "password" && el.value);
    if (!password) {
      const user = shown.find((el) => textLike(el) && looksLikeUser(el) && el.value);
      return user ? { username: user.value.trim(), password: "" } : undefined;
    }
    const before = shown
      .slice(0, shown.indexOf(password))
      .filter((el) => textLike(el) && el.value && (!password.form || el.form === password.form));
    const user = [...before].reverse().find(looksLikeUser) || before[before.length - 1];
    return { username: user ? user.value.trim() : "", password: password.value };
  }

  globalThis.VaultFields = { isSignInField, isNewPasswordField, isCodeField, fieldRules, putNewPassword, typedLogin };
})();
