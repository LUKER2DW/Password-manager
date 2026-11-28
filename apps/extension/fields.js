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

  /**
   * Whether `el` is marked for the browser's passkey suggestions (`autocomplete="username
   * webauthn"`): where the site expects them when it asks for a field's suggestions.
   */
  function isPasskeyField(el) {
    if (!el || el.tagName !== "INPUT" || !usable(el)) return false;
    if (!textLike(el) && type(el) !== "password") return false;
    return (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).includes("webauthn");
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

  /** Whether a click on `control` (a button or an input of a form) submits its form. */
  function submits(control) {
    if (control.tagName === "BUTTON") return type(control) === "submit";
    if (control.tagName === "INPUT") return ["submit", "image"].includes(type(control));
    return false;
  }

  // Attributes read through `Element.prototype`: a field named "action" or "getAttribute"
  // inside a form would otherwise stand in for the real attribute.
  const attribute = (el, name) => Element.prototype.getAttribute.call(el, name);
  /** An address as the browser resolves a form's: against the page's base URL (`<base>`). */
  function resolved(raw) {
    try {
      return raw ? new URL(raw, document.baseURI).href : location.href;
    } catch {
      return "";
    }
  }

  /**
   * Everywhere a form may send what is typed in it ("" outside a form): its `action`, and the
   * `formaction` of each of its submit buttons (also those outside it, tied by `form="…"`),
   * each one resolved against the page's base URL as the browser does. One line each.
   * fill.js computes it the same way.
   */
  function destinationOf(form) {
    if (!form) return "";
    const places = [resolved(attribute(form, "action"))];
    for (const el of document.querySelectorAll("button, input")) {
      if (el.form !== form || !submits(el)) continue;
      const raw = attribute(el, "formaction");
      if (raw !== null) places.push(resolved(raw));
    }
    return places.join("\n");
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
   * The filled sign-in fields of one scope: a form, or `null` for the fields outside any form.
   * The first filled password field and the username before it; with no password, the
   * username alone (the first step of a two-step sign-in).
   */
  function loginFields(inputs, scope) {
    const shown = inputs.filter((el) => usable(el) && (el.form ?? null) === scope);
    const password = shown.find((el) => type(el) === "password" && el.value);
    if (!password) {
      const user = shown.find((el) => textLike(el) && looksLikeUser(el) && el.value);
      return user ? { user, password: undefined } : undefined;
    }
    const before = shown.slice(0, shown.indexOf(password)).filter((el) => textLike(el) && el.value);
    const user = [...before].reverse().find(looksLikeUser) || before[before.length - 1];
    return { user, password };
  }

  /**
   * What was typed in the fields an event sends (see `sentScope`). `undefined` when the
   * scope is `undefined`: the event sends nothing, so nothing is read.
   */
  function typedLogin(inputs, scope) {
    if (scope === undefined) return undefined;
    const fields = loginFields(inputs, scope);
    if (!fields) return undefined;
    return { username: fields.user ? fields.user.value.trim() : "", password: fields.password ? fields.password.value : "" };
  }

  // What a button that sends a sign-in says, in the app's languages and a few more: its whole
  // label, short, starting with one of these words ("Sign in", "Entrar na conta", "Next").
  // A label that asks for help, names another way in or another account, or asks a question
  // ("Can't log in?", "Login help", "Continue with Google", "Entrar com Google", "Não
  // consigo acessar") is not one.
  const SENDS =
    /^(log[ -]?in|log[ -]?on|sign[ -]?in|sign[ -]?on|continue|next|submit|entrar|acessar|continuar|pr[oó]ximo|avan[cç]ar|iniciar sesi[oó]n|ingresar|siguiente|anmelden|einloggen|weiter|connexion|se connecter|continuer|suivant|accedi|avanti|inloggen|volgende)(\s|$)/i;
  const NOT_SENDS =
    /\?|\b(help|ajuda|aide|hilfe|ayuda|aiuto|forgot|esque\w*|reset|recover\w*|recuper\w*|trouble|problem\w*|can'?t|cannot|n[aã]o|not|with|com|using|usando|via|mit|avec|con|google|apple|facebook|microsoft|github|twitter|linkedin|sso|saml|passkey|guest|convidad\w*|another|outr[ao]|different|code|c[oó]digo|link|magic|sms)\b/i;
  const LABEL_MAX = 40;
  /** A control's label from one source: its `aria-label`, else its text, else its value. */
  function labelOf(el) {
    const text =
      (attribute(el, "aria-label") || "").trim() ||
      (el.textContent || "").trim() ||
      (el.tagName === "INPUT" ? (el.value || "").trim() : "");
    return text.replace(/\s+/g, " ").replace(/[\s→›»>.!…:]+$/u, "");
  }
  function readsLikeSignIn(el) {
    const label = labelOf(el);
    return label.length > 0 && label.length <= LABEL_MAX && SENDS.test(label) && !NOT_SENDS.test(label);
  }

  /** Whether `control` sits next to `field`: inside one of the field's few nearest containers. */
  function near(field, control) {
    let node = field.parentElement;
    for (let level = 0; level < 4 && node && !["BODY", "HTML"].includes(node.tagName); level++) {
      if (node.contains(control)) return true;
      node = node.parentElement;
    }
    return false;
  }

  // The fields where Enter sends their form (implicit submission). On a button, a file
  // input or a reset, Enter only presses that control.
  const ENTER_SENDS = ["text", "email", "tel", "", "password", "number", "search", "url", "checkbox", "radio"];

  /**
   * Which sign-in fields an event sends, as the scope `typedLogin` reads: the form being
   * submitted, or `null` for fields outside any form. `undefined` when the event sends
   * nothing: what was typed is read only when that very form is sent.
   *
   * - `submit`: the form submitted (content.js takes only one that follows the person's own
   *   act in that form).
   * - `enter`: the form of the field Enter was pressed in, for a field where Enter sends it;
   *   outside a form, only Enter in the sign-in fields themselves.
   * - `click`: only a button that reads like signing in (`readsLikeSignIn`): a button of a
   *   form, submit or not (pages that sign in by script use `type=button`), sends that form;
   *   a `role=button` element sends the form it is in, and a button outside a form the
   *   fields outside forms, only when it sits next to them. Any other button sends nothing
   *   by its click: a form's other submit button (a Help without a `type`, an eye) is read
   *   only when the form really is submitted, by its `submit` event.
   */
  function sentScope(kind, target, inputs) {
    if (kind === "submit") return target?.tagName === "FORM" ? target : undefined;
    if (kind === "enter") {
      if (target?.tagName !== "INPUT" || !ENTER_SENDS.includes(type(target))) return undefined;
      if (target.form) return target.form;
      const fields = loginFields(inputs, null);
      return fields && (target === fields.password || target === fields.user) ? null : undefined;
    }
    if (kind !== "click") return undefined;
    const control = target?.closest?.("button, input, [role=button]");
    if (!control) return undefined;
    const native = control.tagName === "BUTTON" || control.tagName === "INPUT";
    if (control.tagName === "INPUT" && !["submit", "image", "button"].includes(type(control))) return undefined;
    if (!readsLikeSignIn(control)) return undefined;
    const scope = (native ? control.form : control.closest("form")) ?? null;
    const fields = loginFields(inputs, scope);
    const field = fields?.password || fields?.user;
    if (!field) return undefined;
    // A form's own button belongs to it (also one outside it, tied by `form="…"`); anything
    // else must sit next to the fields it would send.
    return (native && scope) || near(field, control) ? scope : undefined;
  }

  const CARD_NUMBER = /card.?num|cc.?num|cardnumber|credit.?card.?(no|num)|card.?no|n[uú]mero.?(do.?)?cart/;
  const CARD_OTHER =
    /(cvc|cvv|cvv2|csc)|security.?code|card.?code|expir|exp.?date|valid.?thru|card.?holder|name.?on.?card|cc.?name|nameoncard/;

  /**
   * Whether `el` is a payment field of the page (a card's number, name, expiry or security
   * code): marked `cc-*` for the browser's autofill, or named like one. Where the card from
   * the vault is offered (F5; card-fill.js fills them).
   */
  function isCardField(el) {
    if (!el || el.tagName !== "INPUT" || !usable(el)) return false;
    if (!["text", "tel", "number", "", "password"].includes(type(el))) return false;
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    if (auto.some((part) => part.startsWith("cc-"))) return true;
    const text = words(el);
    return CARD_NUMBER.test(text) || CARD_OTHER.test(text);
  }

  globalThis.VaultFields = {
    isSignInField,
    isCardField,
    isNewPasswordField,
    isCodeField,
    isPasskeyField,
    fieldRules,
    destinationOf,
    putNewPassword,
    typedLogin,
    sentScope,
  };
})();
