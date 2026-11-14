// Runs inside the page, once, after the person picked a login in the extension's window.
//
// It is handed to chrome.scripting.executeScript as a function, so it must stand on its own:
// nothing outside its body exists where it runs. It runs in the extension's isolated world
// (the page's scripts can't see its variables) and only in the top frame.

/**
 * Types a login into the page's sign-in fields.
 *
 * @param {string} expectedOrigin the origin the login belongs to
 * @param {string} username
 * @param {string} password
 * @returns {"both" | "password" | "username" | "none" | "wrong_page"}
 */
export function fillLogin(expectedOrigin, username, password) {
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
  const hint = (el) =>
    `${el.getAttribute("autocomplete") || ""} ${el.name || ""} ${el.id || ""}`.toLowerCase();
  const textLike = (el) => ["text", "email", "tel", ""].includes((el.type || "").toLowerCase());
  const looksLikeUser = (el) =>
    (el.type || "").toLowerCase() === "email" || /user|email|e-mail|login|account|identifier/.test(hint(el));

  const inputs = Array.from(document.querySelectorAll("input")).filter(usable);
  // A field for choosing a new password (sign-up, change password) is not a sign-in field.
  const passwordField = inputs.find(
    (el) => (el.type || "").toLowerCase() === "password" && !hint(el).includes("new-password"),
  );

  if (passwordField) {
    // The username is the closest text field before the password, in the same form if any.
    const before = inputs
      .slice(0, inputs.indexOf(passwordField))
      .filter((el) => textLike(el) && (!passwordField.form || el.form === passwordField.form));
    const userField = before.reverse().find(looksLikeUser) || before[0];
    if (userField && username) put(userField, username);
    put(passwordField, password);
    return userField && username ? "both" : "password";
  }

  // Sign-in in two steps: only the username is asked on this page.
  const userField = inputs.find((el) => textLike(el) && looksLikeUser(el));
  if (userField && username) {
    put(userField, username);
    return "username";
  }
  return "none";
}
