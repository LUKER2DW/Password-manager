// Address fields: the function that types an identity's details into them (F5, with the
// identity items of F7).
//
// It is handed to chrome.scripting.executeScript, so it must stand on its own: nothing outside
// its body exists where it runs. It runs in the extension's isolated world, in the tab's top
// document only: an address goes to the page in front, never to a frame of another site.

/**
 * Types identity `who` into the address fields of the page, when the page is still
 * `expectedOrigin` and isn't sandboxed. Only fields that read as address fields get anything
 * (marked for the browser's autofill, or named like one); a form that sends over plain `http:`
 * gets nothing.
 *
 * @param {string} expectedOrigin
 * @param {{ name: string, email: string, phone: string, address: string, city: string,
 *   region: string, postal_code: string, country: string, company: string }} who
 * @returns {"filled" | "none" | "wrong_page" | "insecure_form"}
 */
export function fillAddress(expectedOrigin, who) {
  if (window.top !== window || window.location.origin !== expectedOrigin || window.origin !== expectedOrigin) {
    return "wrong_page";
  }
  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  };
  const words = (el) =>
    [el.getAttribute("autocomplete"), el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label")]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  const lines = String(who.address || "").split(/\r?\n/);
  const [given, ...rest] = String(who.name || "").trim().split(/\s+/);
  const family = rest.join(" ");
  // The autofill marks first (WHATWG's tokens), then common names.
  const MARKS = {
    name: who.name,
    "given-name": given,
    "family-name": family,
    email: who.email,
    tel: who.phone,
    organization: who.company,
    "street-address": who.address,
    "address-line1": lines[0],
    "address-line2": lines.slice(1).join(", "),
    "address-level2": who.city,
    "address-level1": who.region,
    "postal-code": who.postal_code,
    "country-name": who.country,
    country: who.country,
  };
  const NAMED = [
    [/first.?name|given.?name|fname/, given],
    [/last.?name|family.?name|surname|lname/, family],
    [/full.?name|^name$|your.?name/, who.name],
    [/e-?mail/, who.email],
    [/phone|tel\b|mobile/, who.phone],
    [/company|organi[sz]ation/, who.company],
    [/address.?(line)?.?2|addr2|apartment|suite/, lines.slice(1).join(", ")],
    [/address|street|addr1|endere[cç]o|logradouro/, lines[0]],
    [/city|town|cidade|locality/, who.city],
    [/state|region|province|estado|county/, who.region],
    [/zip|postal|postcode|cep/, who.postal_code],
    [/country|pa[ií]s/, who.country],
  ];
  const valueFor = (el) => {
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    // A field marked for something else (a password, a card, a one-time code) is not ours.
    if (auto.some((part) => /password|cc-|one-time-code|webauthn|username/.test(part))) return undefined;
    const token = auto.find((part) => Object.hasOwn(MARKS, part));
    if (token) return MARKS[token];
    const text = words(el);
    if (/pass|card|cvc|cvv|otp|code|search|coupon|promo/.test(text)) return undefined;
    for (const [pattern, value] of NAMED) if (pattern.test(text)) return value;
    return undefined;
  };
  const attribute = (el, name) => window.Element.prototype.getAttribute.call(el, name);
  const insecure = (form) => {
    if (!form) return false;
    const places = [attribute(form, "action")];
    for (const el of form.querySelectorAll("button, input")) places.push(attribute(el, "formaction"));
    return places.some((raw) => {
      try {
        return raw !== null && new URL(raw || window.location.href, document.baseURI).protocol === "http:";
      } catch {
        return false;
      }
    });
  };
  const put = (el, value) => {
    if (el.tagName === "SELECT") {
      const wanted = String(value).trim().toLowerCase();
      const option = Array.from(el.options).find(
        (o) => o.value.trim().toLowerCase() === wanted || o.textContent.trim().toLowerCase() === wanted,
      );
      if (!option) return false;
      el.value = option.value;
    } else {
      const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
      el.focus();
      setter.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  };
  let filled = 0;
  for (const el of document.querySelectorAll("input, select")) {
    if (!usable(el)) continue;
    const type = (el.type || "").toLowerCase();
    if (el.tagName === "INPUT" && !["text", "email", "tel", ""].includes(type)) continue;
    // Something already typed stays.
    if (el.tagName === "INPUT" && el.value) continue;
    const value = valueFor(el);
    if (!value) continue;
    if (insecure(el.form)) return "insecure_form";
    if (put(el, value)) filled++;
  }
  return filled > 0 ? "filled" : "none";
}
