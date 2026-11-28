// Payment fields: which fields of a document ask for a card, and the function that types a card
// into them (F5).
//
// Both functions are handed to chrome.scripting.executeScript, so each must stand on its own:
// nothing outside its body exists where it runs. They run in the extension's isolated world,
// in the page's top document and in the frames the worker names (cards.js): a payment
// provider's fields often sit in a frame of its own site inside the shop's page.

/**
 * What the document it runs in asks of a card: its origin, and how many payment fields of each
 * kind it shows. Nothing is read from the fields but their attributes.
 *
 * @returns {{ origin: string, sandboxed: boolean, kinds: Record<string, number> }}
 */
export function cardFieldsHere() {
  const kinds = {};
  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const box = el.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0) return false;
    const style = window.getComputedStyle(el);
    return style.display !== "none" && style.visibility !== "hidden";
  };
  const words = (el) =>
    [
      el.getAttribute("autocomplete"),
      el.name,
      el.id,
      el.getAttribute("placeholder"),
      el.getAttribute("aria-label"),
      el.getAttribute("data-elements-stable-field-name"),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  const kindOf = (el) => {
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    const marked = auto.find((part) => part.startsWith("cc-"));
    if (marked) {
      if (marked === "cc-number") return "number";
      if (marked === "cc-csc") return "csc";
      if (marked === "cc-exp") return "exp";
      if (marked === "cc-exp-month") return "month";
      if (marked === "cc-exp-year") return "year";
      if (["cc-name", "cc-given-name", "cc-family-name"].includes(marked)) return "name";
      return undefined;
    }
    const text = words(el);
    if (/card.?num|cc.?num|cardnumber|credit.?card.?(no|num)|card.?no\b|n[uú]mero.?(do.?)?cart/.test(text)) return "number";
    if (/\b(cvc|cvv|cvv2|csc|cid)\b|security.?code|card.?code|c[oó]digo.?de.?seguran/.test(text)) return "csc";
    if (/expir|exp.?date|mm.?\/?.?yy|valid.?thru|validade|vencimento/.test(text)) return "exp";
    if (/exp.*month|card.?month|cc.?month/.test(text)) return "month";
    if (/exp.*year|card.?year|cc.?year/.test(text)) return "year";
    if (/card.?holder|holder.?name|name.?on.?card|cc.?name|nameoncard|titular/.test(text)) return "name";
    return undefined;
  };
  for (const el of document.querySelectorAll("input, select")) {
    if (!usable(el)) continue;
    const type = (el.type || "").toLowerCase();
    if (el.tagName === "INPUT" && !["text", "tel", "number", "", "password"].includes(type)) continue;
    const kind = kindOf(el);
    if (kind) kinds[kind] = (kinds[kind] || 0) + 1;
  }
  return { origin: window.location.origin, sandboxed: window.origin !== window.location.origin, kinds };
}

/**
 * Types card `card` into the payment fields of the document it runs in, when that document's
 * origin is one of `origins` (the page's own, and the frames the person approved for it: the
 * worker decides) and the document is not sandboxed. Only fields that read as payment fields
 * get anything; a form that sends over plain `http:` gets nothing.
 *
 * @param {string[]} origins the origins that may get the card
 * @param {{ holder: string, number: string, month: number, year: number, security_code: string }} card
 * @returns {"filled" | "none" | "wrong_page" | "insecure_form"}
 */
export function fillCard(origins, card) {
  if (!Array.isArray(origins) || !origins.includes(window.location.origin) || window.origin !== window.location.origin) {
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
    [
      el.getAttribute("autocomplete"),
      el.name,
      el.id,
      el.getAttribute("placeholder"),
      el.getAttribute("aria-label"),
      el.getAttribute("data-elements-stable-field-name"),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  // The same reading of a field as cardFieldsHere (which can't be shared: each function stands
  // alone where it runs).
  const kindOf = (el) => {
    const auto = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    const marked = auto.find((part) => part.startsWith("cc-"));
    if (marked) {
      if (marked === "cc-number") return "number";
      if (marked === "cc-csc") return "csc";
      if (marked === "cc-exp") return "exp";
      if (marked === "cc-exp-month") return "month";
      if (marked === "cc-exp-year") return "year";
      if (["cc-name", "cc-given-name", "cc-family-name"].includes(marked)) return "name";
      return undefined;
    }
    const text = words(el);
    if (/card.?num|cc.?num|cardnumber|credit.?card.?(no|num)|card.?no\b|n[uú]mero.?(do.?)?cart/.test(text)) return "number";
    if (/\b(cvc|cvv|cvv2|csc|cid)\b|security.?code|card.?code|c[oó]digo.?de.?seguran/.test(text)) return "csc";
    if (/expir|exp.?date|mm.?\/?.?yy|valid.?thru|validade|vencimento/.test(text)) return "exp";
    if (/exp.*month|card.?month|cc.?month/.test(text)) return "month";
    if (/exp.*year|card.?year|cc.?year/.test(text)) return "year";
    if (/card.?holder|holder.?name|name.?on.?card|cc.?name|nameoncard|titular/.test(text)) return "name";
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
      const wanted = String(value);
      const option = Array.from(el.options).find((option) => {
        const v = option.value.trim();
        const text = option.textContent.trim();
        return v === wanted || text === wanted || Number(v) === Number(wanted) || Number(text) === Number(wanted);
      });
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
  const two = (n) => String(n).padStart(2, "0");
  // A year field as wide as four digits (a select listing 2030, a placeholder "YYYY") gets
  // four; else two.
  const yearFor = (el) => {
    const hint = `${el.getAttribute("placeholder") || ""} ${el.getAttribute("maxlength") || ""}`.toLowerCase();
    const options = el.tagName === "SELECT" ? Array.from(el.options).map((o) => o.value) : [];
    const wide = /yyyy|\b4\b/.test(hint) || options.some((v) => /^\d{4}$/.test(v.trim()));
    return wide ? String(card.year) : two(card.year % 100);
  };
  const expFor = (el) => {
    const hint = (el.getAttribute("placeholder") || "").toLowerCase();
    const max = Number(el.getAttribute("maxlength")) || 0;
    let sep = "/";
    if (max === 4) sep = "";
    else if (/mm\s*-\s*yy/.test(hint)) sep = "-";
    else if (/mm\s\/\s(yy|aa)/.test(hint)) sep = " / ";
    const year = /yyyy/.test(hint) || max >= 7 ? String(card.year) : two(card.year % 100);
    return `${two(card.month)}${sep}${year}`;
  };

  let filled = 0;
  for (const el of document.querySelectorAll("input, select")) {
    if (!usable(el)) continue;
    const type = (el.type || "").toLowerCase();
    if (el.tagName === "INPUT" && !["text", "tel", "number", "", "password"].includes(type)) continue;
    const kind = kindOf(el);
    if (!kind) continue;
    if (insecure(el.form)) return "insecure_form";
    let value;
    if (kind === "number") value = card.number;
    else if (kind === "csc") value = card.security_code;
    else if (kind === "name") value = card.holder;
    else if (kind === "exp" && card.month) value = expFor(el);
    else if (kind === "month" && card.month) value = el.tagName === "SELECT" ? card.month : two(card.month);
    else if (kind === "year" && card.year) value = yearFor(el);
    if (value === undefined || value === "") continue;
    if (put(el, value)) filled++;
  }
  return filled > 0 ? "filled" : "none";
}
