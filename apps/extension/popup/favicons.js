// Site icons from the browser's own cache of the pages it has shown (Chrome and Edge's
// `favicon` permission). Nothing is fetched from the sites themselves, so no site learns that
// its login was looked at, and no other service learns the list of sites.
//
// For a page it has no icon of, the browser answers with its grey globe rather than an error;
// that globe is recognised (compared with the one it gives for a page that can't exist) and
// the next likely page is tried, then the login's coloured initial stays. Where the browser
// has no such cache (Firefox), every lookup fails at once and the initials stay.

import { iconPages } from "./icon-pages.js";

const NO_PAGE = "https://no-icon.invalid/";

/** Lookups already made in this window, by pages and size. */
const found = new Map();
/** The browser's globe at each size, as pixels (or `undefined` where there is no cache). */
const globes = new Map();

const source = (page, px) => `${chrome.runtime.getURL("/_favicon/")}?pageUrl=${encodeURIComponent(page)}&size=${px}`;

function load(src) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve(img.naturalWidth > 0 ? img : undefined);
    img.onerror = () => resolve(undefined);
    img.src = src;
  });
}

function pixels(img, px) {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = px;
    canvas.height = px;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(img, 0, 0, px, px);
    return context.getImageData(0, 0, px, px).data;
  } catch {
    return undefined;
  }
}

function same(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function globe(px) {
  if (!globes.has(px)) globes.set(px, load(source(NO_PAGE, px)).then((img) => (img ? pixels(img, px) : undefined)));
  return globes.get(px);
}

/**
 * The address of the icon the browser has for `site` (trying the pages `iconPages` gives,
 * `page` being the tab in front), or `undefined` when it has none but its globe.
 */
export function lookIcon(site, page, px) {
  const pages = iconPages(site, page);
  const key = `${px}|${pages.join("|")}`;
  if (!found.has(key)) {
    found.set(
      key,
      (async () => {
        if (pages.length === 0) return undefined;
        const blank = await globe(px);
        // No globe either: this browser keeps no icons for extensions.
        if (!blank) return undefined;
        for (const candidate of pages) {
          const src = source(candidate, px);
          const img = await load(src);
          if (img && !same(pixels(img, px), blank)) return src;
        }
        return undefined;
      })(),
    );
  }
  return found.get(key);
}
