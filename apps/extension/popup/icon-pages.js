// Which pages to ask the browser's icon cache about for a saved website. The browser keeps a
// site's icon under the pages it has shown, so a login saved as "github.com" may find nothing
// under https://github.com/ while https://github.com/login has one: a few likely pages are
// tried in turn, the page in front first when it is that site (its icon is certainly there).
//
// No DOM and no `chrome` here: tested on its own (test/popup.test.mjs).

/** At most this many pages per site. */
export const MAX_PAGES = 4;

function parse(address) {
  try {
    const url = new URL(address);
    return url.protocol === "https:" || url.protocol === "http:" ? url : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The pages to try for `site` (as saved: "example.com", "*.example.com", a full address),
 * with `page` the address of the tab in front (used only when it is on that same host).
 */
export function iconPages(site, page) {
  const bare = String(site ?? "")
    .trim()
    .replace(/^\*\./, "");
  if (!bare) return [];
  const saved = parse(/^[a-z][a-z0-9+.-]*:\/\//i.test(bare) ? bare : `https://${bare}`);
  if (!saved) return [];
  const pages = [];
  const add = (url) => {
    if (url && !pages.includes(url) && pages.length < MAX_PAGES) pages.push(url);
  };
  const front = parse(page ?? "");
  if (front && front.host === saved.host) add(`${front.origin}${front.pathname}`);
  if (saved.pathname !== "/") add(`${saved.origin}${saved.pathname}`);
  add(`${saved.origin}/`);
  // The same site with or without "www.": a name, not an address or a single word.
  const name = saved.hostname.replace(/^www\./, "");
  if (name.includes(".") && !/^[\d.]+$/.test(name) && !name.startsWith("[")) {
    const other = saved.hostname.startsWith("www.") ? name : `www.${name}`;
    add(`${saved.protocol}//${other}${saved.port ? `:${saved.port}` : ""}/`);
  }
  return pages;
}
