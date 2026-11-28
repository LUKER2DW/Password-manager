// Cards filled into a page's payment fields (F5), for the worker and the extension's window.
//
// The rule for frames (as S22 does on the phone): the page's own document, and frames of the
// very same origin, get the card; a frame of any other origin (a payment provider's fields
// embedded in a shop's checkout) gets it only when the person approved that frame's site for
// this page's site, in the card's own frame or the extension's window. The approval is kept by
// the app with the site's rules (`card_frames`, Settings → Browser extension → Site rules), so
// a page can't give it, and the frame's origin is the browser's own word for its document
// (`location.origin` read in the isolated world; a sandboxed document is nobody's). A frame
// that isn't approved is named to the person, never filled.

import { ask, originOf } from "./app.js";
import { cardFieldsHere, fillCard } from "./card-fill.js";

/** The key a site's rule is kept under (`vault_browser::rules::site_key`): host, no `www.`. */
export function siteKey(origin) {
  try {
    const url = new URL(origin);
    if (!["https:", "http:"].includes(url.protocol) || !url.hostname) return "";
    const host = url.hostname.toLowerCase().replace(/^www\./, "");
    return url.port && url.port !== "443" ? `${host}:${url.port}` : host;
  } catch {
    return "";
  }
}

/**
 * Which documents of the tab may get a card. `frames` are what `cardFieldsHere` found in each
 * (with the browser's `frameId`), `top` the tab's origin, `approved` the frame sites the person
 * approved for this site. Answers the frames to fill, and the sites of those left waiting for
 * an approval.
 */
export function cardTargets(frames, top, approved) {
  const allowed = [];
  const waiting = [];
  for (const frame of frames) {
    if (!frame || frame.sandboxed || typeof frame.origin !== "string" || !frame.origin.startsWith("https://")) continue;
    // The tab's own document must be the tab's origin, or the page moved on.
    if (frame.frameId === 0 && frame.origin !== top) continue;
    if (frame.origin === top) {
      allowed.push(frame);
      continue;
    }
    const site = siteKey(frame.origin);
    if (site && Array.isArray(approved) && approved.includes(site)) allowed.push(frame);
    else if (site && !waiting.includes(site)) waiting.push(site);
  }
  return { allowed, waiting };
}

/** The documents of tab `tabId` that show payment fields. */
export async function cardFrames(tabId) {
  let results = [];
  try {
    results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: cardFieldsHere });
  } catch {
    return [];
  }
  return results
    .filter((ran) => ran?.result && Object.keys(ran.result.kinds ?? {}).length > 0)
    .map((ran) => ({ frameId: ran.frameId, ...ran.result }));
}

/**
 * Fills card `id` into the payment fields of `tab`, as the person's rule `rule` allows
 * (`rule.card_frames`). `send` asks the app for the card (the worker's `ask` with Windows
 * Hello, or the window's `guarded`, which asks for the PIN); it may answer `undefined` (the
 * person turned back). Answers `{ done, waiting, reply }`: `waiting` names the sites of frames
 * with payment fields that were left out for want of an approval, `reply` is the app's answer
 * when it refused.
 */
export async function fillCardInTab(tab, id, rule, send = ask) {
  const top = originOf(tab.url);
  const frames = await cardFrames(tab.id);
  const { allowed, waiting } = cardTargets(frames, top, rule?.card_frames ?? []);
  // Nothing to fill here: the card's details are not even asked for.
  if (allowed.length === 0) return { done: false, waiting, none: waiting.length === 0 };
  const reply = await send({ type: "card_fill", url: tab.url, id });
  if (reply?.type !== "card_fill") return { done: false, waiting, reply };
  const now = await chrome.tabs.get(tab.id);
  if (originOf(now.url) !== reply.origin) return { done: false, waiting, changed: true };
  const card = {
    holder: reply.holder ?? "",
    number: reply.number ?? "",
    month: Number(reply.month) || 0,
    year: Number(reply.year) || 0,
    security_code: reply.security_code ?? "",
  };
  reply.number = "";
  reply.security_code = "";
  let done = false;
  try {
    const ran = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: allowed.map((frame) => frame.frameId) },
      func: fillCard,
      args: [Array.from(new Set(allowed.map((frame) => frame.origin))), card],
    });
    done = ran.some((one) => one?.result === "filled");
  } catch {
    done = false;
  }
  card.number = "";
  card.security_code = "";
  return { done, waiting };
}

/** Approves the frames of `site` (a frame's site) for cards on the page of `tab`. */
export async function approveCardFrame(tab, site) {
  const reply = await ask({ type: "site_rule", url: tab.url, rule: { allow_card_frame: site } });
  return reply?.type === "site_rule" ? reply.rule : undefined;
}
