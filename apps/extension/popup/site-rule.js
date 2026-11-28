// The person's rule for the site in front as the window reads it, and the request that changes
// one switch (F16). On its own so it can be tested apart from the window.

/** The switches, in the order they are listed, with their words. */
export const SWITCHES = [
  ["never_save", "ruleNeverSave"],
  ["no_card", "ruleNoCard"],
  ["never_fill", "ruleNeverFill"],
  ["no_passkeys", "ruleNoPasskeys"],
];

/** The rule the app sent with the page's logins, read strictly: unknown parts are left out. */
export function ruleOf(listing) {
  const rule = listing?.rule;
  const out = { site: "", card_frames: [] };
  for (const [key] of SWITCHES) out[key] = rule?.[key] === true;
  if (typeof rule?.site === "string") out.site = rule.site.slice(0, 253);
  if (Array.isArray(rule?.card_frames)) {
    out.card_frames = rule.card_frames.filter((host) => typeof host === "string").slice(0, 16);
  }
  return out;
}

/** The request that turns switch `key` on or off for the page at `url`. */
export function ruleRequest(url, key, on) {
  return { type: "site_rule", url, rule: { [key]: Boolean(on) } };
}
