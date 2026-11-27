// What this window knows while it is open: the tab it was opened over and what the app said
// about it. Nothing here is a secret, and nothing here outlives the window.

export const here = {
  /** The system the browser runs on (`chrome.runtime.getPlatformInfo`): "win", "linux", "mac"… */
  os: undefined,
  /** The tab in front when the window opened. */
  tab: undefined,
  /** The app's `logins` answer for that tab's page, and why there is none. */
  site: undefined,
  siteProblem: undefined,
  /** The app's `vault` answer, and why there is none. */
  vault: undefined,
  vaultProblem: undefined,
  /** The app's `status` answer. */
  status: undefined,
  /** A login typed into the page and not saved yet. */
  pending: undefined,
  /**
   * What the page in front was warned about where the browser draws no warning in pages
   * (Firefox): another site's password pasted or sent there (`pasted`, `sent`: site names), a key
   * of the kit refused (`kit`). From the worker, said once.
   */
  warnings: undefined,
  /** Which tab of the window is shown: "site", "vault", "codes" or "gen". */
  place: "site",
  /** False once the app said it doesn't know `lock` (an older app): the button goes. */
  canLock: true,
  /** False once the app said it doesn't show codes (an older app): "Show code" goes. */
  showsCodes: true,
};

/**
 * The window's places, filled in by popup.js, so the views can send the person to one
 * another without importing each other in a circle.
 */
export const routes = {
  site: () => {},
  vault: () => {},
  codes: () => {},
  gen: () => {},
  /** One login: `(entry, listing, back)`. */
  entry: () => {},
  /** A new login, with a generated password `{ id, password }` or none. */
  newLogin: () => {},
  connect: () => {},
  /** Asks the app again for everything and shows the right place. */
  refresh: () => {},
  /** Asks the app again for the lists, without changing the view. */
  reload: async () => {},
};
