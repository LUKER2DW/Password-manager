// Stand-in for app.js in test/preview.html: the real module's helpers, with `ask` answered
// from the preview's fixed test data (`previewAnswer`) instead of the app, so the window's
// views can be looked at without the app and without sealing.

export * from "../app.js?real";

export async function ask(request) {
  return globalThis.previewAnswer(request);
}
