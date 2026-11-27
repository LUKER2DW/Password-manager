// The generator. The app makes every password; this view only says what kind. The password
// follows the length slider while it is dragged: the app is asked about every 120 ms, for the
// newest length, and the last length is always the one shown in the end. The choices (never
// a password) are kept for the next window.

import { ask } from "../app.js";
import { canMake, generateRequest, keptOptions, LENGTH, separatorOf, startOptions, WORDS } from "./options.js";
import { here, routes } from "./state.js";
import { strengthOf } from "./strength.js";
import { throttleLatest } from "./throttle.js";
import { $, drawColoured, explain, mark, t, toast, view } from "./ui.js";

const KEPT = "generatorOptions";
const LIVE_MS = 120;

/** The choices on screen. */
let options = startOptions();
/** The last password the app made here, and the id that keeps it in the app's history. */
let made;
let ready = false;

/** Asks the app for a password with `fields` (a `generate` request's), for the page in front. */
export async function generate(fields) {
  const reply = await ask({ type: "generate", ...fields, url: here.tab?.url });
  if (reply.type !== "generated") return { error: reply.code };
  return { id: reply.id, password: reply.password, bits: reply.bits };
}

/** The choices as the generator has them, for a password made elsewhere in the window. */
export async function currentRequest() {
  await loadOptions();
  return canMake(options) ? generateRequest(options) : generateRequest(startOptions());
}

async function loadOptions() {
  if (ready) return;
  ready = true;
  try {
    const { [KEPT]: kept } = await chrome.storage.local.get(KEPT);
    options = keptOptions(kept);
  } catch {
    options = startOptions();
  }
}

function keepOptions() {
  chrome.storage.local.set({ [KEPT]: { ...options } }).catch(() => {});
}

const live = throttleLatest({
  interval: LIVE_MS,
  run: (fields) => generate(fields),
  apply: (result) => showMade(result),
});

/** Shows what the app made (or why nothing). */
function showMade(result) {
  const password = $("gen-password");
  const meter = $("gen-meter");
  if (!result || result.error) {
    made = undefined;
    // The app is gone, or doesn't know this window any more: said in place of the view.
    if (["not_running", "not_paired", "bad_answer"].includes(result?.error)) return explain(result.error);
    password.textContent = t(result ? "genFailed" : "genImpossible");
    password.classList.add("none");
    meter.dataset.level = "0";
    $("gen-strength").textContent = "";
    $("gen-bits").textContent = "";
    $("gen-copy").disabled = true;
    $("gen-use").disabled = true;
    return;
  }
  made = result;
  password.classList.remove("none");
  drawColoured(password, result.password);
  const strength = strengthOf(result.bits);
  meter.dataset.level = String(strength.level);
  meter.dataset.tone = strength.tone;
  $("gen-strength").textContent = t(strength.key);
  $("gen-strength").dataset.tone = strength.tone;
  $("gen-bits").textContent = t("bitsLabel", result.bits);
  $("gen-copy").disabled = false;
  $("gen-use").disabled = false;
}

/** Asks for a new password with the choices on screen. */
function remake() {
  if (!canMake(options)) {
    live.cancel();
    return showMade(undefined);
  }
  live.push(generateRequest(options));
}

/** Puts the choices on screen. */
function drawOptions() {
  const words = options.words;
  $("gen-mode-chars").setAttribute("aria-pressed", String(!words));
  $("gen-mode-words").setAttribute("aria-pressed", String(words));
  $("gen-chars").hidden = words;
  $("gen-words").hidden = !words;
  const bounds = words ? WORDS : LENGTH;
  const value = words ? options.count : options.length;
  for (const id of ["gen-count", "gen-count-number"]) {
    $(id).min = String(bounds.min);
    $(id).max = String(bounds.max);
    $(id).value = String(value);
  }
  $("gen-count-label").textContent = t(words ? "wordsLabel" : "lengthLabel");
  fillSlider();
  for (const name of ["upper", "lower", "digits", "symbols", "avoid_ambiguous", "capitalize", "number"]) {
    $(`gen-${name}`).checked = options[name];
  }
  const presets = [...document.querySelectorAll("#gen-separators button[data-separator]")];
  const preset = presets.find((button) => button.dataset.separator === options.separator);
  for (const button of presets) button.setAttribute("aria-pressed", String(button === preset));
  $("gen-separator").value = preset ? "" : options.separator;
}

/** The slider's track is filled up to the knob (the browser draws no fill of its own). */
function fillSlider() {
  const slider = $("gen-count");
  const span = Number(slider.max) - Number(slider.min) || 1;
  const part = ((Number(slider.value) - Number(slider.min)) / span) * 100;
  slider.style.setProperty("--fill", `${part}%`);
}

/** The length or the number of words changed (slider or box): a new password, live. */
function setCount(value, { fromBox = false } = {}) {
  const bounds = options.words ? WORDS : LENGTH;
  const n = Math.round(Number(value));
  if (!Number.isFinite(n)) return;
  const clamped = Math.min(bounds.max, Math.max(bounds.min, n));
  options[options.words ? "count" : "length"] = clamped;
  $("gen-count").value = String(clamped);
  if (!fromBox) $("gen-count-number").value = String(clamped);
  fillSlider();
  keepOptions();
  remake();
}

let wired = false;

function wire() {
  if (wired) return;
  wired = true;
  $("gen-mode-chars").onclick = () => {
    options.words = false;
    drawOptions();
    keepOptions();
    remake();
  };
  $("gen-mode-words").onclick = () => {
    options.words = true;
    drawOptions();
    keepOptions();
    remake();
  };
  // Every move of the knob (drag, arrow keys) asks; the throttle keeps it to a few a second.
  $("gen-count").addEventListener("input", (event) => setCount(event.target.value));
  const box = $("gen-count-number");
  box.addEventListener("input", () => {
    if (box.value !== "" && box.checkValidity()) setCount(box.value, { fromBox: true });
  });
  box.addEventListener("change", () => {
    setCount(box.value === "" ? (options.words ? options.count : options.length) : box.value);
  });
  for (const name of ["upper", "lower", "digits", "symbols", "avoid_ambiguous", "capitalize", "number"]) {
    $(`gen-${name}`).addEventListener("change", (event) => {
      options[name] = event.target.checked;
      keepOptions();
      remake();
    });
  }
  for (const button of document.querySelectorAll("#gen-separators button[data-separator]")) {
    button.addEventListener("click", () => {
      options.separator = button.dataset.separator;
      drawOptions();
      keepOptions();
      remake();
    });
  }
  const own = $("gen-separator");
  own.addEventListener("input", () => {
    const typed = separatorOf(own.value);
    if (own.value !== typed) own.value = typed;
    if (!typed) return;
    options.separator = typed;
    for (const button of document.querySelectorAll("#gen-separators button[data-separator]")) {
      button.setAttribute("aria-pressed", String(button.dataset.separator === typed));
    }
    keepOptions();
    remake();
  });
  $("gen-again").onclick = () => {
    $("gen-again").classList.remove("turn");
    void $("gen-again").offsetWidth;
    $("gen-again").classList.add("turn");
    remake();
  };
  $("gen-copy").onclick = async () => {
    if (!made) return;
    // The app copies it (out of clipboard history, cleared later) and keeps it in its history.
    const reply = await ask({ type: "keep", id: made.id, copy: true });
    if (reply.type === "copied") toast(t("copiedSecret", String(reply.seconds)));
    else if (reply.code === "no_match") remake();
    else explain(reply.code);
  };
  $("gen-use").onclick = () => made && routes.newLogin(made);
}

export async function showGenerator() {
  mark("gen");
  view("tabs", "gen", "foot");
  $("gen-mode-chars").textContent = t("modeChars");
  $("gen-mode-words").textContent = t("modeWords");
  $("gen-upper-label").textContent = t("kindUpper");
  $("gen-lower-label").textContent = t("kindLower");
  $("gen-digits-label").textContent = t("kindDigits");
  $("gen-symbols-label").textContent = t("kindSymbols");
  $("gen-avoid_ambiguous-label").textContent = t("avoidAmbiguous");
  $("gen-capitalize-label").textContent = t("capitalize");
  $("gen-number-label").textContent = t("addNumber");
  $("gen-separator-label").textContent = t("separatorLabel");
  $("gen-separator").placeholder = t("separatorOwn");
  $("gen-separator").setAttribute("aria-label", t("separatorOwnLabel"));
  $("gen-space").setAttribute("aria-label", t("separatorSpace"));
  $("gen-space").title = t("separatorSpace");
  $("gen-again").title = t("anotherButton");
  $("gen-again").setAttribute("aria-label", t("anotherButton"));
  $("gen-count-number").setAttribute("aria-label", t("countBoxLabel"));
  $("gen-copy").textContent = t("copyButton");
  $("gen-use").textContent = t("useForLogin");
  $("gen-note").textContent = t("genNote");
  await loadOptions();
  wire();
  drawOptions();
  remake();
}
