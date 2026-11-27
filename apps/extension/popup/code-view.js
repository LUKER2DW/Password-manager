// A login's one-time code on screen, as its password is: dots and an eye. The eye asks the app
// for the current code (the PIN, or Windows Hello where the app offers it, each time); the
// code then shows in two halves with a ring that counts down to when it goes back to dots
// (when it runs out, 15 seconds at most). It never comes back by itself.
// Used by a login's page (entry.js) and by the Codes tab (codes.js).

import { spacedCode } from "./cells.js";
import { codeClock } from "./countdown.js";
import { guarded } from "./guard.js";
import { keepShown } from "./secrets.js";
import { here } from "./state.js";
import { explainRefusal, eye, t } from "./ui.js";

const CODE_DOTS = "••• •••";
/** The ring's length (radius 9): its stroke is drawn for the part of the period left. */
const RING = 2 * Math.PI * 9;
const SVG = "http://www.w3.org/2000/svg";

/** What hides each shown code sooner (its eye clicked again), by its eye. */
const hiders = new WeakMap();

/** The ring and its seconds, for a code drawn by script (the Codes tab). */
export function codeClockElement() {
  const clock = document.createElement("span");
  clock.className = "code-clock";
  clock.hidden = true;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const track = document.createElementNS(SVG, "circle");
  const arc = document.createElementNS(SVG, "circle");
  for (const [circle, name] of [
    [track, "track"],
    [arc, "arc"],
  ]) {
    circle.setAttribute("class", name);
    circle.setAttribute("cx", "12");
    circle.setAttribute("cy", "12");
    circle.setAttribute("r", "9");
  }
  arc.setAttribute("transform", "rotate(-90 12 12)");
  svg.append(track, arc);
  const seconds = document.createElement("span");
  seconds.className = "code-left";
  clock.append(svg, seconds);
  return clock;
}

/** The eye button, as the password's. */
export function eyeElement() {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "eye";
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const open = document.createElementNS(SVG, "g");
  open.setAttribute("class", "open");
  const lid = document.createElementNS(SVG, "path");
  lid.setAttribute(
    "d",
    "M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0",
  );
  const pupil = document.createElementNS(SVG, "circle");
  for (const [name, value] of [
    ["cx", "12"],
    ["cy", "12"],
    ["r", "3"],
  ]) {
    pupil.setAttribute(name, value);
  }
  open.append(lid, pupil);
  const shut = document.createElementNS(SVG, "path");
  shut.setAttribute("class", "shut");
  shut.setAttribute("d", "M3 10.5c4.8 5.6 13.2 5.6 18 0M7 14.2l-1.6 2.6M12 15.6v3M17 14.2l1.6 2.6");
  svg.append(open, shut);
  button.append(svg);
  return button;
}

/** Dots, the eye shut (or no eye, when the app can't show codes here). */
function reset(parts) {
  if (!parts) return;
  parts.digits.textContent = CODE_DOTS;
  parts.digits.classList.remove("shown");
  parts.clock.hidden = true;
  parts.eye.hidden = !here.showsCodes;
  eye(parts.eye, false);
}

function show(parts, reply) {
  const clock = codeClock(reply, Date.now());
  parts.digits.textContent = spacedCode(reply.code);
  parts.digits.classList.add("shown");
  parts.clock.hidden = false;
  eye(parts.eye, true);
  const arc = parts.clock.querySelector(".arc");
  arc.setAttribute("stroke-dasharray", RING.toFixed(2));
  const tick = () => {
    const now = clock.at(Date.now());
    arc.setAttribute("stroke-dashoffset", (RING * (1 - now.fraction)).toFixed(2));
    parts.clock.querySelector(".code-left").textContent = t("secondsShort", now.seconds);
    parts.clock.classList.toggle("ending", now.seconds <= 5);
  };
  tick();
  const timer = setInterval(tick, 250);
  const hide = keepShown(() => {
    clearInterval(timer);
    hiders.delete(parts.eye);
    // Run out (or the window moved on): back to dots, and showing it again asks again.
    reset(parts);
  }, clock.until - Date.now());
  hiders.set(parts.eye, hide);
}

/**
 * Puts `entry`'s code behind dots and an eye. `find()` gives its elements (`digits`, `clock`,
 * `eye`) as they are now: a PIN form may replace the view, and `again()` draws it anew.
 * `isHere()` says whether the person is still where the code was asked for; `shown()`
 * whether that view is on screen (not the PIN form).
 */
export function codeControl(entry, listing, { find, again, isHere, shown }) {
  const parts = find();
  reset(parts);
  parts.eye.onclick = async () => {
    const hide = hiders.get(parts.eye);
    if (hide) return hide();
    const reply = await guarded(entry, listing, { type: "reveal", id: entry.id, what: "code" }, t("showButton"), again);
    if (!reply || !isHere()) return;
    if (reply.type !== "code_shown" && (reply.code === "bad_request" || reply.type !== "error")) {
      // An app older than codes shown here doesn't understand the question; whatever else
      // it answered is dropped unread. The eye goes; Copy and Fill stay.
      for (const name of Object.keys(reply)) reply[name] = undefined;
      here.showsCodes = false;
      if (!shown()) again();
      else reset(find());
      return;
    }
    if (reply.type !== "code_shown") return explainRefusal(reply, listing);
    if (!shown()) again();
    const now = find();
    if (now) show(now, reply);
    reply.code = "";
  };
}
