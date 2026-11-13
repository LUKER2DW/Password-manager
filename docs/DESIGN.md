# Design

> The visual system of the desktop app (`crates/desktop/ui`). Tokens live in `theme.slint`.

## Direction: a locksmith's notebook

The product is a personal vault for someone who has had passwords stolen before. The most
characteristic object in that world is the **emergency kit on paper**, and the gesture of marking
what matters by hand. So the interface reads like a technical notebook: cool carbon-copy paper,
navy ink, and a yellow highlighter used for exactly one thing at a time — what you selected or
what you should do next. Hand-drawn strokes appear only where a person would actually draw.

## Tokens

| Token | Value | Use |
|---|---|---|
| Paper | `#E9EDF1` | window background |
| Sheet | `#F8FAFB` | raised surfaces: item page, kit slip |
| Ink | `#1F2A3D` | text and strokes |
| Graphite | `#677385` | secondary text, labels |
| Rule | `#C3CCD6` | idle underlines and dividers |
| Marker | `#F4D648` | highlighter: selection, primary actions |
| Seal | `#B3261E` | danger and errors only |

Type (all ship with Windows 10+; Linux falls back to the default sans):

- **Bahnschrift** (DIN): the whole interface. Light (300) for page titles, 600 for emphasis.
- **Cascadia Mono**: only secrets shown as data (revealed passwords, keys, one-time codes) —
  never for labels.
- **Ink Free**: only the handwritten notes on the emergency kit, the one screen meant for paper.

Scale: 12 / 14 / 17 / 22 / 30 / 46 px.

## Rules

1. **One marker at a time.** The highlighter sweeps under the selected item, the active index
   tab, the active choice, or behind the primary button — never as decoration.
2. **Left-aligned pages.** No centered login card. Fields are written on lines, like a notebook.
3. **Labels in sentence case.** No all-caps eyebrows, no numbered markers unless the content is a
   real sequence (onboarding has two real steps, so it is numbered).
4. **Motion only answers an action**: the marker sweep (220 ms) when something is chosen, opacity
   on hover. Nothing moves on its own.
5. **Red means danger.** Errors and destructive actions only.
6. **Words** say what happens: "Create vault", "Open my vault", "Copy". Errors say what went
   wrong and what to do; they don't apologize.

## Hand-drawn strokes

`src/sketch.rs` generates rough.js-style paths (each line drawn twice as a slightly bowed Bézier)
with fixed seeds, so the drawing is identical on every launch. Shapes: box outlines, marker
swashes, underlines, the padlock, check mark and star. Slint stretches each view box to the
element, so one path serves many sizes.

## Not yet

- Dark theme ("carbon" variant of the same tokens).
- Screen-reader pass on the custom secure field and the hand-drawn controls.
- Visual review: this first version was built and tested headlessly, without screenshots.
