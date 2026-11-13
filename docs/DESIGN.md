# Design

> The visual system of the desktop app (`crates/desktop/ui`). Tokens live in `theme.slint`.
> Review every screen without opening the app:
> `cargo run -p vault-desktop --example screenshots` renders them off-screen to
> `target/screenshots/` (PNG + `index.html`).

## Direction

A calm, dark workspace for one person's secrets. Plain, well-spaced surfaces; one warm accent —
a highlighter yellow — that marks the single thing that matters on screen. A few small
hand-drawn details (the stroke under what you selected, the padlock, the check mark, the star)
keep it from feeling like a template, without turning the interface into a sketchbook.

The emergency kit is the exception: it is drawn as a light slip of paper in both themes,
because it is the one screen meant to be copied onto paper.

## Tokens (dark, the default)

| Token | Dark | Light | Use |
|---|---|---|---|
| canvas | `#121821` | `#EEF1F4` | window |
| panel | `#161D27` | `#E6EAEF` | index and list columns |
| sheet | `#1A222D` | `#FAFBFC` | page on the right |
| field | `#0F141B` | `#FFFFFF` | input wells |
| ink | `#E3E8EF` | `#1F2A3D` | text |
| graphite | `#8E9AAC` | `#5F6B7D` | labels, secondary text |
| rule | `#283240` | `#D3DAE2` | hairlines, field edges |
| marker | `#E7C54B` | `#F2CF45` | primary button, selection, focus edge |
| accent-stroke | `#E7C54B` | `#B88A00` | thin hand-drawn strokes (contrast on light) |
| seal | `#F06A60` | `#B3261E` | danger and errors only |

Type (all ship with Windows 10+): **Bahnschrift** for the interface (Light 300 for page titles),
**Cascadia Mono** only for secrets shown as data, **Ink Free** only for the note on the kit.
Scale 12 / 14 / 16 / 21 / 28 / 44 px. Radius 6 px. Controls 38 px tall.

## Components

- **Button** — the one primary action per screen: filled marker yellow. `danger` variant in red
  for confirmed destructive actions.
- **QuietButton** — everything else: text that gains a soft background on hover; `outlined` adds
  a hairline when it must read as a button (Edit, Delete, Show notes).
- **Fields** — a recessed well with a hairline edge; the bottom edge lights up yellow on focus and
  red on error. Labels in sentence case above the well.
- **SecretField** — same look; keystrokes go to Rust, the UI only draws dots.
- **Hint "(?)"** — a small circle next to terms that need explaining (Secret Key, Recovery Key,
  one-time code secret, locking, entropy). Click to open, click anywhere to close.
- **Choice** — a few words; the chosen one gets the hand-drawn marker stroke.
- **Notice** — confirmations ("Copied", "Saved") bottom-right, never over content.

## Rules

1. **One yellow thing at a time**: the primary button, the selection, or the focused field.
2. **Hand-drawn only for small details** — never for boxes, fields or buttons.
3. **Left-aligned pages**, sentence-case labels, no all-caps, no decorative numbering (onboarding
   has two real steps, so it is numbered).
4. **Motion answers an action**: the marker stroke drawing in (200 ms), hover backgrounds.
5. **Red means danger** (errors, delete).
6. **Words say what happens** ("Create vault", "Open my vault", "Copy"); errors say what went
   wrong and how to fix it.

## Not yet

- Screen-reader pass on the custom secure field and hints.
- Real-window check of the femtovg renderer (screens are reviewed with the software renderer).
