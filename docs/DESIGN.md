# Design

> The visual system of the desktop app (`apps/desktop/ui`). Tokens live in `theme.slint`.
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

Type: **Bahnschrift** for the interface (Light 300 for page titles) and **Ink Free** only for
the note on the kit, both shipped with Windows 10+; **JetBrains Mono** only for secrets shown as
data, built into both apps (`apps/desktop/ui/fonts/`, SIL OFL 1.1): a shown password is drawn
one character to a box, which needs a font whose characters are all as wide.
Scale 12 / 14 / 16 / 21 / 28 / 44 px. Radius 6 px. Controls 38 px tall.

## Components

- **Button** — the one primary action per screen: filled marker yellow. `danger` variant in red
  for confirmed destructive actions.
- **QuietButton** — everything else: text that gains a soft background on hover; `outlined` adds
  a hairline when it must read as a button (Edit, Delete, Show notes).
- **Fields** — a recessed well with a hairline edge; the bottom edge lights up yellow on focus and
  red on error. Labels in sentence case above the well.
- **SecretField** — same look; keystrokes go to Rust, the UI only draws dots.
- **Hint "(?)"** — a small vector circle, only next to fields and terms that are genuinely
  unclear (Secret Key, Recovery Key, one-time code secret, recovery codes, passphrase, crack time,
  website icons, Windows Hello, unencrypted export) — not on obvious fields. The text says
  *what to type* there (and where to find it, e.g. the one-time code key behind "Can't scan
  it?"), not just a definition. Click to open, click anywhere to close; the popup keeps a margin
  from the window edge.
- **ItemIcon** — a rounded tile in front of every item, three tiers:
  1. the site's own icon on a pale tile (logins, only when "Show website icons" is on);
  2. a line glyph for the type (card, secure note, passkey) on a fixed muted colour;
  3. the title's initial on a muted colour hashed from the site, so a service keeps its colour.
  On the light theme the pale favicon tile gets a hairline edge.
- **List selection** — a soft background only; no accent bar.
- **Choice** — a few words; the chosen one gets the hand-drawn marker stroke.
- **Slider** — a hairline track filled in marker yellow with a round knob; drag, click or use the
  arrow keys (generator length and word count).
- **Dropdown** — looks like a field with a chevron; opens a list below it (folder picker).
- **Dialog** — a card centered on a dimmed window (folder settings, delete a folder). Clicking
  outside does nothing, so typing isn't lost by a stray click; Escape or Cancel closes it. The
  main action sits bottom right, a destructive one bottom left in red text.
- **Right-click menu** — a small card at the pointer: an icon and a few words per entry, rules
  between groups, the destructive entry last in red. Items get copy, open, edit, favourite and
  delete; folders get open, settings, move up/down and delete.
- **Links** — a website on the item page reads as text with a hairline underline that turns
  yellow on hover; clicking it (or Open) opens the browser.
- **Back and forward** — two small chevrons next to the vault name, faint when there is nowhere
  to go; the mouse's side buttons and Alt+arrows do the same.
- **Entry screens** (lock, new vault, recovery) — a side panel (logo, steps, what is set up on
  this computer) and the form centered in the remaining space, never a lone column. On the lock
  and recovery screens the form sits on a card in front of the vault wall (see Backgrounds).
- **Strength** — a 4 px meter (red < 50 bits, yellow < 70, green above) plus the estimated time to
  crack and a light historical comparison ("If they'd started while the pyramids were being
  built, they'd still be at it.").
- **Authenticator row** — icon, title and account, the code in large monospaced digit groups,
  seconds left, Copy; a thin yellow bar under the row drains with the period.
- **Vault chooser** — replaces the unlock form in place: recent vaults (current one marked,
  missing files greyed out with Forget), then "Open a vault file…" and "Create a new vault…".
- **Field icons** — a line icon in the field's own colour before each label (key, person,
  envelope, globe, card, calendar, shield, keypad, clock…), no tile behind it. The index uses the
  same icons. They come from Lucide (ISC licence, lucide.dev), converted to one path each.
- **Problems in plain words** — the health page says what is wrong in a sentence under the
  item ("Same password as 2 other logins", "Last changed 3 years ago"), red when it needs
  changing; no badges. A site's own icon is shown as it is, without a tile; without one, its initial on a
  colour.
- **Brand marks** — cards show their network's mark; the import page shows each source's icon.
  Source icons come from Simple Icons (CC0, simpleicons.org) in each brand's colour; Chrome, Edge,
  Proton Pass and NordPass are drawn. The marks belong to their owners and only identify where
  data comes from.
- **Tool pages** (generator, health, kit, import & export, settings, authenticator) take the
  whole width next to the index; the item list is only there while browsing items.
- **Notice** — confirmations ("Copied", "Saved") bottom-right, never over content.

## Logo

A small safe with a dial, drawn with a dark rim on a steel tile, chosen from a gallery of
drafts (padlocks, keys, vault doors, dials) that is no longer kept. Two drawings:

- **Full** (`logo.svg`, `logo-light.svg`): lit door face, hinges on the left, rivets, a knurled yellow dial,
  the lever. From about 48 px up: the lock screen, the extension's 128 px icon.
- **Small** (`logo-small.svg`, `logo-small-light.svg`): the same safe redrawn for 16–48 px (thicker rim, bigger knob, four
  ticks, no rivets): the side panel and vault header (`Logo { small: true; }`), the window and
  tray icon, the extension's 16/32/48 px icons.

They live in `apps/desktop/ui/brand/` (`logo*.svg`, `icon-64.png`); the extension's PNGs,
the .exe's icon and the Android launcher icon (an adaptive icon whose safe fits round masks)
are rendered from the same drawings.

## Backgrounds

- **Lock and recovery** — the inside of a bank vault: a wall of safe-deposit boxes in mixed
  sizes, each with a number plate and one or two lock plates (a bank box takes two keys, as the
  vault takes a password and a Secret Key). A few doors stand open on their hinge, showing what
  is kept inside (gold, coins, keys, notes, a ring box). The middle fades to the canvas so the
  form card sits on calm ground (`brand/lock-scene*.svg`, cover-fit). It shows behind the form
  and, faded toward the top, in the side panel. The card's shadow is drawn as a few translucent
  layers, so every renderer shows it.
- **Open vault** — the page on the right carries a light doodle texture: our own hand-drawn
  security and bank objects scattered at random, with small fillers and a fine grain, barely off
  the page colour (`brand/vault-texture*.png`, a seamless 720 px tile, `Backdrop` in
  `widgets.slint`).

Where each one goes is `Theme.backdrop` / `Theme.lock-backdrop`; the screenshots render the
other placements too, for review.

These are the two places where drawing goes beyond small details; both stay low in contrast
so text on top keeps its full contrast.

## Rules

1. **One yellow thing at a time**: the primary button, the selection, or the focused field.
2. **Hand-drawn only for small details** — never for boxes, fields or buttons.
3. **Left-aligned pages**, sentence-case labels, no all-caps, no decorative numbering (onboarding
   has two real steps, so it is numbered).
4. **Motion answers an action**: the marker stroke drawing in (200 ms), hover backgrounds.
5. **Red means danger** (errors, delete).
6. **Words say what happens** ("Create vault", "Open my vault", "Copy"); errors say what went
   wrong and how to fix it.

## Website icons and privacy

Off by default. When turned on, the app asks each saved site for its own icon (`<link rel=icon>`
or `/favicon.ico`) directly, over HTTPS only, with size and time limits — never through a
third-party icon service, so no one else learns the list of sites. Icons are cached on the
device encrypted under a vault subkey (`Vault::seal_local("icons")`); a site without an icon is
retried after a week. Turning the option off deletes the cache. The trade-off — someone on the
network can see which sites were contacted — is stated in the setting's hint.

`SHOT_ICONS=1 cargo run -p vault-desktop --example screenshots` renders the screens with real
icons (it fetches them for the demo sites).

## On a phone

The phone app (`apps/mobile`, docs/MOBILE.md) uses these tokens and widgets with
`Theme.touch` on: body text 16 px, controls 48 px tall, radius 8 px. One column; four places
at the bottom (Vault, Codes, Generator, Settings) with the marker stroke under the current
one; an item or the editor covers them, with a way back top left. The main action sits at
the bottom of the screen, within reach of a thumb. Facts on the item page are rows: label,
value, Copy on the right. Confirmations sit just above whatever is at the bottom.

## Not yet

- Screen-reader pass on the custom secure field and hints.
- Real-window check of the femtovg renderer (screens are reviewed with the software renderer).
