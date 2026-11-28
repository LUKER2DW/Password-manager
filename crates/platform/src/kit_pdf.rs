//! The emergency kit as a printable PDF: a page with the Secret Key and room to write the
//! master password, then one page for each recovery part, so the parts can be kept apart.
//!
//! Written by hand on purpose: the file holds the Secret Key and the recovery parts, so it is
//! built from a few hundred auditable lines instead of a PDF library. It uses only the 14
//! standard PDF fonts (no embedding, no images, no scripts, no compression), A4 portrait.
//!
//! A filled kit also carries each key as a QR code, drawn as black squares (still no
//! picture), so the phone can scan it: the Secret Key at its first unlock, the parts when it
//! recovers the vault.
//!
//! A kit saved as a file is encrypted with the PDF's own AES-256 password protection
//! (`protect.rs`, CRYPTO.md §3.10), so a copy of the file alone gives nothing away; the
//! printed kit's temporary file is not, so printing asks for nothing.

use std::fmt::Write as _;

use anyhow::Result;
use zeroize::Zeroizing;

mod protect;

pub use protect::open as open_protected;

/// What goes on the kit. Text fields are printed as given.
#[derive(Debug, Clone, Copy)]
pub struct KitContents<'a> {
    pub secret_key: &'a str,
    /// Parts A, B and C, right after they are issued; `None` once they can't be shown (they
    /// are not stored anywhere), and the kit is its first page only.
    pub parts: Option<[&'a str; 3]>,
    pub vault_id: &'a str,
    /// Unix seconds, printed as a date.
    pub created_at: u64,
    /// `false`: empty boxes, for writing the keys in by hand from the screen, so a printer
    /// (and its memory) never sees them.
    pub filled: bool,
    /// Part C is kept elsewhere (the app hid it in a picture): its page says it is kept apart,
    /// without saying where, so the paper kit has A and B only and never points at the third.
    pub part_c_elsewhere: bool,
}

const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 56.0;
const WIDTH: f32 = PAGE_W - 2.0 * MARGIN;

#[derive(Clone, Copy)]
enum Font {
    Regular,
    Bold,
    Mono,
    MonoBold,
}

impl Font {
    fn name(self) -> &'static str {
        match self {
            Font::Regular => "F1",
            Font::Bold => "F2",
            Font::Mono => "F3",
            Font::MonoBold => "F4",
        }
    }

    /// Advance width of `c` in 1/1000 em (Adobe AFM metrics for Helvetica and Courier).
    fn width(self, c: char) -> f32 {
        match self {
            Font::Mono | Font::MonoBold => 600.0,
            Font::Regular => helvetica_width(c),
            Font::Bold => helvetica_width(c) * 1.06,
        }
    }

    fn text_width(self, text: &str, size: f32) -> f32 {
        text.chars().map(|c| self.width(c)).sum::<f32>() * size / 1000.0
    }
}

fn helvetica_width(c: char) -> f32 {
    match c {
        ' ' | '.' | ',' | ':' | ';' | '!' | '/' | '\\' | 'f' | 't' | 'I' => 278.0,
        'i' | 'j' | 'l' => 222.0,
        '\'' => 191.0,
        'r' | '-' | '(' | ')' => 333.0,
        'c' | 'k' | 's' | 'v' | 'x' | 'y' | 'z' | 'J' => 500.0,
        'm' | 'M' => 833.0,
        'w' | 'C' | 'D' | 'H' | 'N' | 'R' | 'U' => 722.0,
        'A' | 'B' | 'E' | 'K' | 'P' | 'S' | 'V' | 'X' | 'Y' | '&' => 667.0,
        'F' | 'T' | 'Z' => 611.0,
        'G' | 'O' | 'Q' => 778.0,
        'L' => 556.0,
        'W' => 944.0,
        '@' => 1015.0,
        '—' => 1000.0,
        _ => 556.0,
    }
}

/// Text for a PDF string literal in WinAnsiEncoding: escapes `\ ( )`, maps the few typographic
/// characters we use, and replaces anything outside Latin-1 with `?`.
fn pdf_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '—' => out.push_str("\\227"),
            '–' => out.push_str("\\226"),
            '’' => out.push_str("\\222"),
            '•' => out.push_str("\\225"),
            c if (' '..='~').contains(&c) => out.push(c),
            c if (c as u32) >= 0xA0 && (c as u32) <= 0xFF => {
                let _ = write!(out, "\\{:03o}", c as u32);
            }
            _ => out.push('?'),
        }
    }
    out
}

/// Splits `text` into lines no wider than `width` (breaking long words, such as paths, too).
fn wrap(text: &str, font: Font, size: f32, width: f32) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split(' ') {
        let candidate = if line.is_empty() {
            word.to_owned()
        } else {
            format!("{line} {word}")
        };
        if font.text_width(&candidate, size) <= width {
            line = candidate;
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        // A single word wider than the line: cut it.
        let mut piece = String::new();
        for c in word.chars() {
            piece.push(c);
            if font.text_width(&piece, size) > width {
                piece.pop();
                lines.push(std::mem::take(&mut piece));
                piece.push(c);
            }
        }
        line = piece;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Builds the page's content stream, top to bottom.
struct Page {
    ops: String,
    y: f32,
}

impl Page {
    fn new() -> Self {
        Self {
            ops: String::new(),
            y: PAGE_H - MARGIN,
        }
    }

    fn gap(&mut self, points: f32) {
        self.y -= points;
    }

    fn text_at(&mut self, x: f32, y: f32, font: Font, size: f32, gray: f32, text: &str) {
        let _ = writeln!(
            self.ops,
            "BT {gray:.2} g /{} {size:.1} Tf {x:.1} {y:.1} Td ({}) Tj ET",
            font.name(),
            pdf_string(text)
        );
    }

    /// A wrapped paragraph; the cursor moves below it.
    fn paragraph(&mut self, font: Font, size: f32, gray: f32, text: &str) {
        let leading = size * 1.35;
        for line in wrap(text, font, size, WIDTH) {
            self.y -= leading;
            self.text_at(MARGIN, self.y, font, size, gray, &line);
        }
    }

    fn rect(&mut self, y: f32, height: f32, fill: f32, stroke: f32) {
        let _ = writeln!(
            self.ops,
            "{fill:.2} g {stroke:.2} G 0.8 w {MARGIN:.1} {y:.1} {WIDTH:.1} {height:.1} re B"
        );
    }
}

impl Page {
    fn boxes(&mut self, x: f32, y: f32, w: f32, h: f32, stroke: f32) {
        let _ = writeln!(
            self.ops,
            "1 g {stroke:.2} G 0.7 w {x:.1} {y:.1} {w:.1} {h:.1} re B"
        );
    }

    /// A key of fixed shape written into boxes, one character per box, so it can also be
    /// copied by hand: `prefix` printed, then `groups` groups of `group_len` boxes,
    /// `per_row` groups per line. `value` (with or without dashes) fills the boxes; `None`
    /// leaves them empty.
    #[allow(clippy::too_many_arguments)]
    fn key_grid(
        &mut self,
        label: &str,
        prefix: &str,
        groups: usize,
        group_len: usize,
        per_row: usize,
        value: Option<&str>,
        note: &str,
    ) {
        const GROUP_GAP: f32 = 11.0;
        const ROW_GAP: f32 = 7.0;
        let prefix_size = 12.0;
        let prefix_w = Font::MonoBold.text_width(prefix, prefix_size) + 9.0;
        // As large as fits `per_row` groups on one line, never larger than handwriting needs.
        let avail = WIDTH - 28.0 - prefix_w;
        let box_w =
            ((avail - (per_row as f32 - 1.0) * GROUP_GAP) / (per_row * group_len) as f32).min(17.0);
        let box_h = (box_w * 1.3).round();
        let char_size = (box_w * 0.82).min(12.0);
        let rows = groups.div_ceil(per_row);
        let note_lines = wrap(note, Font::Regular, 9.0, WIDTH - 28.0);
        let chars: Vec<char> = value
            .map(|v| {
                v.strip_prefix(prefix)
                    .unwrap_or(v)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect()
            })
            .unwrap_or_default();
        // The key as one piece of text, `R0-XXXXXX-…`: what copying the boxes gives, and a
        // line under them to copy from in viewers that don't honour that.
        let as_text = (!chars.is_empty()).then(|| {
            let mut text = prefix.to_owned();
            for group in chars.chunks(group_len) {
                text.push('-');
                text.extend(group);
            }
            Zeroizing::new(text)
        });
        let text_line = if as_text.is_some() { 9.0 * 1.6 } else { 0.0 };
        let note_height = if note_lines.is_empty() {
            0.0
        } else {
            4.0 + note_lines.len() as f32 * 9.0 * 1.35
        };
        let height =
            14.0 + 9.0 + 14.0 + rows as f32 * (box_h + ROW_GAP) + text_line + note_height + 8.0;
        let top = self.y;
        self.rect(top - height, height, 0.96, 0.75);
        let x0 = MARGIN + 14.0;
        let mut y = top - 14.0 - 9.0;
        self.text_at(x0, y, Font::Bold, 9.0, 0.35, label);
        y -= 14.0;

        let baseline = (box_h - char_size * 0.62) / 2.0;
        // Copying the boxes gives the key itself, not its letters spread out with spaces.
        if let Some(text) = &as_text {
            let _ = writeln!(
                self.ops,
                "/Span << /ActualText ({}) >> BDC",
                pdf_string(text)
            );
        }
        for row in 0..rows {
            let box_y = y - box_h;
            if row == 0 {
                self.text_at(
                    x0,
                    box_y + baseline,
                    Font::MonoBold,
                    prefix_size,
                    0.0,
                    prefix,
                );
            }
            let mut x = x0 + prefix_w;
            for group in row * per_row..((row + 1) * per_row).min(groups) {
                for slot in 0..group_len {
                    self.boxes(x, box_y, box_w, box_h, 0.5);
                    if let Some(c) = chars.get(group * group_len + slot) {
                        let s = c.to_string();
                        let cw = Font::MonoBold.text_width(&s, char_size);
                        self.text_at(
                            x + (box_w - cw) / 2.0,
                            box_y + baseline,
                            Font::MonoBold,
                            char_size,
                            0.0,
                            &s,
                        );
                    }
                    x += box_w;
                }
                // A printed dash between groups, as in the app.
                if group + 1 < groups && (group + 1) % per_row != 0 {
                    self.text_at(
                        x + GROUP_GAP / 2.0 - 2.0,
                        box_y + baseline,
                        Font::Bold,
                        10.0,
                        0.5,
                        "-",
                    );
                }
                x += GROUP_GAP;
            }
            y = box_y - ROW_GAP;
        }
        if let Some(text) = &as_text {
            let _ = writeln!(self.ops, "EMC");
            y -= 9.0 * 1.2;
            self.text_at(x0, y, Font::Mono, 9.0, 0.2, text);
            y -= 9.0 * 0.4;
        }
        y -= 4.0;
        for line in &note_lines {
            y -= 9.0 * 1.35;
            self.text_at(x0, y, Font::Regular, 9.0, 0.35, line);
        }
        self.y = top - height;
    }

    /// `text` as a QR code at the left margin, `SIDE` points square, with `caption` beside it;
    /// the cursor moves below it. The black modules are rectangles in the content stream, one
    /// per run along a row (no picture). The code's own buffers hold what the text printed
    /// above holds, for the moment it takes to draw them.
    fn qr(&mut self, text: &str, caption: &str) {
        const SIDE: f32 = 118.0;
        const QUIET: f32 = 4.0;
        let Ok(code) =
            qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
        else {
            return;
        };
        let width = code.width();
        let dark: Vec<bool> = code
            .to_colors()
            .into_iter()
            .map(|color| color == qrcode::Color::Dark)
            .collect();
        let module = SIDE / (width as f32 + 2.0 * QUIET);
        let top = self.y;
        let _ = writeln!(
            self.ops,
            "q 1 g 0.75 G 0.7 w {MARGIN:.1} {:.1} {SIDE:.1} {SIDE:.1} re B Q",
            top - SIDE
        );
        let _ = write!(self.ops, "0 g");
        for row in 0..width {
            let mut col = 0;
            while col < width {
                if !dark[row * width + col] {
                    col += 1;
                    continue;
                }
                let start = col;
                while col < width && dark[row * width + col] {
                    col += 1;
                }
                let x = MARGIN + (QUIET + start as f32) * module;
                let y = top - (QUIET + row as f32 + 1.0) * module;
                // A hair taller and wider, so neighbouring squares meet without a seam.
                let _ = write!(
                    self.ops,
                    " {x:.2} {y:.2} {:.2} {:.2} re",
                    (col - start) as f32 * module + 0.15,
                    module + 0.15
                );
            }
        }
        let _ = writeln!(self.ops, " f");
        let x = MARGIN + SIDE + 18.0;
        let mut y = top - 6.0;
        for line in wrap(caption, Font::Regular, 9.5, WIDTH - SIDE - 18.0) {
            y -= 9.5 * 1.35;
            self.text_at(x, y, Font::Regular, 9.5, 0.25, &line);
        }
        self.y = top - SIDE;
    }

    /// A labelled empty box to write in by hand, the full width of the page.
    fn write_box(&mut self, label: &str, height: f32) {
        self.y -= 9.0;
        self.text_at(MARGIN, self.y, Font::Bold, 9.0, 0.35, label);
        self.y -= 6.0 + height;
        let _ = writeln!(
            self.ops,
            "0.5 G 0.7 w {MARGIN:.1} {y:.1} {WIDTH:.1} {height:.1} re S",
            y = self.y
        );
    }
}

/// A recovery part's printed shape (`A0` + groups of characters).
pub const PART_GROUPS: usize = vault_core::RecoveryPart::GROUPS;
pub const PART_GROUP_LEN: usize = vault_core::RecoveryPart::GROUP_LEN;

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn date_text(unix: u64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let (year, month, day) = civil_from_days(i64::try_from(unix / 86_400).unwrap_or(0));
    format!("{day} {} {year}", MONTHS[(month - 1) as usize])
}

impl Page {
    /// The dark band across the top, so the pages are easy to spot among papers, and a title.
    fn heading(&mut self, title: &str, aside: &str) {
        let _ = writeln!(
            self.ops,
            "0.12 g 0 {:.1} {PAGE_W:.1} 10 re f",
            PAGE_H - 10.0
        );
        self.gap(6.0);
        self.text_at(MARGIN, self.y, Font::Bold, 24.0, 0.1, title);
        self.text_at(
            PAGE_W - MARGIN - Font::Regular.text_width(aside, 11.0),
            self.y + 4.0,
            Font::Regular,
            11.0,
            0.45,
            aside,
        );
        self.gap(10.0);
    }

    fn subheading(&mut self, text: &str) {
        self.text_at(MARGIN, self.y - 12.0, Font::Bold, 11.0, 0.1, text);
        self.gap(14.0);
    }

    fn bullets(&mut self, steps: &[&str]) {
        for step in steps {
            self.paragraph(Font::Regular, 9.5, 0.25, &format!("\u{2022}  {step}"));
            self.gap(3.0);
        }
    }

    /// The small print at the foot: what to do with the file, and which vault this is.
    fn footer(&mut self, vault_id: &str, protected: bool) {
        self.y = MARGIN - 22.0;
        self.text_at(
            MARGIN,
            self.y,
            Font::Regular,
            8.0,
            0.5,
            if protected {
                "Made offline by Vault. This file opens only with the kit's PDF password."
            } else {
                "Made offline by Vault. If this page was saved as a file, delete the file after printing."
            },
        );
        let id = format!("Vault {vault_id}");
        self.text_at(
            PAGE_W - MARGIN - Font::Mono.text_width(&id, 7.0),
            self.y,
            Font::Mono,
            7.0,
            0.55,
            &id,
        );
    }
}

/// Renders the kit to print: a page with the Secret Key and room for the master password (and
/// the saved files' password), then a page for each recovery part. With `filled` off, the
/// boxes are empty, to be written in by hand. Not protected: it is for the printer, from a
/// temporary file. The bytes contain the keys: they are wiped from memory when dropped.
pub fn render(kit: &KitContents<'_>) -> Zeroizing<Vec<u8>> {
    let mut pages = kit_pages(kit, false);
    let streams: Vec<Zeroizing<Vec<u8>>> = pages
        .iter()
        .map(|page| Zeroizing::new(page.as_bytes().to_vec()))
        .collect();
    assemble(&mut pages, streams, None)
}

/// The kit as a file to keep, protected by `password` (the kit's PDF password as written,
/// CRYPTO.md §3.10): the same pages as [`render`], encrypted with AES-256 (PDF revision 6).
pub fn render_protected(kit: &KitContents<'_>, password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let protection = protect::Protection::new(password)?;
    let mut pages = kit_pages(kit, true);
    let streams = encrypt_pages(&pages, &protection)?;
    Ok(assemble(&mut pages, streams, Some(&protection)))
}

/// One recovery part alone, as a PDF of one page, not protected (see
/// [`render_part_protected`]).
pub fn render_part(
    label: vault_core::PartLabel,
    part: &str,
    vault_id: &str,
    created_at: u64,
    filled: bool,
) -> Zeroizing<Vec<u8>> {
    let date = date_text(created_at);
    let mut pages = [part_page(label, part, filled, &date, vault_id, false)];
    let streams = vec![Zeroizing::new(pages[0].as_bytes().to_vec())];
    assemble(&mut pages, streams, None)
}

/// One recovery part alone, as a protected PDF of one page (see [`render_protected`]): saved
/// as a file of its own, so the three parts (which together open the vault without the master
/// password) never share a file.
pub fn render_part_protected(
    label: vault_core::PartLabel,
    part: &str,
    vault_id: &str,
    created_at: u64,
    filled: bool,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let protection = protect::Protection::new(password)?;
    let date = date_text(created_at);
    let mut pages = [part_page(label, part, filled, &date, vault_id, true)];
    let streams = encrypt_pages(&pages, &protection)?;
    Ok(assemble(&mut pages, streams, Some(&protection)))
}

fn encrypt_pages(
    pages: &[String],
    protection: &protect::Protection,
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    pages
        .iter()
        .map(|page| protection.encrypt(page.as_bytes()))
        .collect()
}

/// The kit's pages' content streams; `protected`: for a file to keep (its footer says so, and
/// it has no boxes for its own password).
fn kit_pages(kit: &KitContents<'_>, protected: bool) -> Vec<String> {
    let date = date_text(kit.created_at);
    let mut pages = Vec::with_capacity(4);
    let mut page = Page::new();
    page.heading("Emergency kit", &date);
    page.gap(18.0);
    page.key_grid(
        "SECRET KEY",
        "S0",
        PART_GROUPS,
        PART_GROUP_LEN,
        PART_GROUPS,
        kit.filled.then_some(kit.secret_key),
        "",
    );
    if kit.filled {
        page.gap(14.0);
        page.qr(
            kit.secret_key,
            "Scan it with the phone the first time it opens this vault: under the Secret Key \
             field, tap the QR button. It never leaves the phone.",
        );
    }
    page.gap(26.0);
    page.write_box("MASTER PASSWORD", 44.0);
    if kit.parts.is_none() {
        page.gap(26.0);
        page.paragraph(
            Font::Regular,
            9.5,
            0.35,
            "Recovery parts A, B and C are printed only with the kit that makes them.",
        );
    }
    page.footer(kit.vault_id, protected);
    pages.push(page.ops);

    if let Some(parts) = kit.parts {
        for (label, value) in vault_core::PartLabel::ALL.into_iter().zip(parts) {
            if kit.part_c_elsewhere && label == vault_core::PartLabel::C {
                let mut page = Page::new();
                page.heading("Recovery part C", &format!("3 of 3, {date}"));
                page.gap(18.0);
                page.paragraph(
                    Font::Regular,
                    11.0,
                    0.1,
                    "Part C is not printed: it is kept apart from parts A and B, where you chose \
                     to keep it.",
                );
                page.gap(10.0);
                page.paragraph(
                    Font::Regular,
                    9.5,
                    0.35,
                    "Parts A and B together bring back your Secret Key; with part C as well they \
                     let you choose a new master password.",
                );
                page.footer(kit.vault_id, protected);
                pages.push(page.ops);
                continue;
            }
            pages.push(part_page(
                label,
                value,
                kit.filled,
                &date,
                kit.vault_id,
                protected,
            ));
        }
    }
    pages
}

/// A recovery part's page: its boxes (filled or empty), its QR code, what it does.
fn part_page(
    label: vault_core::PartLabel,
    value: &str,
    filled: bool,
    date: &str,
    vault_id: &str,
    protected: bool,
) -> String {
    let letter = label.letter();
    let mut page = Page::new();
    page.heading(
        &format!("Recovery part {letter}"),
        &format!("{} of 3, {date}", label as u8 + 1),
    );
    page.gap(18.0);
    page.key_grid(
        &format!("PART {letter}"),
        label.prefix(),
        PART_GROUPS,
        PART_GROUP_LEN,
        PART_GROUPS,
        filled.then_some(value),
        "",
    );
    if filled {
        page.gap(14.0);
        page.qr(
            value,
            "Recovering on the phone: on its unlock screen tap Forgot your master \
             password, then the QR button next to each part.",
        );
    }
    page.gap(26.0);
    page.subheading("What it does");
    page.bullets(&[
        "With any other part: brings back your Secret Key. You still need your master \
         password.",
        "With both other parts: lets you choose a new master password.",
        "On its own: opens nothing, so losing one part, or having it found, is not the end. \
         Make a new kit in the app if that happens.",
    ]);
    page.footer(vault_id, protected);
    page.ops
}

/// Wraps content streams into a complete PDF file, one page each: `streams` are the pages'
/// contents as the file holds them (encrypted by `protection` when there is one). The pages'
/// text held the keys: it is wiped here.
fn assemble(
    pages: &mut [String],
    streams: Vec<Zeroizing<Vec<u8>>>,
    protection: Option<&protect::Protection>,
) -> Zeroizing<Vec<u8>> {
    let fonts = ["Helvetica", "Helvetica-Bold", "Courier", "Courier-Bold"];
    // 1 catalog, 2 page tree, 3–6 fonts, then a page and its content for each page, then the
    // encrypt dictionary of a protected file.
    let first_page = 3 + fonts.len();
    let kids: Vec<String> = (0..pages.len())
        .map(|index| format!("{} 0 R", first_page + 2 * index))
        .collect();
    let catalog = if protection.is_some() {
        // Revision 6 was first published as Adobe's extension level 8 to PDF 1.7.
        "<< /Type /Catalog /Pages 2 0 R \
         /Extensions << /ADBE << /BaseVersion /1.7 /ExtensionLevel 8 >> >> >>"
    } else {
        "<< /Type /Catalog /Pages 2 0 R >>"
    };
    let mut objects: Vec<Zeroizing<Vec<u8>>> = vec![
        Zeroizing::new(catalog.as_bytes().to_vec()),
        Zeroizing::new(
            format!(
                "<< /Type /Pages /Kids [{}] /Count {} >>",
                kids.join(" "),
                pages.len()
            )
            .into_bytes(),
        ),
    ];
    for base in fonts {
        objects.push(Zeroizing::new(
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
            )
            .into_bytes(),
        ));
    }
    for (index, stream) in streams.into_iter().enumerate() {
        let content_id = first_page + 2 * index + 1;
        objects.push(Zeroizing::new(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents {content_id} 0 R \
                 /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> >>"
            )
            .into_bytes(),
        ));
        let mut body = Zeroizing::new(Vec::with_capacity(stream.len() + 48));
        body.extend_from_slice(format!("<< /Length {} >>\nstream\n", stream.len()).as_bytes());
        body.extend_from_slice(&stream);
        // The end of line before `endstream`: the plain text ends with one already.
        if !stream.ends_with(b"\n") {
            body.push(b'\n');
        }
        body.extend_from_slice(b"endstream");
        objects.push(body);
    }
    if let Some(protection) = protection {
        objects.push(Zeroizing::new(protection.dictionary().into_bytes()));
    }

    let total: usize = objects.iter().map(|body| body.len()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(total + 1024));
    out.extend_from_slice(if protection.is_some() {
        b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"
    } else {
        b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"
    });
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for offset in offsets {
        let _ = writeln!(table, "{offset:010} 00000 n ");
    }
    // The encrypt dictionary is the last object.
    let encrypt = protection.map_or_else(String::new, |protection| {
        format!(" /Encrypt {} 0 R /ID {}", objects.len(), protection.id())
    });
    let _ = write!(
        table,
        "trailer\n<< /Size {} /Root 1 0 R{encrypt} >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    );
    out.extend_from_slice(table.as_bytes());
    // The content streams held the keys in Strings: wipe them too (`objects` wipes itself).
    for text in pages.iter_mut() {
        zeroize::Zeroize::zeroize(text);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PDF_PASSWORD: &str = "cupped reverend native quaking";

    const PARTS: [&str; 3] = [
        "A0-AAAAAAA-BBBBBBB-CCCCCCC-DDDDDDD",
        "B0-EEEEEEE-FFFFFFF-GGGGGGG-HHHHHHH",
        "C0-JJJJJJJ-KKKKKKK-MMMMMMM-NNNNNNN",
    ];

    fn kit(parts: Option<[&str; 3]>) -> Zeroizing<Vec<u8>> {
        kit_as(parts, true)
    }

    fn kit_as(parts: Option<[&str; 3]>, filled: bool) -> Zeroizing<Vec<u8>> {
        render(&KitContents {
            secret_key: "S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345",
            parts,
            vault_id: "0123456789abcdef0123456789abcdef",
            created_at: 1_794_441_600, // 12 November 2026
            filled,
            part_c_elsewhere: false,
        })
    }

    #[test]
    fn a_part_saved_alone_holds_only_that_part() {
        let alone = render_part_protected(
            vault_core::PartLabel::B,
            PARTS[1],
            "0123456789abcdef0123456789abcdef",
            1_794_441_600,
            true,
            PDF_PASSWORD,
        )
        .unwrap();
        check_xref(&alone);
        assert!(!String::from_utf8_lossy(&alone).contains("EEEEEEE"));
        let opened = open_protected(&alone, PDF_PASSWORD).unwrap();
        let text = String::from_utf8_lossy(&opened);
        assert!(text.contains("EEEEEEE") && text.contains("Recovery part B"));
        assert!(!text.contains("AAAAAAA") && !text.contains("JJJJJJJ"));
        assert!(!text.contains("ABCDEFG"), "nor the Secret Key");
        assert_eq!(text.matches("/Type /Page ").count(), 1, "one page");
    }

    #[test]
    fn part_c_kept_in_a_picture_stays_off_the_paper() {
        let kit = |part_c_elsewhere| {
            render(&KitContents {
                secret_key: "S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345",
                parts: Some(PARTS),
                vault_id: "0123456789abcdef0123456789abcdef",
                created_at: 1_794_441_600,
                filled: true,
                part_c_elsewhere,
            })
        };
        let qr_codes = |bytes: &[u8]| {
            String::from_utf8_lossy(bytes)
                .lines()
                .filter(|l| l.starts_with("0 g ") && l.ends_with(" f"))
                .count()
        };
        let with_c = kit(false);
        let without_c = kit(true);
        // Part C's code (and its characters) are gone; A's and B's and the Secret Key's stay.
        assert_eq!(qr_codes(&with_c), 4);
        assert_eq!(qr_codes(&without_c), 3);
        let text = String::from_utf8_lossy(&without_c);
        assert!(text.contains("Part C is not printed"));
        assert!(!text.contains("JJJJJJJ"), "part C itself is not printed");
        assert!(text.contains("AAAAAAA") && text.contains("EEEEEEE"));
        assert!(String::from_utf8_lossy(&with_c).contains("JJJJJJJ"));
        // Nor where it is kept.
        assert!(!text.contains("picture") && !text.contains("photo"));
    }

    /// Every xref offset (in bytes) points at the start of its object.
    fn check_xref(raw: &[u8]) {
        let tail = String::from_utf8(raw[raw.len() - 64..].to_vec()).unwrap();
        let xref_at: usize = tail
            .rsplit("startxref\n")
            .next()
            .and_then(|t| t.lines().next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        let table = String::from_utf8(raw[xref_at..].to_vec()).unwrap();
        assert!(table.starts_with("xref\n"));
        let count: usize = table.lines().nth(1).unwrap()[2..].parse().unwrap();
        for (index, line) in table.lines().skip(3).take(count - 1).enumerate() {
            let offset: usize = line[..10].parse().unwrap();
            assert!(
                raw[offset..].starts_with(format!("{} 0 obj", index + 1).as_bytes()),
                "object {} offset",
                index + 1
            );
        }
    }

    #[test]
    fn a_kit_with_parts_has_a_page_for_each_part() {
        let bytes = kit(Some(PARTS));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.trim_end().ends_with("%%EOF"));
        assert!(text.contains("/Count 4"));
        assert_eq!(text.matches("/Type /Page ").count(), 4);
        assert!(text.contains("S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345"));
        assert!(text.contains("12 November 2026"));
        assert!(text.contains("MASTER PASSWORD"));
        for (letter, part) in ["A", "B", "C"].iter().zip(PARTS) {
            assert!(text.contains(&format!("(Recovery part {letter}) Tj")));
            // Each part copies as one piece: from the boxes (ActualText) and the line under them.
            assert!(text.contains(&format!("/ActualText ({part})")));
            assert!(text.contains(&format!("({part}) Tj")));
        }
        assert_eq!(text.matches(" BDC").count(), text.matches("EMC").count());
        // One box per character: the Secret Key and 3 parts, each 4 groups of 7.
        assert_eq!(PART_GROUPS * PART_GROUP_LEN, 28);
        assert_eq!(boxes(&text), 4 * 28);
        assert!(text.contains("What it does"));
        // Nothing points at where part C may be kept.
        assert!(!text.contains("picture") && !text.contains("photo"));
        // The vault id is printed, small; where the vault lives is not.
        assert!(text.contains("Vault 0123456789abcdef0123456789abcdef"));
        assert!(!text.contains("AppData"));
        check_xref(&bytes);
    }

    #[test]
    fn without_parts_the_kit_is_one_page() {
        let bytes = kit(None);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("/Count 1"));
        assert!(text.contains("printed only with the kit that makes them"));
        assert!(!text.contains("A0-") && !text.contains("R0-"));
        assert_eq!(boxes(&text), 28);
        check_xref(&bytes);
    }

    #[test]
    fn an_empty_kit_has_boxes_and_no_keys() {
        let bytes = kit_as(Some(PARTS), false);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.contains("/Count 4"));
        assert_eq!(boxes(&text), 4 * 28);
        assert!(!text.contains("ABCDEFG") && !text.contains("AAAAAAA"));
        assert!(!text.contains("ActualText"));
        assert!(text.contains("(S0) Tj") && text.contains("(C0) Tj"));
        check_xref(&bytes);
    }

    /// Handwriting boxes are the only white-filled rectangles.
    fn boxes(text: &str) -> usize {
        text.lines()
            .filter(|l| l.starts_with("1 g ") && l.ends_with("re B"))
            .count()
    }

    #[test]
    fn a_filled_kit_has_a_qr_code_for_each_key() {
        let qr_codes = |bytes: &[u8]| {
            String::from_utf8_lossy(bytes)
                .lines()
                .filter(|l| l.starts_with("0 g ") && l.ends_with(" f"))
                .count()
        };
        // The Secret Key and the three parts.
        assert_eq!(qr_codes(&kit(Some(PARTS))), 4);
        assert_eq!(qr_codes(&kit(None)), 1);
        // Empty boxes to write in by hand: no key anywhere, so no code either.
        assert_eq!(qr_codes(&kit_as(Some(PARTS), false)), 0);
    }

    #[test]
    fn wrapping_and_dates() {
        let lines = wrap(&"word ".repeat(60), Font::Regular, 10.0, 200.0);
        assert!(lines.len() > 1);
        assert!(
            lines
                .iter()
                .all(|l| Font::Regular.text_width(l, 10.0) <= 200.0)
        );
        let long = wrap(&"x".repeat(300), Font::Mono, 10.0, 120.0);
        assert!(long.iter().all(|l| Font::Mono.text_width(l, 10.0) <= 120.0));
        assert_eq!(date_text(0), "1 January 1970");
        assert_eq!(date_text(951_782_400), "29 February 2000");
        assert_eq!(pdf_string("a(b)c\\é—"), "a\\(b\\)c\\\\\\351\\227");
    }

    const SECRET_KEY: &str = "S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345";

    fn contents(parts: Option<[&'static str; 3]>) -> KitContents<'static> {
        KitContents {
            secret_key: SECRET_KEY,
            parts,
            vault_id: "0123456789abcdef0123456789abcdef",
            created_at: 1_794_441_600,
            filled: true,
            part_c_elsewhere: false,
        }
    }

    /// The kit protected by its PDF password (CRYPTO.md §3.10): saved, or printed with its
    /// parts. Nothing of it reads without the password, and the password is not in it.
    #[test]
    fn a_protected_kit_opens_only_with_its_password() {
        let saved = render_protected(&contents(None), PDF_PASSWORD).unwrap();
        let raw = String::from_utf8_lossy(&saved);
        assert!(raw.starts_with("%PDF-1.7"));
        assert!(raw.contains("/ExtensionLevel 8"));
        assert!(raw.contains("/Filter /Standard /V 5 /R 6"));
        assert!(
            raw.contains("/Encrypt 9 0 R /ID [<"),
            "the last object, after one page and its content"
        );
        // Nothing of the keys or the words is readable without the password.
        for clear in ["ABCDEFG", "S0-", "SECRET KEY", "cupped", "Emergency kit"] {
            assert!(!raw.contains(clear), "{clear} in the clear");
        }
        check_xref(&saved);

        // Either spelling opens it, and gives the kit's page, without the password itself.
        let opened = open_protected(&saved, PDF_PASSWORD).unwrap();
        let compact = open_protected(&saved, &PDF_PASSWORD.replace(' ', "")).unwrap();
        assert_eq!(*opened, *compact);
        let text = String::from_utf8_lossy(&opened);
        assert!(text.contains(&format!("/ActualText ({SECRET_KEY})")));
        assert!(text.contains("MASTER PASSWORD"));
        assert!(!text.contains("cupped") && !text.contains("PDF PASSWORD"));
        assert!(text.contains("opens only with the kit's PDF password"));
        assert_eq!(boxes(&text), 28);

        // Not with another password, nor in capitals.
        assert!(open_protected(&saved, "cupped reverend native quakers").is_none());
        assert!(open_protected(&saved, &PDF_PASSWORD.to_uppercase()).is_none());
        assert!(open_protected(&saved, "").is_none());
        // Nor once a stream is altered (its padding no longer checks out, or the text changes).
        let mut altered = saved.to_vec();
        let at = raw
            .find(
                "stream
",
            )
            .unwrap()
            + "stream
"
            .len()
            + 40;
        altered[at] ^= 0x01;
        assert_ne!(
            open_protected(&altered, PDF_PASSWORD).map(|bytes| bytes.to_vec()),
            Some(opened.to_vec())
        );
        // Two saves of the same kit share nothing: new file key, salts and IVs.
        let again = render_protected(&contents(None), PDF_PASSWORD).unwrap();
        assert_ne!(*again, *saved);

        // Printed with its parts: four pages behind the same password.
        let printed = render_protected(&contents(Some(PARTS)), PDF_PASSWORD).unwrap();
        check_xref(&printed);
        let raw = String::from_utf8_lossy(&printed);
        assert!(raw.contains("/Count 4") && !raw.contains("AAAAAAA"));
        let opened = open_protected(&printed, PDF_PASSWORD).unwrap();
        let text = String::from_utf8_lossy(&opened);
        assert!(
            PARTS
                .iter()
                .all(|part| text.contains(&format!("({part}) Tj")))
        );
        assert_eq!(boxes(&text), 4 * 28);
        // The plain kit (empty boxes to fill in by hand holds no key) is as before.
        let plain = render(&contents(None));
        assert!(String::from_utf8_lossy(&plain).starts_with("%PDF-1.4"));
        assert!(String::from_utf8_lossy(&plain).contains("delete the file after printing"));
    }
}
