//! The emergency kit as a one-page, printable PDF.
//!
//! Written by hand on purpose: the file holds the Secret Key and the Recovery Key, so it is built
//! from a few hundred auditable lines instead of a PDF library. It uses only the 14 standard PDF
//! fonts (no embedding, no images, no scripts, no compression), A4 portrait.

use std::fmt::Write as _;

use zeroize::Zeroizing;

/// What goes on the kit. Text fields are printed as given.
#[derive(Debug, Clone, Copy)]
pub struct KitContents<'a> {
    pub secret_key: &'a str,
    /// `None` when it can't be shown (it is not stored anywhere after it is issued).
    pub recovery_key: Option<&'a str>,
    pub vault_id: &'a str,
    pub vault_path: &'a str,
    /// Unix seconds, printed as a date.
    pub created_at: u64,
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

    fn rule(&mut self, gray: f32, width: f32) {
        let _ = writeln!(
            self.ops,
            "{gray:.2} G {width:.2} w {MARGIN:.1} {y:.1} m {x2:.1} {y:.1} l S",
            y = self.y,
            x2 = PAGE_W - MARGIN
        );
    }

    fn rect(&mut self, y: f32, height: f32, fill: f32, stroke: f32) {
        let _ = writeln!(
            self.ops,
            "{fill:.2} g {stroke:.2} G 0.8 w {MARGIN:.1} {y:.1} {WIDTH:.1} {height:.1} re B"
        );
    }

    /// A labelled key in a light box: label, value, then a short explanation.
    fn key_box(&mut self, label: &str, value: &str, value_size: f32, note: &str) {
        let value_lines = wrap(value, Font::MonoBold, value_size, WIDTH - 28.0);
        let note_lines = wrap(note, Font::Regular, 9.0, WIDTH - 28.0);
        let height = 14.0
            + 12.0
            + 8.0
            + value_lines.len() as f32 * value_size * 1.3
            + 6.0
            + note_lines.len() as f32 * 9.0 * 1.35
            + 12.0;
        let top = self.y;
        self.rect(top - height, height, 0.96, 0.75);
        let x = MARGIN + 14.0;
        let mut y = top - 14.0 - 9.0;
        self.text_at(x, y, Font::Bold, 9.0, 0.35, label);
        y -= 8.0;
        for line in &value_lines {
            y -= value_size * 1.3;
            self.text_at(
                x,
                y + value_size * 0.25,
                Font::MonoBold,
                value_size,
                0.0,
                line,
            );
        }
        y -= 6.0;
        for line in &note_lines {
            y -= 9.0 * 1.35;
            self.text_at(x, y, Font::Regular, 9.0, 0.35, line);
        }
        self.y = top - height;
    }
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
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

/// Renders the kit. The bytes contain the keys: they are wiped from memory when dropped.
pub fn render(kit: &KitContents<'_>) -> Zeroizing<Vec<u8>> {
    let mut page = Page::new();

    page.gap(6.0);
    page.text_at(MARGIN, page.y, Font::Bold, 24.0, 0.1, "Emergency kit");
    page.text_at(
        PAGE_W - MARGIN - Font::Regular.text_width("Vault", 11.0),
        page.y + 4.0,
        Font::Regular,
        11.0,
        0.45,
        "Vault",
    );
    page.gap(10.0);
    page.paragraph(
        Font::Regular,
        10.5,
        0.3,
        &format!(
            "Made on {}. Print this page and keep it somewhere safe, away from your computer \
             (a drawer at home, a safe, with your important papers). It is the way back into \
             your vault if you lose this computer or forget your master password.",
            date_text(kit.created_at)
        ),
    );
    page.gap(14.0);
    page.rule(0.8, 0.6);
    page.gap(18.0);

    page.key_box(
        "SECRET KEY",
        kit.secret_key,
        15.0,
        "Combined with your master password to open the vault. Each computer asks for it once. \
         On its own it opens nothing.",
    );
    page.gap(14.0);
    match kit.recovery_key {
        Some(recovery_key) => page.key_box(
            "RECOVERY KEY",
            recovery_key,
            11.0,
            "Opens the vault on its own, for when you forget the master password. Anyone holding \
             it can open your vault: keep this page private.",
        ),
        None => page.key_box(
            "RECOVERY KEY",
            "______________________________________________",
            11.0,
            "Not printed: the app doesn't keep it. Copy it here from your first kit, or issue a \
             new one in the app (Emergency kit > New Recovery Key) and print again.",
        ),
    }
    page.gap(14.0);
    page.key_box(
        "VAULT ID",
        kit.vault_id,
        10.0,
        "Tells you which vault this kit belongs to.",
    );

    page.gap(26.0);
    page.text_at(
        MARGIN,
        page.y,
        Font::Bold,
        9.0,
        0.35,
        "MASTER PASSWORD (write it by hand, or leave blank)",
    );
    page.gap(30.0);
    page.rule(0.2, 0.8);
    page.gap(22.0);
    page.text_at(MARGIN, page.y, Font::Bold, 9.0, 0.35, "VAULT FILE");
    page.paragraph(Font::Mono, 9.0, 0.2, kit.vault_path);

    page.gap(24.0);
    page.rule(0.8, 0.6);
    page.gap(10.0);
    page.text_at(
        MARGIN,
        page.y - 12.0,
        Font::Bold,
        11.0,
        0.1,
        "How to use it",
    );
    page.gap(14.0);
    for step in [
        "New computer: install the app, open your vault file, type the Secret Key above once, \
         then your master password.",
        "Forgot the master password: on the lock screen choose \"Forgot it? Use your emergency \
         kit\", type the Recovery Key and choose a new password. You'll get a new Secret Key; \
         print a new kit.",
        "Lost this page: open the app and print a new kit from Emergency kit. Issuing a new \
         Recovery Key there makes the old one stop working.",
    ] {
        page.paragraph(Font::Regular, 9.5, 0.25, &format!("\u{2022}  {step}"));
        page.gap(4.0);
    }

    page.y = MARGIN;
    page.text_at(
        MARGIN,
        page.y,
        Font::Regular,
        8.0,
        0.5,
        "Made offline by Vault. If this page was saved as a file, delete the file after printing.",
    );

    assemble(&page.ops)
}

/// Wraps a content stream into a complete single-page PDF file.
fn assemble(content: &str) -> Zeroizing<Vec<u8>> {
    let fonts = [
        (5, "Helvetica"),
        (6, "Helvetica-Bold"),
        (7, "Courier"),
        (8, "Courier-Bold"),
    ];
    let mut objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents 4 0 R \
             /Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R /F4 8 0 R >> >> >>"
        ),
        format!(
            "<< /Length {} >>\nstream\n{content}endstream",
            content.len()
        ),
    ];
    for (_, base) in fonts {
        objects.push(format!(
            "<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>"
        ));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(content.len() + 2048));
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
    }
    let xref = out.len();
    let mut table = format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1);
    for offset in offsets {
        let _ = writeln!(table, "{offset:010} 00000 n ");
    }
    let _ = write!(
        table,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.len() + 1
    );
    out.extend_from_slice(table.as_bytes());
    // The content stream held the keys in a String: wipe it too.
    let mut content = content.to_owned();
    zeroize::Zeroize::zeroize(&mut content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kit(recovery: Option<&str>) -> Zeroizing<Vec<u8>> {
        render(&KitContents {
            secret_key: "S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345",
            recovery_key: recovery,
            vault_id: "0123456789abcdef0123456789abcdef",
            vault_path: r"C:\Users\someone\AppData\Local\vault\default (copy).vault",
            created_at: 1_794_441_600, // 12 November 2026
        })
    }

    #[test]
    fn is_a_well_formed_single_page_pdf() {
        let bytes = kit(Some(
            "R0-AAAAAA-BBBBBB-CCCCCC-DDDDDD-EEEEEE-FFFFFF-GGGGGG-HHHHHH-JJJJJJ",
        ));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.trim_end().ends_with("%%EOF"));
        assert!(text.contains("/Count 1"));
        assert!(text.contains("S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345"));
        assert!(text.contains("R0-AAAAAA"));
        assert!(text.contains("12 November 2026"));
        // Parentheses and backslashes in the path are escaped.
        assert!(text.contains(r"default \(copy\).vault"));
        assert!(text.contains(r"C:\\Users"));

        // Every xref offset (in bytes) points at the start of its object.
        let raw: &[u8] = &bytes;
        let tail = String::from_utf8(raw[raw.len() - 64..].to_vec()).unwrap();
        let xref_at: usize = tail
            .rsplit("startxref\n")
            .next()
            .and_then(|t| t.lines().next())
            .and_then(|n| n.parse().ok())
            .unwrap();
        let table = String::from_utf8(raw[xref_at..].to_vec()).unwrap();
        assert!(table.starts_with("xref\n"));
        for (index, line) in table.lines().skip(3).take(8).enumerate() {
            let offset: usize = line[..10].parse().unwrap();
            assert!(
                raw[offset..].starts_with(format!("{} 0 obj", index + 1).as_bytes()),
                "object {} offset",
                index + 1
            );
        }
    }

    #[test]
    fn missing_recovery_key_leaves_a_line_to_fill_in() {
        let text = String::from_utf8_lossy(&kit(None)).into_owned();
        assert!(text.contains("Not printed"));
        assert!(!text.contains("R0-"));
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
}
