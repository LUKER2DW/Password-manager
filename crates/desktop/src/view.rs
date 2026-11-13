//! Pure presentation rules (no UI types), so they can be unit-tested.

use vault_core::{FolderId, ItemData, ItemKind, ItemSummary, card};

/// One extra field as shown on the item page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldView {
    pub label: String,
    /// Empty for sensitive fields (the page shows dots).
    pub value: String,
    pub sensitive: bool,
    /// Position in the item's `custom_fields` (what Copy copies).
    pub index: usize,
    /// Show in red (an expired card).
    pub warning: bool,
}

/// The item's extra fields for the item page. Cards get friendly labels: the number masked with
/// its brand ("Visa •••• 4242"), the expiry flagged when past; the stored brand is not repeated.
pub fn detail_fields(item: &ItemData, now: (u32, u32)) -> Vec<FieldView> {
    let is_card = item.kind == ItemKind::Card;
    let named = |field: &vault_core::CustomField, name: &str| {
        is_card && field.name.eq_ignore_ascii_case(name)
    };
    item.custom_fields
        .iter()
        .enumerate()
        .filter(|(_, f)| !named(f, card::BRAND))
        .map(|(index, f)| {
            let mut view = FieldView {
                label: f.name.clone(),
                value: if f.sensitive {
                    String::new()
                } else {
                    f.value.clone()
                },
                sensitive: f.sensitive,
                index,
                warning: false,
            };
            if named(f, card::NUMBER) {
                view.label = "Card number".into();
                view.value = card::masked(&card::digits(&f.value));
                view.sensitive = false; // masked; Copy still copies the full number as a secret
            } else if named(f, card::EXPIRY)
                && let Some(expiry) = card::parse_expiry(&f.value)
            {
                view.label = "Expires".into();
                let expired = card::is_expired(expiry, now);
                view.value = if expired {
                    format!("{} · expired", card::format_expiry(expiry))
                } else {
                    card::format_expiry(expiry)
                };
                view.warning = expired;
            }
            view
        })
        .collect()
}

/// Current (month, year) in UTC.
pub fn now_month_year() -> (u32, u32) {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (month as u32, year as u32)
}

/// Index tabs: 0 all, 1 favorites, 2 logins, 3 cards, 4 secure notes.
pub const CATEGORY_COUNT: usize = 5;

pub fn kind_to_int(kind: ItemKind) -> i32 {
    match kind {
        ItemKind::Login => 0,
        ItemKind::Card => 1,
        ItemKind::SecureNote => 2,
        ItemKind::Passkey => 3,
    }
}

pub fn int_to_kind(value: i32) -> ItemKind {
    match value {
        1 => ItemKind::Card,
        2 => ItemKind::SecureNote,
        3 => ItemKind::Passkey,
        _ => ItemKind::Login,
    }
}

pub fn in_category(summary: &ItemSummary, category: i32) -> bool {
    match category {
        1 => summary.favorite,
        2 => summary.kind == ItemKind::Login,
        3 => summary.kind == ItemKind::Card,
        4 => summary.kind == ItemKind::SecureNote,
        _ => true,
    }
}

pub fn matches_search(summary: &ItemSummary, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    query.is_empty()
        || [&summary.title, &summary.username, &summary.url]
            .iter()
            .any(|field| field.to_lowercase().contains(&query))
}

/// Items for the list (sorted by title) plus per-category counts. With a older, the list
/// shows that folder's items and category is ignored.
pub fn filter(
    summaries: &[ItemSummary],
    category: i32,
    folder: Option<FolderId>,
    query: &str,
) -> (Vec<usize>, [i32; CATEGORY_COUNT]) {
    let mut counts = [0i32; CATEGORY_COUNT];
    for summary in summaries {
        for (category, count) in counts.iter_mut().enumerate() {
            if in_category(summary, category as i32) {
                *count += 1;
            }
        }
    }
    let mut visible: Vec<usize> = (0..summaries.len())
        .filter(|&i| {
            let shown = match folder {
                Some(folder) => summaries[i].folder == Some(folder),
                None => in_category(&summaries[i], category),
            };
            shown && matches_search(&summaries[i], query)
        })
        .collect();
    visible.sort_by_key(|&i| summaries[i].title.to_lowercase());
    (visible, counts)
}

/// Second line of a list row: username, else the website host.
pub fn subtitle(summary: &ItemSummary) -> String {
    if !summary.card_hint.is_empty() {
        return summary.card_hint.clone();
    }
    if !summary.username.is_empty() {
        return summary.username.clone();
    }
    let url = summary
        .url
        .split_once("://")
        .map_or(summary.url.as_str(), |(_, rest)| rest);
    url.split('/').next().unwrap_or_default().to_owned()
}

/// Fallback letter for an item without an icon.
pub fn initial(title: &str) -> String {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "•".to_owned())
}

/// Muted colours that read well behind white text in both themes.
const TINTS: [(u8, u8, u8); 8] = [
    (0x3B, 0x5B, 0x8C),
    (0x5B, 0x4B, 0x8A),
    (0x2F, 0x6B, 0x5A),
    (0x8A, 0x5A, 0x3B),
    (0x7A, 0x3E, 0x5E),
    (0x2E, 0x6A, 0x7A),
    (0x6E, 0x63, 0x2C),
    (0x4E, 0x64, 0x34),
];

/// Stable fallback colour: cards, notes and passkeys get fixed tones; logins hash their site
/// (or title) so the same service always gets the same colour.
pub fn tint(kind: ItemKind, key: &str) -> (u8, u8, u8) {
    match kind {
        ItemKind::Card => (0x3D, 0x4F, 0x6B),
        ItemKind::SecureNote => (0x3C, 0x5E, 0x54),
        ItemKind::Passkey => (0x5C, 0x4B, 0x7A),
        ItemKind::Login => {
            // FNV-1a: tiny, stable across runs and platforms.
            let hash = key.to_lowercase().bytes().fold(0x811C_9DC5u32, |h, b| {
                (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
            });
            TINTS[hash as usize % TINTS.len()]
        }
    }
}

/// Guesses per second assumed for crack-time estimates: the worst realistic case for a password
/// from a website's leaked database. The site stored fast hashes (MD5), and the attacker runs
/// hashcat on a small rig: one RTX 4090 does about 164 billion MD5 guesses per second (hashcat
/// 6.2 benchmark), so six of them make about a trillion. Slow hashes (bcrypt, Argon2) would take
/// millions of times longer.
pub const GUESSES_PER_SECOND: f64 = 1e12;

const AGE_OF_UNIVERSE_YEARS: f64 = 13.8e9;

/// Years ago (counted from 2026) of the milestones used for comparisons, with their codes in
/// model.slint → Messages.crack-comparison. Sorted from the most recent.
const MILESTONES: [(f64, i32); 12] = [
    (19.0, 7),       // the first iPhone (2007)
    (35.0, 8),       // the World Wide Web opened to everyone (1991)
    (57.0, 9),       // the first Moon landing (1969)
    (250.0, 10),     // James Watt's steam engine (1776)
    (576.0, 11),     // Gutenberg's printing press (~1450)
    (1026.0, 12),    // Vikings reached North America (~1000)
    (2070.0, 13),    // Julius Caesar ruled Rome (44 BC)
    (4580.0, 14),    // the Great Pyramid of Giza (~2560 BC)
    (12_000.0, 15),  // the first farms (~10,000 BC)
    (300_000.0, 16), // the first modern humans
    (66e6, 17),      // the dinosaurs died out
    (4.5e9, 18),     // the Earth formed
];

/// Light-hearted comparison for an average crack time (see `Messages.crack-comparison`).
pub fn crack_comparison(bits: f64) -> i32 {
    let seconds = (bits - 1.0).exp2() / GUESSES_PER_SECOND;
    let years = seconds / (365.25 * 24.0 * 3600.0);
    if seconds < 1.0 {
        1
    } else if seconds < 60.0 {
        2
    } else if seconds < 3600.0 {
        3
    } else if seconds < 24.0 * 3600.0 {
        4
    } else if years < 1.0 {
        5
    } else if years >= AGE_OF_UNIVERSE_YEARS {
        19
    } else {
        // The oldest milestone it outlasts: "if they'd started when …, they'd still be at it".
        MILESTONES
            .iter()
            .rev()
            .find(|(ago, _)| years >= *ago)
            .map_or(6, |(_, code)| *code)
    }
}

/// Crack-time units (texts in model.slint → Messages.crack-time).
pub mod crack {
    pub const INSTANT: i32 = 0;
    pub const SECONDS: i32 = 1;
    pub const MINUTES: i32 = 2;
    pub const HOURS: i32 = 3;
    pub const DAYS: i32 = 4;
    pub const YEARS: i32 = 5;
    pub const THOUSAND_YEARS: i32 = 6;
    pub const MILLION_YEARS: i32 = 7;
    pub const BILLION_YEARS: i32 = 8;
    /// Longer than the universe has existed (13.8 billion years).
    pub const BEYOND: i32 = 9;
}

/// Average time to guess a secret with `bits` of entropy (half the search space), as a unit and
/// a rounded amount, e.g. `(MILLION_YEARS, 40)`.
pub fn crack_time(bits: f64) -> (i32, i32) {
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 60.0 * MINUTE;
    const DAY: f64 = 24.0 * HOUR;
    const YEAR: f64 = 365.25 * DAY;
    let seconds = (bits - 1.0).exp2() / GUESSES_PER_SECOND;
    let years = seconds / YEAR;
    let (unit, amount) = if seconds < 1.0 {
        (crack::INSTANT, 0.0)
    } else if seconds < MINUTE {
        (crack::SECONDS, seconds)
    } else if seconds < HOUR {
        (crack::MINUTES, seconds / MINUTE)
    } else if seconds < DAY {
        (crack::HOURS, seconds / HOUR)
    } else if seconds < YEAR {
        (crack::DAYS, seconds / DAY)
    } else if years < 1e3 {
        (crack::YEARS, years)
    } else if years < 1e6 {
        (crack::THOUSAND_YEARS, years / 1e3)
    } else if years < 1e9 {
        (crack::MILLION_YEARS, years / 1e6)
    } else if years < AGE_OF_UNIVERSE_YEARS {
        (crack::BILLION_YEARS, years / 1e9)
    } else {
        (crack::BEYOND, 0.0)
    };
    (
        unit,
        (amount.round() as i32).max(i32::from(unit != crack::INSTANT && unit != crack::BEYOND)),
    )
}

/// "123456" → "123 456" (easier to read and type).
pub fn group_code(code: &str) -> String {
    if code.len() == 6 || code.len() == 8 {
        let (a, b) = code.split_at(code.len() / 2);
        format!("{a} {b}")
    } else {
        code.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{ItemData, KdfParams, RecoveryKey, SecretKey, Vault};

    fn summaries() -> Vec<ItemSummary> {
        let mut vault = Vault::create(
            "view tests passphrase",
            &SecretKey::generate().unwrap(),
            None::<&RecoveryKey>,
            KdfParams::minimum().unwrap(),
        )
        .unwrap();
        let mut github = ItemData::login("GitHub", "octocat", "p", "https://github.com");
        github.favorite = true;
        vault.add_item(&github).unwrap();
        vault
            .add_item(&ItemData::login(
                "bank",
                "",
                "p",
                "https://www.bank.example/login",
            ))
            .unwrap();
        vault
            .add_item(&ItemData::new(ItemKind::SecureNote, "Alarm code"))
            .unwrap();
        vault
            .add_item(&ItemData::new(ItemKind::Card, "Visa"))
            .unwrap();
        vault.summaries().unwrap()
    }

    #[test]
    fn categories_counts_and_order() {
        let all = summaries();
        let (visible, counts) = filter(&all, 0, None, "");
        assert_eq!(counts, [4, 1, 2, 1, 1]);
        let titles: Vec<&str> = visible.iter().map(|&i| all[i].title.as_str()).collect();
        assert_eq!(
            titles,
            ["Alarm code", "bank", "GitHub", "Visa"],
            "case-insensitive sort"
        );
        let (favorites, _) = filter(&all, 1, None, "");
        assert_eq!(favorites.len(), 1);
    }

    #[test]
    fn search_looks_at_title_username_and_url() {
        let all = summaries();
        assert_eq!(filter(&all, 0, None, "OCTO").0.len(), 1);
        assert_eq!(filter(&all, 0, None, "bank.example").0.len(), 1);
        assert_eq!(
            filter(&all, 2, None, "visa").0.len(),
            0,
            "search respects the category"
        );
    }

    #[test]
    fn subtitles_and_codes() {
        let all = summaries();
        let bank = all.iter().find(|s| s.title == "bank").unwrap();
        assert_eq!(subtitle(bank), "www.bank.example");
        assert_eq!(group_code("123456"), "123 456");
        assert_eq!(group_code("12345678"), "1234 5678");
        assert_eq!(group_code("1234567"), "1234567");
        assert_eq!(int_to_kind(kind_to_int(ItemKind::Card)), ItemKind::Card);
    }

    #[test]
    fn card_fields_on_the_item_page() {
        let mut item = ItemData::new(ItemKind::Card, "Visa");
        card::CardDetails {
            number: "4111111111111111".into(),
            expiry: "08/25".into(),
            security_code: "123".into(),
        }
        .apply(&mut item);
        let fields = detail_fields(&item, (11, 2026));
        let labels: Vec<&str> = fields.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(
            labels,
            ["Card number", "Expires", "Security code"],
            "brand not repeated"
        );
        assert_eq!(fields[0].value, "Visa •••• 1111");
        assert_eq!(fields[0].index, 0);
        assert!(fields[1].warning && fields[1].value.ends_with("expired"));
        assert!(fields[2].sensitive && fields[2].value.is_empty());
        assert_eq!(fields[2].index, 2, "indexes skip nothing in the item");
        let (month, year) = now_month_year();
        assert!((1..=12).contains(&month) && year >= 2026);
    }

    #[test]
    fn crack_time_estimates() {
        assert_eq!(crack_time(20.0), (crack::INSTANT, 0));
        // 2^49 / 1e12 ≈ 563 s ≈ 9 minutes
        assert_eq!(crack_time(50.0), (crack::MINUTES, 9));
        // 2^69 / 1e12 s ≈ 18.7 years
        assert_eq!(crack_time(70.0), (crack::YEARS, 19));
        assert_eq!(crack_time(90.0).0, crack::MILLION_YEARS);
        assert_eq!(crack_time(128.0), (crack::BEYOND, 0));
    }

    #[test]
    fn crack_comparisons() {
        assert_eq!(crack_comparison(20.0), 1, "instant");
        assert_eq!(crack_comparison(50.0), 3, "minutes: a coffee break");
        assert_eq!(
            crack_comparison(66.0),
            6,
            "a couple of years: no milestone yet"
        );
        assert_eq!(
            crack_comparison(70.0),
            6,
            "18.7 years: just short of the iPhone"
        );
        assert_eq!(
            crack_comparison(77.0),
            13,
            "~2,400 years: longer than since Caesar"
        );
        assert_eq!(
            crack_comparison(90.0),
            16,
            "~20 million years: since the first humans"
        );
        assert_eq!(crack_comparison(128.0), 19, "beyond the universe");
    }

    #[test]
    fn initials_and_tints() {
        assert_eq!(initial("github"), "G");
        assert_eq!(initial("  ånd"), "Å");
        assert_eq!(initial("—"), "•");
        assert_eq!(
            tint(ItemKind::Login, "github.com"),
            tint(ItemKind::Login, "GitHub.com")
        );
        assert_eq!(tint(ItemKind::Card, "x"), tint(ItemKind::Card, "y"));
    }
}
