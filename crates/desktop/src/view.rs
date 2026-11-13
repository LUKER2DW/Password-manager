//! Pure presentation rules (no UI types), so they can be unit-tested.

use vault_core::{ItemKind, ItemSummary};

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

/// Items for the list (sorted by title) plus per-category counts.
pub fn filter(
    summaries: &[ItemSummary],
    category: i32,
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
        .filter(|&i| in_category(&summaries[i], category) && matches_search(&summaries[i], query))
        .collect();
    visible.sort_by_key(|&i| summaries[i].title.to_lowercase());
    (visible, counts)
}

/// Second line of a list row: username, else the website host.
pub fn subtitle(summary: &ItemSummary) -> String {
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

/// Guesses per second assumed for crack-time estimates: a well-funded attacker with a GPU rig
/// working offline on a stolen list of fast (unsalted, MD5/SHA-1-like) hashes. The worst
/// realistic case for a website's leaked password database.
pub const GUESSES_PER_SECOND: f64 = 1e12;

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
    /// More than 1000 billion years: far beyond the age of the universe.
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
    } else if years < 1e12 {
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
        let (visible, counts) = filter(&all, 0, "");
        assert_eq!(counts, [4, 1, 2, 1, 1]);
        let titles: Vec<&str> = visible.iter().map(|&i| all[i].title.as_str()).collect();
        assert_eq!(
            titles,
            ["Alarm code", "bank", "GitHub", "Visa"],
            "case-insensitive sort"
        );
        let (favorites, _) = filter(&all, 1, "");
        assert_eq!(favorites.len(), 1);
    }

    #[test]
    fn search_looks_at_title_username_and_url() {
        let all = summaries();
        assert_eq!(filter(&all, 0, "OCTO").0.len(), 1);
        assert_eq!(filter(&all, 0, "bank.example").0.len(), 1);
        assert_eq!(
            filter(&all, 2, "visa").0.len(),
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
