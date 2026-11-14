//! Pure presentation rules (no UI types), so they can be unit-tested.

use vault_core::{FolderId, ItemData, ItemKind, ItemSummary, card, health};

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
    /// Icon name (icons.slint).
    pub icon: &'static str,
    /// Hidden or masked on the page: offers Show.
    pub hideable: bool,
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
                icon: if f.sensitive { "shield" } else { "tag" },
                hideable: f.sensitive,
            };
            if named(f, card::NUMBER) {
                view.label = "Card number".into();
                view.icon = "card";
                view.value = card::masked(&card::digits(&f.value));
                view.sensitive = false; // masked; Copy still copies the full number as a secret
                view.hideable = true;
            } else if named(f, card::EXPIRY)
                && let Some(expiry) = card::parse_expiry(&f.value)
            {
                view.label = "Expires".into();
                view.icon = "calendar";
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

/// The card network mark index used by icons.slint `BrandMark` (0 = unknown).
pub fn brand_mark(brand: card::Brand) -> i32 {
    match brand {
        card::Brand::Visa => 1,
        card::Brand::Mastercard => 2,
        card::Brand::Amex => 3,
        card::Brand::Elo => 4,
        card::Brand::Hipercard => 5,
        card::Brand::Discover => 6,
        card::Brand::Diners => 7,
        card::Brand::Jcb => 8,
        card::Brand::Maestro => 9,
        card::Brand::Unknown => 0,
    }
}

/// Code for `Messages.weakness` (0 = nothing to say).
pub fn weakness_code(strength: &health::Strength) -> i32 {
    use health::Pattern;
    match strength.pattern {
        Pattern::KeyboardPattern => 1,
        Pattern::Repeats => 2,
        Pattern::Common => 3,
        Pattern::SimilarToCommon => 4,
        Pattern::Sequence => 5,
        Pattern::Dates => 6,
        Pattern::SingleWord => 7,
        Pattern::Names => 8,
        Pattern::None if strength.is_weak() => 9,
        Pattern::None => 0,
    }
}

/// How long ago, for `Messages.ago`: (unit, amount) with unit 0 today, 1 days, 2 months,
/// 3 years; (-1, 0) when unknown.
pub fn ago(then: i64, now: i64) -> (i32, i32) {
    if then <= 0 {
        return (-1, 0);
    }
    let days = (now - then).max(0) / 86_400;
    match days {
        0 => (0, 0),
        1..=59 => (1, days as i32),
        60..=729 => (2, (days / 30) as i32),
        _ => (3, (days / 365) as i32),
    }
}

/// `YYYY-MM-DD` in UTC (language-neutral).
pub fn date(unix: i64) -> String {
    if unix <= 0 {
        return String::from("—");
    }
    let days = unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The website typed in "Icon from", tidied: trimmed, `https://` added when missing, empty
/// when nothing usable was typed.
pub fn icon_site(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() || text.contains(char::is_whitespace) {
        return String::new();
    }
    if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    }
}

/// Current Unix time in seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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

/// Seconds before the auto-lock when the countdown shows: the last minute, or the last half
/// of a shorter wait.
pub fn lock_warning_lead(total_seconds: u64) -> u64 {
    60.min(total_seconds / 2)
}

/// The editor's kind for a login kept for its two-step codes only (see [`editor_kind`]).
pub const EDITOR_AUTHENTICATOR: i32 = 3;

/// What the editor shows an item as: 0 login, 1 card, 2 secure note, or
/// [`EDITOR_AUTHENTICATOR`] for a login with a one-time code secret and no password.
pub fn editor_kind(item: &vault_core::ItemData) -> i32 {
    match item.kind {
        ItemKind::Login if item.password.is_empty() && !item.totp.is_empty() => {
            EDITOR_AUTHENTICATOR
        }
        ItemKind::Card => 1,
        ItemKind::SecureNote => 2,
        _ => 0,
    }
}

/// The kind an editor kind is saved as (an authenticator entry is a login).
pub fn editor_kind_to_kind(value: i32) -> ItemKind {
    match value {
        1 => ItemKind::Card,
        2 => ItemKind::SecureNote,
        _ => ItemKind::Login,
    }
}

/// The editor kind for a new item asked for from list `category` (2 logins, 3 cards, 4 notes)
/// or from the Authenticator page.
pub fn new_item_kind(category: i32, authenticator: bool) -> i32 {
    if authenticator {
        return EDITOR_AUTHENTICATOR;
    }
    match category {
        3 => 1,
        4 => 2,
        _ => 0,
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
/// Clear, saturated tones that keep white initials readable (no muddy olives or browns).
const TINTS: [(u8, u8, u8); 8] = [
    (0x3D, 0x6F, 0xD6), // blue
    (0x7B, 0x5C, 0xD6), // violet
    (0x16, 0x93, 0x72), // green
    (0xD2, 0x63, 0x35), // orange
    (0xC0, 0x4A, 0x84), // magenta
    (0x17, 0x8A, 0xB0), // cyan
    (0xC8, 0x45, 0x45), // red
    (0x5B, 0x7F, 0x2E), // leaf
];

/// Stable fallback colour: cards, notes and passkeys get fixed tones; logins hash their site
/// (or title) so the same service always gets the same colour.
pub fn tint(kind: ItemKind, key: &str) -> (u8, u8, u8) {
    match kind {
        ItemKind::Card => (0x4A, 0x5D, 0x7E),
        ItemKind::SecureNote => (0x2F, 0x7D, 0x68),
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

/// Bits above which there are more passwords than atoms in the whole Earth (about 1.3 × 10⁵⁰,
/// close to 2¹⁶⁷).
const EARTH_ATOMS_BITS: f64 = 167.0;
/// Bits above which there are more passwords than atoms in the observable universe (about
/// 10⁸⁰, close to 2²⁶⁶).
const UNIVERSE_ATOMS_BITS: f64 = 266.0;
/// Years until the last, smallest stars (red dwarfs) burn out: about ten trillion.
const LAST_STARS_YEARS: f64 = 1e13;

/// Light-hearted comparison for an average crack time (see `Messages.crack-comparison`).
/// Past the age of the universe it keeps changing as the password grows, instead of
/// repeating the same line.
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
    } else if years < AGE_OF_UNIVERSE_YEARS {
        // The oldest milestone it outlasts: "if they'd started when …, they'd still be at it".
        MILESTONES
            .iter()
            .rev()
            .find(|(ago, _)| years >= *ago)
            .map_or(6, |(_, code)| *code)
    } else if bits >= UNIVERSE_ATOMS_BITS {
        23
    } else if bits >= EARTH_ATOMS_BITS {
        22
    } else if years >= AGE_OF_UNIVERSE_YEARS * 1e9 {
        // Even a billion times more guesses per second would outlast the universe.
        21
    } else if years >= LAST_STARS_YEARS {
        20
    } else {
        19
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
    /// Past the age of the universe (13.8 billion years), counted in ages of the universe:
    /// `n` times, then thousands, millions, billions and trillions of times…
    pub const UNIVERSE_TIMES: i32 = 9;
    pub const UNIVERSE_THOUSANDS: i32 = 10;
    pub const UNIVERSE_MILLIONS: i32 = 11;
    pub const UNIVERSE_BILLIONS: i32 = 12;
    pub const UNIVERSE_TRILLIONS: i32 = 13;
    /// …and beyond that, a 1 followed by `n` zeros times the age of the universe.
    pub const UNIVERSE_POWER: i32 = 14;
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
    let ages = years / AGE_OF_UNIVERSE_YEARS;
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
    } else if ages < 1.0 {
        (crack::BILLION_YEARS, years / 1e9)
    } else if ages < 999.5 {
        (crack::UNIVERSE_TIMES, ages)
    } else if ages < 999.5e3 {
        (crack::UNIVERSE_THOUSANDS, ages / 1e3)
    } else if ages < 999.5e6 {
        (crack::UNIVERSE_MILLIONS, ages / 1e6)
    } else if ages < 999.5e9 {
        (crack::UNIVERSE_BILLIONS, ages / 1e9)
    } else if ages < 999.5e12 {
        (crack::UNIVERSE_TRILLIONS, ages / 1e12)
    } else {
        (crack::UNIVERSE_POWER, ages.log10().floor())
    };
    (
        unit,
        (amount.round().min(f64::from(i32::MAX)) as i32).max(i32::from(unit != crack::INSTANT)),
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
        assert_eq!(
            editor_kind_to_kind(kind_to_int(ItemKind::Card)),
            ItemKind::Card
        );
    }

    #[test]
    fn icon_sites() {
        assert_eq!(icon_site("  nubank.com.br "), "https://nubank.com.br");
        assert_eq!(icon_site("https://x.example/a"), "https://x.example/a");
        assert_eq!(icon_site(""), "");
        assert_eq!(icon_site("two words"), "");
    }

    #[test]
    fn dates_and_ages() {
        assert_eq!(date(0), "—");
        assert_eq!(date(1_700_000_000), "2023-11-14");
        assert_eq!(date(951_782_400), "2000-02-29");
        let now = 1_700_000_000;
        assert_eq!(ago(0, now), (-1, 0));
        assert_eq!(ago(now - 3_600, now), (0, 0));
        assert_eq!(ago(now - 5 * 86_400, now), (1, 5));
        assert_eq!(ago(now - 90 * 86_400, now), (2, 3));
        assert_eq!(ago(now - 800 * 86_400, now), (3, 2));
        assert_eq!(brand_mark(card::Brand::Elo), 4);
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
    fn lock_warning_leads() {
        assert_eq!(lock_warning_lead(300), 60);
        assert_eq!(lock_warning_lead(60), 30);
        assert_eq!(lock_warning_lead(3600), 60);
    }

    #[test]
    fn editor_kinds() {
        let mut login = vault_core::ItemData::new(ItemKind::Login, "GitHub");
        assert_eq!(editor_kind(&login), 0);
        login.totp = "JBSWY3DPEHPK3PXP".into();
        assert_eq!(editor_kind(&login), EDITOR_AUTHENTICATOR);
        login.password = "pw".into();
        assert_eq!(
            editor_kind(&login),
            0,
            "a login with a password stays a login"
        );
        let card = vault_core::ItemData::new(ItemKind::Card, "Visa");
        assert_eq!(editor_kind(&card), 1);
        assert_eq!(editor_kind_to_kind(EDITOR_AUTHENTICATOR), ItemKind::Login);
        assert_eq!(editor_kind_to_kind(2), ItemKind::SecureNote);
        assert_eq!(new_item_kind(3, false), 1);
        assert_eq!(new_item_kind(4, false), 2);
        assert_eq!(new_item_kind(2, false), 0);
        assert_eq!(new_item_kind(0, true), EDITOR_AUTHENTICATOR);
    }

    #[test]
    fn crack_time_estimates() {
        assert_eq!(crack_time(20.0), (crack::INSTANT, 0));
        // 2^49 / 1e12 ≈ 563 s ≈ 9 minutes
        assert_eq!(crack_time(50.0), (crack::MINUTES, 9));
        // 2^69 / 1e12 s ≈ 18.7 years
        assert_eq!(crack_time(70.0), (crack::YEARS, 19));
        assert_eq!(crack_time(90.0).0, crack::MILLION_YEARS);
        // Past the age of the universe the wording keeps growing with the password.
        assert_eq!(crack_time(98.0), (crack::BILLION_YEARS, 5));
        assert_eq!(crack_time(100.0), (crack::UNIVERSE_TIMES, 1));
        assert_eq!(crack_time(110.0), (crack::UNIVERSE_THOUSANDS, 1));
        assert_eq!(crack_time(128.0), (crack::UNIVERSE_MILLIONS, 391));
        assert_eq!(crack_time(140.0), (crack::UNIVERSE_TRILLIONS, 2));
        assert_eq!(crack_time(256.0), (crack::UNIVERSE_POWER, 47));
        // Every step from 60 to 300 bits reads differently from the one 10 bits earlier.
        let mut last = crack_time(50.0);
        for bits in (60..=300).step_by(10) {
            let now = crack_time(f64::from(bits));
            assert_ne!(now, last, "{bits} bits");
            last = now;
        }
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
        assert_eq!(crack_comparison(105.0), 19, "beyond the universe");
        assert_eq!(crack_comparison(128.0), 20, "the last stars burn out first");
        assert_eq!(
            crack_comparison(150.0),
            21,
            "a billion times faster wouldn't do"
        );
        assert_eq!(crack_comparison(180.0), 22, "more than the Earth's atoms");
        assert_eq!(
            crack_comparison(300.0),
            23,
            "more than the universe's atoms"
        );
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
