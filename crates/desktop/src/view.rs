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
}
