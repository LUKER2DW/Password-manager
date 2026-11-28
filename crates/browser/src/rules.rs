//! Per-site rules: what the extension may do on one site (F16).
//!
//! The person sets them in the desktop app (Settings → Browser extension → Site rules) or from
//! the extension's window for the site in front. They are kept in this device's state
//! (`vault_platform::device::SiteRule`), not in the vault: the vault's format has no place for
//! them yet, so they don't sync.
//!
//! A rule names a host and covers it and every host under it: one for `example.com` holds on
//! `www.example.com` and `shop.example.com` too, and the most specific rule wins (one for
//! `shop.example.com` replaces the one for `example.com` there). The app enforces them before a
//! request is answered, locked or not ([`refused`]); the extension also hears them with a
//! page's logins ([`rules_json`]) so it doesn't offer what would be refused.

use url::Url;
use vault_platform::device::SiteRule;

/// The key a rule is kept under for the page or site `text` (a page's address, a saved website
/// or a host typed by the person): its host, lowercase, without `www.`, with the port when it
/// isn't 443. `None` for anything that isn't a web address.
pub fn site_key(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || text.len() > 512 {
        return None;
    }
    let with_scheme = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    };
    let url = Url::parse(&with_scheme).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())?
        .to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    if host.is_empty() {
        return None;
    }
    Some(match url.port() {
        Some(port) if port != 443 => format!("{host}:{port}"),
        _ => host,
    })
}

/// Whether the rule kept under `rule` covers the site kept under `site` (both [`site_key`]s).
fn covers(rule: &str, site: &str) -> bool {
    let (rule_host, rule_port) = rule.rsplit_once(':').map_or((rule, ""), |(h, p)| (h, p));
    let (site_host, site_port) = site.rsplit_once(':').map_or((site, ""), |(h, p)| (h, p));
    rule_port == site_port
        && (site_host == rule_host
            || site_host
                .strip_suffix(rule_host)
                .is_some_and(|rest| rest.ends_with('.')))
}

/// The rule that holds on the page at `url`: the most specific one covering its host.
pub fn rule_for<'a>(rules: &'a [SiteRule], url: &str) -> Option<&'a SiteRule> {
    let site = site_key(url)?;
    rules
        .iter()
        .filter(|rule| covers(&rule.host, &site))
        .max_by_key(|rule| rule.host.len())
}

/// Whether a request of type `kind` about the page at `url` is refused by the person's rule
/// for that site: saving and updating (`never_save`), filling a login, a code or a card
/// (`never_fill`), the vault's passkeys (`no_passkeys`). The card under a field (`no_card`) is
/// the extension's to leave out: nothing is refused for it.
pub fn refused(rules: &[SiteRule], kind: &str, url: &str) -> bool {
    let Some(rule) = rule_for(rules, url) else {
        return false;
    };
    match kind {
        "save" | "changed" | "update" => rule.never_save,
        "fill" | "code" | "card_fill" | "identity_fill" => rule.never_fill,
        "passkeys" | "passkey_get" | "passkey_create" | "passkey_signal" => rule.no_passkeys,
        _ => false,
    }
}

/// Whether a frame from `frame_origin` (another site's, inside the page at `top_url`) may get
/// a card: only when the person approved that frame's host for that site
/// ([`SiteRule::card_frames`]). The page's own origin needs no approval.
pub fn card_frame_allowed(rules: &[SiteRule], top_url: &str, frame_origin: &str) -> bool {
    let (Some(rule), Some(frame)) = (rule_for(rules, top_url), site_key(frame_origin)) else {
        return false;
    };
    !rule.never_fill && rule.card_frames.contains(&frame)
}

/// What the extension hears of the rule for the page at `url`, with its logins: the site it is
/// kept for and the four switches. `None` when no rule holds there.
pub fn rules_json(rules: &[SiteRule], url: &str) -> Option<serde_json::Value> {
    let rule = rule_for(rules, url)?;
    Some(serde_json::json!({
        "site": rule.host,
        "never_save": rule.never_save,
        "no_card": rule.no_card,
        "never_fill": rule.never_fill,
        "no_passkeys": rule.no_passkeys,
        "card_frames": rule.card_frames,
    }))
}

/// A change the person made to one site's rule. `None` leaves a switch as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleChange {
    pub never_save: Option<bool>,
    pub no_card: Option<bool>,
    pub never_fill: Option<bool>,
    pub no_passkeys: Option<bool>,
    /// A frame's host (or origin) approved to get cards in this site's pages.
    pub allow_card_frame: Option<String>,
    /// One taken back.
    pub forbid_card_frame: Option<String>,
}

/// Most sites a device keeps rules for, and most frames approved per site: a list typed by a
/// person, never a page's.
pub const MAX_RULES: usize = 500;
pub const MAX_CARD_FRAMES: usize = 16;

/// Why [`apply`] refused a change: the list is full, or a frame named isn't a web address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused;

/// Applies `change` to the rule kept for `site` (a [`site_key`]), made when there is none and
/// dropped when nothing is left on. Returns the rule as it is now (`None`: no rule), or `Err`
/// when the list is full or a frame named isn't a web address.
pub fn apply(
    rules: &mut Vec<SiteRule>,
    site: &str,
    change: &RuleChange,
) -> Result<Option<SiteRule>, Refused> {
    let at = rules.iter().position(|rule| rule.host == site);
    let mut rule = at.map_or_else(
        || SiteRule {
            host: site.to_owned(),
            ..SiteRule::default()
        },
        |at| rules[at].clone(),
    );
    let set = |field: &mut bool, value: Option<bool>| {
        if let Some(value) = value {
            *field = value;
        }
    };
    set(&mut rule.never_save, change.never_save);
    set(&mut rule.no_card, change.no_card);
    set(&mut rule.never_fill, change.never_fill);
    set(&mut rule.no_passkeys, change.no_passkeys);
    if let Some(frame) = &change.allow_card_frame {
        let frame = site_key(frame).ok_or(Refused)?;
        if frame != site && !rule.card_frames.contains(&frame) {
            if rule.card_frames.len() >= MAX_CARD_FRAMES {
                return Err(Refused);
            }
            rule.card_frames.push(frame);
        }
    }
    if let Some(frame) = &change.forbid_card_frame {
        let frame = site_key(frame).unwrap_or_default();
        rule.card_frames.retain(|kept| *kept != frame);
    }
    match (at, rule.is_empty()) {
        (Some(at), true) => {
            rules.remove(at);
            Ok(None)
        }
        (None, true) => Ok(None),
        (Some(at), false) => {
            rules[at] = rule.clone();
            Ok(Some(rule))
        }
        (None, false) => {
            if rules.len() >= MAX_RULES {
                return Err(Refused);
            }
            rules.push(rule.clone());
            rules.sort_by(|a, b| a.host.cmp(&b.host));
            Ok(Some(rule))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(host: &str) -> SiteRule {
        SiteRule {
            host: host.into(),
            ..SiteRule::default()
        }
    }

    #[test]
    fn a_site_is_kept_by_its_host_without_www() {
        assert_eq!(
            site_key("https://www.Example.com/login?x").as_deref(),
            Some("example.com")
        );
        assert_eq!(site_key("example.com").as_deref(), Some("example.com"));
        assert_eq!(
            site_key("https://intranet.example:8443/").as_deref(),
            Some("intranet.example:8443")
        );
        assert_eq!(
            site_key("https://example.com:443/").as_deref(),
            Some("example.com")
        );
        for nothing in ["", "   ", "file:///c:/x", "chrome://settings", "https://"] {
            assert_eq!(site_key(nothing), None, "{nothing}");
        }
    }

    #[test]
    fn a_rule_covers_its_host_and_those_under_it_the_most_specific_winning() {
        let rules = vec![
            SiteRule {
                never_save: true,
                ..rule("example.com")
            },
            SiteRule {
                never_fill: true,
                ..rule("shop.example.com")
            },
        ];
        let at = |url| rule_for(&rules, url).map(|rule| rule.host.as_str());
        assert_eq!(at("https://example.com/"), Some("example.com"));
        assert_eq!(at("https://www.example.com/"), Some("example.com"));
        assert_eq!(at("https://a.b.example.com/"), Some("example.com"));
        assert_eq!(
            at("https://shop.example.com/cart"),
            Some("shop.example.com")
        );
        assert_eq!(at("https://x.shop.example.com/"), Some("shop.example.com"));
        // Not a name under it, only one that ends alike.
        assert_eq!(at("https://notexample.com/"), None);
        assert_eq!(at("https://example.com.evil.test/"), None);
        // Another port is another site.
        assert_eq!(at("https://example.com:8443/"), None);

        assert!(refused(&rules, "save", "https://example.com/"));
        assert!(refused(&rules, "update", "https://www.example.com/"));
        assert!(!refused(&rules, "fill", "https://example.com/"));
        // The more specific rule holds alone there: it doesn't forbid saving.
        assert!(!refused(&rules, "save", "https://shop.example.com/"));
        assert!(refused(&rules, "card_fill", "https://shop.example.com/"));
        assert!(refused(&rules, "code", "https://shop.example.com/"));
        assert!(!refused(&rules, "logins", "https://shop.example.com/"));
        assert!(!refused(&rules, "save", "https://other.test/"));
    }

    #[test]
    fn rules_are_made_changed_and_dropped_when_nothing_is_left_on() {
        let mut rules = Vec::new();
        let on = RuleChange {
            no_passkeys: Some(true),
            ..RuleChange::default()
        };
        let made = apply(&mut rules, "example.com", &on).unwrap().unwrap();
        assert!(made.no_passkeys);
        assert!(refused(&rules, "passkey_get", "https://example.com/"));
        // Nothing to turn off on a site with no rule: none is made.
        let off = RuleChange {
            no_passkeys: Some(false),
            ..RuleChange::default()
        };
        assert_eq!(apply(&mut rules, "other.test", &off), Ok(None));
        assert_eq!(apply(&mut rules, "example.com", &off), Ok(None));
        assert!(rules.is_empty());
    }

    #[test]
    fn a_frame_of_another_site_gets_a_card_only_once_approved_for_that_site() {
        let mut rules = Vec::new();
        let frame = "https://js.payments.test";
        assert!(!card_frame_allowed(&rules, "https://shop.test/pay", frame));
        let allow = RuleChange {
            allow_card_frame: Some(frame.into()),
            ..RuleChange::default()
        };
        apply(&mut rules, "shop.test", &allow).unwrap();
        assert!(card_frame_allowed(&rules, "https://shop.test/pay", frame));
        assert!(card_frame_allowed(&rules, "https://www.shop.test/", frame));
        // Approved for that shop only, and that frame's host only.
        assert!(!card_frame_allowed(&rules, "https://other.test/", frame));
        assert!(!card_frame_allowed(
            &rules,
            "https://shop.test/",
            "https://evil.payments.test"
        ));
        // Never fill on the site holds over an approval.
        apply(
            &mut rules,
            "shop.test",
            &RuleChange {
                never_fill: Some(true),
                ..RuleChange::default()
            },
        )
        .unwrap();
        assert!(!card_frame_allowed(&rules, "https://shop.test/", frame));
        let forbid = RuleChange {
            forbid_card_frame: Some(frame.into()),
            never_fill: Some(false),
            ..RuleChange::default()
        };
        assert_eq!(apply(&mut rules, "shop.test", &forbid), Ok(None));
        // A frame that isn't a web address is refused.
        let bad = RuleChange {
            allow_card_frame: Some("javascript:alert(1)".into()),
            ..RuleChange::default()
        };
        assert_eq!(apply(&mut rules, "shop.test", &bad), Err(Refused));
    }

    #[test]
    fn the_extension_hears_the_rule_that_holds() {
        let rules = vec![SiteRule {
            no_card: true,
            ..rule("example.com")
        }];
        let heard = rules_json(&rules, "https://www.example.com/").unwrap();
        assert_eq!(heard["site"], "example.com");
        assert_eq!(heard["no_card"], true);
        assert_eq!(heard["never_save"], false);
        assert_eq!(rules_json(&rules, "https://else.test/"), None);
    }
}
