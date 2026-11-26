use super::*;
use vault_core::{GuardCheck, KdfParams, SecretKey};

fn certificate(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "{hex}");
    std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

/// A page at https://`domain` in Chrome.
fn in_chrome(domain: &str) -> Asker {
    Asker {
        app: "com.android.chrome".into(),
        signers: vec![certificate(CHROME)],
        browser: true,
        domain: Some(domain.into()),
        scheme: Some("https".into()),
    }
}

fn site(domain: &str) -> Recipient {
    Recipient::of(&in_chrome(domain)).unwrap()
}

fn app_with_signers(package: &str, signers: Vec<[u8; 32]>) -> Recipient {
    Recipient::of(&Asker {
        app: package.into(),
        signers,
        ..Asker::default()
    })
    .unwrap()
}

/// An app's own fields.
fn app(package: &str) -> Recipient {
    app_with_signers(package, vec![[7; 32]])
}

fn app_address(package: &str, signer: [u8; 32]) -> String {
    App::of(package, &[signer]).unwrap().address()
}

fn test_vault() -> Vault {
    Vault::create(
        "pw",
        &SecretKey::generate().unwrap(),
        None,
        KdfParams::minimum().unwrap(),
    )
    .unwrap()
}

#[test]
fn sites_match_exactly_or_under_a_wildcard() {
    assert!(site_matches("https://github.com/login", "github.com"));
    assert!(site_matches("github.com", "GitHub.com"));
    assert!(site_matches(
        "https://user@accounts.example.com:8443/",
        "accounts.example.com"
    ));
    assert!(!site_matches("https://github.com", "evilgithub.com"));
    assert!(!site_matches("https://github.com", "github.com.evil.net"));
    assert!(
        !site_matches("https://www.github.com", "github.com"),
        "exact host only"
    );
    assert!(site_matches("*.example.com", "example.com"));
    assert!(site_matches("https://*.example.com", "mail.example.com"));
    assert!(!site_matches("*.example.com", "badexample.com"));
    assert!(!site_matches("androidapp://com.example", "com.example"));
    assert_eq!(
        place_of(&site("www.Example.com")),
        (
            "example.com".to_owned(),
            "https://www.example.com".to_owned()
        )
    );
    assert_eq!(
        place_of(&app("com.example.app")),
        (
            "com.example.app".to_owned(),
            app_address("com.example.app", [7; 32])
        )
    );
}

#[test]
fn app_logins_require_a_verified_signing_lineage() {
    let package = "com.example.app";
    let (former, current, attacker) = ([7; 32], [8; 32], [9; 32]);
    let saved = app_address(package, former);
    let alternate = format!(
        "AndroidApp://{}/",
        saved[APP_ADDRESS.len()..].to_ascii_lowercase()
    );
    assert!(app_matches(&saved, package, &[former]));
    assert!(app_matches(&alternate, package, &[former]));
    assert!(app_matches(&saved, package, &[current, former]));
    assert!(!app_matches(&saved, package, &[]));
    assert!(!app_matches(&saved, package, &[attacker]));
    assert!(!app_matches(&saved, "com.example.other", &[former]));
    assert!(!app_matches(
        "androidapp://com.example.app",
        package,
        &[former]
    ));
    assert!(!app_matches(
        "androidapp://not-a-digest@com.example.app",
        package,
        &[former]
    ));
    assert!(!app_matches("https://com.example.app", package, &[former]));

    let mut vault = test_vault();
    vault
        .add_item(&ItemData::login("The app", "me", "test-pw", &saved))
        .unwrap();
    let rotated = app_with_signers(package, vec![current, former]);
    assert_eq!(logins_for(&vault, &rotated).len(), 1, "verified rotation");
    assert!(
        logins_for(&vault, &app_with_signers(package, vec![attacker])).is_empty(),
        "same package with another signer"
    );
    assert_eq!(place_of(&rotated).1, app_address(package, current));
    let original = logins_for(&vault, &rotated).pop().unwrap();
    let replacement = app_with_signers(package, vec![attacker]);
    assert!(login_by_id(&vault, &original.id, &replacement).is_none());
    assert_eq!(
        save_into(&mut vault, &replacement, "me", "other-pw").unwrap(),
        Kept::Added
    );
    assert_eq!(
        login_by_id(&vault, &original.id, &rotated)
            .unwrap()
            .password
            .as_str(),
        "test-pw"
    );
    assert_eq!(
        Recipient::of(&Asker {
            app: package.into(),
            ..Asker::default()
        }),
        None,
        "an app without one verified signer gets nothing"
    );
}

#[test]
fn a_legacy_app_facet_is_rebound_only_by_saving() {
    let package = "com.example.app";
    let signer = [7; 32];
    let from = app_with_signers(package, vec![signer]);
    let mut vault = test_vault();
    let id = vault
        .add_item(&ItemData::login(
            "Legacy",
            "me",
            "old-pw",
            "androidapp://com.example.app",
        ))
        .unwrap();

    assert!(
        logins_for(&vault, &from).is_empty(),
        "never offered for fill"
    );
    assert_eq!(
        save_into(&mut vault, &from, "me", "new-pw").unwrap(),
        Kept::Replaced
    );
    let rebound = vault.get_item(&id).unwrap();
    assert_eq!(rebound.urls, [app_address(package, signer)]);
    assert_eq!(rebound.password, "new-pw");
    assert_eq!(logins_for(&vault, &from).len(), 1);
    assert!(
        logins_for(&vault, &app_with_signers(package, vec![[9; 32]])).is_empty(),
        "the rebound facet remains signer-bound"
    );
}

#[test]
fn a_save_does_not_choose_between_ambiguous_legacy_logins() {
    let mut vault = test_vault();
    let from = app("com.example.app");
    for title in ["First", "Second"] {
        vault
            .add_item(&ItemData::login(
                title,
                "me",
                "old-pw",
                "androidapp://com.example.app",
            ))
            .unwrap();
    }
    assert_eq!(
        save_into(&mut vault, &from, "me", "new-pw").unwrap(),
        Kept::Added
    );
    assert_eq!(passwords(&vault), ["new-pw", "old-pw", "old-pw"]);
    assert_eq!(logins_for(&vault, &from).len(), 1);
}

#[test]
fn queued_app_saves_keep_legacy_and_rotated_accounts_guarded() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = test_vault();
    vault
        .set_item_guard(false, GuardCheck::Master, None, None)
        .unwrap();
    let package = "com.example.app";
    let legacy = "androidapp://com.example.app";
    for (user, url) in [
        ("legacy", legacy.to_owned()),
        ("rotated", app_address(package, [1; 32])),
    ] {
        let mut item = ItemData::login(user, user, "old-pw", &url);
        item.reprompt = true;
        vault.add_item(&item).unwrap();
    }
    std::fs::write(
        dir.path().join(prefs::FIRST_VAULT),
        vault.to_bytes().unwrap(),
    )
    .unwrap();
    assert!(dropped_logins(dir.path(), &vault).is_empty());
    // A queued record written before app facets carried a signer.
    let id = vault.id_hex();
    let mut file = read_drop(dir.path(), &id).unwrap();
    let old = br#"{"title":"Legacy","url":"androidapp://com.example.app","username":"legacy","password":"test-pw"}"#;
    file.entries
        .push(drop_box::seal_entry(&file.public_key, &id, old).unwrap());
    assert!(write_drop(dir.path(), &id, &file));

    let rotated = app_with_signers(package, vec![[2; 32], [1; 32]]);
    for user in ["legacy", "rotated", "new"] {
        assert!(keep_locked(dir.path(), &rotated, user, "test-pw"));
    }
    let items = dropped_logins(dir.path(), &vault);
    assert_eq!(
        items.iter().map(|item| item.reprompt).collect::<Vec<_>>(),
        [true, true, true, false]
    );
    assert_eq!(items[0].urls, [legacy]);
    for item in &items[1..] {
        assert_eq!(item.urls, [app_address(package, [2; 32])]);
    }
}

#[test]
fn a_wildcard_over_a_public_suffix_covers_nothing() {
    // Sites of different owners: a registry's suffix, or a hosting company's (private
    // multi-tenant suffixes are in the list too).
    for (saved, domain) in [
        ("*.co.uk", "shop.co.uk"),
        ("*.co.uk", "bank.co.uk"),
        ("*.com", "example.com"),
        ("*.com.br", "loja.com.br"),
        ("*.github.io", "someone.github.io"),
        ("https://*.github.io/", "someone.github.io"),
        ("*.blogspot.com", "someone.blogspot.com"),
        ("*.herokuapp.com", "someone.herokuapp.com"),
    ] {
        assert!(!site_matches(saved, domain), "{saved} {domain}");
    }
    // Not a plain name, or not https: refused as the extension refuses them.
    for saved in [
        "*.example.com/login",
        "*.example.com:8443",
        "user@*.example.com",
        "http://*.example.com",
        "*.*.example.com",
        "a.*.example.com",
        "*.",
        "*",
    ] {
        assert!(!site_matches(saved, "x.example.com"), "{saved}");
    }
    // A site of one's own under a public suffix still covers what is under it.
    assert!(site_matches("*.shop.co.uk", "www.shop.co.uk"));
    assert!(site_matches("*.shop.co.uk", "shop.co.uk"));
    assert!(!site_matches("*.shop.co.uk", "bank.co.uk"));
    assert!(site_matches("*.someone.github.io", "www.someone.github.io"));
    assert!(!site_matches("*.someone.github.io", "other.github.io"));
    // A backslash ends the host, as in a browser's address bar.
    assert!(!site_matches(
        "https://evil.example\\@github.com",
        "github.com"
    ));
    assert!(site_matches(
        "https://evil.example\\@github.com",
        "evil.example"
    ));
}

#[test]
fn a_rule_that_covers_nothing_is_told_apart() {
    // Skipped by autofill, so the item page says so.
    for saved in [
        "*.co.uk",
        "*.github.io",
        "https://*.github.io/",
        "*.com",
        "*.example.com/login",
        "*.example.com:8443",
        "http://*.example.com",
        "a.*.example.com",
        "*",
    ] {
        assert!(wildcard_unused(saved), "{saved}");
        assert!(!site_matches(saved, "www.example.com"), "{saved}");
    }
    // A rule over one owner's site, and plain addresses, are not.
    for saved in [
        "*.example.com",
        "https://*.example.com/",
        "*.shop.co.uk",
        "example.com",
        "https://github.com/login",
        "",
    ] {
        assert!(!wildcard_unused(saved), "{saved}");
    }
    assert!(site_matches("*.example.com", "www.example.com"));
}

#[test]
fn a_star_in_the_path_is_no_rule() {
    // The address's host is the site, as the extension reads it.
    let page = vault_browser::origin::Origin::of_saved("https://example.com/").unwrap();
    for saved in [
        "https://example.com/*",
        "https://example.com/login?next=*",
        "example.com/*",
    ] {
        assert!(site_matches(saved, "example.com"), "{saved}");
        assert!(!site_matches(saved, "www.example.com"), "{saved}");
        assert!(!wildcard_unused(saved), "{saved}");
        assert!(
            vault_browser::origin::item_matches(&[saved], &page),
            "the extension agrees: {saved}"
        );
    }
}

#[test]
fn stored_wide_rules_are_judged_again_before_logins_are_offered() {
    let mut vault = test_vault();
    // As an import or an older version could have saved them.
    for (title, url) in [
        ("Too wide", "*.co.uk"),
        ("Hosting", "*.github.io"),
        ("Own site", "*.shop.co.uk"),
    ] {
        vault
            .add_item(&ItemData::login(title, "me", "test-pw", url))
            .unwrap();
    }
    let titles = |domain: &str| -> Vec<String> {
        logins_for(&vault, &site(domain))
            .into_iter()
            .map(|login| login.title)
            .collect()
    };
    assert!(titles("bank.co.uk").is_empty(), "another owner's site");
    assert!(titles("someone.github.io").is_empty());
    assert_eq!(titles("www.shop.co.uk"), ["Own site"]);
    let wide = vault
        .item_ids()
        .find(|id| vault.get_item(id).unwrap().title == "Too wide")
        .unwrap()
        .to_hex();
    let bank = site("bank.co.uk");
    assert!(login_by_id(&vault, &wide, &bank).is_none());
    // Saving from that site makes a login of its own, not a change to the wide one.
    assert_eq!(
        save_into(&mut vault, &bank, "me", "new-pw").unwrap(),
        Kept::Added
    );
    let found = logins_for(&vault, &bank);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].title, "bank.co.uk");
    assert_eq!(
        vault
            .get_item(&ItemId::from_hex(&wide).unwrap())
            .unwrap()
            .password,
        "test-pw",
        "the wide login keeps its password"
    );
}

#[test]
fn logins_saved_while_locked_come_in_at_the_next_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = test_vault();
    std::fs::write(
        dir.path().join(prefs::FIRST_VAULT),
        vault.to_bytes().unwrap(),
    )
    .unwrap();
    let (example, other) = (site("example.com"), app("com.example.app"));
    assert!(
        !keep_locked(dir.path(), &example, "me", "pw1"),
        "no drop box before an unlock"
    );
    assert!(dropped_logins(dir.path(), &vault).is_empty());
    assert!(keep_locked(dir.path(), &example, "me", "pw1"));
    assert!(keep_locked(dir.path(), &other, "you", "pw2"));
    let items = dropped_logins(dir.path(), &vault);
    assert_eq!(items.len(), 2);
    for item in &items {
        vault.add_item(item).unwrap();
    }
    empty_drop_box(dir.path(), &vault.id_hex());
    assert!(dropped_logins(dir.path(), &vault).is_empty());
    let found = logins_for(&vault, &example);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].username.as_str(), found[0].password.as_str()),
        ("me", "pw1")
    );
    assert_eq!(logins_for(&vault, &other).len(), 1);
    assert!(logins_for(&vault, &app("com.example.app2")).is_empty());
    // Saving again: the same login gets the new password, another username a new login.
    let mut save =
        |username, password| save_into(&mut vault, &example, username, password).unwrap();
    assert_eq!(save("me", "pw3"), Kept::Replaced);
    assert_eq!(save("me", "pw3"), Kept::Same);
    assert_eq!(save("other", "pw4"), Kept::Added);
    let found = logins_for(&vault, &example);
    assert_eq!(found.len(), 2);
    let me = found.iter().find(|l| l.username == "me").unwrap();
    assert_eq!(me.password.as_str(), "pw3");
    assert!(login_by_id(&vault, &me.id, &example).is_some());
    assert!(
        login_by_id(&vault, &me.id, &site("evil.com")).is_none(),
        "only for its place"
    );
    assert!(suggest().is_some_and(|p| p.chars().count() >= 20));
}

#[test]
fn a_website_counts_only_from_a_known_browser() {
    assert_eq!(site("Example.com.").name(), "example.com");
    // The scheme may be left out by the web view; given, it is https.
    let quiet = Asker {
        scheme: None,
        ..in_chrome("example.com")
    };
    assert_eq!(Recipient::of(&quiet), Some(site("example.com")));
    // Its name with somebody else's certificate, none, or several signers (no list).
    for signers in [vec![], vec![[0; 32]], vec![certificate(FIREFOX)]] {
        let impostor = Asker {
            signers,
            ..in_chrome("example.com")
        };
        assert_eq!(Recipient::of(&impostor), None, "{impostor:?}");
    }
    // A certificate it was rotated from counts, whatever else is there.
    let rotated = Asker {
        signers: vec![certificate(CHROME), [9; 32]],
        ..in_chrome("example.com")
    };
    assert_eq!(Recipient::of(&rotated), Some(site("example.com")));
    // Chrome's certificate doesn't make another package Chrome.
    let other = Asker {
        app: "com.example.app".into(),
        browser: false,
        ..in_chrome("example.com")
    };
    assert_eq!(
        Recipient::of(&other),
        Some(app_with_signers(
            "com.example.app",
            vec![certificate(CHROME)]
        ))
    );
    // A browser this app doesn't know: neither the site nor "the browser".
    for domain in [Some("example.com".to_owned()), None] {
        let unknown = Asker {
            app: "com.example.browser".into(),
            signers: vec![[1; 32]],
            browser: true,
            domain,
            scheme: None,
        };
        assert_eq!(Recipient::of(&unknown), None, "{unknown:?}");
    }
    // A known one's own fields, outside any page: no login belongs to the browser.
    let own = Asker {
        domain: None,
        scheme: None,
        ..in_chrome("example.com")
    };
    assert_eq!(Recipient::of(&own), None);
    assert_eq!(Recipient::of(&Asker::default()), None, "nobody asks");
}

#[test]
fn a_page_without_https_gets_nothing() {
    for scheme in ["http", "HTTP", "ftp", "file", ""] {
        let page = Asker {
            scheme: Some(scheme.into()),
            ..in_chrome("example.com")
        };
        assert_eq!(Recipient::of(&page), None, "{scheme}");
        // Nor does the app that shows it.
        let web_view = Asker {
            app: "com.example.app".into(),
            browser: false,
            ..page
        };
        assert_eq!(Recipient::of(&web_view), None, "{scheme}");
    }
    // A page whose address can't be read, or isn't a plain host.
    for domain in [
        "",
        ".",
        " ",
        "evil.com/@bank.com",
        "bank.com@evil.com",
        "evil.com:8443",
        "evil.com#bank.com",
        "evil.com\\bank.com",
        "*.example.com",
        "[::1]",
        "two words",
    ] {
        assert_eq!(Recipient::of(&in_chrome(domain)), None, "{domain:?}");
    }
    assert_eq!(site("192.0.2.1").name(), "192.0.2.1");
}

#[test]
fn a_domain_nobody_vouches_for_matches_no_website() {
    let mut vault = test_vault();
    let signer = [1; 32];
    for (title, url) in [
        ("Bank", "https://bank.example".to_owned()),
        ("Bank's app", app_address("com.example.bank", signer)),
        ("The app", app_address("com.example.app", signer)),
        ("In Chrome", app_address("com.android.chrome", signer)),
    ] {
        vault
            .add_item(&ItemData::login(title, "me", "test-pw", &url))
            .unwrap();
    }
    let titles = |asker: &Asker| -> Vec<String> {
        Recipient::of(asker)
            .map(|to| logins_for(&vault, &to))
            .unwrap_or_default()
            .into_iter()
            .map(|login| login.title)
            .collect()
    };
    assert_eq!(titles(&in_chrome("bank.example")), ["Bank"]);
    // An app whose view tree says "bank.example" gets its own logins only.
    let claims = Asker {
        app: "com.example.app".into(),
        signers: vec![[1; 32]],
        browser: false,
        ..in_chrome("bank.example")
    };
    assert_eq!(titles(&claims), ["The app"]);
    // One that calls itself Chrome gets nothing, its "own" logins included.
    let impostor = Asker {
        signers: vec![[1; 32]],
        ..in_chrome("bank.example")
    };
    assert!(titles(&impostor).is_empty());
    // Saving follows the same rule: what the app claims isn't the saved address.
    let to = Recipient::of(&claims).unwrap();
    assert_eq!(
        place_of(&to).1,
        app_address("com.example.app", signer),
        "not https://bank.example"
    );
}

#[test]
fn every_known_browser_has_a_whole_certificate() {
    for (package, certificates) in BROWSERS {
        assert!(!certificates.is_empty(), "{package}");
        for hex in certificates {
            assert_eq!(hex.len(), 64, "{package}");
            assert_eq!(hex.to_uppercase(), *hex, "{package}");
            let page = Asker {
                app: package.into(),
                signers: vec![certificate(hex)],
                ..in_chrome("example.com")
            };
            assert_eq!(Recipient::of(&page), Some(site("example.com")), "{package}");
        }
    }
    // The package manager tells this app about browsers only if the manifest asks to see
    // what opens https links (Android 11 on).
    let manifest = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../mobile-android/AndroidManifest.xml"),
    )
    .unwrap();
    let queries = manifest
        .split("<queries>")
        .nth(1)
        .and_then(|rest| rest.split("</queries>").next())
        .expect("the manifest's <queries>");
    assert!(queries.contains("android.intent.action.VIEW"));
    assert!(queries.contains("android:scheme=\"https\""));
}

/// A login for example.com, behind the lock `check` (its own, or all items').
fn guarded(check: GuardCheck, all_items: bool, secret: Option<&str>) -> (Vault, ItemId) {
    let mut vault = test_vault();
    vault
        .set_item_guard(all_items, check, secret, None)
        .unwrap();
    let mut item = ItemData::login("Guarded", "me", "guarded-pw", "https://example.com");
    item.reprompt = !all_items;
    let id = vault.add_item(&item).unwrap();
    (vault, id)
}

fn passwords(vault: &Vault) -> Vec<String> {
    let mut found: Vec<String> = vault
        .item_ids()
        .map(|id| vault.get_item(&id).unwrap().password.clone())
        .collect();
    found.sort();
    found
}

#[test]
fn a_login_waiting_for_the_master_password_is_not_changed_from_another_app() {
    let example = site("example.com");
    for all_items in [false, true] {
        let (mut vault, id) = guarded(GuardCheck::Master, all_items, None);
        // Its secrets are readable here (this check encrypts nothing): the rule holds.
        assert!(!vault.get_item(&id).unwrap().is_locked());
        assert!(logins_for(&vault, &example).is_empty(), "not offered");
        assert_eq!(
            save_into(&mut vault, &example, "me", "new-pw").unwrap(),
            Kept::AddedBeside
        );
        let item = vault.get_item(&id).unwrap();
        assert_eq!(item.password, "guarded-pw", "all items: {all_items}");
        assert!(item.password_history.is_empty());
        assert_eq!(passwords(&vault), ["guarded-pw", "new-pw"]);
        // The new one is behind the lock as well, not a way around it.
        assert!(logins_for(&vault, &example).is_empty());
        // Nor is the same password told apart from another one.
        assert_eq!(
            save_into(&mut vault, &example, "me", "guarded-pw").unwrap(),
            Kept::AddedBeside
        );
    }
}

#[test]
fn a_login_behind_a_pin_is_not_changed_from_another_app() {
    let example = site("example.com");
    for all_items in [false, true] {
        let (mut vault, id) = guarded(GuardCheck::Pin, all_items, Some("4821"));
        vault.lock_secrets();
        assert!(vault.get_item(&id).unwrap().is_locked(), "sealed");
        assert_eq!(
            save_into(&mut vault, &example, "me", "new-pw").unwrap(),
            Kept::AddedBeside
        );
        // Opened for another item just now: still the app's to change.
        assert!(vault.unlock_secrets("4821").unwrap());
        assert_eq!(
            save_into(&mut vault, &example, "me", "newer-pw").unwrap(),
            Kept::AddedBeside
        );
        assert!(logins_for(&vault, &example).is_empty(), "not offered");
        vault.seal_pending().unwrap();
        assert_eq!(passwords(&vault), ["guarded-pw", "new-pw", "newer-pw"]);
        assert_eq!(vault.get_item(&id).unwrap().password, "guarded-pw");
    }
}

#[test]
fn a_new_login_waiting_for_its_seal_is_not_changed_from_another_app() {
    let example = site("example.com");
    let mut vault = test_vault();
    vault
        .set_item_guard(true, GuardCheck::Pin, Some("4821"), None)
        .unwrap();
    vault.lock_secrets();
    // Added while the lock was closed: under the vault key alone until its next opening.
    let id = vault
        .add_item(&ItemData::login(
            "Waiting",
            "me",
            "waiting-pw",
            "https://example.com",
        ))
        .unwrap();
    assert_eq!(vault.pending_seal().unwrap(), 1);
    assert!(!vault.get_item(&id).unwrap().is_locked(), "readable here");
    assert_eq!(
        save_into(&mut vault, &example, "me", "new-pw").unwrap(),
        Kept::AddedBeside
    );
    assert_eq!(vault.get_item(&id).unwrap().password, "waiting-pw");
    assert_eq!(vault.pending_seal().unwrap(), 2, "the new one waits too");
}

#[test]
fn a_login_without_the_lock_gets_its_new_password() {
    let example = site("example.com");
    // Another login is behind the lock: this one isn't.
    let (mut vault, _) = guarded(GuardCheck::Pin, false, Some("4821"));
    vault.lock_secrets();
    let id = vault
        .add_item(&ItemData::login(
            "Open",
            "you",
            "old-pw",
            "https://example.com",
        ))
        .unwrap();
    assert_eq!(
        save_into(&mut vault, &example, "you", "new-pw").unwrap(),
        Kept::Replaced
    );
    let item = vault.get_item(&id).unwrap();
    assert_eq!(item.password, "new-pw");
    assert_eq!(item.password_history[0].password, "old-pw");
    // Next to a locked one of the same username, the open one is the one that changes.
    let id = vault
        .add_item(&ItemData::login(
            "Mine too",
            "me",
            "old-pw",
            "https://example.com",
        ))
        .unwrap();
    assert_eq!(
        save_into(&mut vault, &example, "me", "new-pw").unwrap(),
        Kept::Replaced
    );
    assert_eq!(vault.get_item(&id).unwrap().password, "new-pw");
}

#[test]
fn a_login_saved_while_locked_joins_its_account_behind_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, id) = guarded(GuardCheck::Master, false, None);
    std::fs::write(
        dir.path().join(prefs::FIRST_VAULT),
        vault.to_bytes().unwrap(),
    )
    .unwrap();
    assert!(dropped_logins(dir.path(), &vault).is_empty(), "made now");
    let example = site("example.com");
    assert!(keep_locked(dir.path(), &example, "me", "new-pw"));
    assert!(keep_locked(dir.path(), &example, "you", "other-pw"));
    let items = dropped_logins(dir.path(), &vault);
    let locked: Vec<(&str, bool)> = items
        .iter()
        .map(|item| (item.username.as_str(), item.reprompt))
        .collect();
    assert_eq!(locked, [("me", true), ("you", false)]);
    for item in &items {
        vault.add_item(item).unwrap();
    }
    assert_eq!(vault.get_item(&id).unwrap().password, "guarded-pw");
    let offered = logins_for(&vault, &example);
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].username, "you");
}
