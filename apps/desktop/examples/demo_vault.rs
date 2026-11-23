//! Creates a demo vault full of sample data, for trying the app by hand.
//!
//! ```text
//! VAULT_HOME=<folder>/home cargo run -p vault-desktop --example demo_vault -- <folder> <master password>
//! ```
//!
//! Everything goes into `<folder>`: the vault file (`demo.vault`) and an app folder (`home`,
//! which must be passed as `VAULT_HOME`) with its own settings, so real settings and vaults are
//! untouched. The Secret
//! Key is saved in the OS credential store under the new vault's id, so unlocking asks only for
//! the master password. Start the app with:
//!
//! ```text
//! VAULT_HOME=<folder>/home VAULT_FILE=<folder>/demo.vault cargo run -p vault-desktop
//! ```
//!
//! All data is made up. Never use a demo vault for real passwords.

use std::path::PathBuf;

use vault_core::{
    CustomField, ItemData, ItemKind, KdfParams, PartLabel, RecoveryCode, RecoveryParts, SecretKey,
    Vault, VaultSettings, card::CardDetails, storage,
};
use vault_platform::{DeviceState, secret_store};

const DAY: i64 = 86_400;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().unwrap_or_else(|| "target/demo".into()));
    let password = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: demo_vault <folder> <master password>"))?;
    std::fs::create_dir_all(dir.join("home"))?;
    // Device state (settings, recent vaults) must land in the demo's own app folder.
    let home = std::env::var_os("VAULT_HOME").map(PathBuf::from);
    if home.as_deref() != Some(dir.join("home").as_path()) {
        anyhow::bail!(
            "set VAULT_HOME={} so the demo keeps its own settings",
            dir.join("home").display()
        );
    }

    let secret_key = SecretKey::generate()?;
    let parts = RecoveryParts::generate()?;
    let mut vault = Vault::create(&password, &secret_key, None, KdfParams::recommended()?)?;
    vault.set_recovery_parts(&parts, &secret_key)?;
    vault.set_settings(VaultSettings {
        name: "Demo vault".into(),
        history_limit: 10,
    })?;

    // Folders with their own look.
    let google = vault.add_folder("Google")?;
    vault.style_folder(&google, "globe", 1)?;
    let money = vault.add_folder("Money")?;
    vault.style_folder(&money, "card", 3)?;
    let games = vault.add_folder("Games")?;
    vault.style_folder(&games, "sparkle", 2)?;
    let work = vault.add_folder("Work")?;
    vault.style_folder(&work, "gear", 6)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let login = |title: &str, user: &str, pass: &str, url: &str| {
        let mut item = ItemData::login(title, user, pass, url);
        item.created_at = now - 40 * DAY;
        item.updated_at = item.created_at;
        item.password_changed_at = item.created_at;
        item
    };

    // Strong, with a one-time code, recovery codes and a history entry.
    let mut github = login(
        "GitHub",
        "octo-demo",
        "Gh-demo-7Kq!vR2#pL9w",
        "https://github.com/login",
    );
    github.totp = "JBSWY3DPEHPK3PXP".into();
    github.favorite = true;
    github.folder = Some(work);
    github.recovery_codes =
        RecoveryCode::parse_list("7f3a2-9c1d4\nb84e0-26fa1\n0d9c7-e5b32\n5a61f-c0e98");
    github.recovery_codes[0].used = true;
    github.notes = "Recovery codes are also printed in the safe.".into();
    let github_id = vault.add_item(&github)?;
    let mut changed = vault.get_item(&github_id)?;
    changed.password = "Gh-new-9!xQ2#rTz8wLm".into();
    vault.update_item(&github_id, &changed)?;

    let mut gmail = login(
        "Gmail",
        "demo.person@gmail.example",
        "correct-horse-battery-staple-42",
        "https://mail.google.com",
    );
    gmail.folder = Some(google);
    gmail.favorite = true;
    gmail.totp = "otpauth://totp/Google:demo?secret=KRSXG5CTMVRXEZLU&issuer=Google".into();
    vault.add_item(&gmail)?;

    let mut youtube = login(
        "YouTube",
        "demo.person@gmail.example",
        "Yt-demo-Q8w#Lm3!zP",
        "https://www.youtube.com",
    );
    youtube.folder = Some(google);
    vault.add_item(&youtube)?;

    let mut netflix = login(
        "Netflix",
        "me@example.com",
        "Shared-pass-2019!",
        "https://www.netflix.com",
    );
    netflix.favorite = true;
    vault.add_item(&netflix)?;

    // Reused password (same as Netflix).
    let spotify = login(
        "Spotify",
        "me@example.com",
        "Shared-pass-2019!",
        "https://open.spotify.com",
    );
    vault.add_item(&spotify)?;

    // Weak and old.
    let mut forum = login("Old forum", "demo_user", "123456", "https://forum.example");
    forum.created_at = now - 900 * DAY;
    forum.password_changed_at = forum.created_at;
    vault.add_item(&forum)?;

    let mut steam = login(
        "Steam",
        "demo_gamer",
        "summer2024",
        "https://store.steampowered.com",
    );
    steam.folder = Some(games);
    vault.add_item(&steam)?;

    let mut epic = login(
        "Epic Games",
        "demo_gamer",
        "Ep1c-demo-W9!kz#Q",
        "https://store.epicgames.com",
    );
    epic.folder = Some(games);
    vault.add_item(&epic)?;

    let mut discord = login(
        "Discord",
        "demo#0001",
        "Dc-demo-H7&pX2!vN",
        "https://discord.com",
    );
    discord.folder = Some(games);
    discord.totp = "GEZDGNBVGY3TQOJQ".into();
    vault.add_item(&discord)?;

    let mut bank = login(
        "Nubank",
        "123.456.789-00",
        "Nb-demo-4r#T9!q",
        "https://nubank.com.br",
    );
    bank.folder = Some(money);
    bank.custom_fields.push(CustomField {
        name: "Account".into(),
        value: "0001 / 1234567-8".into(),
        sensitive: false,
    });
    bank.custom_fields.push(CustomField {
        name: "App PIN".into(),
        value: "2580".into(),
        sensitive: true,
    });
    vault.add_item(&bank)?;

    let mut paypal = login(
        "PayPal",
        "me@example.com",
        "Pp-demo-8Kz!w2#R",
        "https://www.paypal.com",
    );
    paypal.folder = Some(money);
    vault.add_item(&paypal)?;

    let amazon = login(
        "Amazon",
        "me@example.com",
        "Am-demo-3x!Q7#vL",
        "https://www.amazon.com",
    );
    vault.add_item(&amazon)?;

    let mut slack = login(
        "Slack",
        "demo@company.example",
        "Sl-demo-6P#n2!kW",
        "https://slack.com",
    );
    slack.folder = Some(work);
    vault.add_item(&slack)?;

    // Cards (test numbers from the networks' documentation).
    for (title, holder, number, expiry, code, pin) in [
        (
            "Travel card",
            "DEMO PERSON",
            "4242 4242 4242 4242",
            "12/29",
            "123",
            "4321",
        ),
        (
            "Everyday card",
            "DEMO PERSON",
            "5555 5555 5555 4444",
            "08/27",
            "456",
            "1234",
        ),
        (
            "Old card",
            "DEMO PERSON",
            "3782 822463 10005",
            "01/24",
            "7890",
            "9999",
        ),
    ] {
        let mut card = ItemData::new(ItemKind::Card, title);
        card.username = holder.into();
        card.password = pin.into();
        card.folder = Some(money);
        CardDetails {
            number: number.into(),
            expiry: expiry.into(),
            security_code: code.into(),
        }
        .apply(&mut card);
        vault.add_item(&card)?;
    }
    // A card whose icon comes from the bank's website.
    let mut nucard = ItemData::new(ItemKind::Card, "Nubank card");
    nucard.username = "DEMO PERSON".into();
    nucard.password = "5678".into();
    nucard.folder = Some(money);
    nucard.icon_url = "https://nubank.com.br".into();
    CardDetails {
        number: "5162 9300 0000 0008".into(),
        expiry: "11/30".into(),
        security_code: "321".into(),
    }
    .apply(&mut nucard);
    vault.add_item(&nucard)?;

    // Secure notes.
    let mut wifi = ItemData::new(ItemKind::SecureNote, "Home Wi-Fi");
    wifi.notes = "Network: DemoNet\nPassword: blue-river-lamp-77".into();
    vault.add_item(&wifi)?;
    let mut server = ItemData::new(ItemKind::SecureNote, "Server notes");
    server.notes = "ssh demo@server.example -p 2222\nBackups run at 03:00.".into();
    server.folder = Some(work);
    server.custom_fields.push(CustomField {
        name: "Root password".into(),
        value: "Srv-demo-9!Lq#2x".into(),
        sensitive: true,
    });
    vault.add_item(&server)?;

    // Save, remember the Secret Key on this computer, and make the demo app folder show icons.
    let path = dir.join("demo.vault");
    let bytes = vault.to_bytes()?;
    storage::write_atomic(&path, &bytes)?;
    secret_store::store(&vault.id_hex(), &secret_key)?;
    let mut state = DeviceState::load().unwrap_or_default();
    state.settings.website_icons = true;
    state.remember_vault(&path);
    state.record_revision(&vault.id_hex(), vault.revision());
    state.save()?;

    println!("vault: {}", path.display());
    println!("home: {}", dir.join("home").display());
    println!("secret key: {}", secret_key.to_display_string().as_str());
    for label in PartLabel::ALL {
        println!(
            "recovery part {}: {}",
            label.letter(),
            parts.part(label).to_display_string().as_str()
        );
    }
    Ok(())
}
