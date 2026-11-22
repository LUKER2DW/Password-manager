//! The phone app in a browser page, for trying it on a computer: the same screens and
//! controller as on a phone (`vault-mobile`), drawn on a canvas, with a demo vault made in the
//! page when it loads. Nothing leaves the page and nothing is kept: closing it forgets all.
//!
//! Build: `apps/mobile-web/build.ps1` (wasm32 target + wasm-bindgen), then open
//! `target/mobile-web/index.html` through any local web server.

#![cfg(target_arch = "wasm32")]

use std::path::PathBuf;

use slint::ComponentHandle;
use vault_core::{ItemData, ItemKind, KdfParams, SecretKey, Vault};
use vault_mobile::{
    Controller,
    platform::{clipboard, files, secret_store},
    ui::PhoneWindow,
};
use wasm_bindgen::prelude::*;

/// The demo vault's master password, shown on the page beside the phone.
pub const DEMO_PASSWORD: &str = "demo phone vault";

/// Where the phone keeps its copy (in this page's memory).
fn vault_path() -> PathBuf {
    PathBuf::from("/phone/vault.vault")
}

/// A demo vault: a few logins (two with one-time codes), a favourite, a secure note. Fake
/// data only. The Secret Key is "remembered on this device", so only the master password is
/// asked, as on a phone that was set up before.
fn demo_vault() -> vault_core::Result<()> {
    let secret_key = SecretKey::generate()?;
    let mut vault = Vault::create(DEMO_PASSWORD, &secret_key, None, KdfParams::minimum()?)?;
    let logins = [
        (
            "Email",
            "demo@example.com",
            "correct-horse-battery-staple",
            "https://mail.example.com",
            "JBSWY3DPEHPK3PXP",
            true,
        ),
        (
            "Bank",
            "demo-customer",
            "G7#pQ2!vX9@mL4zR",
            "https://bank.example.com",
            "",
            true,
        ),
        (
            "Shop",
            "demo-shopper",
            "tulip-anchor-velvet-42",
            "https://shop.example.com",
            "",
            false,
        ),
        (
            "Code host",
            "demo-dev",
            "x8Vb-Qm2r-Lk7p-Ws4n",
            "https://code.example.com",
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            false,
        ),
        (
            "Streaming",
            "demo@example.com",
            "123456",
            "https://video.example.com",
            "",
            false,
        ),
        (
            "Games",
            "demo_player",
            "sunset-river-maple",
            "https://games.example.com",
            "",
            false,
        ),
    ];
    for (title, user, password, url, totp, favorite) in logins {
        let mut item = ItemData::login(title, user, password, url);
        item.totp = totp.to_owned();
        item.favorite = favorite;
        vault.add_item(&item)?;
    }
    let mut note = ItemData::new(ItemKind::SecureNote, "Wi-Fi at home");
    note.notes = "Network: demo-network\nPassword: plum-orbit-candle".to_owned();
    vault.add_item(&note)?;
    let bytes = vault.to_bytes()?;
    files::write_atomic(&vault_path(), &bytes)?;
    let id = Vault::inspect(&bytes)?.id_hex;
    let _ = secret_store::store(&id, &secret_key);
    Ok(())
}

#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    let fail = |e: &dyn std::fmt::Display| JsValue::from_str(&e.to_string());
    demo_vault().map_err(|e| fail(&e))?;
    let app = PhoneWindow::new().map_err(|e| fail(&e))?;
    // Inline: a browser page has no threads; slow work (unlock) runs in place.
    let controller = Controller::start(&app, vault_path(), true);
    // The page lives as long as the app: keep the controller for good.
    std::mem::forget(controller);
    app.run().map_err(|e| fail(&e))
}

/// The demo master password, for the page to show.
#[wasm_bindgen]
pub fn demo_password() -> String {
    DEMO_PASSWORD.to_owned()
}

/// Puts text on the app's clipboard (the page's own: the app can't read the computer's), so
/// Ctrl+V in a field of the app pastes it.
#[wasm_bindgen]
pub fn put_on_clipboard(text: &str) {
    let _ = clipboard::copy_plain(text);
}
