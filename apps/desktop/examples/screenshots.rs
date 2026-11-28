//! Off-screen design review: renders every screen of the real app with Slint's software renderer
//! into PNG files plus an `index.html` gallery. Nothing is shown on screen.
//!
//! ```text
//! cargo run -p vault-desktop --example screenshots -- [output-dir] [scale]
//! ```
//!
//! Set `SHOT_ICONS=1` to also turn on website icons, which fetches real favicons for the demo
//! sites over the network.
//!
//! Uses a throwaway vault with fake data in a temporary folder. The vault's Secret Key is put in
//! the OS credential store during the run and removed at the end.

use std::{
    cell::Cell,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use vault_platform::quick_unlock::{DeviceVerifier, QuickUnlockError};
use zeroize::Zeroizing;

use slint::{
    ComponentHandle, PhysicalSize, PlatformError, Rgb8Pixel,
    platform::{
        Platform, WindowAdapter,
        software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
    },
};
use vault_desktop::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, ExtensionBrowser, ItemLock, NewPassword, PasskeyRow, Secrets, Theme},
};

const WIDTH: u32 = 1180;
const HEIGHT: u32 = 760;
const PASSWORD: &str = "screenshot demo passphrase";

thread_local! {
    static CLOCK: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

struct OffscreenPlatform {
    window: Rc<MinimalSoftwareWindow>,
}

impl Platform for OffscreenPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(self.window.clone())
    }

    fn duration_since_start(&self) -> Duration {
        CLOCK.with(Cell::get)
    }
}

/// Lets time pass so animations (the marker sweep) and timers settle.
fn advance(millis: u64) {
    for _ in 0..(millis / 20).max(1) {
        CLOCK.with(|clock| clock.set(clock.get() + Duration::from_millis(20)));
        slint::platform::update_timers_and_animations();
    }
}

struct Camera {
    window: Rc<MinimalSoftwareWindow>,
    dir: PathBuf,
    shots: Vec<(String, String)>,
}

impl Camera {
    fn shot(&mut self, name: &str, caption: &str) {
        advance(400);
        self.window.request_redraw();
        let size = self.window.size();
        let (width, height) = (size.width as usize, size.height as usize);
        let mut buffer = vec![Rgb8Pixel::default(); width * height];
        self.window.draw_if_needed(|renderer| {
            renderer.render(&mut buffer, width);
        });
        let image = image::RgbImage::from_fn(size.width, size.height, |x, y| {
            let pixel = buffer[y as usize * width + x as usize];
            image::Rgb([pixel.r, pixel.g, pixel.b])
        });
        let file = format!("{:02}-{name}.png", self.shots.len() + 1);
        image.save(self.dir.join(&file)).expect("write PNG");
        println!("  {file}");
        self.shots.push((file, caption.to_owned()));
    }

    fn write_gallery(&self) {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>Vault screens</title><style>\
             body{margin:0;padding:24px 16px;background:#d9dee4;font:15px/1.5 Bahnschrift,'Segoe UI',sans-serif;color:#1f2a3d}\
             main{max-width:1240px;margin:0 auto}h1{font-weight:300;font-size:30px;margin:0 0 4px}\
             p.lead{color:#677385;margin:0 0 28px}figure{margin:0 0 40px}\
             img{width:100%;height:auto;display:block;border:1px solid #b9c2cc;background:#fff}\
             figcaption{padding:8px 2px;color:#40506a}</style></head><body><main>\
             <h1>Vault — screen review</h1>\
             <p class=\"lead\">Rendered off-screen with Slint's software renderer. Fake data only.</p>",
        );
        for (file, caption) in &self.shots {
            html.push_str(&format!(
                "<figure><img src=\"{file}\" alt=\"{caption}\" loading=\"lazy\"><figcaption>{file} — {caption}</figcaption></figure>"
            ));
        }
        html.push_str("</main></body></html>");
        std::fs::write(self.dir.join("index.html"), html).expect("write gallery");
    }
}

/// A left click at a point of the window, in logical pixels.
fn click(app: &AppWindow, x: f32, y: f32) {
    use slint::platform::{PointerEventButton, WindowEvent};
    let position = slint::LogicalPosition::new(x, y);
    let window = app.window();
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed {
        position,
        button: PointerEventButton::Left,
    });
    window.dispatch_event(WindowEvent::PointerReleased {
        position,
        button: PointerEventButton::Left,
    });
    advance(100);
}

/// Stands in for Windows Hello so the screens can show quick unlock without a prompt.
#[derive(Debug)]
struct DemoHello;

impl DeviceVerifier for DemoHello {
    fn name(&self) -> &'static str {
        "Demo Hello"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn enroll(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        self.secret(vault_id)
    }
    fn secret(&self, _vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        Ok(Zeroizing::new(vec![9; 256]))
    }
    fn remove(&self, _vault_id: &str) {}
}

fn type_into(app: &AppWindow, field: i32, text: &str) {
    let secrets = app.global::<Secrets>();
    secrets.invoke_clear(field);
    for c in text.chars() {
        secrets.invoke_insert(field, c.to_string().into());
    }
}

#[allow(clippy::too_many_arguments)]
fn add_item(
    app: &AppWindow,
    kind: i32,
    title: &str,
    username: &str,
    url: &str,
    password: &str,
    totp: &str,
    notes: &str,
    favorite: bool,
    folder: i32,
) {
    app.invoke_new_item();
    app.set_ed_folder(folder);
    app.set_ed_kind(kind);
    app.set_ed_title(title.into());
    app.set_ed_username(username.into());
    app.set_ed_url(url.into());
    app.set_ed_totp(totp.into());
    app.set_ed_notes(notes.into());
    app.set_ed_favorite(favorite);
    type_into(app, 4, password);
    app.invoke_save_item();
}

fn select_title(app: &AppWindow, title: &str) {
    use slint::Model;
    let items = app.get_items();
    if let Some(index) =
        (0..items.row_count()).find(|&i| items.row_data(i).is_some_and(|row| row.title == title))
    {
        app.invoke_select(index as i32);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .map_or_else(|| PathBuf::from("target/screenshots"), PathBuf::from);
    let scale: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1.0);
    std::fs::create_dir_all(&dir).expect("create output dir");
    for entry in std::fs::read_dir(&dir).expect("list output dir").flatten() {
        if entry.path().extension().is_some_and(|e| e == "png") {
            let _ = std::fs::remove_file(entry.path());
        }
    }

    let temp = tempfile::tempdir().expect("temp dir");
    // SAFETY: set at startup, before any other thread exists.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", temp.path().join("home"));
    }
    // The demo's Secret Key goes under a stand-in for the TPM: no key is made in the chip.
    vault_platform::secret_store::use_key_wrapper(Some(std::sync::Arc::new(
        vault_platform::secret_store::MemoryChip::default(),
    )));

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(OffscreenPlatform {
        window: window.clone(),
    }))
    .expect("set platform");

    let app = AppWindow::new().expect("create window");
    apply_sketches(&app);
    app.window()
        .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
            scale_factor: scale,
        });
    window.set_size(PhysicalSize::new(
        (WIDTH as f32 * scale) as u32,
        (HEIGHT as f32 * scale) as u32,
    ));
    app.show().expect("show");
    let controller = Controller::install(
        &app,
        temp.path().join("demo.vault"),
        Runner::Inline,
        Some(Arc::new(DemoHello)),
    )
    .expect("controller");
    let mut camera = Camera {
        window: window.clone(),
        dir: dir.clone(),
        shots: Vec::new(),
    };
    println!("Rendering to {}", dir.display());

    // ---- onboarding ----
    camera.shot("onboarding", "First run: choose a master password");
    type_into(&app, 0, "password1234");
    type_into(&app, 1, "password1234");
    app.invoke_create_vault();
    camera.shot(
        "onboarding-easy",
        "An easy master password: why it matters, six random words offered, keeping it allowed",
    );
    app.global::<NewPassword>().set_check_leaks(true);
    app.global::<NewPassword>().set_warning(2);
    app.global::<NewPassword>().set_arg("3".into());
    camera.shot(
        "onboarding-leaked",
        "The breach check ticked: a master password found in data breaches",
    );
    app.global::<NewPassword>().set_check_leaks(false);
    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, "different");
    app.invoke_suggest_passphrase();
    app.invoke_create_vault();
    camera.shot(
        "onboarding-error",
        "Mismatch error, with a suggested passphrase",
    );
    app.set_onboarding_options(true);
    camera.shot(
        "onboarding-suggestion-options",
        "The suggestion's options: the generator's, as for a new login (never below the floor)",
    );
    app.set_onboarding_options(false);
    type_into(&app, 1, PASSWORD);
    app.invoke_create_vault();
    camera.shot("item-lock-step", "Step 2: the item lock, PIN suggested");
    // The demo vault keeps no item lock, so the later shots show every secret.
    app.set_onboarding_guard(3);
    app.invoke_create_vault();
    let vault_id = app.get_vault_id().to_string();
    camera.shot("emergency-kit", "Step 3: the emergency kit");
    app.set_kit_saved(true);
    camera.shot(
        "emergency-kit-confirmed",
        "Kit confirmed; the vault can open",
    );
    app.set_onboarding_step(4);
    camera.shot("import-step", "Step 4: bring your passwords, or skip");
    app.invoke_finish_onboarding();
    camera.shot("vault-empty", "Empty vault");
    app.set_notice_code(124);
    app.set_notice_count(3);
    app.set_notice_arg("2026-11-26 14:02".into());
    camera.shot(
        "vault-failed-unlocks",
        "Opened after failed tries: how many, and since when, said once",
    );
    app.set_notice_code(0);
    for name in ["Email", "Games"] {
        app.invoke_new_folder();
        app.set_fd_name(name.into());
        app.invoke_folder_dialog_save();
    }
    app.invoke_select_category(0);

    // ---- fake data ----
    add_item(
        &app,
        0,
        "GitHub",
        "octocat",
        "https://github.com/login",
        "Gh-demo-7Kq!vR2#pL9w",
        "JBSWY3DPEHPK3PXP",
        "Recovery codes are in the safe.",
        true,
        0,
    );
    add_item(
        &app,
        0,
        "Proton Mail",
        "me@proton.example",
        "https://account.proton.me",
        "demo-Hb3^tW6&nJ0s",
        "",
        "",
        true,
        1,
    );
    add_item(
        &app,
        0,
        "Bank",
        "000123-4",
        "https://bank.example",
        "demo-Rf5*yU9!cK2d",
        "",
        "",
        false,
        0,
    );
    add_item(
        &app,
        0,
        "Steam",
        "demo_gamer",
        "https://store.steampowered.com",
        "demo-Vt8%gB1#xS4h",
        "",
        "",
        false,
        2,
    );
    add_item(
        &app,
        0,
        "Netflix",
        "me@example.com",
        "https://www.netflix.com",
        "demo-Zc6&jH3^aT8k",
        "",
        "",
        false,
        0,
    );
    // A card (test number from the card networks' documentation).
    app.invoke_new_item();
    app.set_ed_folder(0);
    app.set_ed_kind(1);
    app.set_ed_title("Travel card".into());
    app.set_ed_username("A. Person".into());
    app.set_ed_card_number("4242 4242 4242 4242".into());
    app.invoke_card_number_edited("4242 4242 4242 4242".into());
    app.set_ed_card_expiry("12/29".into());
    app.set_ed_card_code("123".into());
    type_into(&app, 4, "4321");
    camera.shot(
        "editor-card",
        "Card editor: checked number, expiry, code; PIN is never generated",
    );
    app.invoke_save_item();
    camera.shot("vault-card", "A card: masked number with its brand");
    app.invoke_reveal_field(0);
    camera.shot("vault-card-shown", "A card's number shown on request");
    app.invoke_conceal();
    add_item(
        &app,
        2,
        "Home Wi-Fi",
        "",
        "",
        "",
        "",
        "Network DEMO-5G\nPassword on the router label.",
        false,
        0,
    );

    select_title(&app, "GitHub");
    camera.shot(
        "vault-initials",
        "Website icons off (default): initials and type glyphs",
    );
    if std::env::var_os("SHOT_ICONS").is_some() {
        // Real network fetches from each demo site, like the app does when the user opts in.
        app.invoke_open_settings(); // loads the other settings into the form first
        app.set_website_icons(true);
        app.invoke_settings_changed();
        app.invoke_select_category(0);
        select_title(&app, "GitHub");
    }
    camera.shot(
        "vault-detail",
        "Item page: username, hidden password, live one-time code",
    );
    app.invoke_reveal();
    camera.shot("vault-revealed", "Password shown for 15 seconds");
    app.invoke_conceal();
    app.set_notes_shown(true);
    app.invoke_copy_username();
    camera.shot("vault-notes-notice", "Notes shown, copy notice");
    // The trash: an item put there, its list and page, and the question before it goes for good.
    select_title(&app, "Netflix");
    app.invoke_delete_item();
    app.invoke_select_category(10);
    app.invoke_select(0);
    camera.shot(
        "vault-trash",
        "The trash: kept 30 days, with Restore and Delete for good",
    );
    app.set_confirming_delete(true);
    camera.shot("vault-delete-confirm", "Delete for good: asked first");
    app.set_confirming_delete(false);
    app.invoke_restore_item();
    app.invoke_select_category(0);
    select_title(&app, "GitHub");
    // An older exe opened a vault a newer one opened here before; an extension below the floor.
    app.set_notice_arg("0.4.9".into());
    app.set_notice_code(121);
    camera.shot(
        "notice-older-app",
        "A newer version opened this vault here before: someone may have put back an old one",
    );
    app.set_notice_arg("0.4.8".into());
    app.set_notice_code(122);
    camera.shot(
        "notice-extension-outdated",
        "The browser extension is older than this app answers: how to update it",
    );
    app.set_notice_code(0);
    app.set_notice_arg("".into());

    // A login's passkey, made through the browser extension (the rows are set directly here:
    // a real one needs a site and the extension).
    let passkeys = || {
        slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(vec![PasskeyRow {
            site: "github.com".into(),
            user: "octocat".into(),
            created: "12 Nov 2026".into(),
            ..Default::default()
        }])))
    };
    app.set_notes_shown(false);
    app.set_detail_passkeys(passkeys());
    camera.shot("vault-passkey", "A login's passkey on the item page");
    // What the site said through the browser (the Signal API), waiting for the person.
    app.set_detail_passkeys(slint::ModelRc::from(std::rc::Rc::new(
        slint::VecModel::from(vec![PasskeyRow {
            site: "github.com".into(),
            user: "octocat".into(),
            created: "12 Nov 2026".into(),
            signal: 1,
            ..Default::default()
        }]),
    )));
    camera.shot(
        "vault-passkey-signal",
        "A site said it no longer knows a passkey: the person decides",
    );
    app.set_detail_passkeys(passkeys());
    // The question before a saved password is replaced (no master password).
    app.set_confirm_arg("GitHub".into());
    app.set_confirm_kind(1);
    camera.shot(
        "vault-confirm-replace",
        "Replacing a login's saved password asks first",
    );
    app.set_confirm_kind(0);
    app.invoke_edit_item();
    app.set_ed_passkeys(passkeys());
    camera.shot(
        "editor-passkey",
        "The editor: a passkey taken out here is gone once saved",
    );
    app.invoke_cancel_edit();

    // Recovery codes on GitHub: one already used.
    select_title(&app, "GitHub");
    app.invoke_edit_item();
    app.set_ed_recovery_codes(
        "1. 7f3a2-9c1d4\n2. b84e0-26fa1\n3. 0d9c7-e5b32\n4. 5a61f-c0e98\n5. e2b7d-418c6\n6. 9f04a-73d2b".into(),
    );
    app.invoke_save_item();
    app.invoke_show_codes();
    app.invoke_toggle_code_used(0);
    camera.shot(
        "vault-codes",
        "Recovery codes: shown on request, copy one, mark it used",
    );
    app.invoke_hide_codes();

    app.invoke_select_category(101);
    camera.shot(
        "vault-folder",
        "Browsing a folder (edit and delete at the top)",
    );
    app.invoke_edit_folder(1);
    app.set_fd_icon("star".into());
    app.set_fd_color(2);
    camera.shot(
        "vault-folder-edit",
        "Folder settings dialog: name, icon, colour, picture link",
    );
    app.invoke_folder_dialog_save();
    app.invoke_ask_delete_folder(1);
    camera.shot("vault-folder-delete", "Deleting a folder asks first");
    app.invoke_folder_dialog_cancel();
    app.invoke_new_folder();
    app.set_fd_name("Bank".into());
    app.set_fd_link("nope nope".into());
    app.invoke_folder_dialog_save();
    camera.shot(
        "vault-folder-new",
        "New folder: a bad picture link is caught",
    );
    app.invoke_folder_dialog_cancel();
    app.invoke_select_category(0);

    select_title(&app, "Home Wi-Fi");
    camera.shot("vault-note", "A secure note");

    app.invoke_select_category(1);
    camera.shot("vault-favorites", "Favorites tab");
    app.invoke_select_category(0);
    app.set_search_text("zzz".into());
    app.invoke_search("zzz".into());
    camera.shot("vault-no-results", "Search with no results");
    app.set_search_text("".into());
    app.invoke_search("".into());

    // ---- editor ----
    select_title(&app, "GitHub");
    app.invoke_edit_item();
    camera.shot("editor", "Editing an item");
    click(&app, 1106.0, 250.0); // (?) next to "One-time code secret"
    camera.shot("editor-hint", "A (?) hint: what to type in the field");
    click(&app, 800.0, 640.0); // anywhere closes it
    app.invoke_toggle_show_password();
    camera.shot("editor-password-shown", "Editing with the password shown");
    type_into(&app, 4, "summer2024");
    app.invoke_toggle_show_password();
    camera.shot("editor-weak", "Typing a weak password: strength and why");
    // A new password: the old one goes to the history.
    type_into(&app, 4, "Gh-new-9!xQ2#rTz8wLm");
    app.invoke_save_item();
    app.invoke_show_history();
    app.invoke_reveal_history(0);
    camera.shot("vault-history", "Password history, one entry shown");
    app.invoke_hide_history();
    // The item's earlier versions (the password change above kept one).
    app.set_detail_versions_shown(true);
    camera.shot(
        "vault-versions",
        "Earlier versions of the whole item, each with Restore",
    );
    app.set_detail_versions_shown(false);
    // A new identity starts with every detail it offers.
    app.invoke_select_category(7);
    app.invoke_new_item();
    camera.shot("editor-identity", "A new identity: its details as fields");
    app.invoke_cancel_edit();
    app.invoke_select_category(0);
    select_title(&app, "GitHub");
    app.invoke_new_item();
    app.invoke_save_item();
    camera.shot("editor-new-error", "New item: title required");
    app.set_ed_title("Shop".into());
    app.set_ed_gen_open(true);
    app.invoke_generate_for_item();
    app.invoke_toggle_show_password();
    camera.shot(
        "editor-generate",
        "Generate: the generator's options open under the password",
    );
    app.set_gen_mode(1);
    app.invoke_generate_for_item();
    camera.shot(
        "editor-generate-words",
        "Generate: a passphrase, separator buttons and box on one line",
    );
    app.set_gen_mode(0);
    app.set_ed_kind(3);
    app.set_ed_title("".into());
    camera.shot(
        "editor-authenticator",
        "New item: an authenticator code only",
    );
    app.invoke_cancel_edit();

    // ---- generator ----
    app.invoke_open_generator();
    camera.shot("generator", "Generator: random characters");
    app.set_gen_mode(1);
    app.set_gen_word_case(2);
    app.invoke_regenerate();
    camera.shot("generator-words", "Generator: words, Title Case");
    app.set_gen_separator("+".into());
    app.invoke_regenerate();
    camera.shot(
        "generator-words-own-separator",
        "Generator: words with a separator typed in the box",
    );
    app.set_gen_separator("-".into());
    app.set_gen_word_case(0);
    app.set_gen_mode(0);
    app.set_gen_length(64);
    app.invoke_regenerate();
    camera.shot(
        "generator-long",
        "Generator: 64 characters, counted in ages of the universe",
    );
    app.set_gen_length(24);
    app.invoke_regenerate();

    // ---- settings: a category at a time, and the dialogs that ask first ----
    app.invoke_open_settings();
    app.set_settings_section(0);
    app.set_quick_unlock_on(true);
    app.invoke_quick_unlock_toggled(true);
    camera.shot(
        "settings",
        "Settings → Security, Windows Hello just turned on",
    );
    // Each category whole, with a stronger unlock protection chosen.
    let normal = camera.window.size();
    camera
        .window
        .set_size(PhysicalSize::new(normal.width, normal.height * 3 + 300));
    app.set_kdf_level(2);
    // Demo lines of the security log, and the secure desktop offered.
    let line =
        |kind, at: &str, site: &str, title: &str, detail: &str| vault_desktop::ui::SecurityLine {
            kind,
            at: at.into(),
            site: site.into(),
            title: title.into(),
            detail: detail.into(),
        };
    app.set_security_log(slint::ModelRc::from(std::rc::Rc::new(
        slint::VecModel::from(vec![
            line(3, "2026-11-27 21:14", "github.com", "GitHub", "login"),
            line(2, "2026-11-27 21:12", "", "", "password"),
            line(1, "2026-11-27 08:03", "", "", "device"),
            line(6, "2026-11-26 19:40", "", "", "vaultx"),
            line(10, "2026-11-25 10:02", "", "", "Laptop"),
            line(0, "", "", "", ""),
        ]),
    )));
    app.set_security_log_more(12);
    app.set_secure_desktop(true);
    camera.shot(
        "settings-full",
        "Settings → Security, whole: unlock protection level, Apply asks first",
    );
    app.set_secret_key_kept(2);
    camera.shot(
        "settings-secret-key-windows",
        "Settings → Security, whole: no TPM here, the Secret Key kept by Windows alone (weaker)",
    );
    app.set_secret_key_kept(1);
    app.set_kdf_method(2);
    camera.shot(
        "settings-hash-method",
        "Settings → Security, whole: another hash method, with its warning",
    );
    app.invoke_open_settings_dialog(2);
    camera.shot(
        "settings-dialog-kdf",
        "Settings → Security: applying the unlock protection asks for the master password",
    );
    app.invoke_close_settings_dialog();
    app.set_kdf_method(app.get_kdf_current_method());
    app.set_kdf_level(app.get_kdf_current().max(0));
    app.invoke_open_settings_dialog(1);
    camera.shot(
        "settings-dialog-password",
        "Settings → Security: changing the master password, in a dialog",
    );
    app.global::<NewPassword>().set_place(3);
    app.global::<NewPassword>().set_warning(1);
    camera.shot(
        "settings-dialog-password-easy",
        "Changing the master password: an easy new one is warned about",
    );
    app.invoke_close_settings_dialog();
    app.set_guard_check(2);
    app.invoke_open_settings_dialog(3);
    app.global::<NewPassword>().set_place(5);
    app.global::<NewPassword>().set_warning(4);
    camera.shot(
        "settings-dialog-item-password-easy",
        "Saving the item lock: an easy item password is warned about",
    );
    app.invoke_close_settings_dialog();
    app.set_guard_check(1);
    app.invoke_open_settings_dialog(3);
    camera.shot(
        "settings-dialog-item-lock",
        "Settings → Security: saving the item lock asks for the PIN and the master password",
    );
    app.invoke_close_settings_dialog();
    app.set_guard_check(app.get_guard_current_check());
    // A newer item lock set on another device waits here: what to type, and where.
    app.global::<ItemLock>().set_waiting(1);
    app.set_error_code(60);
    camera.shot(
        "settings-lock-waiting",
        "Settings → Security: an item lock changed on another device waits for both PINs",
    );
    app.set_error_code(0);
    app.global::<ItemLock>().set_waiting(0);
    app.set_settings_section(1);
    camera.shot("settings-vault", "Settings → This vault");
    app.set_settings_section(3);
    app.set_browser_extension(true);
    // The browsers of a typical computer, the default one first (the demo finds none of its
    // own: the screenshots never look at this computer's).
    let browsers = |names: &[(&str, i32, bool)]| {
        slint::ModelRc::from(std::rc::Rc::new(slint::VecModel::from(
            names
                .iter()
                .map(|&(name, mark, is_default)| ExtensionBrowser {
                    name: name.into(),
                    mark,
                    is_default,
                })
                .collect::<Vec<_>>(),
        )))
    };
    app.set_extension_browsers(browsers(&[
        ("Chrome", 0, true),
        ("Edge", 1, false),
        ("Firefox", 2, false),
        ("Brave", 3, false),
    ]));
    app.set_extension_browser(0);
    app.set_extension_source(1);
    app.set_extension_version("0.4.8".into());
    camera.shot(
        "settings-browser",
        "Settings → Browser extension: what it may do",
    );
    // Off: the card that adds it to a browser comes right under the first one.
    app.set_browser_extension(false);
    camera.shot(
        "settings-browser-add",
        "Settings → Browser extension: Add to a browser, from GitHub's newest release",
    );
    // A folder of the person's in use, and another browser picked.
    app.set_extension_source(2);
    app.set_extension_version("0.4.8.1".into());
    app.set_extension_local(r"D:\Projects\vault-extension".into());
    app.set_extension_browser(2);
    camera.shot(
        "settings-browser-folder",
        "Settings → Browser extension: the extension from a folder of the person's, Firefox picked",
    );
    app.set_extension_source(1);
    app.set_extension_version("0.4.8".into());
    app.set_extension_local("".into());
    app.set_extension_browser(0);
    app.set_browser_extension(true);
    // Added to Chrome: it opened on its extensions page, the path is copied, and the steps.
    let folder = r"C:\Users\you\AppData\Local\vault\browser-extension";
    app.set_extension_steps_browser("Chrome".into());
    app.set_extension_steps_page("chrome://extensions".into());
    app.set_extension_steps_folder(folder.into());
    app.set_extension_steps_started(true);
    app.set_extension_steps_copied(true);
    app.set_extension_steps(true);
    camera.shot(
        "extension-steps-chrome",
        "Add to Chrome: its extensions page opened, the folder's path copied, the steps",
    );
    app.set_extension_steps_browser("Firefox".into());
    app.set_extension_steps_firefox(true);
    app.set_extension_steps_page("about:debugging#/runtime/this-firefox".into());
    // With the link still off, the last step turns it on.
    app.set_browser_extension(false);
    camera.shot(
        "extension-steps-firefox",
        "Add to Firefox: a temporary add-on until Firefox closes; the link turned on first",
    );
    app.set_browser_extension(true);
    app.set_extension_steps(false);
    app.set_extension_steps_firefox(false);
    // The extension asks to connect: the code both show, to compare, then the master password.
    app.set_pairing_code("74At LSYM".into());
    app.set_pairing_code_chars(slint::ModelRc::new(slint::VecModel::from(
        "74AtLSYM"
            .chars()
            .map(|c| slint::SharedString::from(c.to_string()))
            .collect::<Vec<_>>(),
    )));
    camera.shot(
        "pairing-compare",
        "The browser extension asks to connect: compare its code, then the master password",
    );
    app.set_pairing_code("".into());
    app.set_browser_extension(false);
    app.set_settings_section(4);
    // Starting at sign-in on, so its second check shows too.
    app.set_start_at_sign_in(true);
    camera.shot("settings-appearance", "Settings → Appearance");
    app.set_start_at_sign_in(false);
    app.set_settings_section(5);
    // Check for updates found a newer version (what the person sees after pressing it).
    app.set_update_version("0.5.0".into());
    app.set_update_state(3);
    camera.shot("settings-about", "Settings → About: a newer version is out");
    // The update installing itself: its steps in About and in the title bar's panel.
    app.set_install_step(2);
    app.set_install_done_kb(14 * 1024 + 300);
    app.set_install_total_kb(38 * 1024);
    camera.shot(
        "settings-about-installing",
        "Settings → About: the update downloading, step by step",
    );
    app.set_update_panel(true);
    camera.shot(
        "toolbar-update-downloading",
        "Title bar: the update's panel while it downloads",
    );
    app.set_install_step(6);
    app.set_install_failed_at(3);
    app.set_install_failure(2);
    app.set_install_detail(
        "the program downloaded isn't the one the release's manifest lists (SHA-256 differs)"
            .into(),
    );
    camera.shot(
        "toolbar-update-refused",
        "Title bar: a download that isn't what the signed manifest lists, refused",
    );
    app.set_update_panel(false);
    app.set_install_step(5);
    app.set_install_version("0.5.0".into());
    app.set_restart_asking(true);
    camera.shot(
        "toolbar-restart-dialog",
        "The update installed: restart now, or later",
    );
    app.set_restart_asking(false);
    app.set_update_panel(true);
    camera.shot(
        "toolbar-update-installed",
        "Title bar: the update installed",
    );
    app.set_update_panel(false);
    app.set_install_step(0);
    app.set_update_state(0);
    // The vault's icon on this computer, and the vault menu from the title bar.
    app.set_settings_section(1);
    app.invoke_vault_icon_chosen("briefcase".into());
    camera.shot(
        "settings-vault-icon",
        "Settings → This vault: its icon on this computer",
    );
    app.set_vault_menu_x(6.0);
    app.set_vault_menu(true);
    camera.shot(
        "toolbar-vault-menu",
        "Title bar: the vault menu (switch, open, new, its icon)",
    );
    app.set_vault_menu(false);
    app.invoke_vault_icon_chosen("".into());
    app.invoke_toggle_sidebar();
    camera.shot(
        "toolbar-sidebar-hidden",
        "The sidebar hidden from the title bar",
    );
    app.invoke_toggle_sidebar();
    app.set_settings_section(5);
    // Sync, off: the three places to choose from, then each one's dialog.
    app.set_settings_section(2);
    camera.shot("settings-sync-off", "Settings → Sync: off, three places");
    app.set_sync_form(1);
    app.set_sync_address("https://vault.example-net.ts.net".into());
    camera.shot(
        "settings-sync-server-form",
        "Settings → Sync: joining a server with an invite",
    );
    app.set_sync_form(2);
    app.set_sync_address("https://cloud.example.com/remote.php/dav/files/demo/Vault".into());
    app.set_sync_user("demo".into());
    camera.shot(
        "settings-sync-webdav-form",
        "Settings → Sync: WebDAV address, user and password",
    );
    app.set_sync_form(0);
    // Sync through a folder (demo values): synced a few minutes ago, then waiting for the
    // item lock, then the folder gone. The phone synced through another place.
    app.set_sync_kind(1);
    app.set_sync_others(slint::ModelRc::from(std::rc::Rc::new(
        slint::VecModel::from(vec![
            vault_desktop::ui::DeviceLine {
                name: "Laptop".into(),
                away: false,
                problem: "this copy is older than one already seen from that device".into(),
                problem_at: "2026-11-27 09:42".into(),
                refused: true,
            },
            vault_desktop::ui::DeviceLine {
                name: "Phone".into(),
                away: true,
                ..Default::default()
            },
        ]),
    )));
    app.set_sync_folder(r"D:\Sync\Vault".into());
    app.set_sync_this_device("Desktop".into());
    app.set_sync_devices("Laptop, Phone".into());
    app.set_sync_minutes(3);
    app.set_sync_state(1);
    camera.shot(
        "settings-sync",
        "Settings → Sync: through a folder, one device not there yet",
    );
    app.set_sync_waiting(2);
    app.set_sync_state(4);
    camera.shot(
        "settings-sync-waiting",
        "Settings → Sync: two edits waiting for the item lock",
    );
    // The vault key renewed on the laptop: its new Secret Key is asked here once; the phone
    // still uses the former key.
    app.set_sync_waiting(0);
    app.set_sync_state(1);
    app.set_sync_key_renewed(true);
    app.set_sync_key_behind(1);
    camera.shot(
        "settings-sync-renewed",
        "Settings → Sync: the vault key was renewed on another device",
    );
    app.invoke_open_settings_dialog(14);
    camera.shot(
        "settings-sync-take-key",
        "Settings → Sync: the new Secret Key and the master password",
    );
    app.invoke_close_settings_dialog();
    app.set_sync_key_renewed(false);
    app.set_sync_key_behind(0);
    app.set_sync_detail(r"the folder D:\Sync\Vault can't be reached".into());
    app.set_sync_state(3);
    camera.shot("settings-sync-failed", "Settings → Sync: failed");
    // Through the server: removing a device asks first, then an invite for one more device.
    app.set_sync_detail("".into());
    app.set_sync_state(1);
    app.set_sync_waiting(0);
    app.set_sync_kind(2);
    app.set_sync_folder("https://vault.example-net.ts.net".into());
    app.set_sync_removing(1);
    app.invoke_open_settings_dialog(6);
    camera.shot(
        "settings-sync-remove",
        "Settings → Sync: removing a device asks for the master password",
    );
    app.invoke_close_settings_dialog();
    app.set_sync_removing(-1);
    let link = "vaultsync:1?server=https://vault.example-net.ts.net&vault=0123456789abcdef0123456789abcdef&invite=fedcba9876543210fedcba9876543210";
    app.set_sync_invite(link.into());
    app.set_sync_invite_qr(demo_qr(link));
    camera.shot(
        "settings-sync-server",
        "Settings → Sync: through the server, adding a device",
    );
    app.set_sync_invite("".into());
    // The server reached at another address: the address in use, its pin apart.
    app.invoke_open_settings_dialog(12);
    app.set_sync_new_address("https://vault.example-net.ts.net".into());
    camera.shot(
        "settings-sync-address",
        "Settings → Sync: the server's address changed in a dialog",
    );
    app.invoke_close_settings_dialog();
    // A backup server, while the main one isn't answering.
    app.set_sync_backup("https://192.168.0.9:8750 (pinned certificate)".into());
    app.set_sync_main_down("the sync server can't be reached: connection refused".into());
    camera.shot(
        "settings-sync-backup",
        "Settings → Sync: the main server is down, syncing through the backup",
    );
    app.set_sync_backup("".into());
    app.set_sync_main_down("".into());
    app.set_sync_backup_form(true);
    camera.shot(
        "settings-sync-backup-form",
        "Settings → Sync: adding a backup server",
    );
    app.set_sync_backup_form(false);
    app.invoke_open_settings_dialog(5);
    camera.shot(
        "settings-sync-stop",
        "Settings → Sync: stopping asks for the master password",
    );
    app.invoke_close_settings_dialog();
    app.set_sync_kind(0);
    app.set_sync_folder("".into());
    app.set_sync_state(0);
    app.set_sync_detail("".into());
    app.set_settings_section(0);
    camera.window.set_size(normal);
    app.invoke_open_authenticator();
    camera.shot("authenticator", "Authenticator: every one-time code, live");
    app.invoke_new_item();
    camera.shot(
        "authenticator-add",
        "Authenticator → Add a code: the editor opens on Authenticator",
    );
    app.invoke_cancel_edit();
    app.set_lock_warning_seconds(42);
    camera.shot("lock-warning", "The last minute before the auto-lock");
    app.set_lock_warning_seconds(0);

    // ---- password health: one weak, two sharing a password ----
    add_item(
        &app,
        0,
        "Forum",
        "me",
        "https://forum.example",
        "letmein1",
        "",
        "",
        false,
        0,
    );
    add_item(
        &app,
        0,
        "Old shop",
        "me",
        "https://oldshop.example",
        "Shared-pass-2019!",
        "",
        "",
        false,
        0,
    );
    add_item(
        &app,
        0,
        "Newsletter",
        "me",
        "https://news.example",
        "Shared-pass-2019!",
        "",
        "",
        false,
        0,
    );
    app.invoke_open_health();
    camera.shot("health", "Password health: weak, reused, old, expired");
    // The bell in the title bar, shown while something asks for attention, and its panel.
    app.set_alerts_panel(true);
    camera.shot(
        "toolbar-alerts",
        "Title bar: the alerts (shown only while there are some), each opening its page",
    );
    app.set_alerts_panel(false);
    app.set_health_filter(2);
    app.invoke_health_filter_changed(2);
    camera.shot("health-reused", "Password health: reused only");
    app.set_health_filter(-1);

    app.invoke_open_transfer();
    camera.shot("transfer", "Import & export: where from");
    app.set_import_source(0);
    app.invoke_pick_source(0);
    // The demo has no real browser profiles: show two, as on a typical computer.
    app.set_import_browser_profiles(slint::ModelRc::from(std::rc::Rc::new(
        slint::VecModel::from(vec![
            slint::SharedString::from("Person 1"),
            slint::SharedString::from("Work"),
        ]),
    )));
    camera.shot("transfer-source", "Import from Chrome: read it directly");
    app.set_import_browser_method(1);
    camera.shot("transfer-csv", "Import from Chrome: from an exported CSV");
    app.set_import_browser_method(0);
    click(&app, 410.0, 260.0);
    camera.shot(
        "transfer-browsers",
        "Browsers, with the ones on this computer marked",
    );
    click(&app, 900.0, 700.0);
    app.set_import_source(8);
    app.invoke_pick_source(8);
    click(&app, 410.0, 260.0);
    camera.shot("transfer-managers", "Password managers and files");
    click(&app, 900.0, 700.0);
    app.set_import_source(-1);
    let demo_export = temp.path().join("export.json");
    std::fs::write(
        &demo_export,
        r#"{"encrypted": false, "folders": [{"id": "f", "name": "Shopping"}], "items": [
            {"type": 1, "name": "Shop", "folderId": "f", "login": {"username": "me", "password": "x1"}},
            {"type": 1, "name": "Forum", "login": {"username": "me", "password": "x2"}},
            {"type": 1, "name": "GitHub", "login": {"username": "octocat", "password": "Gh-demo-7Kq!vR2#pL9w", "uris": [{"uri": "https://github.com/login"}]}},
            {"type": 1, "name": "Old site", "login": {"fido2Credentials": [{}]}}]}"#,
    )
    .expect("demo export");
    controller.start_import(demo_export);
    camera.shot(
        "transfer-preview",
        "Import review: every entry, passwords hidden, duplicates unticked",
    );
    app.set_import_target(2);
    camera.shot("transfer-target", "Import review: all into one folder");
    app.set_import_target(0);
    app.invoke_import_confirm();
    camera.shot(
        "transfer-done",
        "Imported: offer to wipe the plain-text file",
    );
    app.invoke_import_wipe();
    // Exporting asks in a dialog: the master password, and a password for a protected file.
    app.set_export_format(3);
    app.set_export_asking(true);
    camera.shot(
        "transfer-export-protected",
        "Export protected by a password: asked in a dialog",
    );
    type_into(&app, 6, "a file password");
    type_into(&app, 7, "a file password");
    app.invoke_export_plain();
    camera.shot(
        "transfer-export-weak",
        "A protected export's password too easy to guess: refused, a passphrase offered",
    );
    app.set_error_code(0);
    app.set_export_format(1);
    camera.shot(
        "transfer-export-plain",
        "Export unencrypted: a dialog that says so plainly",
    );
    app.set_export_asking(false);
    app.set_export_format(0);

    app.invoke_open_kit();
    camera.shot(
        "kit-locked",
        "Emergency kit page: shown after the master password",
    );
    app.set_kit_asking(true);
    camera.shot(
        "kit-ask",
        "Emergency kit: the master password asked in a dialog",
    );
    type_into(&app, 5, PASSWORD);
    app.invoke_show_kit();
    camera.shot("kit", "Emergency kit page: print or save as PDF");
    // Behind an item lock, the keys and the PDF password wait for its check.
    app.set_kit_keys_locked(true);
    camera.shot(
        "kit-keys-locked",
        "Emergency kit page: the keys behind the item lock",
    );
    app.set_kit_keys_locked(false);
    app.set_kit_confirming_new_parts(true);
    camera.shot(
        "kit-new-parts-ask",
        "Emergency kit: issuing new parts asks in a dialog",
    );
    type_into(&app, 5, PASSWORD);
    app.invoke_new_parts();
    camera.shot(
        "kit-new-parts",
        "Emergency kit page: new recovery parts, shown this once",
    );
    // The whole page: printing, then the ways to keep a copy and to change the keys.
    let normal = camera.window.size();
    camera
        .window
        .set_size(PhysicalSize::new(normal.width, normal.height * 2));
    camera.shot(
        "kit-whole",
        "Emergency kit page, whole: print, keep a copy in a file, change the keys",
    );
    camera.window.set_size(normal);
    // Keep a copy of the printable PDF next to the screenshots (fake keys only).
    app.invoke_print_kit();
    if let Ok(entries) = std::fs::read_dir(temp.path().join("home").join("print")) {
        for entry in entries.flatten() {
            let _ = std::fs::copy(entry.path(), dir.join("emergency-kit-demo.pdf"));
        }
    }
    // And the kit as Save as PDF and Save each part apart write it: protected by the kit's
    // PDF password (CRYPTO.md §3.10), written next to them, to check in any PDF viewer.
    write_protected_demo(&app, &dir);
    app.set_kit_confirming_renew(true);
    camera.shot(
        "kit-renew-ask",
        "Emergency kit: renewing the vault key asks in a dialog",
    );
    app.set_kit_confirming_renew(false);
    app.invoke_hide_kit();

    // ---- where the doodle texture goes (the page is the default), for review ----
    app.invoke_select_category(0);
    select_title(&app, "GitHub");
    for (value, name, caption) in [
        (0, "backdrop-none", "Background: none"),
        (2, "backdrop-index", "Background: on the index only"),
        (
            3,
            "backdrop-index-list",
            "Background: on the index and the list",
        ),
        (4, "backdrop-everywhere", "Background: everywhere, fainter"),
    ] {
        app.global::<Theme>().set_backdrop(value);
        camera.shot(name, caption);
    }
    app.global::<Theme>().set_backdrop(1);

    // ---- light theme, for comparison ----
    app.invoke_appearance_changed(false);
    app.invoke_select_category(0);
    select_title(&app, "GitHub");
    camera.shot("light-detail", "Light theme: item page");
    app.invoke_open_settings();
    camera.shot("light-settings", "Light theme: settings");
    app.invoke_appearance_changed(true);

    // ---- item lock: a PIN before any item's secrets show ----
    select_title(&app, "Netflix");
    app.invoke_edit_item();
    app.set_ed_reprompt(true);
    camera.shot("editor-protected", "Editor: lock this item's secrets");
    app.invoke_cancel_edit();
    app.invoke_open_settings();
    app.set_guard_check(1);
    app.set_guard_all(true);
    app.set_guard_hello(true);
    type_into(&app, 12, "4821");
    type_into(&app, 13, PASSWORD);
    app.invoke_save_guard();
    app.invoke_select_category(0);
    select_title(&app, "Netflix");
    camera.shot(
        "vault-protected",
        "Item lock: who the account is stays visible, secrets wait for the PIN",
    );
    type_into(&app, 11, "0000");
    app.invoke_unlock_item();
    camera.shot(
        "vault-protected-wrong",
        "Item lock: a wrong PIN, tries left",
    );
    app.invoke_open_authenticator();
    camera.shot(
        "authenticator-locked",
        "Authenticator: codes of locked items masked until the PIN",
    );
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    camera.shot(
        "authenticator-open",
        "Authenticator: one PIN opened every code; lock again",
    );
    app.invoke_select_category(0);
    select_title(&app, "Netflix");
    camera.shot(
        "vault-protected-open",
        "Item lock: open, with a Lock button",
    );
    app.invoke_lock_secrets();
    app.invoke_new_item();
    app.set_ed_title("New while locked".into());
    camera.shot(
        "editor-needs-pin",
        "Editor: a new item will be sealed, so saving asks for the PIN",
    );
    app.invoke_cancel_edit();
    app.invoke_open_settings();
    camera.shot("settings-item-lock", "Settings with a PIN item lock");
    app.invoke_open_settings();
    app.set_guard_check(0);
    app.set_guard_all(false);
    type_into(&app, 13, PASSWORD);
    app.invoke_save_guard();
    app.invoke_select_category(0);

    // ---- locked ----
    app.invoke_lock();
    camera.shot("unlock", "Locked, with Windows Hello set up");
    app.set_update_state(3);
    app.set_install_step(5);
    camera.shot(
        "unlock-update-installed",
        "Locked: the title bar shows the file's name and an update waiting for a restart",
    );
    app.set_install_step(0);
    app.set_update_state(0);
    // Where the vault wall goes (side panel and behind the form is the default), for review.
    for (value, name, caption) in [
        (0, "unlock-plain", "Lock screen background: none"),
        (
            1,
            "unlock-wall-form",
            "Lock screen background: behind the form only",
        ),
        (
            2,
            "unlock-wall-side",
            "Lock screen background: in the side panel only",
        ),
    ] {
        app.global::<Theme>().set_lock_backdrop(value);
        camera.shot(name, caption);
    }
    app.global::<Theme>().set_lock_backdrop(3);
    app.set_choosing_vault(true);
    camera.shot("unlock-chooser", "Choosing among vaults");
    app.set_choosing_vault(false);
    type_into(&app, 0, "wrong password");
    app.invoke_unlock();
    camera.shot("unlock-error", "Wrong master password");
    app.set_quick_unlock_on(false);
    app.set_error_code(0);
    type_into(&app, 0, "");
    camera.shot("unlock-password-only", "Locked, without Windows Hello");
    app.set_error_code(1);
    app.set_unlock_failed(6);
    app.set_unlock_wait(83);
    camera.shot(
        "unlock-wait",
        "Six failed tries in a row: the next one waits, counted down",
    );
    app.set_unlock_wait(0);
    app.set_unlock_failed(0);
    app.set_error_code(0);
    app.set_needs_keyfile(true);
    app.set_keyfile_path(r"E:\vault.keyfile".into());
    camera.shot(
        "unlock-keyfile",
        "Locked: this vault also needs its keyfile",
    );
    app.set_needs_keyfile(false);
    app.set_keyfile_path("".into());
    let _ = vault_platform::secret_store::forget(&vault_id);
    app.set_needs_secret_key(true);
    type_into(&app, 0, "");
    camera.shot(
        "unlock-new-device",
        "A computer that hasn't seen this vault",
    );
    app.set_error_code(90);
    camera.shot(
        "unlock-chip-cleared",
        "The security chip was cleared: the kit's Secret Key is asked for once",
    );
    app.set_error_code(0);
    app.set_can_use_parts(true);
    app.set_use_parts(true);
    camera.shot(
        "unlock-parts",
        "No Secret Key at hand: two recovery parts stand in for it",
    );
    app.set_use_parts(false);
    app.invoke_show_recovery();
    camera.shot("recover", "Recovery with the emergency kit");

    // ---- the notification area menu (a window of its own) ----
    app.hide().expect("hide");
    drop(controller);
    let menu = vault_desktop::ui::TrayMenu::new().expect("tray menu");
    menu.set_locked(false);
    menu.set_vault_name("Personal".into());
    menu.set_minutes_left(4);
    menu.show().expect("show menu");
    window.set_size(PhysicalSize::new(
        (196.0 * scale) as u32,
        (menu.get_content_height() * scale) as u32,
    ));
    camera.shot("tray-menu", "The notification area icon's menu");
    vault_desktop::i18n::apply("pt_BR");
    menu.set_locked(true);
    camera.shot("tray-menu-pt", "The same menu in Portuguese (locked)");
    vault_desktop::i18n::apply("en");

    camera.write_gallery();
    println!("Gallery: {}", dir.join("index.html").display());
}

#[allow(dead_code)]
fn _assert_path(_: &Path) {}

/// A QR code as the app draws it (black on white, a quiet zone).
fn demo_qr(text: &str) -> slint::Image {
    let code = qrcode::QrCode::new(text).unwrap();
    let modules = code.width();
    let colors = code.to_colors();
    let (quiet, scale) = (4, 6);
    let side = (modules + 2 * quiet) * scale;
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    for (i, pixel) in buffer.make_mut_slice().iter_mut().enumerate() {
        let (x, y) = (i % side / scale, i / side / scale);
        let dark = x >= quiet
            && y >= quiet
            && x - quiet < modules
            && y - quiet < modules
            && colors[(y - quiet) * modules + (x - quiet)] == qrcode::Color::Dark;
        let v = if dark { 0 } else { 255 };
        *pixel = slint::Rgb8Pixel { r: v, g: v, b: v };
    }
    slint::Image::from_rgb8(buffer)
}

/// The demo kit as the app saves it: the Secret Key's page and part A's page, each protected
/// by the kit's PDF password, and the password in a text file beside them (fake keys only),
/// to open them in any PDF viewer.
fn write_protected_demo(app: &AppWindow, dir: &Path) {
    use vault_platform::kit_pdf::{self, KitContents};
    let password = app.get_kit_pdf_password();
    let secret_key = app.get_kit_secret_key();
    let vault_id = app.get_vault_id();
    if password.is_empty() || secret_key.is_empty() {
        return;
    }
    let created_at = 1_794_441_600;
    let kit = KitContents {
        secret_key: &secret_key,
        parts: None,
        vault_id: &vault_id,
        created_at,
        filled: true,
        part_c_elsewhere: false,
    };
    if let Ok(bytes) = kit_pdf::render_protected(&kit, &password) {
        let _ = std::fs::write(dir.join("emergency-kit-demo-protected.pdf"), &*bytes);
    }
    let part_a = app.get_kit_part_a();
    if !part_a.is_empty()
        && let Ok(bytes) = kit_pdf::render_part_protected(
            vault_core::PartLabel::A,
            &part_a,
            &vault_id,
            created_at,
            true,
            &password,
        )
    {
        let _ = std::fs::write(dir.join("recovery-part-A-demo-protected.pdf"), &*bytes);
    }
    let _ = std::fs::write(
        dir.join("emergency-kit-demo-password.txt"),
        format!("{password}\n"),
    );
}
