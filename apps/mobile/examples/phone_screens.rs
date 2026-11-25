//! Off-screen design review of the phone app: renders every screen with Slint's software
//! renderer into PNG files plus an `index.html` gallery. Nothing is shown on screen.
//!
//! ```text
//! cargo run -p vault-mobile --example phone_screens -- [output-dir] [scale]
//! ```
//!
//! Uses a throwaway vault with fake data in a temporary folder. The vault's Secret Key is put
//! in the OS credential store during the run and removed at the end.

use std::{cell::Cell, path::PathBuf, rc::Rc, time::Duration};

use slint::{
    ComponentHandle, PhysicalSize, PlatformError, Rgb8Pixel,
    platform::{
        Platform, WindowAdapter, WindowEvent,
        software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
    },
};
use vault_mobile::{
    Controller,
    ui::{PhoneWindow, Place, Secrets, Theme},
};

const WIDTH: u32 = 390;
const HEIGHT: u32 = 844;
const PASSWORD: &str = "phone demo passphrase";

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

/// Lets time pass so animations (the marker stroke) settle.
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

    /// A finger drag from (x, `from_y`) to (x, `to_y`) in logical pixels, in small steps, as a
    /// phone sends it: scrolls what is under it.
    fn drag(&self, from_y: f32, to_y: f32) {
        let scale = self.window.scale_factor();
        let at = |y: f32| slint::LogicalPosition::new(WIDTH as f32 / 2.0, y);
        let _ = scale;
        self.window.dispatch_event(WindowEvent::PointerPressed {
            position: at(from_y),
            button: slint::platform::PointerEventButton::Left,
        });
        let steps = 12;
        for step in 1..=steps {
            let y = from_y + (to_y - from_y) * step as f32 / steps as f32;
            advance(16);
            self.window
                .dispatch_event(WindowEvent::PointerMoved { position: at(y) });
        }
        self.window.dispatch_event(WindowEvent::PointerReleased {
            position: at(to_y),
            button: slint::platform::PointerEventButton::Left,
        });
        advance(1200);
    }

    /// Scrolls the page to its end (several drags) and takes a shot at the phone's height.
    fn shot_scrolled(&mut self, name: &str, caption: &str) {
        for _ in 0..14 {
            self.drag(700.0, 140.0);
        }
        self.shot(name, caption);
    }

    fn write_gallery(&self) {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>Vault phone screens</title><style>\
             body{margin:0;padding:24px 16px;background:#d9dee4;font:15px/1.5 Bahnschrift,'Segoe UI',sans-serif;color:#1f2a3d}\
             h1{font-weight:300;font-size:30px;margin:0 0 4px}p.lead{color:#677385;margin:0 0 28px}\
             main{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:28px 20px}\
             figure{margin:0}img{width:100%;height:auto;display:block;border:1px solid #b9c2cc;border-radius:18px}\
             figcaption{padding:8px 2px;color:#40506a}</style></head><body>\
             <h1>Vault on a phone: screen review</h1>\
             <p class=\"lead\">Rendered off-screen with Slint's software renderer. Fake data only.</p><main>",
        );
        for (file, caption) in &self.shots {
            html.push_str(&format!(
                "<figure><img src=\"{file}\" alt=\"{caption}\" loading=\"lazy\"><figcaption>{caption}</figcaption></figure>"
            ));
        }
        html.push_str("</main></body></html>");
        std::fs::write(self.dir.join("index.html"), html).expect("write gallery");
    }
}

/// Two vaults for the vault chooser (demo names and places only).
fn demo_vaults(first_open: bool) -> slint::ModelRc<vault_mobile::ui::VaultRow> {
    slint::ModelRc::new(slint::VecModel::from(vec![
        vault_mobile::ui::VaultRow {
            icon: "".into(),
            icon_color: 0,
            icon_bg: 0,
            name: "Personal".into(),
            initial: "P".into(),
            tint: slint::Color::from_rgb_u8(0x3D, 0x6F, 0xD6),
            place: "vault.example-net.ts.net".into(),
            open: first_open,
        },
        vault_mobile::ui::VaultRow {
            icon: "briefcase".into(),
            icon_color: 0,
            icon_bg: 0,
            name: "Work".into(),
            initial: "W".into(),
            tint: slint::Color::from_rgb_u8(0xC0, 0x4A, 0x84),
            place: "".into(),
            open: false,
        },
    ]))
}

fn type_secret(app: &PhoneWindow, field: i32, text: &str) {
    app.global::<Secrets>().invoke_clear(field);
    app.global::<Secrets>().invoke_insert(field, text.into());
}

/// Saves one demo login through the editor, as a person would.
fn add_login(app: &PhoneWindow, title: &str, user: &str, password: &str, site: &str, totp: &str) {
    app.invoke_new_item();
    app.set_ed_kind(0);
    app.set_ed_title(title.into());
    app.set_ed_username(user.into());
    app.set_ed_website(site.into());
    app.set_ed_totp(totp.into());
    type_secret(app, 3, password);
    app.invoke_save_item();
    app.invoke_close_item();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .unwrap_or_else(|| "target/phone-screens".to_owned()),
    );
    let scale: f32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2.0);
    std::fs::create_dir_all(&dir).expect("create the output folder");

    let home = tempfile::tempdir().expect("temporary folder");
    // SAFETY: set before any other thread exists; the app reads it for its data folder.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", home.path());
    }

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(OffscreenPlatform {
        window: window.clone(),
    }))
    .expect("set the off-screen platform");
    window.set_size(PhysicalSize::new(
        (WIDTH as f32 * scale) as u32,
        (HEIGHT as f32 * scale) as u32,
    ));
    window.dispatch_event(WindowEvent::ScaleFactorChanged {
        scale_factor: scale,
    });

    // The vault as the desktop app would have made it, in a file to bring to the phone.
    let key = vault_core::SecretKey::generate().expect("a Secret Key");
    let mut made = vault_core::Vault::create(
        PASSWORD,
        &key,
        None,
        vault_core::KdfParams::minimum().expect("parameters"),
    )
    .expect("a demo vault");
    let mut settings = made.settings().clone();
    settings.name = "Personal".into();
    made.set_settings(settings).expect("a name");
    let from_computer = home.path().join("from-the-computer.vault");
    std::fs::write(&from_computer, made.to_bytes().expect("bytes")).expect("write the file");
    drop(made);

    let app = PhoneWindow::new().expect("create the window");
    app.show().expect("show the window");
    let path = home.path().join("phone").join("vault.vault");
    let controller = Controller::start(&app, path.clone(), true);
    // English, unless VAULT_LANG says otherwise (`VAULT_LANG=pt-BR` for the Portuguese screens),
    // whatever this computer's language is.
    let language = std::env::var("VAULT_LANG").unwrap_or_else(|_| "en".to_owned());
    app.invoke_language_changed(vault_mobile::i18n::choice_of(&language).max(1));
    let mut camera = Camera {
        window,
        dir,
        shots: Vec::new(),
    };

    camera.shot(
        "start",
        "No vault on this phone yet: the server's invite, or the file",
    );
    app.set_can_pick_file(false);
    camera.shot(
        "start-browser",
        "In a browser (no file picker): the server's invite",
    );
    app.set_can_pick_file(true);
    controller.bring_vault(b"a photo, not a vault".to_vec());
    camera.shot("start-wrong", "A file that isn't a vault, in words");
    controller.bring_vault_file(&from_computer);
    type_secret(&app, 1, &key.to_display_string());
    type_secret(&app, 0, PASSWORD);
    camera.shot("first-unlock", "The first time: the Secret Key, once");
    // Its eye: the key as the kit prints it, two groups to a line.
    app.global::<Secrets>().invoke_toggle_shown(1);
    camera.shot(
        "first-unlock-key-shown",
        "The Secret Key shown, box by box as on the kit",
    );
    app.global::<Secrets>().invoke_toggle_shown(1);
    // On Android: no file picker yet, and the app's own keyboard for the secret fields.
    app.set_can_pick_file(false);
    app.set_drawn_keyboard(true);
    app.global::<Secrets>().set_focused(0);
    camera.shot(
        "first-unlock-keyboard",
        "On Android: the app's own keyboard types the master password",
    );
    app.global::<Secrets>().set_focused(-1);
    app.set_drawn_keyboard(false);
    app.set_can_pick_file(true);
    app.invoke_unlock();
    camera.shot("empty", "An empty vault");

    add_login(
        &app,
        "GitHub",
        "octocat",
        "gh-demo-Passw0rd!",
        "github.com",
        "JBSWY3DPEHPK3PXP",
    );
    add_login(
        &app,
        "Mail",
        "me@example.com",
        "mail-demo-Passw0rd!",
        "mail.example.com",
        "GEZDGNBVGY3TQOJQ",
    );
    add_login(
        &app,
        "Bank",
        "0001-2345",
        "bank-demo-Passw0rd!",
        "bank.example",
        "",
    );
    add_login(
        &app,
        "Forum",
        "nightowl",
        "forum-demo-Passw0rd!",
        "forum.example",
        "",
    );
    add_login(
        &app,
        "Streaming",
        "me@example.com",
        "tv-demo-Passw0rd!",
        "tv.example",
        "",
    );
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Wi-Fi at home".into());
    app.set_ed_notes("Network: demo-net\nRouter page: 192.0.2.1".into());
    app.invoke_save_item();
    app.invoke_close_item();
    app.invoke_open_item(1);
    app.invoke_toggle_favorite();
    app.invoke_close_item();
    advance(4000);

    camera.shot("vault", "The vault: search, filters, the list");
    app.set_search("ex".into());
    app.invoke_search_changed("ex".into());
    camera.shot("search", "Searching");
    app.set_search("".into());
    app.invoke_search_changed("".into());

    app.invoke_open_item(2);
    camera.shot("item", "One login: every field, a tap copies");
    app.invoke_toggle_password();
    camera.shot("item-shown", "The password, while asked for");
    app.invoke_copy(1);
    camera.shot("item-copied", "Copied: said just above the bottom");
    // The notice goes after a few seconds of real time; the other shots go without it.
    app.set_notice_code(0);
    advance(4000);
    app.invoke_edit_item();
    camera.shot("editor", "Editing a login");
    app.invoke_ask(10);
    camera.shot("editor-ask", "Make a strong one: asked first");
    app.invoke_confirmed(10);
    camera.shot(
        "editor-generator",
        "The generator, for the login: Use brings it back",
    );
    app.invoke_gen_use();
    camera.shot(
        "editor-generated",
        "A strong password made in the generator",
    );
    camera.shot_scrolled(
        "editor-end",
        "The editor's end: folder, icon, favourite, delete",
    );
    app.set_ed_glyph("bank".into());
    app.set_ed_glyph_color(0);
    app.set_ed_glyph_bg(0);
    app.set_ed_icons_open(true);
    camera.shot_scrolled(
        "editor-icons",
        "Choose: a line icon in its own colours, or colours chosen",
    );
    app.set_ed_glyph_bg(1);
    camera.shot_scrolled("editor-icons-tile", "The same icon on a blue tile");
    app.set_ed_icons_open(false);
    app.invoke_cancel_edit();
    app.invoke_close_item();

    app.invoke_new_item();
    app.set_ed_kind(4);
    app.set_ed_title("Home server".into());
    app.set_ed_username("me@laptop".into());
    app.invoke_ed_ssh_generate();
    camera.shot(
        "editor-ssh",
        "An SSH key: its type, fingerprint and public half",
    );
    app.invoke_cancel_edit();

    app.invoke_new_item();
    camera.shot("new", "A new login or note");
    app.invoke_save_item();
    camera.shot("new-error", "What is missing, in words");
    app.invoke_cancel_edit();

    app.set_place(Place::Codes);
    camera.shot("codes", "One-time codes with their countdown and seconds");
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    camera.shot("generator", "The generator: characters");
    app.set_gen_mode(1);
    app.invoke_gen_changed();
    camera.shot("generator-words", "The generator: words");
    app.set_gen_mode(0);
    app.invoke_gen_changed();
    app.invoke_gen_copy();
    app.set_notice_code(0);
    camera.shot_scrolled(
        "generator-history",
        "The generator's history: copied or used, masked",
    );
    // "Check this password" on a login (demo values: no breach service is asked here).
    app.set_place(Place::Items);
    app.invoke_open_item(2);
    app.set_d_checked(true);
    app.set_d_bits(38);
    app.set_d_crack_unit(2);
    app.set_d_crack_amount(3);
    app.set_d_weakness(3);
    app.set_d_leak(12_345);
    app.set_d_leak_count("12,345".into());
    camera.shot(
        "item-checked",
        "Check this password: its strength and the leak check",
    );
    app.invoke_close_item();
    // The vault chooser on the vault's name.
    app.set_vaults(demo_vaults(true));
    app.set_vault_current(0);
    app.set_choosing_vault(true);
    camera.shot("vault-chooser", "The vault's name opens the vault chooser");
    app.set_choosing_vault(false);

    app.set_place(Place::Settings);
    app.set_settings_section(-1);
    app.set_autofill_available(true);
    camera.shot("settings", "Settings: the groups");
    let tall = |camera: &mut Camera, factor: f32| {
        camera.window.set_size(PhysicalSize::new(
            (WIDTH as f32 * scale) as u32,
            (HEIGHT as f32 * scale * factor) as u32,
        ));
    };
    app.set_bio_available(true);
    app.set_bio_on(true);
    app.set_settings_section(0);
    tall(&mut camera, 1.6);
    camera.shot(
        "settings-security",
        "Security: fingerprint, locking, screenshots, clipboard",
    );
    tall(&mut camera, 1.0);
    app.invoke_ask(12);
    camera.shot(
        "settings-password",
        "Security: changing the master password, in the sheet",
    );
    app.set_error_code(13);
    camera.shot(
        "settings-password-wrong",
        "The sheet stays open and says what went wrong",
    );
    app.set_error_code(0);
    app.set_confirming(0);
    app.set_settings_section(1);
    tall(&mut camera, 1.0);
    camera.shot("settings-autofill", "Autofill: Android's service");
    app.set_settings_section(2);
    app.set_vault_size("24 KB".into());
    tall(&mut camera, 1.6);
    camera.shot(
        "settings-vaults",
        "Vault: this one, the others, adding and removing",
    );
    tall(&mut camera, 1.0);
    camera.shot_scrolled(
        "settings-vaults-end",
        "Vaults, at the phone's height, scrolled to the end",
    );
    app.set_settings_section(3);
    app.set_backup_confirmed("vault-backup-2026-11-21.vault · 24 KB · 2026-11-21 14:03 UTC".into());
    app.set_import_added(12);
    app.set_import_skipped(3);
    tall(&mut camera, 1.6);
    camera.shot(
        "settings-import",
        "Import and export: copies, another manager's export",
    );
    app.set_import_added(-1);
    tall(&mut camera, 1.0);
    app.invoke_ask(7);
    camera.shot(
        "settings-export-protected",
        "A protected export: the master password, then the export's own, in the sheet",
    );
    app.set_confirming(0);
    app.set_import_name("passwords.kdbx".into());
    app.invoke_ask(11);
    camera.shot(
        "settings-import-password",
        "A file with a password: asked for when it is chosen",
    );
    app.set_confirming(0);
    app.set_import_name("".into());
    app.set_settings_section(4);
    tall(&mut camera, 1.0);
    camera.shot("settings-sync-off", "Sync: off, an invite line to paste");
    // Joined (demo values only: no server is reached here).
    app.set_sync_place("https://vault.example-net.ts.net".into());
    app.set_sync_minutes(2);
    app.set_sync_state(1);
    app.set_sync_copies(3);
    app.set_sync_total("72 KB".into());
    app.set_sync_own("24 KB".into());
    app.set_sync_devices(slint::ModelRc::new(slint::VecModel::from(vec![
        vault_mobile::ui::DeviceRow {
            name: "Phone".into(),
            added: "2026-11-20".into(),
            own: true,
            away: false,
        },
        vault_mobile::ui::DeviceRow {
            name: "Desktop".into(),
            added: "2026-11-02".into(),
            own: false,
            away: false,
        },
        vault_mobile::ui::DeviceRow {
            name: "Laptop".into(),
            added: "2026-11-12".into(),
            own: false,
            away: true,
        },
    ])));
    app.set_sync_pinned(true);
    tall(&mut camera, 1.0);
    camera.shot(
        "settings-synced",
        "Sync: how it stands, the devices, the server",
    );
    camera.shot_scrolled(
        "settings-synced-end",
        "Sync, at the phone's height, scrolled to the end",
    );
    app.set_sync_explained(true);
    tall(&mut camera, 2.2);
    camera.shot(
        "settings-synced-whole",
        "Sync: the whole page, how it works open",
    );
    app.set_sync_explained(false);
    app.set_sync_removing(2);
    tall(&mut camera, 1.0);
    app.invoke_ask(3);
    camera.shot("settings-device-remove", "Removing a device, asked first");
    app.set_confirming(0);
    app.set_sync_removing(-1);
    // The vault key renewed on the computer: its new Secret Key is asked once.
    app.set_sync_key_renewed(true);
    app.set_sync_key_behind(1);
    camera.shot(
        "settings-sync-renewed",
        "Sync: the vault key was renewed on another device",
    );
    app.invoke_ask(19);
    camera.shot(
        "settings-sync-take-key",
        "Sync: the new Secret Key and the master password",
    );
    app.set_confirming(0);
    app.set_sync_key_renewed(false);
    app.set_sync_key_behind(0);
    app.set_sync_state(3);
    app.set_sync_detail("the sync server can't be reached".into());
    tall(&mut camera, 1.0);
    camera.shot("settings-sync-failed", "Sync: the server can't be reached");
    app.set_sync_place("".into());
    app.set_sync_state(0);
    app.set_sync_detail("".into());
    app.set_sync_copies(0);
    app.set_settings_section(5);
    camera.shot(
        "settings-appearance",
        "Appearance: theme, language, background, icons",
    );
    app.set_updates_available(true);
    app.set_update_state(3);
    app.set_update_version("0.3.0".into());
    app.set_settings_section(6);
    camera.shot(
        "settings-about",
        "About and updates: the version, updates, what changed",
    );
    app.set_settings_section(-1);
    app.set_updates_available(false);
    app.set_update_state(0);
    app.set_settings_section(7);
    app.invoke_health_opened();
    camera.shot(
        "settings-health",
        "Password health: what needs a look, and why",
    );
    app.set_health_filter(1);
    app.invoke_health_filtered(1);
    camera.shot(
        "settings-health-weak",
        "Password health: a count tapped, only those logins",
    );
    app.set_health_filter(-1);
    app.invoke_health_filtered(-1);
    app.set_settings_section(8);
    app.set_folder_editing(-1);
    app.set_folder_name("Work".into());
    app.set_folder_icon("briefcase".into());
    app.invoke_folder_save();
    app.set_folder_editing(-1);
    app.set_folder_name("Old".into());
    app.set_folder_parent(0);
    app.set_folder_icon("database".into());
    app.set_folder_color(4);
    app.invoke_folder_save();
    camera.shot(
        "settings-folders",
        "Folders: a folder inside another, each with an icon",
    );
    app.invoke_folder_edit(1);
    app.set_folder_choosing_parent(true);
    camera.shot_scrolled(
        "settings-folder-inside",
        "A folder's form: what it is inside",
    );
    app.set_folder_editing(-2);
    app.set_settings_section(2);
    app.set_vault_icons_open(true);
    camera.shot_scrolled(
        "settings-vault-icon",
        "The vault's icon on this phone, and its colours",
    );
    app.set_vault_icons_open(false);
    app.invoke_ask(1);
    camera.shot(
        "settings-vault-remove-asked",
        "Removing a vault from the phone: asked first",
    );
    app.set_confirming(0);
    app.set_settings_section(-1);

    // The folders, as the list shows them (after the change of place has settled: it closes
    // the folder picker).
    app.set_place(Place::Items);
    camera.shot("vault-with-folders", "The list, with the Folders button");
    app.set_folders_open(true);
    camera.shot("vault-folders", "Folders: every one, with its count");
    app.set_folders_open(false);
    app.set_folder_filter(0);
    app.invoke_filter_changed(0);
    camera.shot("vault-in-folder", "In a folder: its name, and x to leave");
    app.set_folder_filter(-1);
    app.invoke_filter_changed(0);
    camera.shot_scrolled("vault-folders-under-all", "Under All: the folders");

    app.global::<Theme>().set_dark(false);
    app.set_place(Place::Items);
    camera.shot("vault-light", "The vault on the light theme");
    app.invoke_open_item(2);
    camera.shot("item-light", "One login on the light theme");
    app.invoke_close_item();
    app.invoke_lock_now();
    camera.shot("unlock-light", "Locked, light theme");
    app.global::<Theme>().set_dark(true);
    camera.shot("unlock", "Locked");
    app.set_bio_ready(true);
    app.set_vaults(demo_vaults(false));
    app.set_choosing_vault(true);
    camera.shot(
        "unlock-fingerprint",
        "Locked: the fingerprint, and another vault",
    );
    app.set_choosing_vault(false);
    app.set_bio_ready(false);
    type_secret(&app, 0, "not the password");
    app.invoke_unlock();
    camera.shot("unlock-wrong", "A wrong password, in words");
    app.invoke_start_recovery(0);
    camera.shot(
        "recover",
        "Forgot the master password: the kit's three parts, then a new one",
    );
    app.invoke_recover();
    camera.shot("recover-wrong", "Recovery: what is missing, in words");
    app.set_recovered_key("S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345".into());
    camera.shot(
        "recover-key",
        "Recovered: the new Secret Key, before the vault opens (demo value)",
    );
    app.set_recovered_key("".into());
    app.invoke_cancel_recovery();
    controller.bring_vault_file(&from_computer);
    camera.shot(
        "newer-copy",
        "A newer copy chosen: it replaces the phone's once it opens",
    );

    camera.write_gallery();
    println!(
        "Wrote {} screens to {}",
        camera.shots.len(),
        camera.dir.display()
    );

    // Leave nothing behind in the OS credential store.
    drop(controller);
    if let Ok(bytes) = std::fs::read(&path)
        && let Ok(info) = vault_core::Vault::inspect(&bytes)
    {
        let _ = vault_platform::secret_store::forget(&info.id_hex);
    }
}
