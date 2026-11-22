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
    app.invoke_ed_generate();
    camera.shot("editor-generated", "A strong password made in the editor");
    app.invoke_cancel_edit();
    app.invoke_close_item();

    app.invoke_new_item();
    camera.shot("new", "A new login or note");
    app.invoke_save_item();
    camera.shot("new-error", "What is missing, in words");
    app.invoke_cancel_edit();

    app.set_place(Place::Codes);
    camera.shot("codes", "One-time codes with their countdown");
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    camera.shot("generator", "The generator: characters");
    app.set_gen_mode(1);
    app.invoke_gen_changed();
    camera.shot("generator-words", "The generator: words");
    app.set_gen_mode(0);
    app.set_place(Place::Settings);
    camera.shot("settings", "Settings: sync off, an invite line to paste");
    // The whole page at once, in a window twice as tall: the master password being
    // changed, and the last copy saved and checked.
    app.set_changing_password(true);
    app.set_backup_confirmed("vault-backup-2026-11-21.vault · 24 KB · 2026-11-21 14:03 UTC".into());
    camera.window.set_size(PhysicalSize::new(
        (WIDTH as f32 * scale) as u32,
        (HEIGHT as f32 * scale * 2.0) as u32,
    ));
    camera.shot(
        "settings-whole",
        "Settings, whole page: the master password, a checked copy",
    );
    camera.window.set_size(PhysicalSize::new(
        (WIDTH as f32 * scale) as u32,
        (HEIGHT as f32 * scale) as u32,
    ));
    app.set_changing_password(false);
    // Joined (demo values only: no server is reached here).
    app.set_sync_place("https://vault.example-net.ts.net".into());
    app.set_sync_minutes(2);
    app.set_sync_state(1);
    camera.shot("settings-synced", "Settings: syncing through the server");
    app.set_sync_state(3);
    app.set_sync_detail("the sync server can't be reached".into());
    camera.shot(
        "settings-sync-failed",
        "Settings: the server can't be reached",
    );
    app.set_sync_place("".into());
    app.set_sync_state(0);
    app.set_sync_detail("".into());

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
    type_secret(&app, 0, "not the password");
    app.invoke_unlock();
    camera.shot("unlock-wrong", "A wrong password, in words");
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
