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
    ui::{AppWindow, Secrets},
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
) {
    app.invoke_new_item();
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
    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, "different");
    app.invoke_suggest_passphrase();
    app.invoke_create_vault();
    camera.shot(
        "onboarding-error",
        "Mismatch error, with a suggested passphrase",
    );
    type_into(&app, 1, PASSWORD);
    app.invoke_create_vault();
    let vault_id = app.get_vault_id().to_string();
    camera.shot("emergency-kit", "Step 2: the emergency kit");
    app.set_kit_saved(true);
    camera.shot(
        "emergency-kit-confirmed",
        "Kit confirmed; the vault can open",
    );
    app.invoke_finish_onboarding();
    camera.shot("vault-empty", "Empty vault");

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
    );
    add_item(
        &app,
        1,
        "Visa ending 4242",
        "A. Person",
        "",
        "000",
        "",
        "Expires 12/29",
        false,
    );
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
    app.set_confirming_delete(true);
    camera.shot("vault-delete-confirm", "Delete confirmation");
    app.set_confirming_delete(false);

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
    app.invoke_cancel_edit();
    app.invoke_new_item();
    app.invoke_save_item();
    camera.shot("editor-new-error", "New item: title required");
    app.invoke_cancel_edit();

    // ---- generator ----
    app.invoke_open_generator();
    camera.shot("generator", "Generator: random characters");
    app.set_gen_mode(1);
    app.invoke_regenerate();
    camera.shot("generator-words", "Generator: words");

    // ---- settings ----
    app.invoke_open_settings();
    app.set_quick_unlock_on(true);
    app.invoke_quick_unlock_toggled(true);
    camera.shot("settings", "Settings, Windows Hello just turned on");
    click(&app, 729.0, 184.0); // (?) next to "Show website icons"
    camera.shot("settings-icons-hint", "Privacy note for website icons");
    click(&app, 1000.0, 720.0);
    type_into(&app, 5, PASSWORD);
    app.invoke_show_kit();
    camera.shot(
        "settings-kit",
        "Settings: Secret Key shown after re-entering the password",
    );
    app.invoke_hide_kit();

    // ---- light theme, for comparison ----
    app.invoke_appearance_changed(false);
    app.invoke_select_category(0);
    select_title(&app, "GitHub");
    camera.shot("light-detail", "Light theme: item page");
    app.invoke_open_settings();
    camera.shot("light-settings", "Light theme: settings");
    app.invoke_appearance_changed(true);

    // ---- locked ----
    app.invoke_lock();
    camera.shot("unlock", "Locked, with Windows Hello set up");
    type_into(&app, 0, "wrong password");
    app.invoke_unlock();
    camera.shot("unlock-error", "Wrong master password");
    app.set_quick_unlock_on(false);
    app.set_error_code(0);
    type_into(&app, 0, "");
    camera.shot("unlock-password-only", "Locked, without Windows Hello");
    let _ = vault_platform::secret_store::forget(&vault_id);
    app.set_needs_secret_key(true);
    type_into(&app, 0, "");
    camera.shot(
        "unlock-new-device",
        "A computer that hasn't seen this vault",
    );
    app.invoke_show_recovery();
    camera.shot("recover", "Recovery with the emergency kit");

    camera.write_gallery();
    drop(controller);
    println!("Gallery: {}", dir.join("index.html").display());
}

#[allow(dead_code)]
fn _assert_path(_: &Path) {}
