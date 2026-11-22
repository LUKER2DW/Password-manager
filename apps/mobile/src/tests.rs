//! The phone app end to end, headless: a vault made on the computer is brought in, then
//! items, the item page, codes, generator, lock, unlock, a newer copy, and sync through a
//! running server. Slow work runs
//! inline; test values only.

use std::{
    cell::{Cell, RefCell},
    path::Path,
    rc::Rc,
};

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Unlock, Vault};
use zeroize::Zeroizing;

use vault_platform::sync::{self, ServerTarget, Target as _};

use crate::{
    Controller,
    system::{PromptWords, System},
    ui::{Page, PhoneWindow, Place, Screen, Secrets},
};

/// The phone's system as the tests see it: a fingerprint that is always the right one, a
/// "secure hardware" that seals by flipping bits, and what the app asked of it.
#[derive(Default)]
struct FakeSystem {
    /// What the app handed over last: a secret to seal, or a sealed one to open.
    handed: RefCell<Option<Vec<u8>>>,
    off_screenshots: Cell<Option<bool>>,
    forgotten: RefCell<Vec<String>>,
    /// An update handed to the installer.
    installed: RefCell<Option<Vec<u8>>>,
}

impl System for FakeSystem {
    fn biometrics(&self) -> bool {
        true
    }

    fn seal_with_biometrics(
        &self,
        _: &str,
        secret: &[u8],
        words: &PromptWords,
    ) -> Result<(), String> {
        assert!(!words.title.is_empty() && !words.cancel.is_empty());
        *self.handed.borrow_mut() = Some(secret.to_vec());
        Ok(())
    }

    fn open_with_biometrics(&self, _: &str, sealed: &[u8], _: &PromptWords) -> Result<(), String> {
        *self.handed.borrow_mut() = Some(sealed.to_vec());
        Ok(())
    }

    fn forget_biometrics(&self, vault_id: &str) {
        self.forgotten.borrow_mut().push(vault_id.to_owned());
    }

    fn keep_off_screenshots(&self, on: bool) {
        self.off_screenshots.set(Some(on));
    }

    fn autofill(&self) -> Option<bool> {
        Some(false)
    }

    fn installs_updates(&self) -> bool {
        true
    }

    fn install_update(&self, package: &[u8]) -> Result<(), String> {
        *self.installed.borrow_mut() = Some(package.to_vec());
        Ok(())
    }
}

fn flip(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ 0x5a).collect()
}

const PASSWORD: &str = "phone test master passphrase";

/// A vault-server on a free local port, for as long as it lives.
struct TestServer {
    url: String,
    data: tempfile::TempDir,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let data = tempfile::tempdir().unwrap();
        let root = data.path().to_owned();
        let (ready, address) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready.send(listener.local_addr().unwrap()).unwrap();
                vault_server::serve(&root, listener, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
            });
        });
        let address: std::net::SocketAddr = address.recv().unwrap();
        Self {
            url: format!("http://{address}"),
            data,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn type_secret(app: &PhoneWindow, field: i32, text: &str) {
    app.global::<Secrets>().invoke_clear(field);
    app.global::<Secrets>().invoke_insert(field, text.into());
}

fn length(app: &PhoneWindow, field: usize) -> i32 {
    app.global::<Secrets>()
        .get_lengths()
        .row_data(field)
        .unwrap()
}

fn open_file(path: &Path, secret_key: &str) -> Vault {
    let key = SecretKey::parse(secret_key).unwrap();
    Vault::open(
        &std::fs::read(path).unwrap(),
        Unlock::Password {
            password: PASSWORD,
            secret_key: &key,
        },
    )
    .unwrap()
}

#[test]
fn the_phone_app_from_a_computer_vault_to_a_locked_one() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: the only test of this crate; nothing else reads the environment meanwhile.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", dir.path().join("home"));
    }

    // ---- the vault, as the desktop app made it ----
    let key = SecretKey::generate().unwrap();
    let secret_key = key.to_display_string().to_string();
    let mut made = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    let mut settings = made.settings().clone();
    settings.name = "Test vault".into();
    made.set_settings(settings).unwrap();
    let from_computer = dir.path().join("from-the-computer.vault");
    std::fs::write(&from_computer, made.to_bytes().unwrap()).unwrap();
    let vault_id = made.id_hex();
    drop(made);

    i_slint_backend_testing::init_no_event_loop();
    let app = PhoneWindow::new().unwrap();
    let path = dir.path().join("phone").join("vault.vault");
    let controller = Controller::start(&app, path.clone(), true);

    // ---- the system keyboard (Android): the hidden input only ever holds stand-ins ----
    {
        let secrets = app.global::<Secrets>();
        let p = '\u{1}';
        assert_eq!(secrets.invoke_placeholders(0), "");
        assert_eq!(secrets.invoke_typed(0, "ab".into()), format!("{p}{p}"));
        assert_eq!(length(&app, 0), 2);
        // One more letter after the stand-ins.
        assert_eq!(
            secrets.invoke_typed(0, format!("{p}{p}c").into()),
            format!("{p}{p}{p}")
        );
        // Backspace: one stand-in gone.
        assert_eq!(
            secrets.invoke_typed(0, format!("{p}{p}").into()),
            format!("{p}{p}")
        );
        assert_eq!(length(&app, 0), 2);
        // All selected and typed over: none left, the new letter in.
        assert_eq!(secrets.invoke_typed(0, "x".into()), format!("{p}"));
        assert_eq!(secrets.invoke_placeholders(0), format!("{p}"));
        secrets.invoke_clear(0);
        assert_eq!(length(&app, 0), 0);

        // Letters of every UTF-8 length: each stand-in is as long as its letter in UTF-8 and
        // UTF-16, so the keyboard's cursor (placed by Slint right after) is never inside one.
        // With same-length stand-ins, this is where typing on the phone crashed the app.
        let typed = "aé€😀";
        let back = secrets.invoke_typed(0, typed.into());
        assert_eq!(back.len(), typed.len());
        assert_eq!(back.encode_utf16().count(), typed.encode_utf16().count());
        assert!((0..=typed.len()).all(|i| typed.is_char_boundary(i) == back.is_char_boundary(i)));
        assert!(!back.chars().any(|c| typed.contains(c)));
        assert_eq!(length(&app, 0), 4);
        // Then a pasted line after them, and one of them deleted from the end.
        let back = secrets.invoke_typed(0, format!("{back}ção").into());
        assert_eq!(back.len(), format!("{typed}ção").len());
        assert_eq!(length(&app, 0), 7);
        let shorter: String = back.chars().take(6).collect();
        assert_eq!(secrets.invoke_typed(0, shorter.as_str().into()), shorter);
        assert_eq!(length(&app, 0), 6);
        // A control character the keyboard sent isn't in the field, and stays as it is.
        let back = secrets.invoke_typed(0, format!("{shorter}\t").into());
        assert!(back.ends_with('\t'));
        assert_eq!(length(&app, 0), 6);
        assert_eq!(secrets.invoke_typed(0, shorter.as_str().into()), shorter);
        assert_eq!(length(&app, 0), 6);
        secrets.invoke_clear(0);
    }

    // ---- no vault on the phone: one is brought in, never made ----
    assert_eq!(app.get_screen(), Screen::Start);
    controller.bring_vault(b"not a vault at all".to_vec());
    assert_eq!((app.get_error_code(), app.get_screen()), (2, Screen::Start));
    controller.bring_vault_file(&from_computer);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_incoming() && !app.get_has_copy());
    assert!(app.get_needs_secret_key(), "a new phone asks for the key");
    app.invoke_cancel_incoming();
    assert_eq!(app.get_screen(), Screen::Start, "back to choosing a file");
    controller.bring_vault_file(&from_computer);
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, "S0-not-a-key");
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 3);
    type_secret(&app, 0, "not the master password");
    type_secret(&app, 1, &secret_key);
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (1, Screen::Unlock)
    );
    assert!(
        !path.exists(),
        "a file that didn't open is not kept on the phone"
    );
    // This time as the phone's keyboard types it: one key at a time, each edit the whole
    // input (the stand-ins given back, then the new letter), with a mistake taken back.
    let secrets = app.global::<Secrets>();
    secrets.invoke_clear(0);
    let mut input = secrets.invoke_placeholders(0).to_string();
    for (i, letter) in PASSWORD.chars().enumerate() {
        if i == 3 {
            input = secrets.invoke_typed(0, format!("{input}#").into()).into();
            input.pop();
            input = secrets.invoke_typed(0, input.as_str().into()).into();
        }
        input = secrets
            .invoke_typed(0, format!("{input}{letter}").into())
            .into();
    }
    assert!(!input.chars().any(|c| PASSWORD.contains(c)));
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(&from_computer).unwrap(),
        "the phone keeps its own copy"
    );
    assert_eq!(app.get_vault_name(), "Test vault");
    assert_eq!(
        (length(&app, 0), length(&app, 1)),
        (0, 0),
        "typed keys wiped"
    );
    assert_eq!((app.get_total(), app.get_items().row_count()), (0, 0));

    // ---- a login ----
    app.invoke_new_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 5, "a name is needed");
    app.set_ed_title("GitHub".into());
    app.set_ed_username("octocat".into());
    app.set_ed_website("github.com".into());
    app.set_ed_totp("not a key!".into());
    type_secret(&app, 3, "gh-test-password-1");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 10);
    app.set_ed_totp("JBSWY3DPEHPK3PXP".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), 3);
    assert_eq!(app.get_page(), Page::Item, "the saved login is shown");
    assert_eq!(app.get_d_title(), "GitHub");
    assert_eq!(app.get_d_username(), "octocat");
    assert!(app.get_d_has_password());
    assert_eq!(app.get_d_password(), "", "hidden until asked for");
    assert!(app.get_d_has_code());
    assert_eq!(app.get_d_code().replace(' ', "").len(), 6);
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "gh-test-password-1");
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "");
    app.invoke_toggle_favorite();
    assert!(app.get_d_favorite());
    app.invoke_close_item();
    assert_eq!(app.get_page(), Page::None);
    assert_eq!(app.get_d_title(), "", "nothing of the item stays behind");

    // ---- a note, then the list ----
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Wi-Fi".into());
    app.set_ed_notes("network: test-net".into());
    app.invoke_save_item();
    app.invoke_close_item();
    assert_eq!(app.get_total(), 2);
    let titles = |app: &PhoneWindow| -> Vec<String> {
        app.get_items()
            .iter()
            .map(|row| row.title.to_string())
            .collect()
    };
    assert_eq!(titles(&app), ["GitHub", "Wi-Fi"]);
    assert!(app.get_items().row_data(0).unwrap().favorite);
    app.set_search("wi".into());
    app.invoke_search_changed("wi".into());
    assert_eq!(titles(&app), ["Wi-Fi"]);
    app.set_search("".into());
    app.invoke_search_changed("".into());
    for (filter, expected) in [
        (1, vec!["GitHub"]),
        (2, vec!["GitHub"]),
        (4, vec!["Wi-Fi"]),
        (3, vec![]),
    ] {
        app.set_filter(filter);
        app.invoke_filter_changed(filter);
        assert_eq!(titles(&app), expected, "filter {filter}");
    }
    app.set_filter(0);
    app.invoke_filter_changed(0);

    // ---- a card: checked, its PIN kept as the item's secret ----
    app.invoke_new_item();
    app.set_ed_kind(1);
    app.set_ed_title("Test card".into());
    app.set_ed_username("Test Person".into());
    app.set_ed_card_number("4111 1111 1111 1112".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 17, "a number that fails the check");
    app.set_ed_card_number("4111 1111 1111 1111".into());
    app.invoke_ed_card_number_edited("4111 1111 1111 1111".into());
    assert_eq!(app.get_ed_card_brand(), "Visa");
    app.set_ed_card_expiry("8/29".into());
    app.set_ed_card_code("123".into());
    type_secret(&app, 3, "12");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 20, "a PIN is 4 to 12 digits");
    type_secret(&app, 3, "4321");
    app.set_ed_website("https://bank.example".into());
    app.invoke_save_item();
    assert_eq!(app.get_page(), Page::Item, "{}", app.get_error_code());
    assert_eq!(app.get_d_card_expiry(), "08/29");
    assert!(app.get_d_card().ends_with("1111"));
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "4321");
    app.invoke_edit_item();
    assert_eq!(app.get_ed_kind(), 1);
    assert_eq!(app.get_ed_card_code(), "123");
    app.invoke_cancel_edit();
    app.invoke_close_item();

    // ---- an authenticator item from the Codes page: named after its setup key ----
    app.invoke_new_code();
    assert_eq!((app.get_page(), app.get_ed_kind()), (Page::Editor, 3));
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 21, "the setup key comes first");
    app.set_ed_totp(
        "otpauth://totp/Example%20Mail:me%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example%20Mail"
            .into(),
    );
    app.invoke_save_item();
    assert_eq!(app.get_page(), Page::Item, "{}", app.get_error_code());
    assert_eq!(app.get_d_title(), "Example Mail");
    assert_eq!(app.get_d_username(), "me@example.com");
    assert!(app.get_d_has_code() && !app.get_d_has_password());
    app.invoke_close_item();
    assert!(
        app.get_codes()
            .iter()
            .any(|row| row.title == "Example Mail")
    );
    assert_eq!(app.get_total(), 4);

    // ---- an SSH key made on the phone, with a file attached ----
    app.invoke_new_item();
    app.set_ed_kind(4);
    app.set_ed_title("Home server".into());
    app.set_ed_username("me@phone".into());
    app.invoke_ed_ssh_generate();
    assert!(app.get_ed_ssh_has_key() && app.get_ed_ssh_public().ends_with(" me@phone"));
    controller.picked_file(
        2,
        "id_ed25519.pub",
        b"ssh-ed25519 AAAA only the public half".to_vec(),
    );
    assert_eq!(
        app.get_error_code(),
        22,
        "a .pub file isn't the private key"
    );
    controller.picked_file(1, "scan.pdf", b"%PDF test".to_vec());
    controller.picked_file(1, "too big", vec![0; vault_core::Attachment::MAX_BYTES + 1]);
    assert_eq!(app.get_error_code(), 23);
    assert_eq!(app.get_ed_files().row_count(), 1);
    app.invoke_save_item();
    assert_eq!(app.get_page(), Page::Item, "{}", app.get_error_code());
    assert_eq!(app.get_d_kind(), 4);
    assert!(app.get_d_ssh_public().starts_with("ssh-ed25519 "));
    assert_eq!(app.get_d_files().row_count(), 1);
    let (name, bytes) = controller.file_to_save(0).unwrap();
    assert_eq!(
        (name.as_str(), bytes.as_slice()),
        ("scan.pdf", &b"%PDF test"[..])
    );
    assert!(controller.file_written(Ok(bytes)));
    assert!(
        !controller.file_written(Ok(b"something else".to_vec())),
        "a file read back differently"
    );
    app.invoke_toggle_password();
    assert!(
        app.get_d_password()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    app.invoke_toggle_password();
    app.invoke_close_item();
    app.set_filter(5);
    app.invoke_filter_changed(5);
    assert_eq!(app.get_items().row_count(), 1, "the SSH filter");
    app.set_filter(0);
    app.invoke_filter_changed(0);
    assert_eq!(app.get_total(), 5);
    // Both go again, so the rest of this test sees the vault it expects.
    for title in ["Example Mail", "Test card", "Home server"] {
        let index = app
            .get_items()
            .iter()
            .position(|row| row.title == title)
            .unwrap();
        app.invoke_open_item(i32::try_from(index).unwrap());
        app.invoke_edit_item();
        app.invoke_delete_item();
        app.invoke_delete_item();
    }
    assert_eq!(app.get_total(), 2);

    // ---- edit: the password changes, the rest stays ----
    app.invoke_open_item(0);
    app.invoke_edit_item();
    assert_eq!(app.get_ed_title(), "GitHub");
    assert_eq!(
        length(&app, 3),
        18,
        "the editor holds the password, not the screen"
    );
    assert_eq!(app.get_ed_password(), "");
    app.invoke_ed_generate();
    let generated = app.get_ed_password().to_string();
    assert_eq!(generated.chars().count(), 20, "a made password is shown");
    app.invoke_save_item();
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), generated.as_str());
    app.invoke_close_item();

    // ---- codes and the generator ----
    app.set_place(Place::Codes);
    let codes = app.get_codes();
    assert_eq!(codes.row_count(), 1);
    let row = codes.row_data(0).unwrap();
    assert_eq!(
        (row.title.as_str(), row.account.as_str()),
        ("GitHub", "octocat")
    );
    assert!(row.left >= 1 && row.left <= 30 && row.period == 30);
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    assert_eq!(app.get_gen_password().chars().count(), 20);
    assert!(app.get_gen_bits() > 100);
    for off in [
        PhoneWindow::set_gen_upper,
        PhoneWindow::set_gen_lower,
        PhoneWindow::set_gen_digits,
        PhoneWindow::set_gen_symbols,
    ] {
        off(&app, false);
    }
    app.invoke_gen_changed();
    assert_eq!(
        (app.get_gen_password().as_str(), app.get_error_code()),
        ("", 11)
    );
    app.set_gen_mode(1);
    app.invoke_gen_changed();
    assert_eq!(app.get_gen_password().split('-').count(), 6);
    assert_eq!(app.get_error_code(), 0);

    // ---- the item lock: a PIN before the secrets ----
    {
        let mut vault = open_file(&path, &secret_key);
        vault
            .set_item_guard(true, GuardCheck::Pin, Some("4821"), None)
            .unwrap();
        // As another device would have written it: the phone must not overwrite it.
        std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    }
    app.set_place(Place::Items);
    app.invoke_open_item(0);
    app.invoke_toggle_favorite();
    assert_eq!(
        app.get_error_code(),
        6,
        "a file changed elsewhere is not overwritten"
    );
    app.invoke_lock_now();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!controller.is_unlocked());
    assert_eq!(app.get_items().row_count(), 0);
    assert!(!app.get_needs_secret_key(), "this phone has the Secret Key");
    assert!(!app.get_incoming());

    // ---- unlock ----
    type_secret(&app, 0, "not the master password");
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (1, Screen::Unlock)
    );
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert!(app.get_items().row_data(0).unwrap().locked);
    app.set_place(Place::Codes);
    assert_eq!(
        app.get_codes().row_data(0).unwrap().code,
        "",
        "no digits behind the lock"
    );
    app.set_place(Place::Items);
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "the PIN is asked for");
    assert!(!app.get_d_has_password() && !app.get_d_has_code());
    assert_eq!(
        app.get_d_username(),
        "octocat",
        "who the account is stays visible"
    );
    app.invoke_toggle_password();
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(
        (app.get_d_password().as_str(), app.get_notice_code()),
        ("", 0),
        "nothing shown, nothing copied"
    );
    type_secret(&app, 2, "0000");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (7, 2));
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    assert_eq!((app.get_error_code(), app.get_d_check()), (0, 0));
    assert!(app.get_d_has_password() && app.get_d_has_code());
    app.invoke_close_item();
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "closed again when the item is left");
    app.invoke_close_item();

    // ---- delete, asked twice ----
    app.invoke_open_item(1);
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_delete_item();
    assert!(app.get_ed_confirm_delete());
    assert_eq!(app.get_total(), 2);
    app.invoke_delete_item();
    assert_eq!((app.get_total(), app.get_page()), (1, Page::None));
    assert_eq!(app.get_notice_code(), 4);

    // ---- the master password changes on the phone (and back, for what follows) ----
    const NEW_PASSWORD: &str = "phone new master passphrase";
    app.set_place(Place::Settings);
    app.set_changing_password(true);
    type_secret(&app, 5, "not the password");
    type_secret(&app, 6, NEW_PASSWORD);
    type_secret(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_error_code(), 13, "{}", app.get_error_detail());
    assert_eq!(length(&app, 5), 0, "a wrong current password is cleared");
    type_secret(&app, 5, PASSWORD);
    type_secret(&app, 7, "phone new master passphrasE");
    app.invoke_change_password();
    assert_eq!(app.get_error_code(), 14);
    type_secret(&app, 6, "short");
    type_secret(&app, 7, "short");
    app.invoke_change_password();
    assert_eq!(app.get_error_code(), 15);
    type_secret(&app, 6, NEW_PASSWORD);
    type_secret(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 10, "{}", app.get_error_detail());
    assert!(!app.get_changing_password());
    assert_eq!(
        (length(&app, 5), length(&app, 6), length(&app, 7)),
        (0, 0, 0),
        "wiped after use"
    );
    assert_eq!(app.get_screen(), Screen::Vault, "still open");
    {
        let key = SecretKey::parse(&secret_key).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let with = |password| {
            Vault::open(
                &bytes,
                Unlock::Password {
                    password,
                    secret_key: &key,
                },
            )
        };
        assert!(with(NEW_PASSWORD).is_ok(), "written to the file");
        assert!(with(PASSWORD).is_err(), "the old one no longer opens it");
    }
    app.set_changing_password(true);
    type_secret(&app, 5, NEW_PASSWORD);
    type_secret(&app, 6, PASSWORD);
    type_secret(&app, 7, PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 10, "{}", app.get_error_detail());
    app.set_place(Place::Items);

    // ---- the phone's system: screenshots, autofill, fingerprint unlock (a stand-in) ----
    let system = Rc::new(FakeSystem::default());
    controller.set_system(system.clone());
    assert_eq!(
        system.off_screenshots.get(),
        Some(true),
        "out of screenshots by default"
    );
    app.invoke_allow_capture_changed(true);
    assert_eq!(system.off_screenshots.get(), Some(false));
    app.invoke_allow_capture_changed(false);
    assert!(app.get_autofill_available() && !app.get_autofill_on());
    assert!(app.get_bio_available() && !app.get_bio_on());
    app.invoke_bio_toggled(true);
    let secret = system.handed.borrow_mut().take().expect("a secret to seal");
    assert_eq!(secret.len(), 32);
    controller.biometric_sealed(Ok(flip(&secret)));
    assert!(app.get_bio_on());
    assert_eq!(app.get_notice_code(), 14);
    app.invoke_lock_now();
    assert!(app.get_bio_ready(), "offered on the unlock screen");
    assert_eq!(
        app.get_vault_name(),
        "Test vault",
        "a locked vault keeps its name"
    );
    // The person chose the master password instead: nothing happens.
    app.invoke_bio_unlock();
    assert_eq!(system.handed.borrow_mut().take(), Some(flip(&secret)));
    controller.biometric_opened(Err(String::new()));
    assert_eq!(
        (app.get_screen(), app.get_error_code()),
        (Screen::Unlock, 0)
    );
    app.invoke_bio_unlock();
    let sealed = system.handed.borrow_mut().take().unwrap();
    controller.biometric_opened(Ok(Zeroizing::new(flip(&sealed))));
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    // Every 14 days the master password is asked again.
    let unlock_file = path.with_file_name(format!("unlock-{vault_id}.json"));
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&unlock_file).unwrap()).unwrap();
    let typed_at = json["password_at"].clone();
    json["password_at"] = 0.into();
    std::fs::write(&unlock_file, serde_json::to_vec(&json).unwrap()).unwrap();
    app.invoke_lock_now();
    assert!(
        !app.get_bio_ready() && app.get_bio_stale(),
        "the master password is due"
    );
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    app.invoke_lock_now();
    assert!(app.get_bio_ready(), "typing it brings the fingerprint back");
    json["password_at"] = typed_at;
    // A new master password revokes it: it was bound to the old one.
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    app.set_changing_password(true);
    type_secret(&app, 5, PASSWORD);
    type_secret(&app, 6, NEW_PASSWORD);
    type_secret(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 16, "{}", app.get_error_detail());
    assert!(!app.get_bio_on() && !unlock_file.exists());
    assert_eq!(
        system.forgotten.borrow().as_slice(),
        std::slice::from_ref(&vault_id)
    );
    app.set_changing_password(true);
    type_secret(&app, 5, NEW_PASSWORD);
    type_secret(&app, 6, PASSWORD);
    type_secret(&app, 7, PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 10, "{}", app.get_error_detail());
    // "Lock as soon as I leave the app".
    controller.left_app();
    assert!(controller.is_unlocked(), "off by default");
    app.invoke_lock_on_leave_changed(true);
    controller.left_app();
    assert!(!controller.is_unlocked());
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    app.invoke_lock_on_leave_changed(false);
    assert!(controller.is_unlocked());
    // The language: kept, shown as chosen.
    app.invoke_language_changed(2);
    assert_eq!(app.get_language_choice(), 2);
    app.invoke_language_changed(0);
    assert_eq!(app.get_language_choice(), 0);

    // ---- a copy of the vault: confirmed only after it is read back and checked ----
    let (name, copy) = controller
        .copy_to_save()
        .expect("an open vault has a copy to save");
    assert!(name.starts_with("vault-backup-") && name.ends_with(".vault"));
    assert_eq!(
        copy,
        std::fs::read(&path).unwrap(),
        "the phone's file as it is"
    );
    let mut damaged = copy.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(!controller.copy_written("Downloads/backup.vault", Ok(damaged)));
    assert_eq!(
        app.get_error_code(),
        16,
        "a damaged copy is refused (and deleted)"
    );
    assert_eq!(app.get_backup_confirmed(), "");
    let (_, copy) = controller.copy_to_save().unwrap();
    assert!(!controller.copy_written("Downloads/backup.vault", Err("disk full".into())));
    assert_eq!(app.get_error_detail(), "disk full");
    assert!(
        !controller.copy_written("Downloads/backup.vault", Ok(copy.clone())),
        "a copy nobody asked for"
    );
    let (_, copy) = controller.copy_to_save().unwrap();
    assert!(controller.copy_written("Downloads/backup.vault", Ok(copy)));
    assert_eq!(app.get_notice_code(), 11);
    assert!(
        app.get_backup_confirmed()
            .starts_with("Downloads/backup.vault · ")
    );

    // ---- a copy older than the phone's: refused, the phone's copy stays ----
    let phone_copy = std::fs::read(&path).unwrap();
    controller.bring_vault_file(&from_computer);
    assert!(
        !controller.is_unlocked(),
        "the open vault left memory first"
    );
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_incoming() && app.get_has_copy());
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (8, Screen::Unlock)
    );
    assert_eq!(std::fs::read(&path).unwrap(), phone_copy);
    app.invoke_cancel_incoming();
    assert!(!app.get_incoming(), "back to the phone's own copy");

    // ---- a newer copy from the computer: it replaces the phone's ----
    {
        let mut vault = open_file(&path, &secret_key);
        vault
            .add_item(&ItemData::new(
                ItemKind::SecureNote,
                "Added on the computer",
            ))
            .unwrap();
        std::fs::write(&from_computer, vault.to_bytes().unwrap()).unwrap();
    }
    controller.bring_vault_file(&from_computer);
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total(), 2);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(&from_computer).unwrap()
    );
    app.invoke_open_item(0);
    app.invoke_toggle_favorite();
    assert_eq!(
        app.get_error_code(),
        0,
        "the new copy is the one this phone saves to"
    );
    app.invoke_close_item();

    // ---- a second vault on the phone ----
    let work_key = SecretKey::generate().unwrap();
    let work_secret_key = work_key.to_display_string().to_string();
    let mut work = Vault::create(PASSWORD, &work_key, None, KdfParams::minimum().unwrap()).unwrap();
    let mut work_settings = work.settings().clone();
    work_settings.name = "Work".into();
    work.set_settings(work_settings).unwrap();
    let work_file = dir.path().join("work.vault");
    std::fs::write(&work_file, work.to_bytes().unwrap()).unwrap();
    let work_id = work.id_hex();
    drop(work);
    assert_eq!(app.get_vaults().row_count(), 1);
    app.invoke_add_vault();
    assert!(app.get_adding_vault() && !controller.is_unlocked());
    assert_eq!(app.get_screen(), Screen::Start);
    app.invoke_cancel_add_vault();
    assert_eq!(
        (app.get_screen(), app.get_adding_vault()),
        (Screen::Unlock, false)
    );
    assert_eq!(controller.path(), path, "back to the first vault");
    app.invoke_add_vault();
    controller.bring_vault_file(&work_file);
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, &work_secret_key);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_vault_name(), "Work");
    assert_eq!(controller.path(), path.with_file_name("vault-2.vault"));
    let rows: Vec<(String, bool)> = app
        .get_vaults()
        .iter()
        .map(|v| (v.name.to_string(), v.open))
        .collect();
    assert_eq!(
        rows,
        [("Test vault".to_owned(), false), ("Work".to_owned(), true)]
    );
    assert_eq!(app.get_vault_current(), 1);

    // Import: another manager's CSV, once and then again (nothing twice).
    let csv = "name,url,username,password\nForum,https://forum.example.com,tester,password123\n";
    controller.picked_file(3, "export.csv", csv.as_bytes().to_vec());
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!((app.get_import_added(), app.get_import_skipped()), (1, 0));
    assert_eq!(app.get_total(), 1);
    controller.picked_file(3, "export.csv", csv.as_bytes().to_vec());
    assert_eq!((app.get_import_added(), app.get_import_skipped()), (0, 1));
    controller.picked_file(3, "export.kdbx", vec![0x03, 0xd9, 0xa2, 0x9a, 0, 0]);
    assert_eq!(
        app.get_error_code(),
        26,
        "a protected file needs its password"
    );

    // "Check this password": its strength here, the leak check only on the tap.
    controller.set_leak_lookup(|password| {
        assert_eq!(password, "password123");
        Ok(12_345)
    });
    app.invoke_open_item(0);
    assert!(!app.get_d_checked());
    app.invoke_check_password();
    assert!(app.get_d_checked() && app.get_d_weakness() != 0);
    assert_eq!(
        (app.get_d_leak(), app.get_d_leak_count().as_str()),
        (12_345, "12,345")
    );
    app.invoke_close_item();
    controller.set_leak_lookup(|_| Err("offline".into()));
    app.invoke_open_item(0);
    assert!(!app.get_d_checked(), "nothing stays from the last item");
    app.invoke_check_password();
    assert_eq!(app.get_d_leak(), -2);
    app.invoke_close_item();

    // Switching: the open vault locks, the other one's unlock shows.
    app.invoke_switch_vault(0);
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(
        (app.get_vault_name().as_str(), controller.path()),
        ("Test vault", path.clone())
    );
    app.invoke_switch_vault(1);
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_vault_name(), "Work");
    // Removing it from the phone: its copy and its Secret Key go; the first one shows.
    app.invoke_remove_vault();
    assert_eq!(app.get_notice_code(), 17);
    assert!(!path.with_file_name("vault-2.vault").exists());
    assert!(
        vault_platform::secret_store::load(&work_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(app.get_vaults().row_count(), 1);
    assert_eq!(
        (app.get_screen(), controller.path()),
        (Screen::Unlock, path.clone())
    );
    type_secret(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );

    // ---- sync through a server: the computer invites the phone ----
    let server = TestServer::start();
    let pc_id = vault_core::sync::DeviceId::generate().unwrap();
    let pc_server = ServerTarget::join(
        &server.url,
        &vault_id,
        pc_id,
        "PC",
        &vault_server::admin_invite(server.data.path(), 1).unwrap().0,
    )
    .unwrap();
    let mut pc = open_file(&path, &secret_key);
    let mut pc_seen = vault_core::sync::SeenRevisions::new();
    sync::join(&mut pc, pc_id, "PC").unwrap();
    pc.add_item(&ItemData::new(ItemKind::SecureNote, "From the computer"))
        .unwrap();
    pc_server.put(pc_id, &pc.to_bytes().unwrap()).unwrap();
    let link = pc_server
        .invite_link(&pc_server.invite().unwrap())
        .to_text()
        .to_string();

    assert_eq!(app.get_sync_state(), 0, "off until joined");
    assert_eq!(app.get_sync_place(), "");
    // WebDAV over plain http to the internet is refused before anything is sent.
    app.set_sync_form(1);
    app.set_sync_address("http://dav.example.com/vault".into());
    app.set_sync_user("tester".into());
    type_secret(&app, 4, "webdav-test-password");
    app.invoke_sync_use_webdav();
    assert_eq!(app.get_sync_state(), 3);
    assert!(
        app.get_sync_detail().contains("https"),
        "{}",
        app.get_sync_detail()
    );
    assert_eq!(app.get_sync_place(), "", "nothing kept");
    app.set_sync_form(0);
    app.set_sync_invite_typed("not an invite".into());
    app.invoke_sync_join();
    assert_eq!(app.get_sync_state(), 3);
    assert!(app.get_sync_detail().contains("vaultsync"));
    app.set_sync_invite_typed(link.as_str().into());
    app.invoke_sync_join();
    assert_eq!(
        (app.get_sync_state(), app.get_sync_detail().as_str()),
        (1, ""),
        "joined and synced"
    );
    assert_eq!(app.get_sync_place(), server.url.as_str());
    assert_eq!(app.get_total(), 3, "the computer's note came in");
    assert_eq!(app.get_notice_code(), 9);
    assert_eq!(
        app.get_sync_invite_typed(),
        "",
        "the invite line is cleared"
    );

    // An item made on the phone reaches the computer.
    app.invoke_new_item();
    app.set_ed_title("From the phone".into());
    app.set_ed_username("phone-user".into());
    type_secret(&app, 3, "phone-test-password");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    app.invoke_close_item();
    controller.sync_round();
    assert_eq!(app.get_sync_state(), 1, "{}", app.get_sync_detail());
    let fetched = sync::fetch(&pc_server, pc_id, &sync::Tags::new()).unwrap();
    let round = sync::merge_all(&mut pc, &fetched, &mut pc_seen);
    assert!(round.changed());
    let titles: Vec<String> = pc
        .summaries()
        .unwrap()
        .iter()
        .map(|s| s.title.clone())
        .collect();
    assert!(titles.iter().any(|t| t == "From the phone"), "{titles:?}");
    // Settings → Sync: the copies the server keeps, and the devices.
    assert_eq!(app.get_sync_copies(), 2, "the computer's and this phone's");
    assert!(app.get_sync_total().ends_with("KB") && !app.get_sync_own().is_empty());
    let devices: Vec<(String, bool)> = app
        .get_sync_devices()
        .iter()
        .map(|d| (d.name.to_string(), d.own))
        .collect();
    assert_eq!(
        devices,
        [("Phone".to_owned(), true), ("PC".to_owned(), false)]
    );
    // Settings → Sync, as on a computer: invite another device (a QR code and its line).
    app.invoke_sync_add_device();
    assert!(
        app.get_sync_invite().starts_with("vaultsync:"),
        "{}",
        app.get_sync_detail()
    );
    assert!(app.get_sync_invite_qr().size().width > 0);
    app.invoke_sync_copy_invite();
    assert_eq!(app.get_notice_code(), 7);
    app.invoke_sync_hide_invite();
    assert_eq!(app.get_sync_invite(), "");
    // The server's address changes: the server there must know this phone's key.
    let other = TestServer::start();
    app.set_sync_new_address(other.url.as_str().into());
    app.invoke_sync_change_address();
    assert_eq!(app.get_sync_state(), 3, "another server is refused");
    assert_eq!(app.get_sync_place(), server.url.as_str());
    let renamed = server.url.replace("127.0.0.1", "localhost");
    app.set_sync_new_address(renamed.as_str().into());
    app.invoke_sync_change_address();
    assert_eq!(app.get_notice_code(), 19, "{}", app.get_sync_detail());
    assert_eq!(app.get_sync_place(), renamed.as_str());
    assert_eq!(app.get_sync_state(), 1, "{}", app.get_sync_detail());
    // A backup server: joined with an invite from `vault-server invite`, then removed.
    let backup_invite = vault_server::admin_invite(other.data.path(), 1).unwrap().0;
    app.set_sync_backup_invite(backup_invite.as_str().into());
    app.set_sync_backup_address(other.url.as_str().into());
    app.invoke_sync_join_backup();
    assert_eq!(app.get_notice_code(), 18, "{}", app.get_sync_detail());
    assert_eq!(app.get_sync_backup(), other.url.as_str());
    app.invoke_sync_remove_backup();
    assert_eq!(app.get_sync_backup(), "");
    drop(other);
    // Settings → Updates: the server's owner published one; the phone fetches it, checks it
    // and hands it to Android's installer.
    assert!(app.get_updates_available());
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        2,
        "nothing published yet: the newest"
    );
    let package = b"PK a test package, not an app".to_vec();
    let store = vault_server::Store::open(server.data.path()).unwrap();
    store.publish_app(&package, "0.0.0").unwrap();
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        2,
        "the same version isn't an update"
    );
    store.publish_app(&package, "99.0.0").unwrap();
    app.invoke_check_update();
    assert_eq!(
        (app.get_update_state(), app.get_update_version().as_str()),
        (3, "99.0.0"),
        "{}",
        app.get_error_detail()
    );
    app.invoke_install_update();
    assert_eq!(
        system.installed.borrow().as_deref(),
        Some(package.as_slice())
    );
    controller.update_installing("");
    assert_eq!(app.get_update_state(), 6);

    // A new phone is set up from the server alone: the invite line on its start screen.
    {
        // Its own app folder: a new phone has no device state yet.
        // SAFETY: the only test of this crate; set back below.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("VAULT_HOME", dir.path().join("second phone home"));
        }
        let fresh = PhoneWindow::new().unwrap();
        let fresh_path = dir.path().join("second phone").join("vault.vault");
        let second = Controller::start(&fresh, fresh_path.clone(), true);
        assert_eq!(fresh.get_screen(), Screen::Start);
        fresh.set_setup_invite("not an invite".into());
        fresh.invoke_setup_from_server();
        assert_eq!(fresh.get_error_code(), 12);
        let link = pc_server
            .invite_link(&pc_server.invite().unwrap())
            .to_text()
            .to_string();
        fresh.set_setup_invite(link.as_str().into());
        fresh.invoke_setup_from_server();
        assert_eq!(
            fresh.get_screen(),
            Screen::Unlock,
            "{}",
            fresh.get_error_detail()
        );
        assert!(fresh.get_incoming(), "the copy waits to prove itself");
        // Trying again with the same (now used) line goes on with the key the phone got.
        assert_eq!(
            fresh.get_setup_invite(),
            "",
            "the line is cleared once used"
        );
        fresh.set_setup_invite(link.as_str().into());
        fresh.invoke_setup_from_server();
        assert_eq!(
            (fresh.get_error_code(), fresh.get_screen()),
            (0, Screen::Unlock),
            "{}",
            fresh.get_error_detail()
        );
        type_secret(&fresh, 0, PASSWORD);
        fresh.invoke_unlock();
        assert_eq!(
            fresh.get_screen(),
            Screen::Vault,
            "{}",
            fresh.get_error_detail()
        );
        assert_eq!(fresh.get_total(), 4, "everything from both devices");
        assert_eq!(fresh.get_sync_place(), server.url.as_str());
        assert!(fresh_path.exists());
        second.lock();
        // SAFETY: as above.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("VAULT_HOME", dir.path().join("home"));
        }
    }

    // Settings → Sync → Remove: the second phone leaves the vault, its copy the server.
    controller.sync_round();
    let rows: Vec<(String, bool)> = app
        .get_sync_devices()
        .iter()
        .map(|d| (d.name.to_string(), d.own))
        .collect();
    assert_eq!(rows.len(), 3, "{rows:?}");
    let second_phone = rows
        .iter()
        .position(|(name, own)| !own && name == "Phone")
        .unwrap();
    app.invoke_sync_remove_device(i32::try_from(second_phone).unwrap());
    assert_eq!(app.get_notice_code(), 15, "{}", app.get_error_detail());
    assert_eq!(app.get_sync_devices().row_count(), 2);
    assert_eq!(
        pc_server.list().unwrap().len(),
        2,
        "its copy left the server"
    );

    // Stop: the phone forgets its server key; the copies stay on the server.
    app.invoke_sync_stop();
    assert_eq!(
        (app.get_sync_state(), app.get_sync_place().as_str()),
        (0, "")
    );
    assert_eq!(
        pc_server.list().unwrap().len(),
        2,
        "the computer's and this phone's"
    );
    drop(server);

    // ---- another phone: the Secret Key is typed once ----
    app.invoke_lock_now();
    vault_platform::secret_store::forget(&vault_id).unwrap();
    app.invoke_lock_now();
    assert!(app.get_needs_secret_key());
    type_secret(&app, 0, PASSWORD);
    type_secret(&app, 1, &secret_key);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    app.invoke_lock_now();
    assert!(!app.get_needs_secret_key(), "kept on the phone from now on");
    vault_platform::secret_store::forget(&vault_id).unwrap();
}
