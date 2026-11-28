//! The phone app end to end, headless: a vault made on the computer is brought in, then
//! items, the item page, codes, generator, lock, unlock, a newer copy, and sync through a
//! running server. Then, each on a phone of its own: leaving the app while a job holds the
//! vault, recovery with two parts of the kit, fingerprint unlock's 14 days, the generator's
//! history behind the item lock. Slow work runs inline; test values only.

use std::{
    cell::{Cell, RefCell},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{Mutex, MutexGuard, PoisonError},
};

use slint::{ComponentHandle, Model};
use vault_core::{
    GuardCheck, ItemData, ItemKind, KdfParams, PartLabel, RecoveryParts, SecretKey, Unlock, Vault,
};
use zeroize::Zeroizing;

use vault_platform::sync::{self, ServerTarget, Target as _};
use vault_sync_wire::releases::{
    self, Verified as GithubRelease,
    testing::{self as signing, TestKey},
};

use crate::{
    Controller,
    autofill::{self, Asker, Kept, Recipient},
    controller::Github,
    system::{PdfPage, PdfPages, PromptWords, System},
    ui::{Page, PhoneWindow, Place, Screen, Secrets, Words},
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
    /// This phone is set to Brazilian Portuguese: "the phone's" is Portuguese in Settings.
    fn language(&self) -> Option<String> {
        Some("pt-BR".into())
    }

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

/// The tests that open windows here point `VAULT_HOME` (the app's folder: device state, the
/// leak watch, caches) at a folder of their own: one at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Takes this test's turn and points `VAULT_HOME` at `home` while it is held. The Secret Keys
/// the tests keep go under a stand-in for the security chip (CRYPTO.md §2.2.1), so none makes
/// a key in this computer's TPM.
fn app_home(home: &Path) -> MutexGuard<'static, ()> {
    let turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    static CHIP: std::sync::Once = std::sync::Once::new();
    CHIP.call_once(|| {
        vault_platform::secret_store::use_key_wrapper(Some(std::sync::Arc::new(
            vault_platform::secret_store::MemoryChip::default(),
        )));
    });
    // SAFETY: every test that sets the environment holds this turn while it does, and the
    // other tests of this crate don't read it.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", home);
    }
    turn
}

thread_local! {
    /// Slint's test platform, set up once on each test's thread.
    static SLINT: std::cell::OnceCell<()> = const { std::cell::OnceCell::new() };
}

fn window() -> PhoneWindow {
    SLINT.with(|ready| {
        ready.get_or_init(i_slint_backend_testing::init_no_event_loop);
    });
    PhoneWindow::new().unwrap()
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

/// An Ed25519 key with the passphrase "test passphrase" (`ssh-keygen -a 16`), made for these
/// tests only and used nowhere else.
const TEST_KEY_WITH_PASSPHRASE: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA0TjAB38
/sg1ThhtxIUIrWAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIoWYkuAAQY0S/aO
sdrqJB5LP0uxLhmWnAw72FYU0prvAAAAkNYSHmRVPZ2HrZW6em03/rdF4JNdpZ4zLsn2pM
hZrUpq/EM7MrDjl02ntzjYCY3da9wWOCj7wAco4y5RjA+Ga4ThXNwSDjIGttUkNVLzbNBU
YN2/uZfR9kREhL4bPgjwnGEgQq9pKW2VzA/CgSGzJJEZINpVZAE2yCsoFzqo0csEE16SRm
ka3lGSi0BDvKit3g==
-----END OPENSSH PRIVATE KEY-----
";

/// An edit of a secret field's input on the phone, with the keyboard's cursor at its end.
fn typed_end(secrets: &Secrets<'_>, id: i32, text: slint::SharedString) -> slint::SharedString {
    let end = i32::try_from(text.len()).unwrap();
    secrets.invoke_typed(id, text, end)
}

/// What a secret field holds, read through its eye (opened and closed again).
fn field_text(app: &PhoneWindow, field: i32) -> String {
    let secrets = app.global::<Secrets>();
    secrets.invoke_toggle_shown(field);
    let index = usize::try_from(field).unwrap();
    let text = secrets.get_shown().row_data(index).unwrap().to_string();
    secrets.invoke_toggle_shown(field);
    text
}

fn caret(app: &PhoneWindow, field: usize) -> i32 {
    app.global::<Secrets>()
        .get_carets()
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
    let _turn = app_home(&dir.path().join("home"));

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

    let app = window();
    let path = dir.path().join("phone").join("vault.vault");
    let controller = Controller::start(&app, path.clone(), true);
    // The phone's own language may be Portuguese (this computer's): the test starts in English.
    app.invoke_language_changed(1);

    // ---- a QR code scanned on the start screen ----
    // No scanner here (a computer's window): no Scan button.
    assert!(!app.get_can_scan());
    // A code that isn't an invite is said so, with its own message, under the field.
    controller.code_scanned(crate::controller::scan::SETUP, "https://example.com/menu");
    assert_eq!(app.get_setup_invite(), "https://example.com/menu");
    assert_eq!(app.get_error_code(), 28);
    // No Play services on the phone: the message says to paste the line instead.
    controller.scan_failed("unavailable");
    assert_eq!(app.get_error_code(), 29);
    assert!(
        app.global::<Words>()
            .invoke_error(29, "unavailable".into())
            .contains("Paste the line")
    );
    app.set_setup_invite("".into());
    app.set_error_code(0);

    // ---- the system keyboard (Android): the hidden input only ever holds stand-ins ----
    {
        let secrets = app.global::<Secrets>();
        let p = '\u{1}';
        assert_eq!(secrets.invoke_placeholders(0), "");
        assert_eq!(typed_end(&secrets, 0, "ab".into()), format!("{p}{p}"));
        assert_eq!(length(&app, 0), 2);
        // One more letter after the stand-ins.
        assert_eq!(
            typed_end(&secrets, 0, format!("{p}{p}c").into()),
            format!("{p}{p}{p}")
        );
        // Backspace: one stand-in gone.
        assert_eq!(
            typed_end(&secrets, 0, format!("{p}{p}").into()),
            format!("{p}{p}")
        );
        assert_eq!(length(&app, 0), 2);
        // All selected and typed over: none left, the new letter in.
        assert_eq!(typed_end(&secrets, 0, "x".into()), format!("{p}"));
        assert_eq!(secrets.invoke_placeholders(0), format!("{p}"));
        secrets.invoke_clear(0);
        assert_eq!(length(&app, 0), 0);

        // Letters of every UTF-8 length: each stand-in is as long as its letter in UTF-8 and
        // UTF-16, so the keyboard's cursor (placed by Slint right after) is never inside one.
        // With same-length stand-ins, this is where typing on the phone crashed the app.
        let typed = "aé€😀";
        let back = typed_end(&secrets, 0, typed.into());
        assert_eq!(back.len(), typed.len());
        assert_eq!(back.encode_utf16().count(), typed.encode_utf16().count());
        assert!((0..=typed.len()).all(|i| typed.is_char_boundary(i) == back.is_char_boundary(i)));
        assert!(!back.chars().any(|c| typed.contains(c)));
        assert_eq!(length(&app, 0), 4);
        // Then a pasted line after them, and one of them deleted from the end.
        let back = typed_end(&secrets, 0, format!("{back}ção").into());
        assert_eq!(back.len(), format!("{typed}ção").len());
        assert_eq!(length(&app, 0), 7);
        let shorter: String = back.chars().take(6).collect();
        assert_eq!(typed_end(&secrets, 0, shorter.as_str().into()), shorter);
        assert_eq!(length(&app, 0), 6);
        // A control character the keyboard sent isn't in the field, and stays as it is.
        let back = typed_end(&secrets, 0, format!("{shorter}\t").into());
        assert!(back.ends_with('\t'));
        assert_eq!(length(&app, 0), 6);
        assert_eq!(typed_end(&secrets, 0, shorter.as_str().into()), shorter);
        assert_eq!(length(&app, 0), 6);
        secrets.invoke_clear(0);

        // The cursor anywhere in the field: a mistake is put right where it is.
        typed_end(&secrets, 0, "abcd".into());
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("abcd", 4));
        // A letter typed with the keyboard's cursor after the second character.
        let back = secrets.invoke_typed(0, format!("{p}{p}X{p}{p}").into(), 3);
        assert_eq!(back, format!("{p}{p}{p}{p}{p}"));
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("abXcd", 3));
        // Backspace there: the cursor now after the second character, one stand-in fewer.
        secrets.invoke_typed(0, format!("{p}{p}{p}{p}").into(), 2);
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("abcd", 2));
        // A selection typed over: the second and third characters replaced by one.
        secrets.invoke_typed(0, format!("{p}Y{p}").into(), 2);
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("aYd", 2));
        // The app's own keyboard and a computer's: keys go in at the cursor, which the
        // arrows (and a tap) move; Backspace takes the character before it, Delete the one
        // after.
        secrets.invoke_move_caret(0, 1);
        secrets.invoke_insert(0, "Z".into());
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("aZYd", 2));
        secrets.invoke_delete(0);
        assert_eq!(field_text(&app, 0), "aZd");
        secrets.invoke_backspace(0);
        assert_eq!((field_text(&app, 0).as_str(), caret(&app, 0)), ("ad", 1));
        secrets.invoke_move_caret(0, 99);
        assert_eq!(caret(&app, 0), 2);
        // Offsets in the input and character counts, both ways.
        let input = "\u{1}\u{80}\u{E000}\u{F0000}";
        assert_eq!(secrets.invoke_char_at(input.into(), 3), 2);
        assert_eq!(secrets.invoke_byte_at(input.into(), 3), 6);
        assert_eq!(secrets.invoke_byte_at(input.into(), 9), 10);
        secrets.invoke_clear(0);
        assert_eq!(caret(&app, 0), 0);
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
            input = typed_end(&secrets, 0, format!("{input}#").into()).into();
            input.pop();
            input = typed_end(&secrets, 0, input.as_str().into()).into();
        }
        input = typed_end(&secrets, 0, format!("{input}{letter}").into()).into();
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
    // A key with a passphrase (made for this test only): the sheet asks for it; a wrong one
    // says so, the right one opens it and the key is kept without it.
    let generated_public = app.get_ed_ssh_public();
    controller.picked_file(
        2,
        "id_ed25519",
        TEST_KEY_WITH_PASSPHRASE.as_bytes().to_vec(),
    );
    assert_eq!(app.get_confirming(), 17, "asks for the passphrase");
    assert_eq!(
        app.get_ed_ssh_public(),
        generated_public,
        "the key in hand stays"
    );
    type_secret(&app, 11, "not the passphrase");
    app.invoke_confirmed(17);
    assert_eq!((app.get_error_code(), app.get_confirming()), (35, 17));
    assert_eq!(length(&app, 11), 0, "typed again after a try");
    type_secret(&app, 11, "test passphrase");
    app.invoke_confirmed(17);
    assert_eq!((app.get_error_code(), app.get_confirming()), (0, 0));
    assert_eq!(app.get_ed_ssh_type(), "Ed25519");
    assert_eq!(
        app.get_ed_ssh_public(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIoWYkuAAQY0S/aOsdrqJB5LP0uxLhmWnAw72FYU0prv test@phone"
    );
    assert!(app.get_ed_ssh_fingerprint().starts_with("SHA256:"));
    // Back to a key made here for the rest of the test.
    app.invoke_ed_ssh_generate();
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
    // "Make a strong one" (after its confirmation) opens the generator for the editor; Use
    // brings its password back, shown.
    app.invoke_ed_generate();
    assert_eq!(
        (app.get_page(), app.get_place(), app.get_gen_for_editor()),
        (Page::None, Place::Generator, true)
    );
    app.invoke_gen_use();
    assert_eq!(app.get_page(), Page::Editor);
    assert!(!app.get_gen_for_editor());
    let generated = app.get_ed_password().to_string();
    assert_eq!(generated.chars().count(), 20, "a made password is shown");
    // It was used: the generator's history keeps it until a login uses it.
    assert_eq!(app.get_gen_history().row_count(), 1);
    app.invoke_save_item();
    assert_eq!(
        app.get_gen_history().row_count(),
        0,
        "a password a login uses leaves the history"
    );
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
    // A copy goes into the history, masked until shown; it can be deleted.
    app.invoke_gen_copy();
    assert_eq!(app.get_gen_history().row_count(), 1);
    let masked = app.get_gen_history().row_data(0).unwrap().text;
    assert!(masked.chars().all(|c| c == '•'), "masked until shown");
    app.set_gen_history_shown(true);
    app.invoke_gen_history_toggled();
    assert_eq!(
        app.get_gen_history().row_data(0).unwrap().text,
        app.get_gen_password()
    );
    // When: the day and the time, to the minute.
    let when = app.get_gen_history().row_data(0).unwrap().when;
    assert_eq!(when.len(), "2026-11-23 19:42".len(), "{when}");
    // Deleting one, as the screen does it: the sheet asks first, Cancel keeps it.
    app.set_gen_deleting(0);
    app.invoke_ask(15);
    app.set_confirming(0);
    app.invoke_sheet_closed(15);
    assert_eq!(app.get_gen_history().row_count(), 1, "kept on Cancel");
    app.set_gen_deleting(0);
    app.invoke_ask(15);
    app.invoke_confirmed(15);
    assert_eq!(app.get_gen_history().row_count(), 0);
    assert_eq!((app.get_confirming(), app.get_gen_deleting()), (0, -1));
    // The whole list, the same way.
    app.invoke_gen_copy();
    app.invoke_ask(14);
    app.invoke_confirmed(14);
    assert_eq!(app.get_gen_history().row_count(), 0);
    app.set_gen_history_shown(false);
    // "New login with it": the editor opens with the password in it.
    app.invoke_gen_new_login();
    assert_eq!((app.get_page(), app.get_ed_new()), (Page::Editor, true));
    assert_eq!(
        length(&app, 3),
        i32::try_from(app.get_gen_password().chars().count()).unwrap()
    );
    app.invoke_cancel_edit();
    app.set_place(Place::Items);

    // ---- folders: made in Settings, chosen in the editor, a filter on the list ----
    app.set_folder_editing(-1);
    app.set_folder_name("Work".into());
    app.set_folder_icon("briefcase".into());
    app.invoke_folder_save();
    assert_eq!(app.get_folders().row_count(), 1);
    assert_eq!(app.get_folders().row_data(0).unwrap().icon, "briefcase");
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Office wifi".into());
    app.set_ed_notes(
        "**Network**: guest
- one
- two"
            .into(),
    );
    app.set_ed_folder(0);
    app.set_ed_glyph("wifi".into());
    app.set_ed_glyph_color(3);
    app.set_ed_glyph_bg(9);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(
        (app.get_d_folder().as_str(), app.get_d_glyph().as_str()),
        ("Work", "wifi")
    );
    assert_eq!((app.get_d_glyph_color(), app.get_d_glyph_bg()), (3, 9));
    assert!(!app.get_d_created().is_empty());
    app.invoke_close_item();
    assert_eq!(app.get_folders().row_data(0).unwrap().count, 1);
    app.set_folder_filter(0);
    app.invoke_filter_changed(0);
    assert_eq!(app.get_items().row_count(), 1, "only the folder's items");
    let row = app.get_items().row_data(0).unwrap();
    assert_eq!(
        (row.glyph.as_str(), row.glyph_color, row.glyph_bg),
        ("wifi", 3, 9)
    );
    app.set_folder_filter(-1);
    app.invoke_filter_changed(0);

    // A folder inside it (Inside: Work), with an icon colour: shown under Work, by its own
    // name; Work counts and shows the items of both.
    app.set_folder_editing(-1);
    app.set_folder_name("Old".into());
    app.set_folder_parent(0);
    app.set_folder_icon("database".into());
    app.set_folder_color(4);
    app.invoke_folder_save();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let inner = app.get_folders().row_data(1).unwrap();
    assert_eq!(
        (
            inner.name.as_str(),
            inner.label.as_str(),
            inner.depth,
            inner.color
        ),
        ("Work/Old", "Old", 1, 4)
    );
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Old router".into());
    app.set_ed_folder(1);
    app.invoke_save_item();
    app.invoke_close_item();
    assert_eq!(
        app.get_folders().row_data(0).unwrap().count,
        2,
        "Work and Old"
    );
    assert_eq!(app.get_folders().row_data(1).unwrap().count, 1);
    app.set_folder_filter(0);
    app.invoke_filter_changed(0);
    assert_eq!(app.get_items().row_count(), 2, "Work shows Old's items too");
    app.set_folder_filter(-1);
    app.invoke_filter_changed(0);
    // Work renamed: Old follows it. Work can't go inside Old.
    app.invoke_folder_edit(0);
    assert_eq!(app.get_folder_not_parent().row_data(1), Some(true));
    app.set_folder_parent(1);
    app.invoke_folder_save();
    assert_eq!(app.get_error_code(), 5, "not inside a folder inside it");
    app.set_folder_parent(-1);
    app.set_folder_name("Office".into());
    app.invoke_folder_save();
    assert_eq!(app.get_folders().row_data(1).unwrap().name, "Office/Old");
    // Old leaves (its item stays, in no folder), the rest goes back as it was.
    app.invoke_folder_edit(1);
    assert_eq!(
        (app.get_folder_name().as_str(), app.get_folder_parent()),
        ("Old", 0)
    );
    app.invoke_folder_delete();
    app.invoke_folder_edit(0);
    app.set_folder_name("Work".into());
    app.invoke_folder_save();
    let index = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "Old router")
        .unwrap();
    app.invoke_open_item(i32::try_from(index).unwrap());
    app.invoke_edit_item();
    app.invoke_ask(5);
    app.invoke_confirmed(5);

    // ---- a counter-based code: Next moves it on, in the item (it syncs) ----
    app.invoke_new_code();
    app.set_ed_totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());
    app.set_ed_counter(true);
    app.set_ed_title("Bank token".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert!(app.get_d_counter_based());
    assert_eq!(app.get_d_code(), "755 224", "RFC 4226, counter 0");
    app.invoke_next_code();
    assert_eq!(app.get_d_code(), "287 082", "counter 1");
    app.invoke_close_item();
    let codes = app.get_codes();
    let bank = (0..codes.row_count())
        .find(|&i| codes.row_data(i).unwrap().title == "Bank token")
        .unwrap();
    assert!(codes.row_data(bank).unwrap().counter);

    // ---- password health: the weak and reused ones, the worst first ----
    app.invoke_health_opened();
    assert!(app.get_health_logins() >= 1);
    assert_eq!(
        app.get_health_rows().row_count(),
        app.get_health_score() as usize
    );

    // ---- export: asked in the sheet, the master password first (checked against the
    // file); a protected one needs a password of its own; the bytes wait to be saved ----
    app.invoke_ask(7);
    assert_eq!(app.get_confirming(), 7);
    app.invoke_confirmed(7);
    assert_eq!(app.get_error_code(), 13, "no master password");
    type_secret(&app, 10, "not the master password");
    app.invoke_confirmed(7);
    assert_eq!(app.get_error_code(), 30, "no password for the export");
    type_secret(&app, 9, "an export password");
    app.invoke_confirmed(7);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (13, 7),
        "a wrong master password: the sheet stays"
    );
    assert!(controller.file_to_save(-1).is_none());
    assert_eq!(length(&app, 10), 0, "cleared after the check");
    type_secret(&app, 10, PASSWORD);
    app.invoke_confirmed(7);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (0, 0),
        "{}",
        app.get_error_detail()
    );
    assert_eq!(
        (length(&app, 9), length(&app, 10)),
        (0, 0),
        "wiped after use"
    );
    let (name, protected_export) = controller.file_to_save(-1).unwrap();
    assert!(name.ends_with(".vaultx"));
    assert!(!protected_export.is_empty());
    app.invoke_ask(6);
    type_secret(&app, 10, PASSWORD);
    app.invoke_confirmed(6);
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    let (name, json) = controller.file_to_save(-1).unwrap();
    assert!(name.ends_with(".json"));
    assert!(String::from_utf8_lossy(&json).contains("Office wifi"));
    assert!(controller.file_to_save(-1).is_none(), "handed out once");
    // Cancelled: what was typed goes.
    app.invoke_ask(8);
    type_secret(&app, 10, PASSWORD);
    app.set_confirming(0);
    app.invoke_sheet_closed(8);
    assert_eq!(length(&app, 10), 0);

    // ---- the vault's icon on this phone, its colours, its name ----
    app.invoke_vault_icon_changed("home".into(), 0, 0);
    assert_eq!(app.get_vault_icon(), "home");
    app.invoke_vault_icon_changed("home".into(), 2, 9);
    assert_eq!(
        (app.get_vault_icon_color(), app.get_vault_icon_bg()),
        (2, 9)
    );
    let row = app.get_vaults().row_data(0).unwrap();
    assert_eq!(
        (row.icon.as_str(), row.icon_color, row.icon_bg),
        ("home", 2, 9)
    );
    app.invoke_vault_icon_changed("".into(), 0, 0);
    assert_eq!(app.get_vault_icon(), "");
    let before = app.get_vault_name();
    app.set_vault_new_name("   ".into());
    app.invoke_vault_rename();
    assert_eq!(app.get_error_code(), 5, "a name is needed");
    app.set_vault_new_name("Renamed on the phone".into());
    app.invoke_vault_rename();
    assert_eq!(app.get_vault_name(), "Renamed on the phone");
    assert!(!app.get_vault_renaming());
    assert_eq!(
        app.get_vaults().row_data(0).unwrap().name,
        "Renamed on the phone"
    );
    app.set_vault_new_name(before);
    app.invoke_vault_rename();

    // What these steps made goes again, for what follows: the two items, the folder.
    for title in ["Office wifi", "Bank token"] {
        let index = (0..app.get_items().row_count())
            .find(|&i| app.get_items().row_data(i).unwrap().title == title)
            .unwrap();
        app.invoke_open_item(i32::try_from(index).unwrap());
        app.invoke_edit_item();
        app.invoke_delete_item();
    }
    app.invoke_folder_edit(0);
    app.invoke_folder_delete();
    assert_eq!(app.get_folders().row_count(), 0);

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
    app.invoke_ask(13);
    type_secret(&app, 2, "0000");
    app.invoke_confirmed(13);
    assert_eq!(
        (
            app.get_error_code(),
            app.get_d_check(),
            app.get_confirming()
        ),
        (7, 2, 13)
    );
    type_secret(&app, 2, "4821");
    app.invoke_confirmed(13);
    assert_eq!(
        (
            app.get_error_code(),
            app.get_d_check(),
            app.get_confirming()
        ),
        (0, 0, 0),
        "shown, and the sheet closed"
    );
    assert!(app.get_d_has_password() && app.get_d_has_code());
    app.invoke_close_item();
    app.invoke_open_item(0);
    assert_eq!(app.get_d_check(), 2, "closed again when the item is left");
    app.invoke_close_item();

    // ---- delete, once the confirmation sheet said yes ----
    app.invoke_open_item(1);
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    assert_eq!(app.get_total(), 2);
    app.invoke_delete_item();
    assert_eq!((app.get_total(), app.get_page()), (1, Page::None));
    assert_eq!(app.get_notice_code(), 4);

    // ---- the master password changes on the phone (and back, for what follows) ----
    const NEW_PASSWORD: &str = "phone new master passphrase";
    app.set_place(Place::Settings);
    app.invoke_ask(12);
    type_secret(&app, 5, "not the password");
    type_secret(&app, 6, NEW_PASSWORD);
    type_secret(&app, 7, NEW_PASSWORD);
    app.invoke_confirmed(12);
    assert_eq!(app.get_error_code(), 13, "{}", app.get_error_detail());
    assert_eq!(app.get_confirming(), 12, "the sheet stays");
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
    assert_eq!(app.get_confirming(), 0, "the sheet closed");
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
    app.invoke_ask(12);
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
    app.invoke_ask(12);
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
    app.invoke_ask(12);
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
    // The language: kept, shown as chosen, and the words change with it. "Give it a name
    // first." is the English text of Words.error(5); its Portuguese is in translations/.
    let words = app.global::<Words>();
    app.invoke_language_changed(2);
    assert_eq!(app.get_language_choice(), 2);
    assert_eq!(
        words.invoke_error(5, "".into()),
        "Dê um nome primeiro.",
        "Portuguese chosen"
    );
    app.invoke_language_changed(1);
    assert_eq!(
        words.invoke_error(5, "".into()),
        "Give it a name first.",
        "English chosen"
    );
    // "The phone's" follows the phone, which is set to Portuguese in this test.
    app.invoke_language_changed(0);
    assert_eq!(app.get_language_choice(), 0);
    assert_eq!(
        words.invoke_error(5, "".into()),
        "Dê um nome primeiro.",
        "the phone's language"
    );

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
        (app.get_confirming(), app.get_import_name().as_str()),
        (11, "export.kdbx"),
        "a protected file: its password is asked for"
    );
    app.invoke_confirmed(11);
    assert_eq!(app.get_error_code(), 26, "nothing typed");
    type_secret(&app, 8, "a password");
    app.invoke_confirmed(11);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (25, 11),
        "not a database after all: told in the sheet"
    );
    app.set_confirming(0);
    app.invoke_sheet_closed(11);
    assert_eq!(app.get_import_name(), "", "the file is dropped");

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

    // The leak watch (off until turned on): once a day, every login checked; a new leak is told
    // once and marked in the list.
    controller.set_leak_batch(|queries| Ok(queries.iter().map(|(i, _)| (*i, 7)).collect()));
    app.set_notice_code(0);
    app.invoke_leak_watch_changed(true);
    assert_eq!(app.get_notice_code(), 21, "{}", app.get_error_detail());
    assert!(app.get_items().row_data(0).unwrap().leaked);
    app.set_notice_code(0);
    app.invoke_leak_watch_changed(true);
    assert_eq!(
        app.get_notice_code(),
        0,
        "checked today already: nothing new to tell"
    );
    app.invoke_leak_watch_changed(false);
    assert!(
        !app.get_items().row_data(0).unwrap().leaked,
        "off: nothing marked"
    );

    // The protected export made above: its password, asked in the sheet; a wrong one is told
    // there and the file keeps waiting.
    controller.picked_file(3, "vault-export.vaultx", protected_export);
    assert_eq!(app.get_confirming(), 11);
    type_secret(&app, 8, "not the export password");
    app.invoke_confirmed(11);
    assert_eq!((app.get_error_code(), app.get_confirming()), (26, 11));
    assert_eq!(length(&app, 8), 0, "typed again");
    type_secret(&app, 8, "an export password");
    app.invoke_confirmed(11);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (0, 0),
        "{}",
        app.get_error_detail()
    );
    assert!(app.get_import_added() > 0);

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
        &vault_server::admin_invite(server.data.path(), 1, None)
            .unwrap()
            .0,
    )
    .unwrap();
    let mut pc = open_file(&path, &secret_key);
    let mut pc_seen = vault_core::sync::SeenRevisions::new();
    sync::join(&mut pc, pc_id, "PC").unwrap();
    // A login with a passkey the computer's browser made.
    let mut from_pc = ItemData::login("From the computer", "pc-user", "", "https://pc.example");
    from_pc.passkeys = vec![
        vault_core::Passkey::new("pc.example", b"pc-user-id", "pc-user@pc.example", "PC user")
            .unwrap(),
    ];
    pc.add_item(&from_pc).unwrap();
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
    // Typed apart (Type the address): a pin that isn't one is refused before anything is sent.
    app.set_sync_by_hand(true);
    app.set_sync_address(server.url.as_str().into());
    app.set_sync_pin("not a pin".into());
    app.invoke_sync_join();
    assert_eq!(app.get_sync_state(), 3);
    assert!(
        app.get_sync_detail().contains("pin"),
        "{}",
        app.get_sync_detail()
    );
    app.set_sync_by_hand(false);
    app.set_sync_pin("".into());
    app.set_sync_invite_typed(link.as_str().into());
    app.invoke_sync_join();
    assert_eq!(
        (app.get_sync_state(), app.get_sync_detail().as_str()),
        (1, ""),
        "joined and synced"
    );
    assert_eq!(app.get_sync_place(), server.url.as_str());
    assert_eq!(app.get_total(), 3, "the computer's login came in");
    assert_eq!(app.get_notice_code(), 9);
    // Its passkey shows on the phone, and stays through an edit there.
    let open_from_pc = || {
        let index = (0..app.get_items().row_count())
            .find(|&i| app.get_items().row_data(i).unwrap().title == "From the computer")
            .unwrap();
        app.invoke_open_item(i32::try_from(index).unwrap());
    };
    open_from_pc();
    assert_eq!(app.get_d_passkeys().row_count(), 1);
    let passkey = app.get_d_passkeys().row_data(0).unwrap();
    assert_eq!(
        (passkey.site.as_str(), passkey.user.as_str()),
        ("pc.example", "pc-user@pc.example")
    );
    // The vault locks every item with the PIN (above): the computer's login too.
    assert_eq!(app.get_d_check(), 2);
    type_secret(&app, 2, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    app.invoke_close_item();
    open_from_pc();
    assert_eq!(
        app.get_d_passkeys().row_count(),
        1,
        "kept through an edit on the phone"
    );
    app.invoke_close_item();
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
    // Settings → Sync, as on a computer: invite another device (a QR code and its line),
    // once the master password is typed again in the sheet.
    app.invoke_ask(16);
    type_secret(&app, 10, "not the password");
    app.invoke_confirmed(16);
    assert_eq!((app.get_error_code(), app.get_confirming()), (13, 16));
    assert!(app.get_sync_invite().is_empty(), "no invite without it");
    type_secret(&app, 10, PASSWORD);
    app.invoke_confirmed(16);
    assert_eq!(app.get_confirming(), 0);
    assert_eq!(length(&app, 10), 0);
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
    let backup_invite = vault_server::admin_invite(other.data.path(), 1, None)
        .unwrap()
        .0;
    app.set_sync_backup_invite(backup_invite.as_str().into());
    app.set_sync_backup_address(other.url.as_str().into());
    app.invoke_sync_join_backup();
    assert_eq!(app.get_notice_code(), 18, "{}", app.get_sync_detail());
    assert_eq!(app.get_sync_backup(), other.url.as_str());
    app.invoke_sync_remove_backup();
    assert_eq!(app.get_sync_backup(), "");
    drop(other);
    // Settings → Updates, from the vault server rather than GitHub: the server's owner
    // published one; the phone fetches it, checks it and hands it to Android's installer.
    // The manifests here are signed with a key made for this test, which the phone is told
    // to take in place of the project's.
    let key = TestKey::new();
    controller.use_release_keys(vec![key.public()]);
    assert!(app.get_updates_available());
    app.invoke_update_source_changed(1);
    assert!(app.get_update_servers());
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        7,
        "nothing published yet: the server has none"
    );
    let package = b"PK a test package, not an app".to_vec();
    let store = vault_server::Store::open(server.data.path()).unwrap();
    store.publish_app(&package, "0.0.0", None).unwrap();
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        2,
        "the same version isn't an update"
    );
    // A newer one without the release's signed manifest (the owner's own build, or a server
    // older than this): never offered.
    store.publish_app(&package, "99.0.0", None).unwrap();
    app.invoke_check_update();
    assert_eq!(
        (app.get_update_state(), app.get_error_code()),
        (5, 27),
        "{}",
        app.get_error_detail()
    );
    // Signed by another key than the one taken: refused too.
    let stranger = TestKey::new();
    store
        .publish_app(
            &package,
            "99.0.0",
            Some(&signed_update(&stranger, "99.0.0", &package)),
        )
        .unwrap();
    app.invoke_check_update();
    assert_eq!(app.get_update_state(), 5, "{}", app.get_error_detail());
    // A server that changes what it hands on: another package under the signed manifest, or
    // the manifest itself rewritten for its own package. The phone refuses both.
    let signed = signed_update(&key, "99.0.0", &package);
    let other_package = b"PK\x03\x04 a package the server swapped in".to_vec();
    store
        .publish_app(&other_package, "99.0.0", Some(&signed))
        .unwrap();
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        5,
        "another package than the signed one"
    );
    let rewritten = releases::SignedManifest {
        manifest: signing::manifest_of(
            "99.0.0",
            &[(
                &releases::phone_package_name("99.0.0"),
                other_package.as_slice(),
            )],
        ),
        signature: signed.signature.clone(),
    };
    store
        .publish_app(&other_package, "99.0.0", Some(&rewritten))
        .unwrap();
    app.invoke_check_update();
    assert_eq!(
        app.get_update_state(),
        5,
        "a manifest changed after signing"
    );
    // The release's own manifest and signature, as `--app-updates` keeps them: offered.
    store
        .publish_app(&package, "99.0.0", Some(&signed))
        .unwrap();
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
        // SAFETY: this test holds the turn (`app_home`); set back below.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("VAULT_HOME", dir.path().join("second phone home"));
        }
        let fresh = PhoneWindow::new().unwrap();
        let fresh_path = dir.path().join("second phone").join("vault.vault");
        let second = Controller::start(&fresh, fresh_path.clone(), true);
        assert_eq!(fresh.get_screen(), Screen::Start);
        // The start screen tells of the look for updates, with its switch, on by default.
        assert!(fresh.get_update_checks());
        fresh.set_setup_invite("not an invite".into());
        fresh.invoke_setup_from_server();
        assert_eq!(fresh.get_error_code(), 28, "not an invite: its own message");
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

/// A phone of its own for one test: a vault as the computer makes it (`PASSWORD`, a new
/// Secret Key), brought in. Its Secret Key leaves the credential store at the end.
struct Phone {
    controller: Rc<Controller>,
    app: PhoneWindow,
    /// The phone's copy of the vault.
    path: PathBuf,
    secret_key: String,
    vault_id: String,
    _dir: tempfile::TempDir,
    _turn: MutexGuard<'static, ()>,
}

impl Phone {
    /// The vault (`made` adds to it) brought to a new phone: the unlock screen, nothing typed.
    fn brought(made: impl FnOnce(&mut Vault, &SecretKey)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let turn = app_home(&dir.path().join("home"));
        let key = SecretKey::generate().unwrap();
        let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
        made(&mut vault, &key);
        let from_computer = dir.path().join("from-the-computer.vault");
        std::fs::write(&from_computer, vault.to_bytes().unwrap()).unwrap();
        let app = window();
        let path = dir.path().join("phone").join("vault.vault");
        let controller = Controller::start(&app, path.clone(), true);
        app.invoke_language_changed(1);
        controller.bring_vault_file(&from_computer);
        assert_eq!(app.get_screen(), Screen::Unlock);
        Self {
            controller,
            app,
            path,
            secret_key: key.to_display_string().to_string(),
            vault_id: vault.id_hex(),
            _dir: dir,
            _turn: turn,
        }
    }

    /// [`Phone::brought`], then opened with the master password and the Secret Key.
    fn open(made: impl FnOnce(&mut Vault, &SecretKey)) -> Self {
        let phone = Self::brought(made);
        type_secret(&phone.app, 1, &phone.secret_key);
        phone.unlock(PASSWORD);
        phone
    }

    fn unlock(&self, password: &str) {
        type_secret(&self.app, 0, password);
        self.app.invoke_unlock();
        assert_eq!(
            self.app.get_screen(),
            Screen::Vault,
            "{}",
            self.app.get_error_detail()
        );
    }

    /// The vault file on the phone, as another device's sync would see it.
    fn file(&self) -> Vault {
        open_file(&self.path, &self.secret_key)
    }

    fn has_recovery_parts(&self) -> bool {
        Vault::inspect(&std::fs::read(&self.path).unwrap())
            .unwrap()
            .has_recovery_parts
    }

    fn keeps_secret_key(&self) -> bool {
        vault_platform::secret_store::load(&self.vault_id)
            .unwrap()
            .is_some()
    }

    fn open_item(&self, title: &str) {
        let index = (0..self.app.get_items().row_count())
            .find(|&i| self.app.get_items().row_data(i).unwrap().title == title)
            .unwrap();
        self.app.invoke_open_item(i32::try_from(index).unwrap());
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        let _ = vault_platform::secret_store::forget(&self.vault_id);
    }
}

#[test]
fn leaving_the_app_while_a_job_holds_the_vault_locks_it() {
    let phone = Phone::open(|vault, _| {
        vault
            .add_item(&ItemData::login(
                "Mail",
                "me",
                "mail-test-password",
                "mail.example",
            ))
            .unwrap();
    });
    let (app, controller) = (&phone.app, &phone.controller);
    app.invoke_lock_on_leave_changed(true);
    // The job starts, the app goes to the background before it is back, then it comes back.
    let leave_during = |start: &dyn Fn()| {
        controller.hold_jobs();
        start();
        assert!(app.get_busy(), "the job is on its way");
        controller.left_app();
        assert!(!controller.is_unlocked(), "locked although a job held it");
        controller.finish_held_jobs();
        assert!(
            !controller.is_unlocked(),
            "the job's end doesn't open it again"
        );
        assert_eq!(app.get_screen(), Screen::Unlock);
        assert_eq!(app.get_items().row_count(), 0);
        assert!(!app.get_busy());
    };

    // An export: nothing waits to be saved.
    leave_during(&|| {
        app.invoke_ask(6);
        type_secret(app, 10, PASSWORD);
        app.invoke_confirmed(6);
    });
    assert!(
        controller.file_to_save(-1).is_none(),
        "the export was dropped"
    );
    phone.unlock(PASSWORD);

    // A confirmation of a sensitive change: removing the vault from the phone isn't done.
    leave_during(&|| {
        app.invoke_ask(1);
        type_secret(app, 10, PASSWORD);
        app.invoke_confirmed(1);
    });
    assert!(phone.path.exists(), "the vault is still on the phone");
    assert_eq!(app.get_vaults().row_count(), 1);
    phone.unlock(PASSWORD);
    assert_eq!(app.get_total(), 1);

    // An unlock on its way when the app is left opens nothing.
    app.invoke_lock_now();
    controller.hold_jobs();
    type_secret(app, 0, PASSWORD);
    app.invoke_unlock();
    controller.left_app();
    controller.finish_held_jobs();
    assert!(!controller.is_unlocked());
    assert_eq!(app.get_screen(), Screen::Unlock);
    phone.unlock(PASSWORD);

    // A new master password: written before the job came back, so that is said, and it is
    // the one that opens the vault now; the vault stays locked meanwhile.
    const NEW_PASSWORD: &str = "phone new master passphrase";
    leave_during(&|| {
        app.invoke_ask(12);
        type_secret(app, 5, PASSWORD);
        type_secret(app, 6, NEW_PASSWORD);
        type_secret(app, 7, NEW_PASSWORD);
        app.invoke_confirmed(12);
    });
    assert_eq!(app.get_notice_code(), 10, "the change is told");
    type_secret(app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Unlock,
        "the old one no longer opens it"
    );
    phone.unlock(NEW_PASSWORD);
    assert_eq!(app.get_total(), 1);

    // Without the setting, leaving the app locks nothing (and the job's end puts it back).
    app.invoke_lock_on_leave_changed(false);
    controller.hold_jobs();
    app.invoke_ask(6);
    type_secret(app, 10, NEW_PASSWORD);
    app.invoke_confirmed(6);
    controller.left_app();
    assert!(controller.is_unlocked());
    controller.finish_held_jobs();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert!(controller.file_to_save(-1).is_some());
}

/// The vault with an emergency kit's three parts, and a login.
fn with_kit(parts: &RecoveryParts) -> impl FnOnce(&mut Vault, &SecretKey) + '_ {
    |vault, key| {
        vault.set_recovery_parts(parts, key).unwrap();
        vault
            .add_item(&ItemData::login("Mail", "me", "mail-test-password", ""))
            .unwrap();
    }
}

/// Recovery with two parts, from the unlock screen of a phone without the Secret Key.
fn recover_with(phone: &Phone, parts: &RecoveryParts, labels: [PartLabel; 2]) {
    let app = &phone.app;
    assert!(app.get_needs_secret_key());
    app.invoke_start_recovery(1);
    type_secret(app, 12, &parts.part(labels[0]).to_display_string());
    type_secret(app, 13, &parts.part(labels[1]).to_display_string());
    type_secret(app, 0, PASSWORD);
    app.invoke_recover();
}

#[test]
fn two_recovery_parts_work_once_on_the_phone() {
    let parts = RecoveryParts::generate().unwrap();
    // A chosen file, on a phone without the Secret Key.
    let phone = Phone::brought(with_kit(&parts));
    let app = &phone.app;
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::B]);
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total(), 1);
    assert!(
        !phone.has_recovery_parts(),
        "the file written has no recovery parts any more"
    );
    assert!(phone.keeps_secret_key(), "kept once they were retired");
    // They don't work again, nor does any other pair of that kit.
    app.invoke_lock_now();
    vault_platform::secret_store::forget(&phone.vault_id).unwrap();
    app.invoke_lock_now();
    recover_with(&phone, &parts, [PartLabel::B, PartLabel::C]);
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (39, Screen::Recover),
        "no recovery parts any more"
    );
    assert!(!phone.keeps_secret_key());
}

#[test]
fn two_part_recovery_keeps_the_parts_when_it_cannot_finish() {
    let parts = RecoveryParts::generate().unwrap();
    let phone = Phone::open(with_kit(&parts));
    let (app, controller) = (&phone.app, &phone.controller);
    // The Secret Key leaves the phone: its own copy is what is recovered from now on.
    app.invoke_lock_now();
    vault_platform::secret_store::forget(&phone.vault_id).unwrap();
    app.invoke_lock_now();
    let refused = |what: &str| {
        assert_eq!(
            (app.get_error_code(), app.get_screen()),
            (41, Screen::Recover),
            "{what}: {}",
            app.get_error_detail()
        );
        assert!(!controller.is_unlocked(), "{what}");
        assert!(phone.has_recovery_parts(), "{what}: the parts still work");
        assert!(
            !phone.keeps_secret_key(),
            "{what}: the Secret Key wasn't kept"
        );
    };

    // The file can't be written (where its `.bak` copy goes, a folder that can't be
    // replaced): said so, nothing changed.
    let before = std::fs::read(&phone.path).unwrap();
    let in_the_way = phone.path.with_file_name("vault.vault.bak");
    std::fs::create_dir_all(in_the_way.join("inside")).unwrap();
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::B]);
    refused("a failed write");
    assert_eq!(std::fs::read(&phone.path).unwrap(), before);
    std::fs::remove_dir_all(&in_the_way).unwrap();

    // The keystore refuses the Secret Key: the file is put back as it was.
    controller.refuse_secret_keys(true);
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::B]);
    refused("a refused Secret Key");
    assert_eq!(std::fs::read(&phone.path).unwrap(), before, "put back");
    controller.refuse_secret_keys(false);

    // Another device's sync writes the file while the master password is checked: what it
    // wrote stays.
    controller.hold_jobs();
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::C]);
    let mut other = phone.file();
    other
        .add_item(&ItemData::new(ItemKind::SecureNote, "From another device"))
        .unwrap();
    let theirs = other.to_bytes().unwrap();
    std::fs::write(&phone.path, &theirs).unwrap();
    controller.finish_held_jobs();
    refused("a file changed meanwhile");
    assert_eq!(
        std::fs::read(&phone.path).unwrap(),
        theirs,
        "not written over"
    );

    // Then it works, on the newest file.
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::C]);
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total(), 2, "the other device's note is there");
    assert!(!phone.has_recovery_parts());
    assert!(phone.keeps_secret_key());
}

#[test]
fn fingerprint_unlock_renews_nothing_but_the_master_password() {
    let phone = Phone::open(|_, _| {});
    let (app, controller) = (&phone.app, &phone.controller);
    let system = Rc::new(FakeSystem::default());
    controller.set_system(system.clone());
    let unlock_file = phone
        .path
        .with_file_name(format!("unlock-{}.json", phone.vault_id));
    let password_at = || -> i64 {
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&unlock_file).unwrap()).unwrap();
        json["password_at"].as_i64().unwrap()
    };
    let set_password_at = |at: i64| {
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&unlock_file).unwrap()).unwrap();
        json["password_at"] = at.into();
        std::fs::write(&unlock_file, serde_json::to_vec(&json).unwrap()).unwrap();
    };
    let turn_on = || {
        app.invoke_bio_toggled(true);
        let secret = system.handed.borrow_mut().take().expect("a secret to seal");
        controller.biometric_sealed(Ok(flip(&secret)));
        assert!(app.get_bio_on());
    };
    let now = crate::view::now_unix();
    let day = 86_400;

    // The master password was typed 13 days ago: turning fingerprint unlock on (and off and
    // on again, with nothing but the open vault) starts from then, not from now.
    controller.set_password_typed_at(&phone.vault_id, now - 13 * day);
    turn_on();
    assert_eq!(password_at(), now - 13 * day);
    app.invoke_bio_toggled(false);
    turn_on();
    assert_eq!(
        password_at(),
        now - 13 * day,
        "turned on again: the same date"
    );
    app.invoke_lock_now();
    assert!(app.get_bio_ready());

    // 15 days ago: on again, it asks for the master password at once.
    phone.unlock(PASSWORD);
    controller.set_password_typed_at(&phone.vault_id, now - 15 * day);
    app.invoke_bio_toggled(false);
    turn_on();
    assert_eq!(password_at(), now - 15 * day);
    app.invoke_lock_now();
    assert!(!app.get_bio_ready() && app.get_bio_stale());

    // Typing the master password renews it.
    phone.unlock(PASSWORD);
    assert!(password_at() >= now, "{}", password_at());
    app.invoke_lock_now();
    assert!(app.get_bio_ready());

    // A date still to come (the clock moved back since) counts as long ago.
    set_password_at(crate::view::now_unix() + day);
    controller.came_back(false);
    assert!(!app.get_bio_ready() && app.get_bio_stale());
    app.invoke_bio_unlock();
    assert!(system.handed.borrow().is_none(), "no prompt");

    // The 14 days run out while the prompt is open: the fingerprint opens nothing.
    set_password_at(crate::view::now_unix());
    controller.came_back(false);
    assert!(app.get_bio_ready());
    app.invoke_bio_unlock();
    let sealed = system.handed.borrow_mut().take().expect("the prompt");
    set_password_at(crate::view::now_unix() - 14 * day);
    controller.biometric_opened(Ok(Zeroizing::new(flip(&sealed))));
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!controller.is_unlocked());
    assert!(app.get_bio_stale(), "the master password is asked");
    phone.unlock(PASSWORD);
}

#[test]
fn the_generator_history_waits_for_the_item_lock() {
    const PIN: &str = "4821";
    let phone = Phone::open(|vault, _| {
        vault
            .set_item_guard(true, GuardCheck::Pin, Some(PIN), None)
            .unwrap();
        vault
            .add_item(&ItemData::login(
                "Sealed",
                "me",
                "sealed-test-password",
                "sealed.example",
            ))
            .unwrap();
    });
    let app = &phone.app;
    assert!(app.get_items().row_data(0).unwrap().locked);
    let history = || app.get_gen_history().row_count();

    // A copied password waits in the list, masked and not copied while an item's secrets
    // are sealed: it may be that item's password.
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    app.invoke_gen_copy();
    assert_eq!(history(), 1);
    assert!(app.get_gen_history_locked());
    app.set_gen_history_shown(true);
    app.invoke_gen_history_toggled();
    let row = app.get_gen_history().row_data(0).unwrap().text;
    assert!(row.chars().all(|c| c == '•'), "masked: {row}");
    app.set_notice_code(0);
    app.invoke_gen_history_copy(0);
    assert_eq!(app.get_notice_code(), 0, "nothing copied");

    // Put into a new login: it leaves the list for good, and the generator's page, which the
    // item page goes back to, shows another one (the item lock decides about this one now).
    let used = app.get_gen_password();
    app.invoke_gen_new_login();
    app.set_ed_title("Made here".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(history(), 0, "the login uses it now");
    assert_ne!(app.get_gen_password(), used, "not on the generator's page");
    assert_eq!(app.get_place(), Place::Generator);
    app.invoke_close_item();
    app.invoke_lock_now();
    phone.unlock(PASSWORD);
    assert_eq!(history(), 0, "gone from the file too");

    // One copied here and then used by a login another device sealed (or one used before
    // this rule): after the next unlock it can't be seen or copied here.
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    let used_elsewhere = app.get_gen_password().to_string();
    app.invoke_gen_copy();
    app.invoke_lock_now();
    {
        let mut other = phone.file();
        assert!(other.unlock_secrets(PIN).unwrap());
        other
            .add_item(&ItemData::login(
                "From another device",
                "me",
                &used_elsewhere,
                "other.example",
            ))
            .unwrap();
        std::fs::write(&phone.path, other.to_bytes().unwrap()).unwrap();
    }
    phone.unlock(PASSWORD);
    app.set_place(Place::Generator);
    assert_eq!(history(), 1);
    assert!(app.get_gen_history_locked());
    app.set_gen_history_shown(true);
    app.invoke_gen_history_toggled();
    let row = app.get_gen_history().row_data(0).unwrap().text;
    assert!(!row.contains(used_elsewhere.as_str()) && row.chars().all(|c| c == '•'));
    app.set_notice_code(0);
    app.invoke_gen_history_copy(0);
    assert_eq!(app.get_notice_code(), 0, "nothing copied");

    // The lock opened: its secrets tell, and the entry goes.
    app.set_place(Place::Items);
    phone.open_item("From another device");
    assert_eq!(app.get_d_check(), 2);
    app.invoke_ask(13);
    type_secret(app, 2, PIN);
    app.invoke_confirmed(13);
    assert_eq!(app.get_d_check(), 0, "{}", app.get_error_detail());
    assert_eq!(history(), 0);
    app.invoke_close_item();
    app.invoke_lock_now();
    phone.unlock(PASSWORD);
    assert_eq!(history(), 0, "for good");
}

/// PM-13 on the phone: once a sync takes another device's item lock, whatever the replaced
/// lock opened here closes (the item's page, an editor on a guarded item), and the next look
/// asks for the check again.
#[test]
fn taking_another_devices_item_lock_closes_what_the_old_one_opened() {
    const PIN: &str = "4821";
    let phone = Phone::open(|vault, _| {
        vault
            .set_item_guard(true, GuardCheck::Pin, Some(PIN), None)
            .unwrap();
        vault
            .add_item(&ItemData::login(
                "Sealed",
                "me",
                "sealed-test-password",
                "sealed.example",
            ))
            .unwrap();
    });
    let (app, controller) = (&phone.app, &phone.controller);
    let open_with_pin = || {
        phone.open_item("Sealed");
        assert_eq!(app.get_d_check(), 2, "the PIN is asked");
        app.invoke_ask(13);
        type_secret(app, 2, PIN);
        app.invoke_confirmed(13);
        assert_eq!(app.get_d_check(), 0, "{}", app.get_error_detail());
        assert_eq!(app.get_page(), Page::Item);
    };

    // The item's page, opened by the old lock.
    open_with_pin();
    controller.after_guard_changed();
    assert_eq!(app.get_page(), Page::None, "back to the list");
    phone.open_item("Sealed");
    assert_eq!(app.get_d_check(), 2, "asked again");
    app.invoke_close_item();

    // Its editor, too.
    open_with_pin();
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Editor);
    controller.after_guard_changed();
    assert_eq!(app.get_page(), Page::None, "the editor closed");
    phone.open_item("Sealed");
    assert_eq!(app.get_d_check(), 2, "asked again");
}

#[test]
fn the_generator_history_waits_for_a_locked_item_sync_brings() {
    const PIN: &str = "4821";
    let phone = Phone::open(|vault, _| {
        vault
            .set_item_guard(true, GuardCheck::Pin, Some(PIN), None)
            .unwrap();
    });
    let app = &phone.app;
    // Copied here, shown on the generator's page: no item is behind the lock yet.
    app.set_place(Place::Generator);
    app.invoke_gen_changed();
    let copied = app.get_gen_password().to_string();
    app.invoke_gen_copy();
    app.set_gen_history_shown(true);
    app.invoke_gen_history_toggled();
    assert!(!app.get_gen_history_locked());
    assert_eq!(app.get_gen_history().row_data(0).unwrap().text, copied);

    // The computer puts it into a login behind the item lock, and the phone syncs it in while
    // the page is on screen: it is masked at once, as after an unlock.
    let server = TestServer::start();
    let pc_id = vault_core::sync::DeviceId::generate().unwrap();
    let pc_server = ServerTarget::join(
        &server.url,
        &phone.vault_id,
        pc_id,
        "PC",
        &vault_server::admin_invite(server.data.path(), 1, None)
            .unwrap()
            .0,
    )
    .unwrap();
    let mut pc = phone.file();
    sync::join(&mut pc, pc_id, "PC").unwrap();
    assert!(pc.unlock_secrets(PIN).unwrap());
    let mut sealed = ItemData::login("Sealed on the computer", "me", &copied, "pc.example");
    sealed.reprompt = true;
    pc.add_item(&sealed).unwrap();
    pc_server.put(pc_id, &pc.to_bytes().unwrap()).unwrap();
    let link = pc_server
        .invite_link(&pc_server.invite().unwrap())
        .to_text()
        .to_string();
    app.set_sync_invite_typed(link.as_str().into());
    app.invoke_sync_join();
    assert_eq!(
        (app.get_sync_state(), app.get_sync_detail().as_str()),
        (1, ""),
        "joined and synced"
    );
    assert_eq!(app.get_total(), 1, "the computer's login came in");
    assert!(app.get_gen_history_locked());
    let row = app.get_gen_history().row_data(0).unwrap().text;
    assert!(
        !row.contains(copied.as_str()) && row.chars().all(|c| c == '•'),
        "masked: {row}"
    );
}

#[test]
fn a_website_rule_autofill_skips_is_told_on_the_item_page() {
    let phone = Phone::open(|vault, _| {
        for (title, url) in [
            ("Too wide", "*.co.uk"),
            ("Own site", "*.shop.co.uk"),
            ("Plain", "https://example.com"),
        ] {
            vault
                .add_item(&ItemData::login(title, "me", "test-pw", url))
                .unwrap();
        }
    });
    for (title, wide) in [("Too wide", true), ("Own site", false), ("Plain", false)] {
        phone.open_item(title);
        assert_eq!(phone.app.get_d_wide(), wide, "{title}");
        phone.app.invoke_close_item();
        assert!(!phone.app.get_d_wide(), "nothing stays from {title}");
    }
}

/// An app's own sign-in form, as Android describes it to autofill.
fn form_of(package: &str) -> Recipient {
    Recipient::of(&Asker {
        app: package.into(),
        signers: vec![[7; 32]],
        ..Asker::default()
    })
    .unwrap()
}

fn app_address(package: &str) -> String {
    format!("androidapp://{}@{package}", "07".repeat(32))
}

/// Username, password and "behind the lock" of every item in the phone's vault file.
fn logins_in(file: &Vault) -> Vec<(String, String, bool)> {
    let mut found: Vec<_> = file
        .item_ids()
        .map(|id| {
            let item = file.get_item(&id).unwrap();
            (item.username.clone(), item.password.clone(), item.reprompt)
        })
        .collect();
    found.sort();
    found
}

#[test]
fn autofill_changes_no_login_behind_the_item_lock() {
    let phone = Phone::open(|vault, _| {
        vault
            .set_item_guard(false, GuardCheck::Master, None, None)
            .unwrap();
        for (title, username, reprompt) in [("Guarded", "guarded", true), ("Open", "open", false)] {
            let mut item =
                ItemData::login(title, username, "old-pw", &app_address("com.example.app"));
            item.reprompt = reprompt;
            vault.add_item(&item).unwrap();
        }
    });
    let (app, controller) = (&phone.app, &phone.controller);
    let from = form_of("com.example.app");
    let offered = || -> Vec<String> {
        let logins = controller.autofill_logins(&from).unwrap();
        logins.into_iter().map(|login| login.username).collect()
    };
    let entry = |username: &str, password: &str, locked: bool| {
        (username.to_owned(), password.to_owned(), locked)
    };
    assert_eq!(offered(), ["open"]);
    let save = |username: &str, password: &str| controller.autofill_save(&from, username, password);
    assert_eq!(save("open", "new-pw"), Some(Kept::Replaced));
    assert_eq!(save("guarded", "new-pw"), Some(Kept::AddedBeside));
    let expected = [
        entry("guarded", "new-pw", true),
        entry("guarded", "old-pw", true),
        entry("open", "new-pw", false),
    ];
    assert_eq!(logins_in(&phone.file()), expected);
    assert_eq!(offered(), ["open"], "the new one is behind the lock too");

    // Its check passed on the item's page is the app's, not another app's.
    phone.open_item("Guarded");
    assert_eq!(app.get_d_check(), 1);
    app.invoke_ask(13);
    type_secret(app, 2, PASSWORD);
    app.invoke_confirmed(13);
    assert_eq!(app.get_d_check(), 0, "{}", app.get_error_detail());
    assert_eq!(save("guarded", "newer-pw"), Some(Kept::AddedBeside));
    assert!(logins_in(&phone.file()).contains(&entry("guarded", "old-pw", true)));
    assert_eq!(offered(), ["open"]);

    // Locked, the vault neither offers nor takes anything here (the drop box does that).
    app.invoke_lock_now();
    assert!(controller.autofill_logins(&from).is_none());
    assert_eq!(save("open", "late-pw"), None);
}

#[test]
fn what_autofill_saves_is_in_the_vault_only_once_it_is_written() {
    let phone = Phone::open(|vault, _| {
        vault
            .add_item(&ItemData::login(
                "Open",
                "open",
                "old-pw",
                &app_address("com.example.app"),
            ))
            .unwrap();
    });
    let (app, controller) = (&phone.app, &phone.controller);
    let from = form_of("com.example.app");
    let offered = || -> Vec<(String, String)> {
        let logins = controller.autofill_logins(&from).unwrap();
        logins
            .into_iter()
            .map(|login| (login.username, login.password.to_string()))
            .collect()
    };
    let open = ("open".to_owned(), "old-pw".to_owned());
    // The vault file can't be written: its backup can't take the place of a folder.
    let backup = phone.path.with_extension("vault.bak");
    let block = || {
        let _ = std::fs::remove_file(&backup);
        std::fs::create_dir(&backup).unwrap();
    };
    let before = std::fs::read(&phone.path).unwrap();
    block();
    assert_eq!(controller.autofill_save(&from, "open", "new-pw"), None);
    assert_eq!(app.get_error_code(), 6);
    assert_eq!(controller.autofill_save(&from, "other", "new-pw"), None);
    let unchanged = std::slice::from_ref(&open);
    assert_eq!(offered(), unchanged, "nor does the open vault have it");
    assert_eq!(std::fs::read(&phone.path).unwrap(), before);

    // The same for the logins that waited in the drop box: they go on waiting there.
    app.invoke_lock_now();
    let folder = phone.path.parent().unwrap();
    assert!(autofill::keep_locked(folder, &from, "waiting", "kept-pw"));
    phone.unlock(PASSWORD);
    assert_eq!(app.get_error_code(), 6);
    assert_eq!(offered(), unchanged);
    // A save that works brings in what it saves, and nothing of those.
    std::fs::remove_dir(&backup).unwrap();
    assert_eq!(
        controller.autofill_save(&from, "third", "third-pw"),
        Some(Kept::Added)
    );
    let third = ("third".to_owned(), "third-pw".to_owned());
    assert_eq!(logins_in(&phone.file()).len(), 2);
    let mut now = offered();
    now.sort();
    assert_eq!(now, [open.clone(), third.clone()]);
    // At the next unlock the one that waited comes in, once.
    app.invoke_lock_now();
    phone.unlock(PASSWORD);
    let mut now = offered();
    now.sort();
    let waited = ("waiting".to_owned(), "kept-pw".to_owned());
    assert_eq!(now, [open, third, waited]);
    app.invoke_lock_now();
    phone.unlock(PASSWORD);
    assert_eq!(offered().len(), 3);
}

/// A phone that draws PDFs: what it hands back for any of them.
struct PdfSystem(RefCell<Result<PdfPages, String>>);

impl System for PdfSystem {
    fn renders_pdf(&self) -> bool {
        true
    }

    fn render_pdf(&self, _: &[u8]) -> Result<PdfPages, String> {
        self.0.borrow().clone()
    }
}

#[test]
fn a_pdf_preview_shows_no_more_than_its_budget() {
    let phone = Phone::open(|vault, _| {
        let mut item = ItemData::new(ItemKind::SecureNote, "Contract");
        let pdf = vault_core::Attachment::new("contract.pdf", b"%PDF-1.7 test".to_vec()).unwrap();
        item.attachments.push(pdf);
        vault.add_item(&item).unwrap();
    });
    let app = &phone.app;
    let system = Rc::new(PdfSystem(RefCell::new(Ok(PdfPages::default()))));
    phone.controller.set_system(system.clone());
    phone.open_item("Contract");
    let pages = |total: u32, count: usize, width: u32, height: u32| {
        let pixels = vec![0xFF; width as usize * height as usize * 4];
        let page = PdfPage {
            width,
            height,
            pixels,
        };
        Ok(PdfPages {
            total,
            pages: vec![page; count],
        })
    };
    // The preview's kind, how many pages it shows, and the notice.
    let shown = |drawn: Result<PdfPages, String>| {
        *system.0.borrow_mut() = drawn;
        app.invoke_close_preview();
        app.set_notice_code(0);
        app.invoke_preview_file(0);
        (
            app.get_preview_kind(),
            app.get_preview_pages().row_count(),
            app.get_notice_code(),
        )
    };
    assert_eq!(shown(pages(2, 2, 8, 4)), (3, 2, 0));
    assert_eq!(app.get_preview_name(), "contract.pdf");
    // More pages than a preview may have, and pages the system didn't draw.
    assert_eq!(shown(pages(60, 60, 1, 1)), (3, 40, 40));
    assert_eq!(app.get_preview_name(), "contract.pdf · 40/60");
    assert_eq!(shown(pages(9, 3, 1, 1)), (3, 3, 40));
    assert_eq!(app.get_notice_arg(), "3");
    // Not even the first page: none drawn, or drawn larger than a page may be.
    assert_eq!(shown(pages(1, 0, 1, 1)), (0, 0, 41));
    assert_eq!(shown(pages(1, 1, 1081, 1)), (0, 0, 41));
    assert_eq!(shown(pages(1, 1, 1, 4097)), (0, 0, 41));
    assert_eq!(app.get_error_code(), 0);
    // One that can't be read, or has no pages.
    for drawn in [Err("broken".to_owned()), Ok(PdfPages::default())] {
        assert_eq!(shown(drawn), (0, 0, 0));
        assert_eq!(app.get_error_code(), 4);
    }
    let words = app.global::<Words>();
    for code in [40, 41] {
        assert!(!words.invoke_notice(code, "3".into()).is_empty());
    }
}

/// The key the tests' releases are signed with (made for these tests, in memory only).
fn release_key() -> &'static TestKey {
    static KEY: std::sync::LazyLock<TestKey> = std::sync::LazyLock::new(TestKey::new);
    &KEY
}

/// A release as GitHub's stand-in gives it: version `version`, its manifest signed and checked
/// (as `vault_platform::updates::latest` hands one back), with the phone's package or, without
/// it, only the desktop app.
fn github_release(version: &str, with_package: bool) -> GithubRelease {
    let name = releases::phone_package_name(version);
    let files: Vec<(&str, &[u8])> = if with_package {
        vec![(&name, b"PK a test package from GitHub")]
    } else {
        vec![("vault-desktop.exe", b"a test program")]
    };
    signing::verified(version, &files, release_key())
}

/// A phone app update as `vault-server` keeps one: `package` as version `version`, with the
/// release's manifest and its signature by `key`.
fn signed_update(key: &TestKey, version: &str, package: &[u8]) -> releases::SignedManifest {
    let manifest = signing::manifest_of(
        version,
        &[(&releases::phone_package_name(version), package)],
    );
    let signature = key.sign_release(&manifest, version);
    releases::SignedManifest {
        manifest,
        signature,
    }
}

/// Settings → About and updates: unless the person chooses the vault's server, the phone
/// asks GitHub (a stand-in here: the tests never reach the network), takes the package of a
/// newer release and hands it to Android's installer; what went wrong is said. The server is
/// the other choice, which needs a vault that syncs through one. Both choices are kept.
#[test]
fn updates_come_from_github_unless_the_server_is_chosen() {
    fn same() -> Result<GithubRelease, String> {
        Ok(github_release("0.0.1", true))
    }
    fn newer() -> Result<GithubRelease, String> {
        Ok(github_release("99.0.0", true))
    }
    fn newer_without_package() -> Result<GithubRelease, String> {
        Ok(github_release("99.0.0", false))
    }
    fn offline() -> Result<GithubRelease, String> {
        Err("offline".into())
    }
    fn package(release: &GithubRelease) -> Result<Vec<u8>, String> {
        assert_eq!(release.version(), "99.0.0");
        Ok(b"PK a test package from GitHub".to_vec())
    }
    let github = |latest| Github { latest, package };

    let phone = Phone::open(|_, _| {});
    let (app, controller) = (&phone.app, &phone.controller);
    let system = Rc::new(FakeSystem::default());
    controller.set_system(system.clone());
    controller.lock();
    phone.unlock(PASSWORD);
    assert!(app.get_updates_available());
    assert_eq!(
        app.get_update_source(),
        0,
        "GitHub, unless chosen otherwise"
    );
    assert!(
        app.get_update_checks(),
        "looked for by itself, unless turned off"
    );

    controller.use_github(github(same));
    app.invoke_check_update();
    assert_eq!(
        (app.get_update_state(), app.get_update_version().as_str()),
        (2, "0.0.1")
    );
    controller.use_github(github(offline));
    app.invoke_check_update();
    assert_eq!((app.get_update_state(), app.get_error_code()), (5, 27));
    assert_eq!(app.get_error_detail(), "offline");
    controller.use_github(github(newer_without_package));
    app.invoke_check_update();
    assert_eq!(app.get_update_state(), 5, "a release without the phone app");
    controller.use_github(github(newer));
    app.invoke_check_update();
    assert_eq!(
        (app.get_update_state(), app.get_update_version().as_str()),
        (3, "99.0.0")
    );
    app.invoke_install_update();
    assert_eq!(
        system.installed.borrow().as_deref(),
        Some(b"PK a test package from GitHub".as_slice())
    );
    controller.update_installing("");
    assert_eq!(app.get_update_state(), 6);

    // The vault's server instead: this vault syncs through none, so there is nothing to ask.
    app.invoke_update_source_changed(1);
    assert_eq!((app.get_update_source(), app.get_update_state()), (1, 0));
    assert!(!app.get_update_servers());
    app.invoke_check_update();
    assert_eq!(app.get_update_state(), 0);
    app.invoke_update_checks_changed(false);
    let kept = crate::prefs::Prefs::load(&crate::prefs::path_for(&phone.path));
    assert_eq!(
        (kept.update_source, kept.update_checks),
        (crate::prefs::UPDATES_FROM_SERVER, false)
    );
    app.invoke_update_source_changed(0);
    assert_eq!(
        crate::prefs::Prefs::load(&crate::prefs::path_for(&phone.path)).update_source,
        crate::prefs::UPDATES_FROM_GITHUB
    );
}

#[test]
fn an_update_the_phone_refuses_says_why() {
    let phone = Phone::brought(|_, _| {});
    let words = phone.app.global::<Words>();
    let general = words.invoke_error(27, "something else".into());
    // The reasons Java gives, each with words of its own.
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../mobile-android/java/org/passwordvault/phone/Updates.java"),
    )
    .unwrap();
    let reasons: Vec<&str> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("static final String "))
        .filter_map(|rest| rest.split('"').nth(1))
        .collect();
    assert_eq!(reasons, ["package", "signature", "older", "installer"]);
    for reason in reasons {
        let text = words.invoke_error(27, reason.into());
        assert!(text.starts_with("The update wasn't installed"), "{reason}");
        assert_ne!(text, general);
        phone.controller.update_installing(reason);
        assert_eq!(phone.app.get_error_code(), 27);
    }
}

#[test]
fn three_part_recovery_writes_over_no_other_device() {
    const NEW_PASSWORD: &str = "phone recovered master passphrase";
    let parts = RecoveryParts::generate().unwrap();
    let phone = Phone::open(with_kit(&parts));
    let (app, controller) = (&phone.app, &phone.controller);
    app.invoke_lock_now();
    let recover = || {
        app.invoke_start_recovery(0);
        for (field, label) in [(12, PartLabel::A), (13, PartLabel::B), (14, PartLabel::C)] {
            type_secret(app, field, &parts.part(label).to_display_string());
        }
        type_secret(app, 6, NEW_PASSWORD);
        type_secret(app, 7, NEW_PASSWORD);
        app.invoke_recover();
    };
    // Another device's sync writes the file while the parts are checked: what it wrote
    // stays, and the parts still work.
    controller.hold_jobs();
    recover();
    let mut other = phone.file();
    other
        .add_item(&ItemData::new(ItemKind::SecureNote, "From another device"))
        .unwrap();
    let theirs = other.to_bytes().unwrap();
    std::fs::write(&phone.path, &theirs).unwrap();
    controller.finish_held_jobs();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (41, Screen::Recover),
        "{}",
        app.get_error_detail()
    );
    assert_eq!(std::fs::read(&phone.path).unwrap(), theirs);
    assert!(phone.has_recovery_parts());
    // Then on the newest file: a new Secret Key, shown, and the new master password.
    recover();
    let shown = app.get_recovered_key().to_string();
    assert!(!shown.is_empty(), "{}", app.get_error_detail());
    assert!(!phone.has_recovery_parts());
    let reopened = Vault::open(
        &std::fs::read(&phone.path).unwrap(),
        Unlock::Password {
            password: NEW_PASSWORD,
            secret_key: &SecretKey::parse(&shown).unwrap(),
        },
    )
    .unwrap();
    assert_eq!(reopened.len(), 2, "the other device's note is there");
}

#[test]
fn recovery_of_an_older_copy_writes_nothing() {
    const NEW_PASSWORD: &str = "phone recovered master passphrase";
    let parts = RecoveryParts::generate().unwrap();
    let phone = Phone::open(with_kit(&parts));
    let (app, controller) = (&phone.app, &phone.controller);
    // The copy as it is now; then two changes saved here, so this phone has seen newer ones.
    let old = std::fs::read(&phone.path).unwrap();
    for title in ["Newer", "Newest"] {
        app.invoke_new_item();
        app.set_ed_kind(2);
        app.set_ed_title(title.into());
        app.invoke_save_item();
        assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
        app.invoke_close_item();
    }
    app.invoke_lock_now();
    // An old copy put in its place: it doesn't open...
    std::fs::write(&phone.path, &old).unwrap();
    type_secret(app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 8, "{}", app.get_error_detail());
    // ...nor is it written over under a new Secret Key that would never be shown: the vault
    // would be lost. The parts still work, on the newest copy.
    app.invoke_start_recovery(0);
    for (field, label) in [(12, PartLabel::A), (13, PartLabel::B), (14, PartLabel::C)] {
        type_secret(app, field, &parts.part(label).to_display_string());
    }
    type_secret(app, 6, NEW_PASSWORD);
    type_secret(app, 7, NEW_PASSWORD);
    app.invoke_recover();
    assert_eq!(
        (app.get_error_code(), app.get_screen()),
        (8, Screen::Recover),
        "{}",
        app.get_error_detail()
    );
    assert!(!controller.is_unlocked());
    assert!(
        std::fs::read(&phone.path).unwrap() == old,
        "nothing written"
    );
    assert!(phone.has_recovery_parts());
    assert!(
        Vault::open(
            &old,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &SecretKey::parse(&phone.secret_key).unwrap(),
            },
        )
        .is_ok(),
        "the Secret Key still opens it"
    );
    // Two parts, on a phone without the Secret Key: the same, and nothing kept.
    vault_platform::secret_store::forget(&phone.vault_id).unwrap();
    app.invoke_lock_now();
    recover_with(&phone, &parts, [PartLabel::A, PartLabel::B]);
    assert_eq!(app.get_error_code(), 8, "{}", app.get_error_detail());
    assert!(
        std::fs::read(&phone.path).unwrap() == old,
        "nothing written"
    );
    assert!(phone.has_recovery_parts());
    assert!(!phone.keeps_secret_key());
}

/// A login with two websites, a hidden field, a one-time code, recovery codes, an attached
/// file, a passkey and an earlier password (the one in use starts like a formula); a card with
/// a PIN; a note.
fn add_what_exports_lose(vault: &mut Vault) {
    let mut mail = ItemData::login("Mail", "me", "first password", "https://mail.example");
    mail.urls.push("https://webmail.example".into());
    mail.totp = "JBSWY3DPEHPK3PXP".into();
    mail.custom_fields.push(vault_core::CustomField {
        name: "Answer".into(),
        value: "blue".into(),
        sensitive: true,
    });
    mail.recovery_codes = vault_core::RecoveryCode::parse_list("test-code-1\ntest-code-2");
    mail.attachments
        .push(vault_core::Attachment::new("scan.txt", b"test attachment".to_vec()).unwrap());
    mail.passkeys
        .push(vault_core::Passkey::new("mail.example", b"user-1", "me", "Me").unwrap());
    let id = vault.add_item(&mail).unwrap();
    let mut changed = vault.get_item(&id).unwrap();
    changed.password = "=second password".into();
    vault.update_item(&id, &changed).unwrap();
    let mut visa = ItemData::new(vault_core::ItemKind::Card, "Visa");
    visa.password = "4821".into();
    visa.custom_fields.push(vault_core::CustomField {
        name: vault_core::card::NUMBER.into(),
        value: "4111111111111111".into(),
        sensitive: true,
    });
    vault.add_item(&visa).unwrap();
    let mut note = ItemData::new(vault_core::ItemKind::SecureNote, "Wifi");
    note.notes = "router".into();
    vault.add_item(&note).unwrap();
}

#[test]
fn an_export_sheet_says_first_what_the_file_leaves_out() {
    use crate::ui::ExportCounts;
    let phone = Phone::open(|vault, _| add_what_exports_lose(vault));
    let (app, controller) = (&phone.app, &phone.controller);
    let notes = || app.get_export_notes().to_string();

    // Protected: every item whole, attached file and passkey included. Nothing is readable.
    app.invoke_ask(7);
    assert_eq!((app.get_confirming(), app.get_error_code()), (7, 0));
    let sealed = ExportCounts::default();
    assert_eq!(app.get_export_counts(), sealed);
    assert_eq!(notes(), "");

    // JSON: the attached file, the passkey and the earlier password stay behind, and
    // everything else is in the clear.
    app.invoke_ask(6);
    let json = ExportCounts {
        attachments: 1,
        passkeys: 1,
        earlier_passwords: 1,
        passwords: 2,
        otp_secrets: 1,
        hidden_fields: 2,
        recovery_codes: 2,
        notes: 1,
        ..ExportCounts::default()
    };
    assert_eq!(app.get_export_counts(), json);
    assert_eq!(
        notes(),
        "Not in this file: 1 attached file, 1 passkey, 1 earlier password.\n\
         Readable by anyone with this file: 2 passwords, 1 one-time code secret, \
         2 hidden fields, 2 recovery codes, the notes of 1 item."
    );

    // CSV: what it has no place for, and no file for a spreadsheet.
    app.invoke_ask(8);
    let csv = ExportCounts {
        extra_websites: 1,
        dates: true,
        hidden_marks: 2,
        recovery_code_lists: 1,
        kinds_changed: 1,
        formula_like: 1,
        ..json.clone()
    };
    assert_eq!(app.get_export_counts(), csv);
    assert_eq!(
        notes(),
        "Not in this file: 1 attached file, 1 passkey, 1 earlier password, \
         1 website after an item's first, the dates of the items.\n\
         In another form: 2 hidden fields not marked hidden, \
         1 list of recovery codes as text, 1 item as another kind.\n\
         Readable by anyone with this file: 2 passwords, 1 one-time code secret, \
         2 hidden fields, 2 recovery codes, the notes of 1 item.\n\
         Don't open this file in a spreadsheet: 1 password or code secret starts like a \
         formula, and a spreadsheet may run it."
    );
    // Confirmed: the file holds what was said, and not what was said to stay behind.
    type_secret(app, 10, PASSWORD);
    app.invoke_confirmed(8);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (0, 0),
        "{}",
        app.get_error_detail()
    );
    let (name, bytes) = controller.file_to_save(-1).unwrap();
    assert!(name.ends_with(".csv"));
    let text = String::from_utf8_lossy(&bytes).into_owned();
    for (held, text_of) in [
        (true, "=second password"),
        (true, "JBSWY3DPEHPK3PXP"),
        (true, "test-code-2"),
        (true, "4111111111111111"),
        (false, "first password"),
        (false, "webmail.example"),
        (false, "test attachment"),
    ] {
        assert_eq!(text.contains(text_of), held, "{text_of}");
    }

    // The vault changes while the sheet is open (a sync): what the file would hold now is
    // shown, and confirmed again before it is made.
    app.invoke_ask(6);
    app.invoke_new_item();
    app.set_ed_title("New".into());
    type_secret(app, 3, "another password");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    type_secret(app, 10, PASSWORD);
    app.invoke_confirmed(6);
    assert!(
        controller.file_to_save(-1).is_none(),
        "not made with other counts shown"
    );
    assert_eq!(app.get_confirming(), 6);
    assert!(app.get_export_recounted());
    assert_eq!(app.get_export_counts().passwords, 3);
    app.invoke_confirmed(6);
    assert_eq!(app.get_confirming(), 0, "{}", app.get_error_detail());
    assert!(controller.file_to_save(-1).is_some());
    // Counted afresh the next time, and said for exports only.
    app.invoke_ask(7);
    assert!(!app.get_export_recounted());
    assert_eq!(app.get_export_counts(), sealed);
    // While something else runs too: never the last sheet's numbers under another name.
    app.set_busy(true);
    app.invoke_ask(8);
    assert_eq!(app.get_export_counts().formula_like, 1);
    assert_eq!(app.get_export_counts().passwords, 3);
    app.set_busy(false);
    app.invoke_ask(12);
    assert_eq!(notes(), "");
}

#[test]
fn an_export_of_locked_items_is_refused_when_its_sheet_opens() {
    let phone = Phone::open(|vault, _| {
        add_what_exports_lose(vault);
        vault
            .set_item_guard(
                true,
                vault_core::GuardCheck::Pin,
                Some("2468"),
                Some(PASSWORD),
            )
            .unwrap();
    });
    let (app, controller) = (&phone.app, &phone.controller);
    for kind in 6..=8 {
        app.invoke_ask(kind);
        assert_eq!((app.get_confirming(), app.get_error_code()), (kind, 32));
        assert_eq!(
            app.get_export_counts(),
            crate::ui::ExportCounts::default(),
            "nothing counted: nothing claimed"
        );
        type_secret(app, 9, "an export password");
        type_secret(app, 10, PASSWORD);
        app.invoke_confirmed(kind);
        assert_eq!((app.get_confirming(), app.get_error_code()), (kind, 32));
        assert!(controller.file_to_save(-1).is_none());
    }
}

#[test]
fn a_plain_csv_export_is_not_called_the_logins_only() {
    let phone = Phone::open(|vault, _| add_what_exports_lose(vault));
    let app = &phone.app;
    let words = app.global::<Words>();
    // Like the JSON, the CSV holds every item's password: a note's, a card's PIN, an SSH key.
    assert_eq!(
        words.invoke_confirm_title(8, "".into()),
        words.invoke_confirm_title(6, "".into())
    );
    let said = words.invoke_confirm_text(8, "".into());
    assert!(said.contains("every password"), "{said}");
    // And the sheet counts them so: the card's PIN is one of its passwords.
    app.invoke_ask(8);
    assert_eq!(app.get_export_counts().passwords, 2);
}

#[test]
fn an_import_on_the_phone_shows_what_it_left_behind() {
    let phone = Phone::open(|_, _| {});
    let (app, controller) = (&phone.app, &phone.controller);

    // A plain file: the first four, a line each, and how many more there are.
    let items: Vec<String> = (1..=6)
        .map(|n| {
            format!(
                r#"{{"type": 1, "name": "Item {n}", "login": {{"username": "me", "password": "import-test-pw-{n}"}},
                    "leftOut": {{"attachments": {n}, "passkeys": 1}}}}"#
            )
        })
        .collect();
    let json = format!(r#"{{"items": [{}]}}"#, items.join(","));
    controller.picked_file(3, "export.json", json.into_bytes());
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!((app.get_import_added(), app.get_import_skipped()), (6, 0));
    let shown = app.get_import_warnings().to_string();
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(lines.len(), 4, "{shown}");
    assert_eq!(
        lines[0],
        "\"Item 1\": 1 attached file and 1 passkey were not in this export; they are only in the vault it was made from"
    );
    assert!(lines[3].starts_with("\"Item 4\": 4 attached files"));
    assert_eq!(app.get_import_more(), 2);
    assert!(!shown.contains("import-test-pw"));

    // Its titles come from the file: a long one, or one of several lines, stays one line.
    let odd = format!(
        r#"{{"items": [{{"type": 1, "name": "One\nTwo", "login": {{"password": "x1"}}, "leftOut": {{"passkeys": 1}}}},
                       {{"type": 1, "name": "{}", "login": {{"password": "x2"}}, "leftOut": {{"passkeys": 1}}}}]}}"#,
        "a".repeat(5000)
    );
    controller.picked_file(3, "export.json", odd.into_bytes());
    let shown = app.get_import_warnings().to_string();
    assert_eq!(shown.lines().count(), 2, "{shown}");
    assert!(shown.starts_with("\"One Two\": 1 passkey"));
    assert!(shown.chars().count() < 1000 && shown.ends_with('…'));
    assert_eq!(app.get_import_more(), 0);

    // A file with a password: told when its sheet closes, not lost with it. (This app's own
    // protected exports keep every item whole: this one is sealed by hand around a document
    // that names what it left out.)
    let document =
        br#"{"items": [{"type": 1, "name": "Mail", "login": {"password": "import-test-pw-m"},
        "leftOut": {"attachments": 1, "passkeys": 1}}]}"#;
    let sealed = vault_core::sealed_export::seal("an export password", document).unwrap();
    controller.picked_file(3, "vault-export.vaultx", sealed);
    assert_eq!(app.get_confirming(), 11);
    type_secret(app, 8, "an export password");
    app.invoke_confirmed(11);
    assert_eq!(
        (app.get_error_code(), app.get_confirming()),
        (0, 0),
        "{}",
        app.get_error_detail()
    );
    assert_eq!((app.get_import_added(), app.get_import_skipped()), (1, 0));
    assert_eq!(
        app.get_import_warnings(),
        "\"Mail\": 1 attached file and 1 passkey were not in this export; they are only in the vault it was made from"
    );

    // Nothing left behind: nothing said, and nothing of the last import stays.
    let csv = "name,url,username,password\nForum,https://forum.example.com,tester,import-test-pw\n";
    controller.picked_file(3, "export.csv", csv.as_bytes().to_vec());
    assert_eq!(app.get_import_added(), 1);
    assert_eq!(
        (app.get_import_warnings().as_str(), app.get_import_more()),
        ("", 0)
    );

    // Locked: no title of it stays on the window.
    controller.picked_file(
        3,
        "export.json",
        br#"{"items": [{"type": 1, "name": "Last", "login": {"password": "x3"}, "leftOut": {"passkeys": 1}}]}"#
            .to_vec(),
    );
    assert!(app.get_import_warnings().contains("Last"));
    app.invoke_lock_now();
    assert_eq!(
        (app.get_import_warnings().as_str(), app.get_import_more()),
        ("", 0)
    );
}

#[test]
fn an_import_that_was_not_saved_is_never_called_imported() {
    let phone = Phone::open(|_, _| {});
    let (app, controller) = (&phone.app, &phone.controller);
    let csv = "name,url,username,password\nForum,https://forum.example.com,tester,import-test-pw\n";
    let import = || controller.picked_file(3, "export.csv", csv.as_bytes().to_vec());

    // The vault file was written by something else: nothing can be saved over it.
    let ours = std::fs::read(&phone.path).unwrap();
    std::fs::write(&phone.path, b"changed by something else").unwrap();
    for _ in 0..2 {
        import();
        assert_eq!(app.get_error_code(), 6, "{}", app.get_error_detail());
        assert_eq!(app.get_import_added(), -1, "nothing is said to be in it");
        assert_eq!(app.get_import_warnings(), "");
    }

    // Once it can be saved, it is imported (not "already in the vault"), and in the file.
    std::fs::write(&phone.path, ours).unwrap();
    import();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!((app.get_import_added(), app.get_import_skipped()), (1, 0));
    assert_eq!(phone.file().len(), 1);
}

/// The vault key renewed on the computer (CRYPTO.md §3.8): the phone can't read its copies
/// until it takes the new key in Settings, Sync, with the new Secret Key and the master
/// password; then the computer's changes come in and the phone's copy opens with the new kit.
#[test]
fn a_key_renewed_on_the_computer_is_taken_on_the_phone() {
    let phone = Phone::open(|_, _| {});
    let app = &phone.app;
    let server = TestServer::start();
    let pc_id = vault_core::sync::DeviceId::generate().unwrap();
    let pc_server = ServerTarget::join(
        &server.url,
        &phone.vault_id,
        pc_id,
        "PC",
        &vault_server::admin_invite(server.data.path(), 1, None)
            .unwrap()
            .0,
    )
    .unwrap();
    let mut pc = phone.file();
    sync::join(&mut pc, pc_id, "PC").unwrap();
    pc_server.put(pc_id, &pc.to_bytes().unwrap()).unwrap();
    let link = pc_server
        .invite_link(&pc_server.invite().unwrap())
        .to_text()
        .to_string();
    app.set_sync_invite_typed(link.as_str().into());
    app.invoke_sync_join();
    assert_eq!(app.get_sync_state(), 1, "{}", app.get_sync_detail());

    // The computer adds a login and renews the key.
    pc.add_item(&ItemData::login(
        "Made on the PC",
        "me",
        "pc-test-pw",
        "pc.example",
    ))
    .unwrap();
    let old_key = SecretKey::parse(&phone.secret_key).unwrap();
    let renewed = pc.renew_key(PASSWORD, &old_key, None).unwrap();
    pc_server.put(pc_id, &pc.to_bytes().unwrap()).unwrap();
    phone.controller.sync_round();
    assert_eq!(app.get_notice_code(), 24);
    assert!(app.get_sync_key_renewed());
    assert_eq!(app.get_total(), 0, "nothing of it came in");

    // The old Secret Key takes nothing.
    app.invoke_ask(19);
    type_secret(app, 1, &phone.secret_key);
    type_secret(app, 10, PASSWORD);
    app.invoke_sync_take_key();
    assert_eq!(app.get_error_code(), 43);
    assert!(
        Vault::open(
            &std::fs::read(&phone.path).unwrap(),
            Unlock::Password {
                password: PASSWORD,
                secret_key: &old_key,
            },
        )
        .is_ok()
    );

    type_secret(app, 1, &renewed.secret_key.to_display_string());
    type_secret(app, 10, PASSWORD);
    app.invoke_sync_take_key();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_notice_code(), 23);
    assert_eq!(app.get_confirming(), 0, "the sheet closed");
    assert!(!app.get_sync_key_renewed());
    assert_eq!(app.get_total(), 1, "the computer's login came in");
    let bytes = std::fs::read(&phone.path).unwrap();
    let unlock = |secret_key| Unlock::Password {
        password: PASSWORD,
        secret_key,
    };
    assert!(Vault::open(&bytes, unlock(&renewed.secret_key)).is_ok());
    assert!(Vault::open(&bytes, unlock(&old_key)).is_err());
    assert!(
        vault_platform::secret_store::load(&phone.vault_id)
            .unwrap()
            .is_some_and(|kept| kept == renewed.secret_key)
    );
    // The computer reads the phone's copy again.
    let fetched = sync::fetch(&pc_server, pc_id, &sync::Tags::default()).unwrap();
    let (_, phone_copy) = fetched
        .copies
        .into_iter()
        .find(|(device, _)| *device != pc_id)
        .unwrap();
    pc.merge(&phone_copy, &mut vault_core::sync::SeenRevisions::new())
        .unwrap();
}

/// A phone that checks the person before each use of a secret, or (`screen_lock` off) one
/// with no screen lock; what each prompt said it was for. The test gives the answer
/// (`Controller::person_checked`).
#[derive(Default)]
struct CheckingSystem {
    screen_lock: Cell<bool>,
    asked: RefCell<Vec<String>>,
}

impl CheckingSystem {
    fn with_screen_lock(on: bool) -> Rc<Self> {
        let system = Rc::new(Self::default());
        system.screen_lock.set(on);
        system
    }

    fn asked(&self) -> usize {
        self.asked.borrow().len()
    }
}

impl System for CheckingSystem {
    fn checks_person(&self) -> Option<bool> {
        Some(self.screen_lock.get())
    }

    fn check_person(&self, words: &PromptWords) -> Result<(), String> {
        assert!(!words.title.is_empty() && !words.cancel.is_empty());
        self.asked.borrow_mut().push(words.title.clone());
        Ok(())
    }
}

const ITEM_PIN: &str = "4821";

/// A login with a one-time code, a card, a secure note, and a login behind a PIN item lock
/// that covers it alone.
fn each_use_vault(vault: &mut Vault, _: &SecretKey) {
    let mut mail = ItemData::login("Mail", "me", "mail-test-password", "https://mail.example");
    mail.totp = "JBSWY3DPEHPK3PXP".into();
    vault.add_item(&mail).unwrap();
    let mut visa = ItemData::new(ItemKind::Card, "Visa");
    visa.custom_fields.push(vault_core::CustomField {
        name: vault_core::card::NUMBER.into(),
        value: "4111111111111111".into(),
        sensitive: true,
    });
    vault.add_item(&visa).unwrap();
    let mut note = ItemData::new(ItemKind::SecureNote, "Wifi");
    note.notes = "router test note".into();
    vault.add_item(&note).unwrap();
    vault
        .set_item_guard(false, GuardCheck::Pin, Some(ITEM_PIN), None)
        .unwrap();
    let mut sealed = ItemData::login("Sealed", "me", "sealed-test-password", "sealed.example");
    sealed.reprompt = true;
    vault.add_item(&sealed).unwrap();
}

#[test]
fn every_use_of_a_secret_asks_the_phone_each_time() {
    let phone = Phone::open(each_use_vault);
    let (app, controller) = (&phone.app, &phone.controller);
    let system = CheckingSystem::with_screen_lock(true);
    controller.set_system(system.clone());
    // On by default, and Settings says the phone asks.
    assert!(app.get_ask_each_use());
    assert_eq!(app.get_ask_each_use_state(), 0);

    // The eye on the password asks, and shows only once the phone said yes.
    phone.open_item("Mail");
    app.invoke_toggle_password();
    assert_eq!(system.asked(), 1);
    assert_eq!(system.asked.borrow()[0], "Show the password");
    assert_eq!(app.get_d_password(), "", "nothing before the answer");
    controller.person_checked(Ok(()));
    assert_eq!(app.get_d_password(), "mail-test-password");
    // Hidden again without asking; shown again only after asking again: no grace period.
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "");
    assert_eq!(system.asked(), 1);
    app.invoke_toggle_password();
    assert_eq!(system.asked(), 2);
    controller.person_checked(Err(String::new()));
    assert_eq!(app.get_d_password(), "", "cancelled: nothing shows");
    // An answer nobody waits for (or a second one) does nothing.
    controller.person_checked(Ok(()));
    assert_eq!(app.get_d_password(), "");

    // Copying the password and the code: each copy asks, a refusal copies nothing.
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!((system.asked(), app.get_notice_code()), (3, 0));
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 1, "password copied");
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(system.asked(), 4);
    controller.person_checked(Err("Too many attempts".into()));
    assert_eq!(
        app.get_notice_code(),
        27,
        "refused: nothing copied, and said why"
    );
    assert_eq!(app.get_notice_arg(), "Too many attempts");
    app.set_notice_code(0);
    app.invoke_copy(2);
    assert_eq!(system.asked.borrow()[4], "Copy the one-time code");
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 5, "code copied");
    // The username is no secret: nothing asked.
    app.set_notice_code(0);
    app.invoke_copy(0);
    assert_eq!((system.asked(), app.get_notice_code()), (5, 2));

    // The editor shows every field: it opens only after the phone said yes.
    app.invoke_edit_item();
    assert_eq!(system.asked(), 6);
    assert_eq!(app.get_page(), Page::Item);
    controller.person_checked(Ok(()));
    assert_eq!(app.get_page(), Page::Editor);
    app.invoke_cancel_edit();

    // An answer that comes once the item was left shows nothing on the next one.
    app.invoke_toggle_password();
    assert_eq!(system.asked(), 7);
    app.invoke_close_item();
    phone.open_item("Mail");
    controller.person_checked(Ok(()));
    assert_eq!(app.get_d_password(), "");
    app.invoke_close_item();

    // The Codes page asks too.
    app.set_place(Place::Codes);
    controller.set_system(system.clone());
    app.set_notice_code(0);
    app.invoke_copy_code(0);
    assert_eq!((system.asked(), app.get_notice_code()), (8, 0));
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 5);
    app.set_place(Place::Items);

    // A card's number and code: shown and copied only after asking.
    phone.open_item("Visa");
    assert!(!app.get_d_card().contains("4111 1111"), "masked");
    app.invoke_toggle_card();
    assert_eq!(system.asked(), 9);
    assert!(!app.get_d_card_shown());
    controller.person_checked(Ok(()));
    assert!(app.get_d_card_shown());
    assert!(app.get_d_card().contains("4111 1111"));
    app.set_notice_code(0);
    app.invoke_copy(5);
    assert_eq!((system.asked(), app.get_notice_code()), (10, 0));
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 7);
    app.invoke_close_item();

    // A secure note's text waits for its button.
    phone.open_item("Wifi");
    assert!(app.get_d_note_waits());
    assert_eq!(app.get_d_notes(), "");
    app.invoke_show_note();
    assert_eq!(system.asked(), 11);
    controller.person_checked(Ok(()));
    assert!(!app.get_d_note_waits());
    assert_eq!(app.get_d_notes(), "router test note");
    app.invoke_close_item();

    // Behind the item lock: "Show the secrets" asks its PIN (and not the phone) and shows
    // them; each later use asks the phone, once.
    phone.open_item("Sealed");
    assert_eq!(app.get_d_check(), 2);
    app.invoke_ask(13);
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(13);
    assert_eq!(app.get_d_check(), 0, "{}", app.get_error_detail());
    assert_eq!(app.get_d_password(), "sealed-test-password");
    assert_eq!(system.asked(), 11, "one check for that action");
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(system.asked(), 12);
    assert_eq!(app.get_confirming(), 0, "the PIN isn't asked again");
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 1);
    app.invoke_close_item();

    // Turned off: nothing more is asked, and the phone remembers it.
    app.invoke_ask_each_use_changed(false);
    phone.open_item("Mail");
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "mail-test-password");
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(app.get_notice_code(), 1);
    assert_eq!(system.asked(), 12);
    app.invoke_close_item();
    phone.open_item("Wifi");
    assert!(!app.get_d_note_waits());
    assert_eq!(app.get_d_notes(), "router test note");
    app.invoke_close_item();
    assert!(!crate::prefs::Prefs::load(&crate::prefs::path_for(&phone.path)).ask_each_use);
}

#[test]
fn a_phone_without_a_screen_lock_asks_the_item_pin_each_time() {
    let phone = Phone::open(each_use_vault);
    let (app, controller) = (&phone.app, &phone.controller);
    let system = CheckingSystem::with_screen_lock(false);
    controller.set_system(system.clone());
    assert_eq!(
        app.get_ask_each_use_state(),
        1,
        "Settings says the item PIN asks"
    );

    // A login outside the lock: its PIN is asked in the sheet, for this use only.
    phone.open_item("Mail");
    app.invoke_toggle_password();
    assert_eq!(app.get_confirming(), 20);
    assert_eq!(system.asked(), 0, "Android can't ask");
    type_secret(app, 2, "0000");
    app.invoke_confirmed(20);
    assert_eq!(app.get_error_code(), 7);
    assert_eq!(app.get_confirming(), 20, "the sheet stays");
    assert_eq!(app.get_d_password(), "");
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(20);
    assert_eq!(app.get_confirming(), 0);
    assert_eq!(app.get_d_password(), "mail-test-password");
    assert_eq!(length(app, 2), 0, "the PIN left its field");
    // Each copy asks it again; cancelled, nothing is copied.
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(app.get_confirming(), 20);
    app.set_confirming(0);
    app.invoke_sheet_closed(20);
    assert_eq!(app.get_notice_code(), 0);
    app.invoke_copy(1);
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(20);
    assert_eq!(app.get_notice_code(), 1);
    app.invoke_close_item();

    // The PIN opened the item lock only for those uses: the sealed login is still locked.
    phone.open_item("Sealed");
    assert_eq!(app.get_d_check(), 2);
    // "Show the secrets" asks the PIN once and shows them; a copy asks it once more.
    app.invoke_ask(13);
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(13);
    assert_eq!(app.get_d_password(), "sealed-test-password");
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(app.get_confirming(), 20, "one PIN for the copy, not two");
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(20);
    assert_eq!(app.get_notice_code(), 1);
    assert_eq!(app.get_d_check(), 0, "still open for this visit");
    app.invoke_close_item();

    // Off: nothing is asked.
    app.invoke_ask_each_use_changed(false);
    phone.open_item("Mail");
    app.invoke_toggle_password();
    assert_eq!(app.get_confirming(), 0);
    assert_eq!(app.get_d_password(), "mail-test-password");
    assert_eq!(system.asked(), 0);
}

#[test]
fn a_phone_without_a_screen_lock_or_an_item_pin_shows_nothing() {
    let phone = Phone::open(|vault, _| {
        vault
            .add_item(&ItemData::login(
                "Mail",
                "me",
                "mail-test-password",
                "https://mail.example",
            ))
            .unwrap();
    });
    let (app, controller) = (&phone.app, &phone.controller);
    let system = CheckingSystem::with_screen_lock(false);
    controller.set_system(system.clone());
    assert_eq!(
        app.get_ask_each_use_state(),
        3,
        "Settings says nothing can ask"
    );
    phone.open_item("Mail");
    app.invoke_toggle_password();
    assert_eq!(app.get_d_password(), "");
    assert_eq!(app.get_confirming(), 0);
    assert_eq!(app.get_notice_code(), 26, "said why, and how to change it");
    app.set_notice_code(0);
    app.invoke_copy(1);
    assert_eq!(app.get_notice_code(), 26);
    app.invoke_edit_item();
    assert_eq!(app.get_page(), Page::Item, "the editor stays shut too");
    // A screen lock set in Android's settings meanwhile: the phone asks from now on.
    system.screen_lock.set(true);
    controller.came_back(false);
    assert_eq!(app.get_ask_each_use_state(), 0);
    app.invoke_toggle_password();
    assert_eq!(system.asked(), 1);
    controller.person_checked(Ok(()));
    assert_eq!(app.get_d_password(), "mail-test-password");
    // The screen lock removed while the prompt was coming: nothing shows.
    app.invoke_toggle_password();
    app.invoke_toggle_password();
    controller.person_checked(Err("no_lock".into()));
    assert_eq!(app.get_d_password(), "");
    assert_eq!(app.get_notice_code(), 26);
}

/// A login with a time-based code, one with a counter-based code, and one with a code behind a
/// PIN item lock that covers it alone.
fn codes_vault(vault: &mut Vault, _: &SecretKey) {
    let mut mail = ItemData::login("Mail", "me", "mail-test-password", "https://mail.example");
    mail.totp = "JBSWY3DPEHPK3PXP".into();
    vault.add_item(&mail).unwrap();
    let mut bank = ItemData::login("Bank", "me", "bank-test-password", "https://bank.example");
    bank.totp = "otpauth://hotp/Bank:me?secret=GEZDGNBVGY3TQOJQ&counter=0".into();
    vault.add_item(&bank).unwrap();
    vault
        .set_item_guard(false, GuardCheck::Pin, Some(ITEM_PIN), None)
        .unwrap();
    let mut sealed = ItemData::login("Sealed", "me", "sealed-test-password", "sealed.example");
    sealed.totp = "GEZDGNBVGY3TQOJQ".into();
    sealed.reprompt = true;
    vault.add_item(&sealed).unwrap();
}

/// The code `secret` gives now, as the screens group it (six digits: "123 456").
fn code_now(secret: &str) -> String {
    let digits = vault_core::totp::Totp::parse(secret).unwrap().now().0;
    format!("{} {}", &digits[..3], &digits[3..])
}

fn code_row(app: &PhoneWindow, title: &str) -> crate::ui::CodeRow {
    let codes = app.get_codes();
    (0..codes.row_count())
        .map(|i| codes.row_data(i).unwrap())
        .find(|row| row.title == title)
        .unwrap()
}

fn code_index(app: &PhoneWindow, title: &str) -> i32 {
    let codes = app.get_codes();
    let index = (0..codes.row_count())
        .find(|&i| codes.row_data(i).unwrap().title == title)
        .unwrap();
    i32::try_from(index).unwrap()
}

#[test]
fn one_time_codes_show_after_the_phone_asks_until_they_run_out() {
    const DOTS: &str = "••• •••";
    let phone = Phone::open(codes_vault);
    let (app, controller) = (&phone.app, &phone.controller);
    let system = CheckingSystem::with_screen_lock(true);
    controller.set_system(system.clone());

    // The item page: dots and an eye, no countdown, until the phone said yes.
    phone.open_item("Mail");
    assert!(app.get_d_has_code() && app.get_d_code_eye() && app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), DOTS);
    app.invoke_toggle_code();
    assert_eq!(system.asked(), 1);
    assert_eq!(system.asked.borrow()[0], "Show the one-time code");
    assert!(app.get_d_code_hidden(), "nothing before the answer");
    controller.person_checked(Ok(()));
    assert!(!app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), code_now("JBSWY3DPEHPK3PXP"));
    // Once that code runs out, dots again; nothing asks by itself, the eye asks again.
    controller.codes_run_out();
    assert!(app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), DOTS);
    assert_eq!(system.asked(), 1);
    app.invoke_toggle_code();
    assert_eq!(system.asked(), 2);
    controller.person_checked(Ok(()));
    assert!(!app.get_d_code_hidden());
    // Hidden with the eye: never asked.
    app.invoke_toggle_code();
    assert!(app.get_d_code_hidden());
    assert_eq!(system.asked(), 2);
    // A refusal shows nothing.
    app.invoke_toggle_code();
    controller.person_checked(Err(String::new()));
    assert!(app.get_d_code_hidden());
    app.invoke_toggle_code();
    controller.person_checked(Err("Too many attempts".into()));
    assert!(app.get_d_code_hidden());
    assert_eq!(app.get_notice_code(), 27);
    // Leaving the item hides it.
    app.invoke_toggle_code();
    controller.person_checked(Ok(()));
    assert!(!app.get_d_code_hidden());
    app.invoke_close_item();
    phone.open_item("Mail");
    assert!(app.get_d_code_hidden());
    assert_eq!(system.asked(), 5);
    app.invoke_close_item();

    // A counter-based code runs out with Next: the new one is dots again.
    phone.open_item("Bank");
    app.invoke_toggle_code();
    controller.person_checked(Ok(()));
    let first = app.get_d_code();
    assert_ne!(first, DOTS);
    app.invoke_next_code();
    assert!(app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), DOTS);
    app.invoke_toggle_code();
    controller.person_checked(Ok(()));
    assert_ne!(app.get_d_code(), first, "the next code");
    app.invoke_close_item();

    // The Codes page: every row dots with an eye; showing one asks for that one only.
    app.set_place(Place::Codes);
    let mail = code_row(app, "Mail");
    assert!(mail.hidden && mail.eye);
    assert_eq!(mail.code, DOTS);
    assert!(code_row(app, "Bank").hidden);
    assert_eq!(
        code_row(app, "Sealed").code,
        "",
        "behind the item lock: as before"
    );
    app.invoke_toggle_code_at(code_index(app, "Mail"));
    assert_eq!(system.asked(), 8);
    assert!(code_row(app, "Mail").hidden);
    controller.person_checked(Ok(()));
    let mail = code_row(app, "Mail");
    assert!(!mail.hidden);
    assert_eq!(mail.code, code_now("JBSWY3DPEHPK3PXP"));
    assert!(code_row(app, "Bank").hidden, "that one only");
    // A refusal on a row shows nothing; a shown row hides with its eye, unasked.
    app.invoke_toggle_code_at(code_index(app, "Bank"));
    controller.person_checked(Err(String::new()));
    assert!(code_row(app, "Bank").hidden);
    app.invoke_toggle_code_at(code_index(app, "Mail"));
    assert!(code_row(app, "Mail").hidden);
    assert_eq!(system.asked(), 9);
    // Shown again, then its code runs out: dots.
    app.invoke_toggle_code_at(code_index(app, "Mail"));
    controller.person_checked(Ok(()));
    assert!(!code_row(app, "Mail").hidden);
    controller.codes_run_out();
    assert!(code_row(app, "Mail").hidden);
    // Copying asks as before, shown or not.
    app.set_notice_code(0);
    app.invoke_copy_code(code_index(app, "Mail"));
    assert_eq!((system.asked(), app.get_notice_code()), (11, 0));
    controller.person_checked(Ok(()));
    assert_eq!(app.get_notice_code(), 5);
    // Locking hides every code.
    app.invoke_toggle_code_at(code_index(app, "Mail"));
    controller.person_checked(Ok(()));
    assert!(!code_row(app, "Mail").hidden);
    app.invoke_lock_now();
    phone.unlock(PASSWORD);
    app.set_place(Place::Codes);
    assert!(code_row(app, "Mail").hidden);
    app.set_place(Place::Items);

    // Behind the item lock: "Show the secrets" asks its PIN once and shows the code too.
    let asked = system.asked();
    phone.open_item("Sealed");
    assert_eq!(app.get_d_check(), 2);
    app.invoke_ask(13);
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(13);
    assert!(!app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), code_now("GEZDGNBVGY3TQOJQ"));
    assert_eq!(system.asked(), asked, "the phone isn't asked as well");
    app.invoke_close_item();

    // Off: codes show as before, with no eye.
    app.invoke_ask_each_use_changed(false);
    phone.open_item("Mail");
    assert!(!app.get_d_code_hidden() && !app.get_d_code_eye());
    assert_eq!(app.get_d_code(), code_now("JBSWY3DPEHPK3PXP"));
    app.invoke_close_item();
    app.set_place(Place::Codes);
    let mail = code_row(app, "Mail");
    assert!(!mail.hidden && !mail.eye);
    assert_eq!(mail.code, code_now("JBSWY3DPEHPK3PXP"));
    assert_eq!(system.asked(), asked);
}

#[test]
fn a_code_on_a_phone_without_a_screen_lock_asks_the_item_pin() {
    let phone = Phone::open(codes_vault);
    let (app, controller) = (&phone.app, &phone.controller);
    let system = CheckingSystem::with_screen_lock(false);
    controller.set_system(system.clone());
    phone.open_item("Mail");
    assert!(app.get_d_code_hidden());
    app.invoke_toggle_code();
    assert_eq!(app.get_confirming(), 20);
    assert_eq!(system.asked(), 0);
    type_secret(app, 2, ITEM_PIN);
    app.invoke_confirmed(20);
    assert_eq!(app.get_confirming(), 0);
    assert!(!app.get_d_code_hidden());
    assert_eq!(app.get_d_code(), code_now("JBSWY3DPEHPK3PXP"));
    app.invoke_close_item();
    // The Codes page asks it per row too; cancelled, nothing shows.
    app.set_place(Place::Codes);
    app.invoke_toggle_code_at(code_index(app, "Mail"));
    assert_eq!(app.get_confirming(), 20);
    app.set_confirming(0);
    app.invoke_sheet_closed(20);
    assert!(code_row(app, "Mail").hidden);
}

/// The keyboard learns nothing typed in the app (M10 S23): the APK builds Slint's Android
/// backend from `vendor/`, whose text fields ask the keyboard not to learn
/// (`IME_FLAG_NO_PERSONALIZED_LEARNING`). After a Slint update cargo would quietly take the
/// published crate instead, without the flag: this fails then, until the copy is made again
/// (`vendor/update-slint-android.ps1`).
#[test]
fn the_keyboard_is_asked_not_to_learn() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();
    let entry = lock
        .split("[[package]]")
        .find(|entry| {
            entry
                .lines()
                .any(|line| line == "name = \"i-slint-backend-android-activity\"")
        })
        .expect("Slint's Android backend is in the lock file");
    assert!(
        !entry.contains("source = "),
        "the lock file takes Slint's Android backend from crates.io, not vendor/: {entry}"
    );
    let vendored = root.join("vendor/i-slint-backend-android-activity");
    let manifest = std::fs::read_to_string(vendored.join("Cargo.toml")).unwrap();
    let version = entry
        .lines()
        .find_map(|line| line.strip_prefix("version = "))
        .unwrap();
    assert!(
        manifest
            .lines()
            .any(|line| line == format!("version = {version}")),
        "vendor/ holds another version than the lock file's {version}"
    );
    let java = std::fs::read_to_string(vendored.join("java/SlintAndroidJavaHelper.java")).unwrap();
    assert!(
        java.contains("| EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING;"),
        "the vendored Java side lacks the keyboard's flag"
    );
}
