//! The phone app end to end, headless: a vault made on the computer is brought in, then
//! items, the item page, codes, generator, lock, unlock, a newer copy, and sync through a
//! running server. Slow work runs
//! inline; test values only.

use std::path::Path;

use slint::{ComponentHandle, Model};
use vault_core::{GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Unlock, Vault};

use vault_platform::sync::{self, ServerTarget, Target as _};

use crate::{
    Controller,
    ui::{Page, PhoneWindow, Place, Screen, Secrets},
};

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
    // Both go again, so the rest of this test sees the vault it expects.
    for title in ["Example Mail", "Test card"] {
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

    // Stop: the phone forgets its server key; the copies stay on the server.
    app.invoke_sync_stop();
    assert_eq!(
        (app.get_sync_state(), app.get_sync_place().as_str()),
        (0, "")
    );
    assert_eq!(
        pc_server.list().unwrap().len(),
        3,
        "the computer's and both phones'"
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
