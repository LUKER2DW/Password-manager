//! Headless end-to-end test: the real Slint window and controller, driven through the same
//! callbacks the UI uses, with Slint's testing backend (nothing is drawn on screen).
//! Argon2id runs at the format's minimum cost here to keep the test fast.

use std::{
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use slint::{ComponentHandle, Model};
use vault_core::{
    Attachment, CustomField, GuardCheck, ItemData, ItemKind, KdfParams, Passkey, RecoveryCode,
    SecretKey, Vault, card,
};
use vault_platform::{
    quick_unlock::{DeviceVerifier, QuickUnlockError},
    secret_store::{self, MemoryChip},
};
use zeroize::Zeroizing;

use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, ExportCounts, Messages, Panel, Screen, Secrets},
};

const PASSWORD: &str = "desktop test passphrase one";
const NEW_PASSWORD: &str = "desktop test passphrase two";

/// Renewing the vault key, and taking one renewed on another device.
mod renew;
/// What the review of the audit fixes found, each on a vault of its own.
mod review;
/// How the Secret Key is kept: under the (stand-in) chip, a cleared chip, one that fails.
mod secret_key;

/// Every label and value the window's accessibility tree gives out as it is now: what a screen
/// reader reads, and any program of this user asking UI Automation.
fn accessible_texts(app: &AppWindow) -> Vec<String> {
    i_slint_backend_testing::ElementQuery::from_root(app)
        .match_descendants()
        .find_all()
        .into_iter()
        .flat_map(|element| [element.accessible_label(), element.accessible_value()])
        .flatten()
        .map(|text| text.to_string())
        .collect()
}

fn type_into(app: &AppWindow, field: i32, text: &str) {
    let secrets = app.global::<Secrets>();
    secrets.invoke_clear(field);
    for c in text.chars() {
        secrets.invoke_insert(field, c.to_string().into());
    }
}

fn length(app: &AppWindow, field: usize) -> i32 {
    app.global::<Secrets>()
        .get_lengths()
        .row_data(field)
        .unwrap()
}

/// Stands in for Windows Hello: "verifies" instantly and returns a fixed secret.
#[derive(Debug, Default)]
struct FakeHello {
    cancel: AtomicBool,
    other_device: AtomicBool,
}

impl DeviceVerifier for FakeHello {
    fn name(&self) -> &'static str {
        "Fake Hello"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn enroll(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        self.secret(vault_id)
    }
    fn secret(&self, vault_id: &str) -> Result<Zeroizing<Vec<u8>>, QuickUnlockError> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(QuickUnlockError::Cancelled);
        }
        let byte = if self.other_device.load(Ordering::SeqCst) {
            2
        } else {
            1
        };
        let mut secret = vec![byte; 256];
        secret[..vault_id.len()].copy_from_slice(vault_id.as_bytes());
        Ok(Zeroizing::new(secret))
    }
    fn remove(&self, _vault_id: &str) {}
}

/// The tests that open the app point `VAULT_HOME` (its folder: device state, caches) at a
/// folder of their own: one at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The stand-in for the security chip that keeps the Secret Keys of this binary's tests
/// (CRYPTO.md §2.2.1), so none makes a key in this computer's TPM. Every test that stores a
/// Secret Key takes its turn first (`app_home`), which puts it in place.
fn memory_chip() -> &'static Arc<MemoryChip> {
    static CHIP: OnceLock<Arc<MemoryChip>> = OnceLock::new();
    CHIP.get_or_init(|| {
        let chip = Arc::new(MemoryChip::default());
        secret_store::use_key_wrapper(Some(chip.clone()));
        chip
    })
}

/// Takes this test's turn and points `VAULT_HOME` at `home` while it is held.
fn app_home(home: &Path) -> MutexGuard<'static, ()> {
    let turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    memory_chip();
    // SAFETY: every test that sets the environment holds this turn while it does, and the
    // other tests of this binary never read VAULT_HOME.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("VAULT_HOME", home);
    }
    turn
}

/// Removes the test vault's Secret Key from the OS credential store, even if the test fails.
struct ForgetOnDrop(String);

impl Drop for ForgetOnDrop {
    fn drop(&mut self) {
        let _ = secret_store::forget(&self.0);
    }
}

#[test]
fn whole_app_flow_headless() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let path = dir.path().join("test.vault");

    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let hello = Arc::new(FakeHello::default());
    let controller = Controller::install(
        &app,
        path.clone(),
        Runner::Inline,
        Some(hello.clone() as Arc<dyn DeviceVerifier>),
    )
    .unwrap();
    assert!(app.get_quick_unlock_available());

    // ---- onboarding ----
    assert_eq!(app.get_screen(), Screen::Onboarding);
    type_into(&app, 0, "short");
    type_into(&app, 1, "short");
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 5, "too short");

    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, &format!("{PASSWORD}x"));
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 4, "mismatch");
    app.global::<Secrets>().invoke_backspace(1);
    assert_eq!(length(&app, 1), PASSWORD.chars().count() as i32);

    app.invoke_suggest_passphrase();
    assert!(app.get_suggestion().split('-').count() >= 6);

    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(app.get_onboarding_step(), 2, "on to the item lock");
    assert!(!path.exists(), "nothing written before the lock is chosen");
    // Suggested: a PIN on every item, with Windows Hello. A bad PIN is caught here.
    assert_eq!(app.get_onboarding_guard(), 0);
    assert!(app.get_guard_all() && app.get_guard_hello());
    type_into(&app, 12, "12ab");
    app.invoke_create_vault();
    assert_eq!(app.get_error_code(), 36, "a PIN is digits");
    assert!(!path.exists());
    // This flow tests the item lock later, from Settings: none for now.
    app.set_onboarding_guard(3);
    app.invoke_create_vault();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_onboarding_step(), 3);
    let secret_key = app.get_kit_secret_key().to_string();
    let parts = [
        app.get_kit_part_a(),
        app.get_kit_part_b(),
        app.get_kit_part_c(),
    ]
    .map(|part| part.to_string());
    let _cleanup = ForgetOnDrop(app.get_vault_id().to_string());
    assert!(secret_key.starts_with("S0-"));
    for (part, prefix) in parts.iter().zip(["A0-", "B0-", "C0-"]) {
        assert!(part.starts_with(prefix));
    }
    assert_eq!(length(&app, 0), 0, "typed password wiped after use");
    assert!(path.exists());

    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(
        app.get_kit_secret_key(),
        "",
        "kit hidden once the vault opens"
    );
    assert_eq!(app.get_total_items(), 0);

    // ---- add a login ----
    app.invoke_new_item();
    assert_eq!(app.get_panel(), Panel::Editor);
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 9, "title required");
    app.set_ed_title("GitHub".into());
    app.set_ed_username("octocat".into());
    app.set_ed_url("https://github.com".into());
    app.set_ed_totp("not a secret!".into());
    type_into(&app, 4, "gh-item-pass");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 10, "bad TOTP rejected");
    app.set_ed_totp("JBSWY3DPEHPK3PXP".into());
    app.invoke_save_item();
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_total_items(), 1);
    assert_eq!(app.get_detail_title(), "GitHub");
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_code().len(), 7, "grouped 6-digit code");
    assert_eq!(app.get_notice_code(), 5);

    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "gh-item-pass");
    // Drawn on screen, but not in what any program of this user reads through UI Automation:
    // neither the password nor the one-time code.
    let exposed = accessible_texts(&app);
    assert!(
        exposed.iter().all(|text| !text.contains("gh-item-pass")),
        "{exposed:?}"
    );
    let code: String = app
        .get_totp_code()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    assert!(
        exposed
            .iter()
            .all(|text| !text.replace(' ', "").contains(&code))
    );
    app.invoke_conceal();
    assert_eq!(app.get_revealed_password(), "");

    // ---- a note, search, categories, favorites ----
    app.invoke_new_item();
    app.set_ed_kind(2);
    app.set_ed_title("Alarm code".into());
    app.set_ed_notes("1234 then #".into());
    app.invoke_save_item();
    assert_eq!(app.get_total_items(), 2);
    let counts: Vec<i32> = app.get_counts().iter().collect();
    assert_eq!(counts, [2, 0, 1, 0, 1, 0, 0]);

    // ---- sync through a folder: another computer's copy is merged in ----
    let sync_dir = dir.path().join("sync folder");
    std::fs::create_dir_all(&sync_dir).unwrap();
    let vault_id = app.get_vault_id().to_string();
    let other_device = vault_core::sync::DeviceId::from_bytes([0x42; 16]);
    {
        // The other computer: the same vault, opened with the same keys, one more item.
        let mut other = vault_core::Vault::open(
            &std::fs::read(&path).unwrap(),
            vault_core::Unlock::Password {
                password: PASSWORD,
                secret_key: &vault_core::SecretKey::parse(&secret_key).unwrap(),
            },
        )
        .unwrap();
        other.set_device(other_device);
        other
            .add_item(&vault_core::ItemData::login(
                "From the laptop",
                "l",
                "laptop-pw",
                "https://laptop.example",
            ))
            .unwrap();
        let devices = sync_dir.join(&vault_id).join("devices");
        std::fs::create_dir_all(&devices).unwrap();
        std::fs::write(
            devices.join(format!("{}.vault", other_device.to_hex())),
            other.to_bytes().unwrap(),
        )
        .unwrap();
    }
    app.invoke_open_settings();
    assert_eq!(app.get_sync_folder(), "", "off until a folder is chosen");
    controller.sync_start(sync_dir.clone());
    assert_eq!(app.get_total_items(), 3, "the laptop's item arrived");
    assert_eq!(app.get_notice_code(), 52);
    assert_eq!(app.get_sync_state(), 1, "synced: {}", app.get_sync_detail());
    assert_eq!(app.get_sync_minutes(), 0);
    assert!(
        !app.get_sync_this_device().is_empty(),
        "this computer is listed"
    );
    let own = std::fs::read_dir(sync_dir.join(&vault_id).join("devices"))
        .unwrap()
        .count();
    assert_eq!(own, 2, "this computer's copy is in the folder too");
    // Nothing new: another round changes nothing.
    app.set_notice_code(0);
    controller.sync_round();
    assert_eq!(app.get_notice_code(), 0);
    assert_eq!(app.get_total_items(), 3);
    app.invoke_sync_stop();
    assert_eq!(app.get_sync_folder(), "");
    assert_eq!(app.get_sync_state(), 0);
    app.invoke_select_category(0);
    let laptop = app
        .get_items()
        .iter()
        .position(|row| row.title == "From the laptop")
        .unwrap();
    app.invoke_select(i32::try_from(laptop).unwrap());
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), 2);

    app.set_search_text("git".into());
    app.invoke_search("git".into());
    assert_eq!(app.get_items().row_count(), 1);
    app.set_search_text("".into());
    app.invoke_search("".into());
    app.invoke_select_category(4);
    assert_eq!(app.get_items().row_count(), 1);
    app.invoke_select(0);
    assert_eq!(app.get_detail_title(), "Alarm code");
    app.invoke_toggle_favorite();
    assert!(app.get_detail_favorite());
    assert_eq!(app.get_counts().row_data(1), Some(1));

    // ---- edit keeps the password; delete ----
    app.invoke_select_category(0);
    let github = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "GitHub")
        .unwrap();
    app.invoke_select(github as i32);
    app.invoke_edit_item();
    assert_eq!(
        length(&app, 4),
        "gh-item-pass".len() as i32,
        "existing password preloaded"
    );
    app.set_ed_username("hubot".into());
    app.invoke_save_item();
    assert_eq!(app.get_detail_username(), "hubot");
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "gh-item-pass");

    app.invoke_select_category(4);
    app.invoke_select(0);
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), 1);
    assert_eq!(app.get_notice_code(), 6);

    // ---- an SSH key made here, with a file attached ----
    app.invoke_select_category(5);
    app.invoke_new_item();
    assert_eq!(app.get_ed_kind(), 4, "the SSH keys list makes SSH keys");
    app.set_ed_title("Build server".into());
    app.set_ed_username("deploy@test".into());
    app.invoke_ssh_generate();
    assert!(app.get_ed_ssh_has_key());
    assert!(
        app.get_ed_ssh_public().starts_with("ssh-ed25519 ")
            && app.get_ed_ssh_public().ends_with(" deploy@test")
    );
    assert!(app.get_ed_ssh_fingerprint().starts_with("SHA256:"));
    let attached = dir.path().join("notes for the server.txt");
    std::fs::write(&attached, b"test attachment").unwrap();
    controller.file_add_from(&attached);
    assert_eq!(app.get_ed_files().row_count(), 1);
    assert_eq!(app.get_ed_files().row_data(0).unwrap().size, "15 B");
    let not_a_key = dir.path().join("not-a-key.pub");
    std::fs::write(&not_a_key, b"ssh-ed25519 AAAA public only").unwrap();
    controller.ssh_load_from(&not_a_key);
    assert_eq!(
        app.get_error_code(),
        52,
        "a .pub file isn't the private key"
    );
    app.invoke_save_item();
    assert_eq!(app.get_detail_kind(), 4);
    assert_eq!(app.get_detail_files().row_count(), 1);
    assert!(
        app.get_detail_fields()
            .iter()
            .any(|f| f.label == "Public key")
    );
    app.invoke_reveal();
    assert!(
        app.get_revealed_password()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    app.invoke_conceal();
    app.invoke_edit_item();
    assert!(app.get_ed_ssh_has_key());
    assert_eq!(
        app.get_ed_fields().row_count(),
        0,
        "the public half has its own place"
    );
    app.invoke_file_remove(0);
    app.invoke_save_item();
    assert_eq!(app.get_detail_files().row_count(), 0);
    app.invoke_delete_item();
    app.invoke_select_category(0);

    // ---- folders and recovery codes ----
    // The folder dialog: a name is required, a picture link must look like one.
    app.invoke_new_folder();
    assert_eq!(app.get_folder_dialog(), 0);
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 30, "a folder needs a name");
    assert_eq!(app.get_folder_dialog(), 0, "the dialog stays open");
    app.set_fd_name("Google".into());
    app.set_fd_link("not a link".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 28);
    app.set_fd_link("".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_folder_dialog(), -1, "closed once saved");
    assert_eq!(app.get_folders().row_count(), 1);
    assert_eq!(app.get_category(), 100, "the new folder opens");
    assert_eq!(app.get_folder_name(), "Google");
    assert_eq!(app.get_items().row_count(), 0);
    // A new item made while browsing a folder starts in it.
    app.invoke_new_item();
    assert_eq!(app.get_ed_folder(), 1);
    app.set_ed_title("Gmail".into());
    app.set_ed_recovery_codes("1. aaaa-1111\n2. bbbb-2222\n3. cccc-3333".into());
    app.invoke_save_item();
    assert_eq!(app.get_items().row_count(), 1);
    assert_eq!(app.get_folders().row_data(0).unwrap().count, 1);
    assert_eq!(app.get_detail_folder(), "Google");
    assert_eq!(app.get_detail_codes_total(), 3);
    assert_eq!(
        app.get_detail_codes().row_count(),
        0,
        "codes hidden until asked"
    );
    app.invoke_show_codes();
    assert_eq!(
        app.get_detail_codes().row_data(0).unwrap().code,
        "aaaa-1111"
    );
    app.invoke_copy_code(0);
    assert_eq!(app.get_notice_code(), 18);
    app.invoke_toggle_code_used(0);
    assert_eq!(app.get_detail_codes_left(), 2);
    assert!(
        app.get_detail_codes().row_data(0).unwrap().used,
        "still shown, marked"
    );
    // Editing keeps the used mark for codes that stay.
    app.invoke_edit_item();
    assert!(app.get_ed_recovery_codes().contains("aaaa-1111"));
    app.set_ed_recovery_codes("aaaa-1111\nbbbb-2222\ndddd-4444".into());
    app.invoke_save_item();
    assert_eq!(
        (app.get_detail_codes_total(), app.get_detail_codes_left()),
        (3, 2)
    );
    // Folder settings: name, icon, colour and a picture link in one go (the picture itself is
    // only downloaded by the app, not in this test).
    app.invoke_edit_folder(0);
    assert_eq!(app.get_folder_dialog(), 1);
    assert_eq!(app.get_fd_name(), "Google");
    app.set_fd_name("Google accounts".into());
    app.set_fd_icon("globe".into());
    app.set_fd_color(3);
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_folder_name(), "Google accounts");
    assert_eq!(app.get_folder_icon(), "globe");
    assert_eq!(app.get_folder_color(), 3);
    let row = app.get_folders().row_data(0).unwrap();
    assert_eq!((row.icon.as_str(), row.color), ("globe", 3));
    assert!(!row.has_image);
    app.invoke_edit_folder(0);
    app.set_fd_name("".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_error_code(), 30, "a folder needs a name");
    app.invoke_folder_dialog_cancel();
    assert_eq!(
        app.get_folder_name(),
        "Google accounts",
        "cancel keeps the folder"
    );

    // Reordering keeps the browsed folder selected.
    app.invoke_new_folder();
    app.set_fd_name("Work".into());
    app.invoke_folder_dialog_save();
    assert_eq!(app.get_category(), 101, "the new folder opens");
    app.invoke_move_folder(1, 0);
    assert_eq!(app.get_folders().row_data(0).unwrap().name, "Work");
    assert_eq!(app.get_category(), 100, "still browsing Work");
    assert_eq!(app.get_folder_name(), "Work");
    app.invoke_ask_delete_folder(0);
    assert_eq!(app.get_folder_dialog(), 2);
    app.invoke_folder_dialog_delete();
    assert_eq!(app.get_folders().row_count(), 1);
    assert_eq!(app.get_notice_code(), 32);

    // Back and forward through the places visited.
    app.invoke_select_category(0);
    app.invoke_open_generator();
    assert!(app.get_can_go_back());
    app.invoke_go_back();
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_category(), 0);
    assert!(app.get_can_go_forward());
    app.invoke_go_forward();
    assert_eq!(app.get_panel(), Panel::Generator);
    assert!(!app.get_can_go_forward());
    app.invoke_select_category(100);

    app.invoke_ask_delete_folder(0);
    app.invoke_folder_dialog_delete();
    assert_eq!(app.get_folders().row_count(), 0);
    assert_eq!(app.get_category(), 0);
    assert_eq!(app.get_total_items(), 2, "the folder's item stays");
    let gmail = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "Gmail")
        .unwrap();
    app.invoke_select(gmail as i32);
    assert_eq!(app.get_detail_folder(), "");
    app.invoke_delete_item();

    // ---- cards: checked fields, no generated PIN ----
    app.invoke_new_item();
    app.set_ed_kind(1);
    app.set_ed_title("Visa".into());
    app.set_ed_username("A. Person".into());
    app.set_ed_card_number("4111 1111 1111 1112".into());
    app.invoke_card_number_edited("4111 1111 1111 1112".into());
    assert_eq!(app.get_ed_card_brand(), "Visa");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 20, "typo caught by the checksum");
    app.set_ed_card_number("4111 1111 1111 1111".into());
    app.set_ed_card_expiry("13/29".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 21);
    app.set_ed_card_expiry("8/2029".into());
    app.set_ed_card_code("12".into());
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 22);
    app.set_ed_card_code("123".into());
    type_into(&app, 4, "12ab");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 23, "a PIN is digits");
    type_into(&app, 4, "1234");
    app.invoke_save_item();
    assert_eq!(
        app.get_panel(),
        Panel::Detail,
        "detail: {}",
        app.get_error_code()
    );
    let fields = app.get_detail_fields();
    assert_eq!(fields.row_data(0).unwrap().value, "Visa •••• 1111");
    assert_eq!(fields.row_data(1).unwrap().value, "08/29");
    assert!(fields.row_data(2).unwrap().sensitive);
    assert_eq!(fields.row_count(), 3, "the brand is not repeated");
    // The masked number and the hidden security code can be shown, one at a time.
    assert!(fields.row_data(0).unwrap().hideable);
    assert!(!fields.row_data(1).unwrap().hideable);
    let number = fields.row_data(0).unwrap().index;
    app.invoke_reveal_field(number);
    assert_eq!(app.get_revealed_field_value(), "4111 1111 1111 1111");
    assert!(app.get_reveal_left() > 0);
    let code = fields.row_data(2).unwrap().index;
    app.invoke_reveal_field(code);
    assert_eq!(app.get_revealed_field(), code);
    assert_eq!(app.get_revealed_field_value(), "123");
    app.invoke_reveal_field(code);
    assert_eq!(app.get_revealed_field(), -1, "a second click hides it");
    assert_eq!(app.get_revealed_field_value(), "");
    let visa = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "Visa")
        .unwrap();
    assert_eq!(
        app.get_items().row_data(visa).unwrap().subtitle,
        "Visa •••• 1111"
    );
    app.invoke_delete_item();

    // ---- authenticator page ----
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_open_authenticator();
    assert_eq!(app.get_panel(), Panel::Authenticator);
    assert_eq!(app.get_auth_rows().row_count(), 1);
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert_eq!(row.title, "GitHub");
    assert_eq!(row.code.len(), 7);
    assert!(row.left >= 1 && row.left <= 30 && row.period == 30);
    app.invoke_auth_copy(0);
    assert_eq!(app.get_notice_code(), 3);
    app.set_auth_search("zzz".into());
    app.invoke_auth_search_changed("zzz".into());
    assert_eq!(app.get_auth_rows().row_count(), 0);
    app.set_auth_search("".into());
    app.invoke_auth_search_changed("".into());
    app.invoke_auth_open(0);
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_detail_title(), "GitHub");

    // ---- browser extension: logins for the exact site, a password only when picked ----
    let raw = |message: &str| {
        String::from_utf8(controller.browser_request(message.as_bytes()).to_vec()).unwrap()
    };
    assert!(raw(r#"{"type":"status"}"#).contains(r#""locked":false"#));
    // Unconnected, nothing is answered: not plain requests, not ones signed with any key.
    let counter = std::cell::Cell::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            * vault_browser::pairing::COUNTER_SCALE,
    );
    // The extension seals each request and reads only the answer sealed to it (pairing.rs);
    // only "not connected" and its like come plain.
    let sealed = |key: &[u8], message: &str| {
        counter.set(counter.get() + 1);
        let key = vault_browser::pairing::PairingKey::from_bytes(key).unwrap();
        let (request, nonce) = key.seal_request(counter.get(), message.as_bytes()).unwrap();
        assert!(!request.contains("github"), "nothing readable on the way");
        let answer = raw(&request);
        match key.open_answer(counter.get(), &nonce, answer.as_bytes()) {
            Some(text) => text.to_string(),
            None => {
                assert!(
                    !answer.contains(r#""type":"sealed""#),
                    "an answer that doesn't open: {answer}"
                );
                answer
            }
        }
    };
    // An extension older than sealed requests signs them, and is answered plain.
    let signed = |key: &[u8], message: &str| {
        use hmac::{Hmac, KeyInit, Mac};
        counter.set(counter.get() + 1);
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&counter.get().to_le_bytes());
        mac.update(message.as_bytes());
        let mac: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let body = message.replace('\\', "\\\\").replace('"', "\\\"");
        raw(&format!(
            r#"{{"type":"signed","counter":{},"body":"{body}","mac":"{mac}"}}"#,
            counter.get()
        ))
    };
    let logins_request = r#"{"type":"logins","url":"https://github.com/login"}"#;
    assert!(raw(logins_request).contains("bad_request"));
    assert!(sealed(&[9u8; 32], logins_request).contains("not_paired"));
    assert!(signed(&[9u8; 32], logins_request).contains("not_paired"));
    let field = |json: &str, name: &str| {
        json.split(&format!(r#""{name}":""#))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap()
            .to_owned()
    };
    // The extension asks to connect: the two agree on a key without sending it, and the app
    // waits for the person to type the code the extension shows (the app itself never shows
    // it).
    let connect = || {
        let extension = vault_browser::pairing::Joiner::new().unwrap();
        let offer = raw(&format!(
            r#"{{"type":"pair","commit":"{}"}}"#,
            extension.commit_hex()
        ));
        let agreed = extension
            .finish(&field(&offer, "key"))
            .expect("the app's public key");
        let waiting = raw(&format!(
            r#"{{"type":"pair_key","key":"{}"}}"#,
            extension.public_hex()
        ));
        assert_eq!(waiting, r#"{"type":"pair_wait"}"#);
        agreed
    };
    // A key other than the one committed to is refused, and spends the offer.
    let committed = vault_browser::pairing::Joiner::new().unwrap();
    raw(&format!(
        r#"{{"type":"pair","commit":"{}"}}"#,
        committed.commit_hex()
    ));
    let stranger = vault_browser::pairing::Joiner::new().unwrap();
    for joiner in [&stranger, &committed] {
        assert!(
            raw(&format!(
                r#"{{"type":"pair_key","key":"{}"}}"#,
                joiner.public_hex()
            ))
            .contains("bad_request")
        );
    }
    assert_eq!(app.get_pairing_code(), "", "nothing waits for the person");
    let pairing = connect();
    let key = pairing.key.as_bytes().to_vec();
    // The app shows the same code as the extension, to compare.
    assert_eq!(app.get_pairing_code(), pairing.code.as_str());
    assert!(app.get_pairing_compare());
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(app.get_pairing_typed(), "");
    assert!(
        sealed(&key, logins_request).contains("not_paired"),
        "the key opens nothing until it is allowed in the app"
    );
    app.invoke_pairing_decided(false);
    assert_eq!(app.get_pairing_code(), "");
    assert!(
        sealed(&key, logins_request).contains("not_paired"),
        "refused"
    );
    // Another request to connect while the first one's master password is being checked:
    // neither key is stored (the approved one was replaced), and the newer request's own
    // code is asked for. (An extension older than the key agreement asks: it is handed the
    // key, with the code that follows from it.)
    let key_of = |reply: &str| -> Vec<u8> {
        (0..32)
            .map(|i| u8::from_str_radix(&field(reply, "key")[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    let first = raw(r#"{"type":"pair"}"#);
    let second = controller.pair_again_while_checking();
    assert!(sealed(&key_of(&first), logins_request).contains("not_paired"));
    assert!(sealed(&key_of(&second), logins_request).contains("not_paired"));
    assert_eq!(app.get_pairing_code(), field(&second, "code").as_str());
    assert!(
        !app.get_pairing_compare(),
        "a key handed over: its code is typed"
    );
    assert_eq!(app.get_error_code(), 43);
    assert!(!app.get_browser_paired());
    // Such a code must be the one typed, with or without the space.
    type_into(&app, 14, PASSWORD);
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_error_code(), 43, "no code typed");
    app.set_pairing_typed("000 000".into());
    if field(&second, "code") != "000 000" {
        app.invoke_pairing_decided(true);
        assert_eq!(app.get_error_code(), 43, "not the extension's code");
        assert_ne!(app.get_pairing_code(), "", "the dialog stays open");
    }
    app.invoke_pairing_decided(false);
    // A request to connect while another waits: the newer one's code is shown, and said to be
    // a new one.
    connect();
    let pairing = connect();
    let key = pairing.key.as_bytes().to_vec();
    assert_eq!(app.get_pairing_code(), pairing.code.as_str());
    assert_eq!(app.get_error_code(), 67);
    // Connecting after comparing the codes takes the master password, nothing typed from the
    // extension.
    assert!(app.get_pairing_needs_password());
    assert!(sealed(&key, logins_request).contains("not_paired"));
    type_into(&app, 14, "");
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_error_code(), 11, "no password typed");
    type_into(&app, 14, "not the master password");
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_error_code(), 11);
    assert_ne!(app.get_pairing_code(), "", "the dialog stays open");
    assert!(sealed(&key, logins_request).contains("not_paired"));
    type_into(&app, 14, PASSWORD);
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(app.get_pairing_code(), "");
    assert_eq!(app.get_pairing_typed(), "");
    assert_eq!(length(&app, 14), 0);
    assert_eq!(app.get_notice_code(), 41);
    assert!(app.get_browser_paired());
    let ask = |message: &str| sealed(&key, message);
    // Every use asks by default; with no Windows Hello and no item lock PIN here yet, the
    // browser gets no password at all, and Settings says so.
    app.invoke_open_settings();
    assert!(app.get_browser_always_asks());
    assert_eq!(app.get_browser_ask_way(), 0);
    let listed = ask(logins_request);
    assert!(listed.contains(r#""always_asks":true"#), "{listed}");
    let github_id = field(&listed, "id");
    let refused = ask(&format!(r#"{{"type":"reveal","id":"{github_id}"}}"#));
    assert!(
        refused.contains(r#""code":"item_locked","check":"app""#),
        "{refused}"
    );
    // The flows below ask only for what the item lock covers.
    app.set_browser_always_asks(false);
    app.invoke_settings_changed();
    // The connected extension hears which version of it this app carries (an older one
    // reloads itself from the app's folder: apps/extension/update.js).
    let version = format!(r#""extension_version":"{}""#, env!("CARGO_PKG_VERSION"));
    let status = ask(r#"{"type":"status"}"#);
    assert!(
        status.contains(r#""locked":false"#) && status.contains(&version),
        "{status}"
    );
    // So does the answer about a page's logins, asked at each sign-in field: a new version is
    // noticed at the extension's next request.
    assert!(ask(logins_request).contains(&version));
    assert!(
        !raw(r#"{"type":"status"}"#).contains("extension_version"),
        "anyone else, only locked or not"
    );
    let logins = ask(logins_request);
    assert!(
        logins.contains(r#""origin":"https://github.com""#),
        "{logins}"
    );
    // An extension older than sealed requests, with the same key: answered plain.
    let plain = signed(&key, logins_request);
    assert!(
        plain.contains(r#""origin":"https://github.com""#),
        "{plain}"
    );
    assert!(logins.contains(r#""title":"GitHub""#) && !logins.contains("password"));
    let id = logins
        .split(r#""id":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_owned();
    app.set_notice_code(0);
    let phishing = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com.evil.example/login","id":"{id}"}}"#
    ));
    assert!(phishing.contains("no_match"), "{phishing}");
    assert_eq!(app.get_notice_code(), 0);
    let filled = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/session","id":"{id}"}}"#
    ));
    assert!(filled.contains(r#""username":""#) && filled.contains(r#""password":""#));
    assert_eq!(app.get_notice_code(), 40, "a fill is announced in the app");
    assert_eq!(app.get_notice_arg(), "GitHub");
    // The same request sent again is refused, and so is one from another time.
    let replayed = format!(
        r#"{{"type":"signed","counter":{},"body":"{{}}","mac":"{}"}}"#,
        counter.get(),
        "00".repeat(32)
    );
    assert!(raw(&replayed).contains("not_paired"));
    counter.set(counter.get() + 1);
    let (again, _) = vault_browser::pairing::PairingKey::from_bytes(&key)
        .unwrap()
        .seal_request(counter.get(), logins_request.as_bytes())
        .unwrap();
    assert!(raw(&again).contains(r#""type":"sealed""#));
    assert!(
        raw(&again).contains("not_paired"),
        "the same sealed request"
    );
    // The extension's Lock button locks the vault here.
    assert!(ask(r#"{"type":"lock"}"#).contains(r#""type":"locked_now""#));
    assert_eq!(app.get_screen(), Screen::Unlock);
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    // ---- passkeys: made by the app for the extension, shown, and taken out in the editor ----
    // (The site discourages a check here; checks for a site that asks are tested in
    // vault-browser's service.)
    let challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    let made = ask(&format!(
        r#"{{"type":"passkey_create","url":"https://github.com/settings/security","user_id":"aHVib3Q","user_name":"hubot","challenge":"{challenge}","user_verification":"discouraged"}}"#
    ));
    assert!(made.contains(r#""type":"attestation""#), "{made}");
    assert_eq!(
        app.get_notice_code(),
        68,
        "kept in the GitHub login (that page and username) and saved"
    );
    assert_eq!(app.get_notice_arg(), "GitHub");
    let github = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "GitHub")
        .unwrap();
    app.invoke_select(github as i32);
    assert_eq!(app.get_detail_passkeys().row_count(), 1);
    let row = app.get_detail_passkeys().row_data(0).unwrap();
    assert_eq!(
        (row.site.as_str(), row.user.as_str()),
        ("github.com", "hubot")
    );
    let listed = ask(r#"{"type":"passkeys","url":"https://github.com/login"}"#);
    let signed_in = ask(&format!(
        r#"{{"type":"passkey_get","url":"https://github.com/login","id":"{}","credential":"{}","challenge":"{challenge}","user_verification":"discouraged"}}"#,
        field(&listed, "id"),
        field(&listed, "credential")
    ));
    assert!(signed_in.contains(r#""type":"assertion""#), "{signed_in}");
    assert_eq!(app.get_notice_code(), 69, "a sign-in with it is told");
    app.invoke_edit_item();
    assert_eq!(app.get_ed_passkeys().row_count(), 1);
    app.invoke_passkey_remove(0);
    assert_eq!(app.get_ed_passkeys().row_count(), 0);
    app.invoke_save_item();
    assert_eq!(app.get_detail_passkeys().row_count(), 0, "gone once saved");
    assert!(
        ask(r#"{"type":"passkeys","url":"https://github.com/login"}"#).contains(r#""items":[]"#)
    );

    // ---- extra fields ----
    app.invoke_edit_item();
    app.invoke_field_add();
    app.invoke_field_edited(0, true, "Customer no.".into());
    app.invoke_field_edited(0, false, "C-42".into());
    app.invoke_field_hidden(0, true);
    assert!(app.get_ed_fields().row_data(0).unwrap().hidden);
    app.invoke_field_add(); // left empty: dropped on save
    app.invoke_save_item();
    let fields = app.get_detail_fields();
    assert_eq!(fields.row_count(), 1);
    assert_eq!(fields.row_data(0).unwrap().label, "Customer no.");
    assert!(fields.row_data(0).unwrap().sensitive);
    assert_eq!(
        fields.row_data(0).unwrap().value,
        "",
        "hidden values stay in Rust"
    );
    app.invoke_reveal_field(0);
    assert_eq!(app.get_revealed_field_value(), "C-42");
    app.invoke_reveal();
    assert_eq!(
        app.get_revealed_field(),
        -1,
        "one secret on screen at a time"
    );
    app.invoke_edit_item();
    assert_eq!(app.get_ed_fields().row_data(0).unwrap().value, "C-42");
    app.invoke_field_remove(0);
    app.invoke_save_item();
    assert_eq!(app.get_detail_fields().row_count(), 0);

    // ---- a change made outside this window is never overwritten ----
    let good = std::fs::read(&path).unwrap();
    let mut other = good.clone();
    other.push(0);
    std::fs::write(&path, &other).unwrap();
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 24);
    assert_eq!(app.get_notice_code(), 23);
    assert_eq!(std::fs::read(&path).unwrap(), other, "left untouched");
    std::fs::write(&path, &good).unwrap();
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 0, "saves again once the file matches");
    app.invoke_toggle_favorite();
    // A backup is the vault as it is open here: never a file replaced meanwhile, even an
    // older, authentic copy of this same vault.
    let backup = dir.path().join("backup.vault");
    let current = std::fs::read(&path).unwrap();
    app.invoke_toggle_favorite();
    assert_eq!(app.get_error_code(), 0);
    let newer = std::fs::read(&path).unwrap();
    std::fs::write(&path, &current).unwrap();
    controller.save_confirmed_backup(&backup);
    assert_eq!(app.get_error_code(), 24, "an older copy put back: refused");
    assert!(!backup.exists());
    std::fs::write(&path, &newer).unwrap();
    controller.save_confirmed_backup(&backup);
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(std::fs::read(&backup).unwrap(), newer);
    app.invoke_toggle_favorite();
    // The extension hears "saved" only once the login is on disk. With the file changed
    // elsewhere it is told `not_saved`, the other change stays, and nothing is kept in memory
    // to be written later; asked again once the file matches, it is saved.
    let current = std::fs::read(&path).unwrap();
    let mut elsewhere = current.clone();
    elsewhere.push(0);
    std::fs::write(&path, &elsewhere).unwrap();
    let save_request = r#"{"type":"save","url":"https://shop.example/login","username":"from-browser","password":"pw-from-browser"}"#;
    let shop_logins = r#"{"type":"logins","url":"https://shop.example/login"}"#;
    let refused = ask(save_request);
    assert!(refused.contains(r#""code":"not_saved""#), "{refused}");
    assert_eq!(std::fs::read(&path).unwrap(), elsewhere, "left untouched");
    std::fs::write(&path, &current).unwrap();
    assert!(
        !ask(shop_logins).contains("from-browser"),
        "nothing kept in memory"
    );
    // A write the disk refuses: the vault in memory goes back as it was.
    #[cfg(windows)]
    {
        let writable = std::fs::metadata(&path).unwrap().permissions();
        let mut readonly = writable.clone();
        readonly.set_readonly(true);
        std::fs::set_permissions(&path, readonly).unwrap();
        let refused = ask(save_request);
        std::fs::set_permissions(&path, writable).unwrap();
        assert!(refused.contains(r#""code":"not_saved""#), "{refused}");
        assert_eq!(std::fs::read(&path).unwrap(), current, "left untouched");
        assert!(!ask(shop_logins).contains("from-browser"), "rolled back");
    }
    let saved = ask(save_request);
    assert!(
        saved.contains(r#""type":"saved""#) && saved.contains(r#""existing":false"#),
        "{saved}"
    );
    assert_ne!(std::fs::read(&path).unwrap(), current, "on disk now");
    let shop = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "shop.example")
        .expect("listed");
    app.invoke_select(shop as i32);
    app.invoke_delete_item();
    let github = (0..app.get_items().row_count())
        .find(|&i| app.get_items().row_data(i).unwrap().title == "GitHub")
        .unwrap();
    app.invoke_select(github as i32);

    // ---- an icon taken from another website ----
    app.invoke_edit_item();
    app.set_ed_icon_url("  github.example ".into());
    app.invoke_save_item();
    app.invoke_edit_item();
    assert_eq!(app.get_ed_icon_url(), "https://github.example");
    app.set_ed_icon_url("".into());
    app.invoke_save_item();

    // ---- password history: the old password is kept when it changes ----
    assert_eq!(app.get_detail_title(), "GitHub");
    assert_eq!(app.get_detail_history_count(), 0);
    assert!(app.get_detail_strength_score() >= 1);
    app.invoke_edit_item();
    type_into(&app, 4, "password123");
    assert!(
        app.get_ed_strength_bits() > 0,
        "strength shown while typing"
    );
    assert_eq!(app.get_ed_weakness(), 3, "a very common password");
    app.invoke_save_item();
    assert_eq!(app.get_detail_history_count(), 1);
    assert_eq!(app.get_detail_strength_score(), 0);
    assert_eq!(app.get_detail_age_unit(), 0, "changed today");
    app.invoke_show_history();
    assert!(app.get_detail_history_shown());
    assert_eq!(app.get_detail_history().row_data(0).unwrap().password, "");
    app.invoke_reveal_history(0);
    assert_eq!(
        app.get_detail_history().row_data(0).unwrap().password,
        "gh-item-pass"
    );
    app.invoke_reveal_history(0);
    assert_eq!(app.get_detail_history().row_data(0).unwrap().password, "");

    // ---- password health ----
    app.invoke_open_health();
    assert_eq!(app.get_panel(), Panel::Health);
    assert!(app.get_health_logins() >= 1);
    assert!(
        app.get_health_counts().row_data(1).unwrap() >= 1,
        "a weak one"
    );
    assert!(app.get_health_score() < 100);
    app.set_health_filter(1);
    app.invoke_health_filter_changed(1);
    let weak = app.get_health_rows();
    let github_row = (0..weak.row_count())
        .find(|&i| weak.row_data(i).unwrap().title == "GitHub")
        .expect("GitHub listed as weak");
    assert_eq!(weak.row_data(github_row).unwrap().problem, 2);
    app.invoke_health_open(i32::try_from(github_row).unwrap());
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_detail_title(), "GitHub");
    app.set_health_filter(-1);
    // The leak watch (off until turned on): every login checked once a day; a new leak is told
    // once and Password health shows it.
    controller.set_leak_batch(|queries| Ok(queries.iter().map(|(i, _)| (*i, 3)).collect()));
    assert!(!app.get_leaks_checked());
    app.set_notice_code(0);
    app.set_leak_watch(true);
    app.invoke_settings_changed();
    assert_eq!(app.get_notice_code(), 67, "{}", app.get_error_detail());
    assert!(app.get_leaks_checked());
    app.set_notice_code(0);
    app.invoke_settings_changed();
    assert_ne!(
        app.get_notice_code(),
        67,
        "checked today already: nothing new to tell"
    );
    app.set_leak_watch(false);
    app.invoke_settings_changed();
    app.invoke_clear_history();
    assert_eq!(app.get_detail_history_count(), 0);
    assert_eq!(app.get_notice_code(), 24);

    // ---- locking with Windows (on by default) ----
    app.invoke_open_settings();
    assert!(app.get_lock_with_windows());
    app.set_lock_with_windows(false);
    app.invoke_settings_changed();
    Controller::windows_session_ended();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "turned off: Windows locking leaves the vault open"
    );
    app.set_lock_with_windows(true);
    app.invoke_settings_changed();

    // ---- starting at sign-in (Windows keeps it; these tests keep it in memory) ----
    app.invoke_open_settings();
    assert!(!app.get_start_at_sign_in());
    assert!(
        app.get_start_in_tray(),
        "waits in the notification area by default"
    );
    app.invoke_start_at_sign_in_changed(true);
    assert!(app.get_start_at_sign_in());
    assert_eq!(app.get_error_code(), 0);
    assert!(controller.starts_in_tray());
    app.set_start_in_tray(false);
    app.invoke_settings_changed();
    assert!(!controller.starts_in_tray());
    assert!(
        !vault_platform::DeviceState::load()
            .unwrap()
            .settings
            .start_in_tray
    );
    app.invoke_open_settings();
    assert!(
        app.get_start_at_sign_in(),
        "still on when Settings opens again"
    );
    assert!(!app.get_start_in_tray());
    app.set_start_in_tray(true);
    app.invoke_settings_changed();
    app.invoke_start_at_sign_in_changed(false);
    assert!(!app.get_start_at_sign_in());
    // The entry started another program file (an older copy, or not Vault at all): said so.
    Controller::sign_in_start_moved(r"C:\Old\vault-desktop.exe");
    assert_eq!(app.get_notice_code(), 90);
    assert_eq!(app.get_notice_arg(), r"C:\Old\vault-desktop.exe");

    // ---- vault settings ----
    app.invoke_open_settings();
    assert_eq!(app.get_history_limit(), 10);
    app.set_vault_name_edit("x".repeat(61).into());
    app.invoke_vault_settings_changed();
    assert_eq!(app.get_error_code(), 27);
    app.set_vault_name_edit("Home".into());
    app.set_history_limit(3);
    app.invoke_vault_settings_changed();
    assert_eq!(app.get_vault_name(), "Home");
    assert_eq!(app.get_notice_code(), 26);
    assert_eq!((app.get_kdf_memory(), app.get_kdf_passes()), (64, 2));

    // ---- generator ----
    app.invoke_open_generator();
    assert_eq!(app.get_panel(), Panel::Generator);
    assert_eq!(app.get_gen_result().chars().count(), 24);
    app.set_gen_mode(1);
    app.invoke_regenerate();
    assert!(app.get_gen_result().split('-').count() >= 6);
    assert!(app.get_gen_bits() >= 77);
    // Word case and separator.
    app.set_gen_word_case(1);
    app.set_gen_separator(".".into());
    app.invoke_regenerate();
    let phrase = app.get_gen_result().to_string();
    assert!(phrase.split('.').count() >= 6, "{phrase}");
    assert_eq!(phrase, phrase.to_uppercase());
    // A word list of one's own.
    let list = dir.path().join("palavras.txt");
    std::fs::write(
        &list,
        (0..600)
            .map(|i| format!("palavra{i}\n"))
            .collect::<String>(),
    )
    .unwrap();
    controller.add_wordlist_file(&list);
    assert_eq!(app.get_gen_wordlist(), 1);
    assert!(app.get_gen_wordlist_removable());
    assert!(
        app.get_gen_result()
            .to_lowercase()
            .split('.')
            .all(|w| w.starts_with("palavra"))
    );
    let short = dir.path().join("short.txt");
    std::fs::write(&short, "um\ndois\n").unwrap();
    controller.add_wordlist_file(&short);
    assert_eq!(app.get_error_code(), 25);
    app.invoke_remove_wordlist();
    assert_eq!(app.get_gen_wordlist(), 0);
    app.set_gen_word_case(0);
    app.set_gen_separator("-".into());
    // Random characters: extended ASCII plus extra characters, minus excluded ones.
    app.set_gen_mode(0);
    app.set_gen_lowercase(false);
    app.set_gen_uppercase(false);
    app.set_gen_digits(false);
    app.set_gen_symbols(false);
    app.set_gen_extended(true);
    app.set_gen_also_use("xyz".into());
    app.set_gen_never_use("é".into());
    app.invoke_regenerate();
    assert_eq!(app.get_gen_alphabet(), 96);
    assert!(
        app.get_gen_result()
            .chars()
            .all(|c| "xyz".contains(c) || ('\u{a1}'..='\u{ff}').contains(&c))
    );
    app.set_gen_lowercase(true);
    app.set_gen_uppercase(true);
    app.set_gen_digits(true);
    app.set_gen_symbols(true);
    app.set_gen_extended(false);
    app.set_gen_also_use("".into());
    app.set_gen_never_use("".into());

    // ---- settings: master password and kit ----
    app.invoke_open_settings();
    type_into(&app, 5, "not the current one");
    type_into(&app, 6, NEW_PASSWORD);
    type_into(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_error_code(), 11, "wrong current password");
    type_into(&app, 5, PASSWORD);
    app.invoke_change_password();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 7);

    // ---- unlock protection: Argon2id level, checked with the current password ----
    app.invoke_open_settings();
    assert_eq!(
        app.get_kdf_current(),
        -1,
        "the test vault uses the minimum cost"
    );
    app.set_kdf_level(0);
    type_into(&app, 9, "not the current one");
    app.invoke_change_kdf();
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_kdf_failed(), "the error shows on that card");
    type_into(&app, 9, NEW_PASSWORD);
    app.invoke_change_kdf();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 30);
    assert_eq!(app.get_kdf_current(), 0);
    assert_eq!(length(&app, 9), 0, "the password field is cleared");
    assert_ne!(app.get_unlock_time(), "");
    // Other hash methods (scrypt, PBKDF2-SHA-256) and back to Argon2id.
    assert_eq!(app.get_kdf_current_method(), 0);
    for method in [1, 2, 0] {
        app.invoke_open_settings();
        app.set_kdf_method(method);
        type_into(&app, 9, NEW_PASSWORD);
        app.invoke_change_kdf();
        assert_eq!(
            app.get_error_code(),
            0,
            "detail: {}",
            app.get_error_detail()
        );
        assert_eq!(
            (app.get_kdf_current_method(), app.get_kdf_current()),
            (method, 0)
        );
        app.invoke_lock();
        type_into(&app, 0, NEW_PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault, "method {method} unlocks");
    }

    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();

    // ---- emergency kit page: printable PDF, wiped on lock ----
    app.invoke_open_kit();
    assert_eq!(app.get_panel(), Panel::Kit);
    assert_eq!(
        app.get_kit_secret_key(),
        "",
        "hidden until the password is typed"
    );
    app.invoke_print_kit();
    let print_dir = dir.path().join("home").join("print");
    assert!(
        !print_dir.exists(),
        "nothing to print before the kit is shown"
    );
    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_print_kit();
    let printed: Vec<_> = std::fs::read_dir(&print_dir).unwrap().flatten().collect();
    assert_eq!(printed.len(), 1);
    let pdf = std::fs::read(printed[0].path()).unwrap();
    assert!(pdf.starts_with(b"%PDF-1.4"));
    assert!(
        pdf.windows(secret_key.len())
            .any(|w| w == secret_key.as_bytes())
    );
    assert_eq!(app.get_notice_code(), 16);

    // ---- a new kit: new recovery parts, and the old ones stop working ----
    assert_eq!(app.get_vault_recovery(), 2);
    assert_eq!(app.get_kit_part_a(), "", "parts can't be shown again");
    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_new_parts();
    assert_eq!(
        app.get_notice_code(),
        8,
        "detail: {}",
        app.get_error_detail()
    );
    let old_parts = parts;
    let parts = [
        app.get_kit_part_a(),
        app.get_kit_part_b(),
        app.get_kit_part_c(),
    ]
    .map(|part| part.to_string());
    assert!(parts[0].starts_with("A0-") && parts[0] != old_parts[0]);
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();
    assert_eq!(app.get_kit_part_c(), "");

    // ---- lock (here: Windows locked the session) and unlock ----
    Controller::windows_session_ended();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_items().row_count(), 0);
    assert_eq!(
        std::fs::read_dir(&print_dir).unwrap().count(),
        0,
        "printed kit wiped on lock"
    );
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 1, "old password no longer works");
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- connecting the extension again replaces the earlier key, locked or not ----
    let earlier = key;
    let pairing = connect();
    let key = pairing.key.as_bytes().to_vec();
    assert_eq!(app.get_pairing_code(), pairing.code.as_str());
    type_into(&app, 14, NEW_PASSWORD);
    app.invoke_pairing_decided(true);
    assert_eq!(app.get_error_code(), 0);
    let ask = |message: &str| sealed(&key, message);
    assert!(sealed(&earlier, logins_request).contains("not_paired"));
    assert!(!ask(logins_request).contains("not_paired"));
    app.invoke_lock();
    assert!(
        sealed(&earlier, logins_request).contains("not_paired"),
        "the earlier key is refused while the vault is locked too"
    );
    assert!(!ask(logins_request).contains("not_paired"));
    // Locked, the status says so, with the extension's version and no name.
    let status = ask(r#"{"type":"status"}"#);
    let version = format!(r#""extension_version":"{}""#, env!("CARGO_PKG_VERSION"));
    assert!(
        status.contains(r#""locked":true"#)
            && status.contains(r#""name":"","#)
            && status.contains(&version),
        "{status}"
    );
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    // ---- item lock: secrets wait for a second check, the rest stays visible ----
    let relock = |app: &AppWindow| {
        app.invoke_lock();
        type_into(app, 0, NEW_PASSWORD);
        app.invoke_unlock();
        assert_eq!(app.get_screen(), Screen::Vault);
    };
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_edit_item();
    app.set_ed_reprompt(true);
    app.invoke_save_item();
    assert!(app.get_detail_locked(), "marked: locked from now on");
    assert!(
        ask(r#"{"type":"logins","url":"https://github.com/"}"#).contains(r#""locked":true"#),
        "the extension sees the item lock too"
    );
    assert_eq!(app.get_detail_check(), 0, "the master password by default");
    assert_eq!(app.get_detail_title(), "GitHub");
    assert_ne!(
        app.get_detail_username(),
        "",
        "who the account is stays visible"
    );
    assert!(app.get_detail_urls().row_count() > 0);
    assert!(!app.get_detail_has_password());
    assert_eq!(app.get_totp_code(), "");
    assert_eq!(app.get_detail_codes_total(), 0);
    app.invoke_copy_username();
    assert_eq!(app.get_notice_code(), 2, "what is visible can be copied");
    // No route reaches the secrets: reveal, copy, edit and delete do nothing.
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "");
    app.invoke_copy_password();
    assert_ne!(app.get_notice_code(), 1);
    app.invoke_copy_totp();
    assert_ne!(app.get_notice_code(), 3);
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Detail);
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), 1);
    // The Authenticator still lists its code, masked and not copyable.
    assert_eq!(app.get_totp_count(), 1);
    app.invoke_open_authenticator();
    assert!(app.get_auth_locked() && !app.get_auth_guarded_open());
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert_eq!(row.title, "GitHub");
    assert!(row.locked && row.code.is_empty());
    app.invoke_auth_copy(0);
    assert_ne!(app.get_notice_code(), 3);
    // The check, typed there, opens every locked item at once.
    type_into(&app, 11, "not the master password");
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 35);
    assert_eq!(app.get_error_detail(), "4", "tries left");
    assert!(app.get_auth_locked());
    type_into(&app, 11, NEW_PASSWORD);
    app.invoke_unlock_item();
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(length(&app, 11), 0, "what was typed is cleared");
    assert!(!app.get_auth_locked() && app.get_auth_guarded_open());
    let row = app.get_auth_rows().row_data(0).unwrap();
    assert!(!row.locked);
    assert_eq!(row.code.len(), 7);
    app.invoke_auth_copy(0);
    assert_eq!(app.get_notice_code(), 3);
    app.invoke_auth_open(0);
    assert_eq!(app.get_panel(), Panel::Detail);
    assert!(!app.get_detail_locked() && app.get_detail_guarded_open());
    assert!(app.get_detail_has_password());
    // Locked again by hand; opened from the item page this time.
    app.invoke_lock_secrets();
    assert_eq!(app.get_notice_code(), 39);
    assert!(app.get_detail_locked() && !app.get_detail_has_password());
    type_into(&app, 11, NEW_PASSWORD);
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    app.invoke_edit_item();
    assert_eq!(app.get_panel(), Panel::Editor);
    app.set_ed_reprompt(false);
    app.invoke_save_item();
    assert!(!app.get_detail_guarded_open());
    app.invoke_lock_secrets();
    assert!(!app.get_detail_locked(), "no longer marked");

    // A PIN for every item, set after a master password check. From here the locked
    // secrets are encrypted under a key only the PIN opens.
    app.invoke_open_settings();
    // No lock yet: the form starts on the suggestion, a PIN on every item, with Hello.
    assert_eq!(
        (
            app.get_guard_all(),
            app.get_guard_check(),
            app.get_guard_current_check()
        ),
        (true, 1, 0)
    );
    assert!(app.get_guard_hello());
    assert!(!app.get_guard_encrypts());
    app.set_guard_check(1);
    app.set_guard_all(true);
    // Windows Hello is turned on further down, on its own.
    app.set_guard_hello(false);
    type_into(&app, 12, "12");
    type_into(&app, 13, "not the current one");
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_guard_failed(), "the error shows on that card");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(app.get_error_code(), 36, "two digits are not a PIN");
    type_into(&app, 12, "4821");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    assert_eq!(app.get_guard_current_check(), 1);
    assert!(app.get_guard_encrypts() && !app.get_secrets_open());
    assert_eq!((length(&app, 12), length(&app, 13)), (0, 0));
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "every item is locked now");
    assert_eq!(app.get_detail_check(), 1);
    // The extension: the PIN typed in its window opens the one login asked for, on the same
    // count of wrong tries, and leaves the app's lock closed.
    let listed = ask(r#"{"type":"logins","url":"https://github.com/"}"#);
    assert!(listed.contains(r#""check":"pin""#) && listed.contains(r#""locked":true"#));
    let fill = |pin: &str| {
        ask(&format!(
            r#"{{"type":"fill","url":"https://github.com/","id":"{id}","check":"{pin}"}}"#
        ))
    };
    assert!(
        ask(&format!(
            r#"{{"type":"fill","url":"https://github.com/","id":"{id}"}}"#
        ))
        .contains(r#""code":"item_locked","check":"pin""#)
    );
    let wrong = fill("0000");
    assert!(
        wrong.contains(r#""code":"wrong_check""#) && wrong.contains(r#""left":4"#),
        "{wrong}"
    );
    app.set_notice_code(0);
    let right = fill("4821");
    assert!(right.contains(r#""password":""#), "{right}");
    assert_eq!(app.get_notice_code(), 40);
    assert!(!app.get_secrets_open());
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "still locked in the app");
    assert!(!app.get_detail_has_password());
    // Windows Hello as the easy way in: turned on with the item lock, it opens locked items
    // in the app and for the extension, with nothing typed.
    assert!(!app.get_guard_hello_on());
    app.invoke_open_settings();
    assert!(!app.get_guard_hello());
    app.set_guard_hello(true);
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked() && app.get_guard_hello_on());
    app.invoke_unlock_item_hello();
    assert!(!app.get_detail_locked() && app.get_detail_has_password());
    app.invoke_lock_secrets();
    let listed = ask(r#"{"type":"logins","url":"https://github.com/"}"#);
    assert!(listed.contains(r#""hello":true"#), "{listed}");
    let by_hello = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/","id":"{id}","hello":true}}"#
    ));
    assert!(by_hello.contains(r#""password":""#), "{by_hello}");
    assert!(!app.get_secrets_open(), "closed again after the one fill");
    // Cancelled at the prompt: the extension is told to ask for the PIN instead.
    hello.cancel.store(true, Ordering::SeqCst);
    let cancelled = ask(&format!(
        r#"{{"type":"fill","url":"https://github.com/","id":"{id}","hello":true}}"#
    ));
    assert!(
        cancelled.contains(r#""code":"item_locked","check":"pin""#),
        "{cancelled}"
    );
    app.invoke_unlock_item_hello();
    assert!(app.get_detail_locked() || !app.get_secrets_open());
    hello.cancel.store(false, Ordering::SeqCst);
    assert_eq!(app.get_detail_title(), "GitHub");
    assert!(!app.get_detail_has_password());
    assert_eq!(app.get_totp_count(), 1);
    // A new item is saved without the PIN, shows as locked, and is sealed under the item
    // lock when it next opens.
    let before = app.get_total_items();
    app.invoke_new_item();
    app.set_ed_title("Sealed at birth".into());
    type_into(&app, 4, "born-locked");
    app.invoke_save_item();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_panel(), Panel::Detail);
    assert_eq!(app.get_total_items(), before + 1);
    assert!(
        app.get_detail_locked(),
        "still asks before showing its secrets"
    );
    assert_eq!(controller.pending_seal(), Some(1));
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert!(app.get_secrets_open() && !app.get_detail_locked());
    assert_eq!(
        controller.pending_seal(),
        Some(0),
        "sealed once the lock opened"
    );
    app.invoke_reveal();
    assert_eq!(app.get_revealed_password(), "born-locked");
    app.invoke_conceal();
    app.invoke_delete_item();
    assert_eq!(app.get_total_items(), before);
    app.invoke_lock_secrets();
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked());
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_code().len(), 7);
    // The generator's result, once it is a locked login's password, is not left on the
    // generator page (nor in Rust, to copy) when the item lock closes.
    app.invoke_open_generator();
    let made = app.get_gen_result().to_string();
    assert!(!made.is_empty());
    app.invoke_select_category(0);
    app.invoke_select(0);
    app.invoke_edit_item();
    app.invoke_use_generated();
    assert_eq!(app.get_panel(), Panel::Editor);
    assert_eq!(
        app.get_gen_result(),
        "",
        "handed to the editor: gone from the generator"
    );
    assert_eq!(controller.generated_result(), None);
    app.invoke_save_item();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    app.invoke_lock_secrets();
    app.invoke_open_generator();
    assert_ne!(
        app.get_gen_result(),
        made.as_str(),
        "a new one, not the item's"
    );
    assert_ne!(
        controller.generated_result().as_deref(),
        Some(made.as_str())
    );
    // Typed into an item by hand and saved: the same.
    let typed = app.get_gen_result().to_string();
    app.invoke_select_category(0);
    app.invoke_select(0);
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    app.invoke_edit_item();
    type_into(&app, 4, &typed);
    app.invoke_save_item();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_gen_result(), "");
    assert_eq!(controller.generated_result(), None);
    // And closing the item lock clears whatever the generator showed.
    app.invoke_open_generator();
    assert!(!app.get_gen_result().is_empty());
    app.invoke_lock_secrets();
    assert_eq!(app.get_gen_result(), "");
    assert_eq!(controller.generated_result(), None);
    app.invoke_select_category(0);
    app.invoke_select(0);
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    // The password the rest of this test expects back.
    app.invoke_edit_item();
    type_into(&app, 4, "password123");
    app.invoke_save_item();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    // The vault locked while an item check runs in the background: when the check comes
    // back, the vault stays locked, on screen and for the extension.
    controller.lock_while_a_job_holds_the_vault();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(!app.get_secrets_open());
    assert!(raw(r#"{"type":"status"}"#).contains(r#""locked":true"#));
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(app.get_detail_locked(), "the item lock is closed again too");
    // A forgotten PIN is replaced with the master password alone.
    relock(&app);
    app.invoke_open_settings();
    type_into(&app, 12, "777777");
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    // The PIN survives a save and a reopen; five wrong tries lock the whole vault.
    relock(&app);
    app.invoke_select(0);
    assert!(app.get_detail_locked());
    for left in ["4", "3", "2", "1"] {
        type_into(&app, 11, "4821");
        app.invoke_unlock_item();
        assert_eq!(app.get_error_code(), 35);
        assert_eq!(app.get_error_detail(), left);
        assert_eq!(app.get_screen(), Screen::Vault);
    }
    type_into(&app, 11, "4821");
    app.invoke_unlock_item();
    assert_eq!(app.get_screen(), Screen::Unlock, "locked out");
    assert_eq!(app.get_notice_code(), 38);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    app.invoke_select(0);
    type_into(&app, 11, "777777");
    app.invoke_unlock_item();
    assert!(!app.get_detail_locked());
    app.invoke_lock_secrets();
    // Back to no lock: the master password opens the sealed secrets for good.
    app.invoke_open_settings();
    app.set_guard_check(0);
    app.set_guard_all(false);
    type_into(&app, 13, NEW_PASSWORD);
    app.invoke_save_guard();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 37);
    assert!(!app.get_guard_encrypts());
    app.invoke_select_category(0);
    app.invoke_select(0);
    assert!(!app.get_detail_locked(), "back to no lock");
    assert!(app.get_detail_has_password());
    assert_eq!(app.get_totp_count(), 1);

    // ---- keyfile: a file needed together with the master password ----
    app.invoke_open_settings();
    assert!(!app.get_keyfile_on());
    let keyfile = dir.path().join("test.keyfile");
    app.set_keyfile_target(keyfile.to_str().unwrap().into());
    type_into(&app, 10, "not the current one");
    app.invoke_keyfile_action(0);
    assert_eq!(app.get_error_code(), 11);
    assert!(app.get_keyfile_failed(), "the error shows on that card");
    assert!(!keyfile.exists(), "nothing written before the check");
    type_into(&app, 10, NEW_PASSWORD);
    app.invoke_keyfile_action(0);
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 35);
    assert!(app.get_keyfile_on());
    assert!(keyfile.is_file());
    assert_eq!(length(&app, 10), 0);
    // The master password still checks out (it now needs the keyfile behind the scenes).
    type_into(&app, 5, NEW_PASSWORD);
    app.invoke_show_kit();
    assert_eq!(app.get_kit_secret_key(), secret_key.as_str());
    app.invoke_hide_kit();

    app.invoke_lock();
    assert!(app.get_needs_keyfile());
    assert_eq!(
        app.get_keyfile_path().as_str(),
        keyfile.to_str().unwrap(),
        "this computer remembers where the file is"
    );
    app.set_keyfile_path("".into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 32, "no keyfile, no vault");
    let other = dir.path().join("other.keyfile");
    std::fs::write(&other, "vault-keyfile-v1 not the right one\n").unwrap();
    app.set_keyfile_path(other.to_str().unwrap().into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_error_code(),
        34,
        "the right password with the wrong file"
    );
    assert_eq!(app.get_screen(), Screen::Unlock);
    app.set_keyfile_path(keyfile.to_str().unwrap().into());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    app.invoke_open_settings();
    assert!(app.get_keyfile_on());
    type_into(&app, 10, NEW_PASSWORD);
    app.invoke_keyfile_action(2);
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_notice_code(), 36);
    assert!(!app.get_keyfile_on());
    app.invoke_lock();
    assert!(!app.get_needs_keyfile());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- quick unlock (fake Windows Hello) ----
    let id = app.get_vault_id().to_string();
    let home = dir.path().join("home");
    let enable = |app: &AppWindow| {
        app.set_quick_unlock_on(true);
        app.invoke_quick_unlock_toggled(true);
    };
    assert!(!app.get_quick_unlock_on());
    hello.cancel.store(true, Ordering::SeqCst);
    enable(&app);
    assert!(!app.get_quick_unlock_on(), "cancelled prompt leaves it off");
    hello.cancel.store(false, Ordering::SeqCst);
    enable(&app);
    assert!(app.get_quick_unlock_on());
    assert_eq!(app.get_notice_code(), 12);
    assert!(home.join(format!("quick-unlock-{id}.bin")).exists());

    app.invoke_lock();
    assert!(app.get_quick_unlock_on(), "offered on the lock screen");
    app.invoke_quick_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!(app.get_total_items(), 1);

    // Cancelling at unlock is silent.
    app.invoke_lock();
    hello.cancel.store(true, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert_eq!(app.get_error_code(), 0);
    hello.cancel.store(false, Ordering::SeqCst);

    // The master password is required again after the interval (here: no record at all).
    std::fs::remove_file(home.join(format!("last-password-{id}.bin"))).unwrap();
    app.invoke_quick_unlock();
    assert_eq!(app.get_error_code(), 16, "password due");
    assert_eq!(app.get_screen(), Screen::Unlock);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    app.invoke_lock();
    app.invoke_quick_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "works again after the password"
    );

    // A different device secret (another PC, a reset TPM) cannot open it, and it is dropped.
    app.invoke_lock();
    hello.other_device.store(true, Ordering::SeqCst);
    app.invoke_quick_unlock();
    assert_eq!(app.get_error_code(), 15);
    assert!(!app.get_quick_unlock_on());
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());
    hello.other_device.store(false, Ordering::SeqCst);
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);

    // Turned on again, then off from Settings.
    app.invoke_open_settings();
    enable(&app);
    assert!(app.get_quick_unlock_on());
    app.set_quick_unlock_on(false);
    app.invoke_quick_unlock_toggled(false);
    assert_eq!(app.get_notice_code(), 13);
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());

    // Changing the master password turns it off.
    enable(&app);
    type_into(&app, 5, NEW_PASSWORD);
    type_into(&app, 6, PASSWORD);
    type_into(&app, 7, PASSWORD);
    app.invoke_change_password();
    assert_eq!(
        app.get_notice_code(),
        15,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(!app.get_quick_unlock_on());
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, NEW_PASSWORD);
    type_into(&app, 7, NEW_PASSWORD);
    app.invoke_change_password();
    assert_eq!(app.get_notice_code(), 7);
    enable(&app);
    assert!(app.get_quick_unlock_on());

    // ---- a new device: the Secret Key must be typed once ----
    app.invoke_lock();
    secret_store::forget(&app.get_vault_id()).unwrap();
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 3, "Secret Key required");
    assert!(app.get_needs_secret_key());
    type_into(&app, 2, &secret_key.to_lowercase());
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(!app.get_needs_secret_key());

    // ---- a new device without the Secret Key: two recovery parts stand in for it ----
    app.invoke_lock();
    secret_store::forget(&app.get_vault_id()).unwrap();
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 3, "Secret Key required");
    assert!(app.get_can_use_parts());
    app.set_use_parts(true);
    type_into(&app, 16, &parts[0]);
    type_into(&app, 17, &parts[0]);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 46, "the same part twice");
    type_into(&app, 17, &old_parts[2]);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 44, "a part of the old kit");
    type_into(&app, 17, "C0-1234567");
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 45, "not a whole part");
    type_into(&app, 17, &parts[2].to_lowercase().replace('-', " "));
    // The eye shows what was typed, a part also in boxes; closed again, nothing is shown.
    let secrets = app.global::<Secrets>();
    secrets.invoke_toggle_shown(17);
    assert_eq!(
        secrets.get_shown().row_data(17).unwrap(),
        parts[2].to_lowercase().replace('-', " ")
    );
    let cells = secrets.get_shown_cells().row_data(17).unwrap();
    assert_eq!(cells.row_count(), 34);
    assert_eq!(cells.row_data(0).unwrap(), "C");
    secrets.invoke_toggle_shown(17);
    assert_eq!(secrets.get_shown().row_data(17).unwrap(), "");
    assert_eq!(
        secrets.get_shown_cells().row_data(17).unwrap().row_count(),
        0
    );
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(!app.get_needs_secret_key() && !app.get_use_parts());
    assert_eq!((length(&app, 16), length(&app, 17)), (0, 0), "parts wiped");
    assert!(
        secret_store::load(&app.get_vault_id()).unwrap().is_some(),
        "the Secret Key the parts brought back is remembered"
    );
    // Parts work once: these stopped working, and a new kit is offered at once.
    assert!(app.get_parts_used());
    assert_eq!(app.get_vault_recovery(), 0);
    let file = std::fs::read(&path).unwrap();
    assert!(
        !vault_core::Vault::inspect(&file)
            .unwrap()
            .has_recovery_parts
    );
    app.set_parts_used(false);
    app.invoke_new_parts_now();
    assert_eq!(app.get_panel(), Panel::Kit);
    assert_eq!(app.get_vault_recovery(), 2);
    let used_parts = parts.clone();
    let parts: Vec<String> = [
        app.get_kit_part_a(),
        app.get_kit_part_b(),
        app.get_kit_part_c(),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert!(parts[0].starts_with("A0-") && parts[0] != used_parts[0]);
    // On paper: the keys, or empty boxes to fill in by hand.
    app.set_kit_filled(false);
    let blank = controller.kit_pdf_for_test(true).unwrap();
    assert!(!String::from_utf8_lossy(&blank).contains(&parts[0]));
    app.set_kit_filled(true);
    assert!(
        String::from_utf8_lossy(&controller.kit_pdf_for_test(true).unwrap()).contains(&parts[0])
    );
    // On screen, the kit's keys stay out of the accessibility tree.
    let exposed = accessible_texts(&app);
    let secret_key = app.get_kit_secret_key().to_string();
    assert!(
        exposed.iter().all(|text| !text.contains(&secret_key)
            && parts.iter().all(|part| !text.contains(part.as_str()))),
        "{exposed:?}"
    );
    // Saved as a file, the kit keeps the Secret Key only: the three parts together open the
    // vault without the master password.
    let saved = controller.kit_pdf_for_test(false).unwrap();
    let saved = String::from_utf8_lossy(&saved);
    assert!(parts.iter().all(|part| !saved.contains(part.as_str())));
    assert!(saved.contains("Secret Key") || saved.contains("SECRET KEY"));

    // ---- recovery with the emergency kit ----
    app.invoke_lock();
    app.invoke_show_recovery();
    assert_eq!(app.get_screen(), Screen::Recover);
    assert!(app.get_recover_with_parts());
    // First the parts, checked; then the new password.
    assert_eq!(app.get_recover_step(), 1);
    type_into(&app, 16, &parts[0]);
    type_into(&app, 17, "B0-not-a-part");
    type_into(&app, 18, &parts[2]);
    app.invoke_check_parts();
    assert_eq!((app.get_error_code(), app.get_recover_step()), (45, 1));
    type_into(&app, 17, &old_parts[1]);
    app.invoke_check_parts();
    assert_eq!(app.get_error_code(), 44, "parts of two kits");
    type_into(&app, 17, &used_parts[1]);
    app.invoke_check_parts();
    assert_eq!(app.get_error_code(), 44, "parts already used");
    type_into(&app, 16, &used_parts[0]);
    type_into(&app, 18, &used_parts[2]);
    app.invoke_check_parts();
    assert_eq!(app.get_error_code(), 44, "a used kit opens nothing");
    type_into(&app, 16, &parts[0]);
    type_into(&app, 17, &parts[1]);
    type_into(&app, 18, &parts[2]);
    app.invoke_check_parts();
    assert_eq!((app.get_error_code(), app.get_recover_step()), (0, 2));
    type_into(&app, 0, PASSWORD);
    type_into(&app, 1, PASSWORD);
    app.invoke_recover();
    assert_eq!(
        app.get_screen(),
        Screen::Onboarding,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(app.get_recovered());
    assert!(!app.get_quick_unlock_on(), "recovery sets a new password");
    assert!(!home.join(format!("quick-unlock-{id}.bin")).exists());
    let new_secret_key = app.get_kit_secret_key().to_string();
    assert!(new_secret_key.starts_with("S0-") && new_secret_key != secret_key);
    assert_eq!(app.get_kit_part_a(), "", "the used parts are gone");
    for part in [16, 17, 18] {
        assert_eq!(length(&app, part), 0, "parts wiped after use");
    }
    let file = std::fs::read(&path).unwrap();
    assert!(
        !vault_core::Vault::inspect(&file)
            .unwrap()
            .has_recovery_parts
    );
    // New ones, without typing the new password again.
    app.invoke_new_parts_now();
    assert!(app.get_kit_part_a().starts_with("A0-"));
    assert_ne!(app.get_kit_part_a(), parts[0]);
    let file = std::fs::read(&path).unwrap();
    assert!(
        vault_core::Vault::inspect(&file)
            .unwrap()
            .has_recovery_parts
    );
    app.set_kit_saved(true);
    app.invoke_finish_onboarding();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_total_items(), 1);

    // ---- import & export ----
    app.invoke_open_transfer();
    assert_eq!(app.get_panel(), Panel::Transfer);
    let export_file = dir.path().join("export.json");
    std::fs::write(
        &export_file,
        r#"{"encrypted": false,
            "folders": [{"id": "f1", "name": "Shopping"}],
            "items": [
              {"type": 1, "name": "Shop", "folderId": "f1",
               "login": {"username": "buyer", "password": "shop-pass", "uris": [{"uri": "https://shop.example"}]}},
              {"type": 1, "name": "GitHub",
               "login": {"username": "hubot", "password": "password123", "uris": [{"uri": "https://github.com"}]}}
            ]}"#,
    )
    .unwrap();
    controller.start_import(export_file.clone());
    assert_eq!(
        app.get_import_stage(),
        2,
        "detail: {}",
        app.get_error_detail()
    );
    // Review: every entry listed, passwords never shown, duplicates unticked.
    let rows = app.get_import_rows();
    assert_eq!(rows.row_count(), 2);
    let shop = rows.row_data(0).unwrap();
    assert_eq!(
        (shop.title.as_str(), shop.folder.as_str()),
        ("Shop", "Shopping")
    );
    assert!(shop.include && shop.has_password && !shop.duplicate);
    assert!(rows.row_data(1).unwrap().duplicate);
    assert_eq!(
        app.get_import_selected(),
        1,
        "GitHub is already in the vault"
    );
    assert_eq!(app.get_import_duplicates(), 1);
    app.invoke_import_select_all(false);
    assert_eq!(app.get_import_selected(), 0);
    app.invoke_import_toggle(0, true);
    assert_eq!(app.get_import_selected(), 1);
    app.invoke_import_confirm();
    assert_eq!(app.get_import_stage(), 3);
    assert_eq!(app.get_import_added(), 1);
    assert_eq!(app.get_notice_code(), 19);
    assert!(app.get_import_plaintext());
    assert_eq!(app.get_folders().row_count(), 1);
    app.invoke_import_wipe();
    assert!(!export_file.exists(), "plain-text export wiped");
    assert_eq!(app.get_import_stage(), 0);

    // A file that isn't an export is refused with a message.
    let junk = dir.path().join("junk.csv");
    std::fs::write(&junk, "a,b\n1,2\n").unwrap();
    controller.start_import(junk);
    assert_eq!(app.get_error_code(), 19);
    app.invoke_import_cancel();

    // Unencrypted export needs the master password, and its dialog (what the file leaves out
    // and who reads it is said there): without it nothing is made.
    app.set_export_format(1);
    type_into(&app, 5, PASSWORD);
    app.invoke_export_plain();
    assert!(!path.with_extension("export.json").exists());
    assert_eq!((app.get_error_code(), length(&app, 5)), (0, 0));
    app.invoke_export_ask();
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 11);
    type_into(&app, 5, PASSWORD);
    app.invoke_export_plain();
    let exported = path.with_extension("export.json");
    let text = std::fs::read_to_string(&exported).unwrap();
    assert!(text.contains("\"Shop\"") && text.contains("Shopping"));
    assert_eq!(app.get_notice_code(), 21);
    std::fs::remove_file(exported).unwrap();

    // An export protected by a password of its own: unreadable as a file, and Import reads
    // it back with that password.
    app.set_export_format(3);
    app.invoke_export_ask();
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, "short");
    type_into(&app, 7, "short");
    app.invoke_export_plain();
    assert_eq!(
        app.get_error_code(),
        5,
        "too short for a file with one password"
    );
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, "a long password for the file");
    type_into(&app, 7, "another one entirely");
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 4);
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, "a long password for the file");
    type_into(&app, 7, "a long password for the file");
    app.invoke_export_plain();
    assert_eq!(
        app.get_error_code(),
        0,
        "detail: {}",
        app.get_error_detail()
    );
    assert_eq!((length(&app, 6), length(&app, 7)), (0, 0));
    let protected = path.with_extension("export.vaultx");
    let bytes = std::fs::read(&protected).unwrap();
    assert!(!bytes.windows(4).any(|w| w == b"Shop"), "nothing readable");
    controller.start_import(protected.clone());
    assert_eq!(app.get_import_stage(), 1, "asks for the file's password");
    type_into(&app, 8, "not the password");
    app.invoke_import_open();
    assert_eq!(app.get_error_code(), 19);
    type_into(&app, 8, "a long password for the file");
    app.invoke_import_open();
    assert_eq!(
        app.get_import_stage(),
        2,
        "detail: {}",
        app.get_error_detail()
    );
    assert!(app.get_import_rows().row_count() >= 2);
    assert_eq!(app.get_import_selected(), 0, "everything is already here");
    app.invoke_import_cancel();
    app.set_export_format(1);
    std::fs::remove_file(protected).unwrap();

    // ---- a second vault, and back to the first ----
    let second = dir.path().join("second.vault");
    controller.switch_vault(second.clone());
    assert_eq!(app.get_screen(), Screen::Onboarding, "no vault there yet");
    assert_eq!(app.get_items().row_count(), 0, "the first vault was locked");
    assert!(app.get_recent_vaults().row_count() >= 2);
    type_into(&app, 0, NEW_PASSWORD);
    type_into(&app, 1, NEW_PASSWORD);
    app.invoke_create_vault();
    // This one starts with the suggested item lock: a PIN on every item.
    app.set_onboarding_guard(0);
    app.set_guard_hello(false);
    type_into(&app, 12, "482193");
    app.invoke_create_vault();
    assert_eq!(app.get_onboarding_step(), 3, "{}", app.get_error_detail());
    let _cleanup_second = ForgetOnDrop(app.get_vault_id().to_string());
    assert_eq!(length(&app, 12), 0, "PIN wiped after use");
    app.set_kit_saved(true);
    app.invoke_finish_onboarding_import();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert_eq!(app.get_panel(), Panel::Transfer, "straight to the import");
    app.invoke_open_settings();
    assert_eq!(
        app.get_guard_current_check(),
        1,
        "the PIN chosen while creating it"
    );
    assert!(app.get_guard_all());
    assert_eq!(app.get_total_items(), 0);
    assert!(second.exists());
    app.invoke_switch_vault();
    assert_eq!(app.get_screen(), Screen::Unlock);
    assert!(app.get_choosing_vault());
    let recent = app.get_recent_vaults();
    assert!(recent.row_data(0).unwrap().current, "most recent first");
    let first = (0..recent.row_count())
        .find(|&i| recent.row_data(i).unwrap().name == "test")
        .unwrap();
    app.invoke_pick_vault(first as i32);
    assert!(!app.get_choosing_vault());
    assert_eq!(app.get_vault_path(), path.display().to_string().as_str());
    type_into(&app, 0, NEW_PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_error_code(), 1, "each vault has its own password");
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(app.get_screen(), Screen::Vault);
    assert!(app.get_total_items() >= 1);

    // ---- nothing readable on disk ----
    let bytes = std::fs::read(&path).unwrap();
    for needle in [
        "GitHub",
        "hubot",
        "gh-item-pass",
        "password123",
        "github.com",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} leaked"
        );
    }
}

/// A login with two websites, a hidden field, a one-time code, recovery codes, an attached
/// file, a passkey and an earlier password (the one in use starts like a formula); a card with
/// a PIN; a note.
fn add_what_exports_lose(vault: &mut Vault) {
    let mut mail = ItemData::login("Mail", "me", "first password", "https://mail.example");
    mail.urls.push("https://webmail.example".into());
    mail.totp = "JBSWY3DPEHPK3PXP".into();
    mail.custom_fields.push(CustomField {
        name: "Answer".into(),
        value: "blue".into(),
        sensitive: true,
    });
    mail.recovery_codes = RecoveryCode::parse_list("test-code-1\ntest-code-2");
    mail.attachments
        .push(Attachment::new("scan.txt", b"test attachment".to_vec()).unwrap());
    mail.passkeys
        .push(Passkey::new("mail.example", b"user-1", "me", "Me").unwrap());
    let id = vault.add_item(&mail).unwrap();
    let mut changed = vault.get_item(&id).unwrap();
    changed.password = "=second password".into();
    vault.update_item(&id, &changed).unwrap();
    let mut visa = ItemData::new(ItemKind::Card, "Visa");
    visa.password = "4821".into();
    visa.custom_fields.push(CustomField {
        name: card::NUMBER.into(),
        value: "4111111111111111".into(),
        sensitive: true,
    });
    vault.add_item(&visa).unwrap();
    let mut note = ItemData::new(ItemKind::SecureNote, "Wifi");
    note.notes = "router".into();
    vault.add_item(&note).unwrap();
}

#[test]
fn an_export_says_first_what_it_leaves_out_and_what_anyone_could_read() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let path = dir.path().join("exports.vault");
    let key = SecretKey::generate().unwrap();
    let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    add_what_exports_lose(&mut vault);
    std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    let _cleanup = ForgetOnDrop(vault.id_hex());
    secret_store::store(&vault.id_hex(), &key).unwrap();

    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let _controller = Controller::install(&app, path.clone(), Runner::Inline, None).unwrap();
    crate::i18n::apply("en");
    type_into(&app, 0, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );
    app.invoke_open_transfer();
    let notes = || {
        app.global::<Messages>()
            .invoke_export_notes(app.get_export_counts())
            .to_string()
    };

    // Protected by a password: every item whole, attached file and passkey included, and
    // nothing readable.
    app.set_export_format(3);
    app.invoke_export_ask();
    assert!(app.get_export_asking() && app.get_error_code() == 0);
    assert_eq!(app.get_export_counts(), ExportCounts::default());
    assert_eq!(notes(), "");
    // Cancelled: what was typed goes.
    type_into(&app, 5, PASSWORD);
    type_into(&app, 6, "a long password for the file");
    app.invoke_export_cancel();
    assert!(!app.get_export_asking());
    assert_eq!((length(&app, 5), length(&app, 6)), (0, 0));

    // JSON: the attached file, the passkey and the earlier password stay behind, and
    // everything else is in the clear.
    app.set_export_format(1);
    app.invoke_export_ask();
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
    app.invoke_export_cancel();

    // CSV: what it has no place for, and no file for a spreadsheet.
    app.set_export_format(2);
    app.invoke_export_ask();
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
    type_into(&app, 5, PASSWORD);
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert!(!app.get_export_asking() && !app.get_export_recounted());
    let exported = path.with_extension("export.csv");
    let text = std::fs::read_to_string(&exported).unwrap();
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
    std::fs::remove_file(exported).unwrap();

    // The vault changes while the dialog is open (a sync, the browser): what the file would
    // hold now is shown, and confirmed again before it is made.
    app.set_export_format(1);
    app.invoke_export_ask();
    app.invoke_new_item();
    app.set_ed_title("New".into());
    type_into(&app, 4, "another password");
    app.invoke_save_item();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    type_into(&app, 5, PASSWORD);
    app.invoke_export_plain();
    let exported = path.with_extension("export.json");
    assert!(!exported.exists(), "not made with other counts shown");
    assert!(app.get_export_asking() && app.get_export_recounted());
    assert_eq!(app.get_export_counts().passwords, 3);
    app.invoke_export_plain();
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert!(!app.get_export_asking());
    assert!(exported.exists());
    assert_eq!(length(&app, 5), 0, "wiped after use");
    std::fs::remove_file(exported).unwrap();

    // Locked with the dialog open: it is not there at the next unlock.
    app.invoke_export_ask();
    assert!(app.get_export_asking());
    app.invoke_lock();
    assert!(!app.get_export_asking());
}

#[test]
fn an_export_of_locked_items_is_counted_before_it_is_made() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let key = SecretKey::generate().unwrap();
    for master_opens in [true, false] {
        let path = dir.path().join(format!("locked-{master_opens}.vault"));
        let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
        add_what_exports_lose(&mut vault);
        vault
            .set_item_guard(
                true,
                GuardCheck::Pin,
                Some("2468"),
                master_opens.then_some(PASSWORD),
            )
            .unwrap();
        std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
        let _cleanup = ForgetOnDrop(vault.id_hex());
        secret_store::store(&vault.id_hex(), &key).unwrap();
        let app = AppWindow::new().unwrap();
        apply_sketches(&app);
        let _controller = Controller::install(&app, path.clone(), Runner::Inline, None).unwrap();
        crate::i18n::apply("en");
        type_into(&app, 0, PASSWORD);
        app.invoke_unlock();
        assert_eq!(
            app.get_screen(),
            Screen::Vault,
            "{}",
            app.get_error_detail()
        );
        app.invoke_open_transfer();

        // Nothing to count yet, and it says why.
        app.set_export_format(3);
        app.invoke_export_ask();
        assert!(app.get_export_asking());
        assert_eq!(app.get_error_code(), 37, "the item lock is in the way");
        assert_eq!(app.get_export_counts(), ExportCounts::default());
        type_into(&app, 5, PASSWORD);
        type_into(&app, 6, "a long password for the file");
        type_into(&app, 7, "a long password for the file");
        app.invoke_export_plain();
        let exported = path.with_extension("export.vaultx");
        if !master_opens {
            // No copy of the lock's key under the master password: it stays in the way.
            assert!(!exported.exists());
            assert!(app.get_export_asking());
            assert_eq!(app.get_error_code(), 37);
            assert!(!app.get_export_recounted());
            app.invoke_export_cancel();
            continue;
        }
        // The master password opened the items for the export. The file keeps every item
        // whole, so it holds nothing the dialog didn't say: it is made at once, and the item
        // lock closes again.
        assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
        assert!(exported.exists() && !app.get_export_asking());
        assert!(!app.get_export_recounted());
        assert!(!app.get_secrets_open());
        app.invoke_select_category(0);
        app.invoke_select(0);
        assert!(app.get_detail_locked(), "for the export only");

        // A protected export refused for its password closes the item lock again too.
        app.invoke_open_transfer();
        app.invoke_export_ask();
        type_into(&app, 5, PASSWORD);
        app.invoke_export_plain();
        assert_eq!(app.get_error_code(), 5, "no password for the file");
        app.invoke_export_cancel();
        app.invoke_select_category(0);
        app.invoke_select(0);
        assert!(app.get_detail_locked());
        app.invoke_reveal();
        assert_eq!(app.get_revealed_password(), "");
    }
}

/// Settings → Browser extension → Add to a browser: the extension's files are written into the
/// app's own folder and the steps show (no browser is started here); while the link runs, a
/// file another program changed is put back and said.
#[test]
fn the_extension_folder_is_written_and_kept_as_the_app_wrote_it() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let _turn = app_home(&home);
    let app = AppWindow::new().unwrap();
    let controller =
        Controller::install(&app, dir.path().join("none.vault"), Runner::Inline, None).unwrap();
    let folder = home.join("browser-extension");

    // Never added: the link's checks leave everything alone.
    controller.check_extension_folder();
    assert!(!folder.exists());

    let browsers = app.get_extension_browsers();
    let index = |name: &str| {
        (0..browsers.row_count())
            .find(|&i| browsers.row_data(i).unwrap().name == name)
            .unwrap() as i32
    };
    app.invoke_add_extension(index("Edge"));
    assert_eq!(app.get_error_code(), 0, "{}", app.get_error_detail());
    assert!(app.get_extension_steps());
    assert_eq!(app.get_extension_steps_browser(), "Edge");
    assert!(!app.get_extension_steps_firefox());
    assert_eq!(app.get_extension_steps_page(), "edge://extensions");
    assert_eq!(
        app.get_extension_steps_folder(),
        folder.display().to_string()
    );
    assert!(!app.get_extension_steps_started() && !app.get_extension_steps_copied());
    // What the release's zip holds, at the app's version.
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
    for name in [
        "background.js",
        "update.js",
        "_locales/en/messages.json",
        "icons/icon128.png",
    ] {
        assert!(folder.join(name).is_file(), "{name}");
    }
    for name in ["test", "package.json", "README.md"] {
        assert!(!folder.join(name).exists(), "{name}");
    }
    app.set_extension_steps(false);
    app.invoke_add_extension(index("Firefox"));
    assert!(app.get_extension_steps_firefox());
    assert_eq!(
        app.get_extension_steps_page(),
        "about:debugging#/runtime/this-firefox"
    );
    assert_eq!(app.get_notice_code(), 0, "nothing was changed");

    // Another program changes the code the browser runs: put back at the link's next check,
    // and said.
    let worker = std::fs::read(folder.join("background.js")).unwrap();
    std::fs::write(folder.join("background.js"), b"stealPasswords();").unwrap();
    std::fs::write(folder.join("more.js"), b"stealPasswords();").unwrap();
    controller.check_extension_folder();
    assert_eq!(app.get_notice_code(), 97);
    assert_eq!(std::fs::read(folder.join("background.js")).unwrap(), worker);
    assert!(!folder.join("more.js").exists());
    app.set_notice_code(0);
    controller.check_extension_folder();
    assert_eq!(app.get_notice_code(), 0, "nothing changed since");
    // So does adding it to a browser again.
    std::fs::write(folder.join("manifest.json"), b"{}").unwrap();
    app.invoke_open_extension_folder();
    assert_eq!(app.get_notice_code(), 97);
    assert!(std::fs::read(folder.join("manifest.json")).unwrap().len() > 2);

    // A folder that can't be written is said on the card: here a file of it another program
    // holds open, sharing nothing.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::write(folder.join("popup.js"), b"changed").unwrap();
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(folder.join("popup.js"))
            .unwrap();
        app.set_extension_steps(false);
        app.invoke_add_extension(index("Chrome"));
        assert_eq!(app.get_error_code(), 70);
        assert!(app.get_error_detail().contains("popup.js"));
        assert!(!app.get_extension_steps());
        // The link's checks say it from the second failure in a row.
        app.set_notice_code(0);
        controller.check_extension_folder();
        assert_eq!(app.get_notice_code(), 0, "once is no news");
        controller.check_extension_folder();
        assert_eq!(app.get_notice_code(), 98);
        assert!(app.get_notice_arg().contains("popup.js"));
        drop(held);
        app.invoke_add_extension(index("Chrome"));
        assert_eq!(app.get_error_code(), 0);
        assert!(app.get_extension_steps());
    }
}

/// A zip of `files`, stored (not compressed), as a release's would be read.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    let (mut zip, mut directory) = (Vec::new(), Vec::new());
    for (name, bytes) in files {
        let header = |signature: u32, central: bool| {
            let mut header = signature.to_le_bytes().to_vec();
            if central {
                header.extend_from_slice(&[20, 0]);
            }
            header.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            header.extend_from_slice(&crc32(bytes).to_le_bytes());
            header.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            header.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            header.extend_from_slice(&(name.len() as u16).to_le_bytes());
            header.extend_from_slice(&[0, 0]);
            header
        };
        let offset = zip.len() as u32;
        zip.extend(header(0x0403_4b50, false));
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(bytes);
        directory.extend(header(0x0201_4b50, true));
        // Its comment's length, disk, internal and external attributes.
        directory.extend_from_slice(&[0; 10]);
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let at = zip.len() as u32;
    zip.extend_from_slice(&directory);
    zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    zip.extend_from_slice(&[0; 4]);
    zip.extend_from_slice(&(files.len() as u16).to_le_bytes());
    zip.extend_from_slice(&(files.len() as u16).to_le_bytes());
    zip.extend_from_slice(&(directory.len() as u32).to_le_bytes());
    zip.extend_from_slice(&at.to_le_bytes());
    zip.extend_from_slice(&[0, 0]);
    zip
}

/// The extension follows the app: a new version of the app rewrites the folder as the link
/// starts, and the extension hears that version; a newer GitHub release is taken only with the
/// digest GitHub lists; a folder of the person's takes their place until they go back.
#[test]
fn the_extension_follows_the_app_its_releases_or_the_persons_folder() {
    use sha2::Digest;
    use vault_platform::{extension_folder, extension_source::Extension};

    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let _turn = app_home(&home);
    let folder = home.join("browser-extension");
    let heard = |answer: &[u8]| -> String {
        let answer: serde_json::Value = serde_json::from_slice(answer).unwrap();
        answer["extension_version"].as_str().unwrap().to_owned()
    };
    let in_folder = || -> String {
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
        manifest["version"].as_str().unwrap().to_owned()
    };

    // The previous version of the app: the link on, and its extension in the folder.
    {
        let app = AppWindow::new().unwrap();
        let _controller =
            Controller::install(&app, dir.path().join("none.vault"), Runner::Inline, None).unwrap();
        app.set_browser_extension(true);
        app.invoke_settings_changed();
    }
    let older = Extension::built_in(
        "0.0.1",
        &[
            (
                "manifest.json",
                br#"{"manifest_version":3,"version":"0.0.1"}"#,
            ),
            ("old.js", b"// before"),
        ],
    );
    extension_folder::install(&older).unwrap();
    assert_eq!(in_folder(), "0.0.1");

    // This version starts: its extension is in the folder as the link starts (before anything
    // is answered), without a word, and the extension hears its version.
    let app = AppWindow::new().unwrap();
    let controller =
        Controller::install(&app, dir.path().join("none.vault"), Runner::Inline, None).unwrap();
    assert_eq!(in_folder(), env!("CARGO_PKG_VERSION"));
    assert!(!folder.join("old.js").exists());
    assert_eq!(app.get_notice_code(), 0);
    assert_eq!(
        heard(&controller.browser_status()),
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(app.get_extension_source(), 0, "built into the app");
    assert_eq!(app.get_extension_version(), env!("CARGO_PKG_VERSION"));

    // A newer release on GitHub: taken only with the digest GitHub lists for it.
    let zip = stored_zip(&[
        (
            "manifest.json",
            br#"{"manifest_version":3,"version":"99.0.0"}"#,
        ),
        ("background.js", b"// 99"),
    ]);
    let sha256: String = sha2::Sha256::digest(&zip)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    controller.take_extension_release("99.0.0", &"0".repeat(64), &zip);
    assert_eq!(app.get_notice_code(), 99);
    assert!(app.get_notice_arg().starts_with("99.0.0: "));
    assert_eq!(in_folder(), env!("CARGO_PKG_VERSION"), "nothing taken");
    app.set_notice_code(0);
    controller.take_extension_release("99.0.0", &sha256, &zip);
    assert_eq!(app.get_notice_code(), 0);
    assert_eq!(in_folder(), "99.0.0");
    assert_eq!(app.get_extension_source(), 1, "from GitHub");
    assert_eq!(heard(&controller.browser_status()), "99.0.0");
    // Kept as such: another program's change is put back and said.
    std::fs::write(folder.join("background.js"), b"stealPasswords();").unwrap();
    controller.check_extension_folder();
    assert_eq!(app.get_notice_code(), 97);
    assert_eq!(
        std::fs::read(folder.join("background.js")).unwrap(),
        b"// 99"
    );
    app.set_notice_code(0);

    // A folder of the person's instead; one without a manifest isn't one.
    let mine = dir.path().join("my-extension");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::write(mine.join("content.js"), b"// mine").unwrap();
    controller.use_extension_folder(&mine);
    assert_eq!(app.get_error_code(), 72);
    assert_eq!(in_folder(), "99.0.0");
    std::fs::write(
        mine.join("manifest.json"),
        br#"{"manifest_version":3,"version":"1.0.0"}"#,
    )
    .unwrap();
    controller.use_extension_folder(&mine);
    assert_eq!(app.get_error_code(), 0);
    assert_eq!(app.get_extension_source(), 2);
    assert_eq!(app.get_extension_local(), mine.display().to_string());
    assert_eq!(in_folder(), "1.0.0");
    assert_eq!(
        std::fs::read(folder.join("content.js")).unwrap(),
        b"// mine"
    );
    assert!(!folder.join("background.js").exists());
    assert_eq!(app.get_notice_code(), 0, "the person's own choice");
    assert_eq!(heard(&controller.browser_status()), "1.0.0");
    // Their changes are followed without a word; another program's change of the copy isn't.
    std::fs::write(mine.join("content.js"), b"// mine, changed").unwrap();
    controller.check_extension_folder();
    assert_eq!(app.get_notice_code(), 0);
    assert_eq!(
        std::fs::read(folder.join("content.js")).unwrap(),
        b"// mine, changed"
    );
    std::fs::write(folder.join("content.js"), b"stealPasswords();").unwrap();
    controller.check_extension_folder();
    assert_eq!(app.get_notice_code(), 97);
    app.set_notice_code(0);

    // Back to GitHub's releases: the newest one there.
    app.invoke_use_extension_release();
    assert_eq!(app.get_extension_source(), 1);
    assert_eq!(in_folder(), "99.0.0");
    assert!(!folder.join("content.js").exists());
    assert_eq!(app.get_notice_code(), 0);
}

/// Check for updates: what each answer shows, with no network (the tests never ask GitHub).
#[test]
fn check_for_updates_says_what_github_answered() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let app = AppWindow::new().unwrap();
    let controller =
        Controller::install(&app, dir.path().join("none.vault"), Runner::Inline, None).unwrap();
    let release = |version: &str| vault_sync_wire::releases::Release {
        version: version.to_owned(),
        page: format!("https://github.com/o/r/releases/tag/v{version}"),
        assets: Vec::new(),
    };

    // Inline (tests): the button asks nothing, and nothing is looked for by itself.
    app.invoke_check_updates();
    assert_eq!(app.get_update_state(), 0);
    assert!(
        vault_platform::device::Settings::default().update_checks,
        "looked for by itself unless turned off"
    );

    controller.finish_update_check(Ok(release(env!("CARGO_PKG_VERSION"))), false);
    assert_eq!(app.get_update_state(), 2, "this is the newest");

    // Found on its own: said once in a notice, and in About.
    controller.finish_update_check(Ok(release("99.0.0")), true);
    assert_eq!(app.get_update_state(), 3, "a newer one is out");
    assert_eq!(app.get_update_version(), "99.0.0");
    assert_eq!(app.get_notice_code(), 89);
    assert_eq!(app.get_notice_arg(), "99.0.0");
    app.set_notice_code(0);
    controller.finish_update_check(Ok(release("99.0.0")), true);
    assert_eq!(
        app.get_notice_code(),
        0,
        "the same version isn't told twice"
    );

    // A look on its own that fails says nothing; the button says why.
    controller.finish_update_check(Err("offline".to_owned()), true);
    assert_eq!(app.get_update_state(), 3);
    controller.finish_update_check(Err("offline".to_owned()), false);
    assert_eq!(app.get_update_state(), 4);
    assert_eq!(app.get_update_detail(), "offline");
}
