//! Format v11 items: the trash, archived items and templates, tags, each item's earlier
//! versions, and how they merge between devices (VAULT_FORMAT.md §5, SYNC.md §4.2–4.3).

use vault_core::{
    CustomField, Error, GuardCheck, ItemData, ItemId, ItemKind, KdfParams, SecretKey, Unlock,
    Vault, VaultSettings,
    sync::{DeviceId, SeenRevisions},
};

const PASSWORD: &str = "test master password";

struct Device {
    vault: Vault,
    seen: SeenRevisions,
}

impl Device {
    fn copy(&mut self) -> Vec<u8> {
        self.vault.to_bytes().unwrap()
    }

    fn take(&mut self, copy: &[u8]) -> vault_core::sync::MergeReport {
        self.vault.merge(copy, &mut self.seen).unwrap()
    }
}

/// Two devices holding the same vault with one login.
fn two_devices() -> (Device, Device, ItemId) {
    let secret_key = SecretKey::generate().unwrap();
    let mut first =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    let id = first
        .add_item(&ItemData::login(
            "Shared",
            "me",
            "first-password",
            "https://shared.example",
        ))
        .unwrap();
    let bytes = first.to_bytes().unwrap();
    let device = || {
        let mut vault = Vault::open(
            &bytes,
            Unlock::Password {
                password: PASSWORD,
                secret_key: &secret_key,
            },
        )
        .unwrap();
        vault.set_device(DeviceId::generate().unwrap());
        Device {
            vault,
            seen: SeenRevisions::new(),
        }
    };
    (device(), device(), id)
}

fn vault() -> Vault {
    let secret_key = SecretKey::generate().unwrap();
    Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap()
}

fn edit(vault: &mut Vault, id: &ItemId, change: impl FnOnce(&mut ItemData)) {
    let mut item = vault.get_item(id).unwrap();
    change(&mut item);
    item.touch();
    vault.update_item(id, &item).unwrap();
}

#[test]
fn the_trash_keeps_an_item_until_it_is_emptied_or_30_days_pass() {
    let mut vault = vault();
    let id = vault
        .add_item(&ItemData::login("A", "a", "pa", "https://a.example"))
        .unwrap();
    let other = vault
        .add_item(&ItemData::login("B", "b", "pb", "https://b.example"))
        .unwrap();
    vault.trash_item(&id).unwrap();
    let item = vault.get_item(&id).unwrap();
    assert!(item.trashed_at > 0 && !item.is_active());
    assert_eq!(item.password, "pa", "nothing else changes");
    vault.to_bytes().unwrap();
    assert_eq!(vault.len(), 2, "kept while it is recent");
    vault.restore_item(&id).unwrap();
    assert!(vault.get_item(&id).unwrap().is_active());

    // Put in the trash 31 days ago: gone at the next save.
    edit(&mut vault, &id, |item| {
        item.trashed_at = 1;
    });
    vault.to_bytes().unwrap();
    assert!(matches!(vault.get_item(&id), Err(Error::ItemNotFound)));
    vault.trash_item(&other).unwrap();
    assert_eq!(vault.empty_trash().unwrap(), 1);
    assert!(vault.is_empty());
}

#[test]
fn a_change_keeps_the_earlier_version_and_one_can_be_restored() {
    let mut vault = vault();
    vault
        .set_settings(VaultSettings {
            name: String::new(),
            history_limit: 2,
        })
        .unwrap();
    let id = vault
        .add_item(&ItemData::login(
            "Site",
            "first",
            "pw-1",
            "https://s.example",
        ))
        .unwrap();
    // A mark, a folder, the trash or a recovery code marked as used are not new contents.
    edit(&mut vault, &id, |item| {
        item.recovery_codes = vault_core::RecoveryCode::parse_list("aaaa-1111");
    });
    assert_eq!(vault.get_item(&id).unwrap().versions.len(), 1);
    edit(&mut vault, &id, |item| {
        item.favorite = true;
        item.recovery_codes[0].used = true;
    });
    assert_eq!(
        vault.get_item(&id).unwrap().versions.len(),
        1,
        "only the codes added"
    );
    edit(&mut vault, &id, |item| item.username = "second".into());
    edit(&mut vault, &id, |item| item.notes = "a note".into());
    edit(&mut vault, &id, |item| item.password = "pw-2".into());
    let item = vault.get_item(&id).unwrap();
    assert_eq!(item.versions.len(), 2, "cut to the history limit");
    assert_eq!(item.versions[0].item.username, "second");
    assert_eq!(item.versions[0].item.notes, "");
    assert_eq!(item.versions[1].item.notes, "a note");
    assert_eq!(item.versions[1].item.password, "pw-1");

    // Restoring brings back its contents, keeps the mark, and keeps what it replaced.
    vault.restore_version(&id, 0).unwrap();
    let item = vault.get_item(&id).unwrap();
    assert_eq!(
        (item.username.as_str(), item.notes.as_str()),
        ("second", "")
    );
    assert_eq!(item.password, "pw-1");
    assert!(item.favorite);
    assert_eq!(item.versions.last().unwrap().item.password, "pw-2");
    assert!(item.password_history.iter().any(|h| h.password == "pw-2"));
    assert!(matches!(
        vault.restore_version(&id, 9),
        Err(Error::ItemNotFound)
    ));
}

#[test]
fn versions_are_sealed_with_the_item_lock() {
    let mut vault = vault();
    let mut login = ItemData::login("Bank", "me", "Unique-Old-Secret", "https://bank.example");
    login.reprompt = true;
    let id = vault.add_item(&login).unwrap();
    edit(&mut vault, &id, |item| {
        item.password = "Unique-New-Secret".into()
    });
    vault
        .set_item_guard(false, GuardCheck::Pin, Some("4821"), None)
        .unwrap();
    vault.lock_secrets();
    let locked = vault.get_item(&id).unwrap();
    assert!(locked.is_locked() && locked.versions.is_empty());
    // Written back while locked (a new title): the sealed versions stay as they were.
    let mut renamed = locked.clone();
    renamed.title = "Bank (renamed)".into();
    vault.update_item(&id, &renamed).unwrap();
    assert!(matches!(
        vault.restore_version(&id, 0),
        Err(Error::SecretsLocked)
    ));
    assert!(vault.unlock_secrets("4821").unwrap());
    let open = vault.get_item(&id).unwrap();
    assert_eq!(open.versions.len(), 1);
    assert_eq!(open.versions[0].item.password, "Unique-Old-Secret");
}

#[test]
fn tags_are_tidied_and_checked() {
    let mut item = ItemData::login("x", "u", "p", "");
    item.set_tags(" Work, bank ,work,, Home\nBANK ").unwrap();
    assert_eq!(item.tags, ["Work", "bank", "Home"]);
    assert!(item.has_tag("HOME"));
    assert!(item.set_tags(&"x".repeat(41)).is_err());
    let many: Vec<String> = (0..33).map(|n| n.to_string()).collect();
    assert!(item.set_tags(&many.join(",")).is_err());
    assert_eq!(
        item.tags,
        ["Work", "bank", "Home"],
        "unchanged when refused"
    );
    let mut vault = vault();
    let mut bad = ItemData::login("y", "u", "p", "");
    bad.tags = vec!["dup".into(), "DUP".into()];
    assert!(matches!(vault.add_item(&bad), Err(Error::InvalidName)));
}

#[test]
fn a_template_shapes_a_new_item_without_its_secrets() {
    let mut template = ItemData::new(ItemKind::Login, "Intranet");
    template.template = true;
    template.urls = vec!["https://intranet.example".into()];
    template.password = "never copied".into();
    template.set_tags("work").unwrap();
    template.custom_fields = vec![
        CustomField {
            name: "Department".into(),
            value: "Testing".into(),
            sensitive: false,
        },
        CustomField {
            name: "Badge PIN".into(),
            value: "1234".into(),
            sensitive: true,
        },
    ];
    let item = template.from_template();
    assert!(!item.template && item.title.is_empty() && item.password.is_empty());
    assert_eq!(item.urls, template.urls);
    assert_eq!(item.tags, ["work"]);
    assert_eq!(item.custom_fields[0].value, "Testing");
    assert_eq!(
        (
            item.custom_fields[1].name.as_str(),
            item.custom_fields[1].value.as_str()
        ),
        ("Badge PIN", "")
    );
}

#[test]
fn an_edit_wins_over_the_trash_on_another_device() {
    let (mut a, mut b, id) = two_devices();
    a.vault.trash_item(&id).unwrap();
    edit(&mut b.vault, &id, |item| {
        item.username = "edited on b".into()
    });
    let from_a = a.copy();
    let from_b = b.copy();
    a.take(&from_b);
    b.take(&from_a);
    for device in [&a, &b] {
        let item = device.vault.get_item(&id).unwrap();
        assert_eq!(item.trashed_at, 0, "out of the trash");
        assert_eq!(item.username, "edited on b");
    }
    assert_eq!(
        a.vault.get_item(&id).unwrap(),
        b.vault.get_item(&id).unwrap()
    );
}

#[test]
fn both_edits_are_kept_one_of_them_as_a_version() {
    let (mut a, mut b, id) = two_devices();
    edit(&mut a.vault, &id, |item| item.notes = "from a".into());
    edit(&mut b.vault, &id, |item| item.notes = "from b".into());
    let from_a = a.copy();
    let from_b = b.copy();
    let report = a.take(&from_b);
    assert_eq!(report.conflicts, [id]);
    b.take(&from_a);
    let (on_a, on_b) = (
        a.vault.get_item(&id).unwrap(),
        b.vault.get_item(&id).unwrap(),
    );
    assert_eq!(on_a, on_b);
    let kept: Vec<&str> = on_a
        .versions
        .iter()
        .map(|v| v.item.notes.as_str())
        .chain([on_a.notes.as_str()])
        .collect();
    assert!(
        kept.contains(&"from a") && kept.contains(&"from b"),
        "{kept:?}"
    );
}

#[test]
fn a_restore_survives_a_deletion_for_good_elsewhere() {
    let (mut a, mut b, id) = two_devices();
    a.vault.trash_item(&id).unwrap();
    let from_a = a.copy();
    b.take(&from_a);
    // A restores it while B, which saw it in the trash, deletes it for good.
    a.vault.restore_item(&id).unwrap();
    b.vault.remove_item(&id).unwrap();
    let from_a = a.copy();
    let from_b = b.copy();
    a.take(&from_b);
    b.take(&from_a);
    for device in [&a, &b] {
        assert_eq!(device.vault.get_item(&id).unwrap().trashed_at, 0);
    }
}

#[test]
fn a_deletion_for_good_removes_the_version_it_saw_everywhere() {
    let (mut a, mut b, id) = two_devices();
    a.vault.remove_item(&id).unwrap();
    let from_a = a.copy();
    let report = b.take(&from_a);
    assert_eq!(report.removed, 1);
    assert!(b.vault.is_empty());
    // And a copy that still has that version doesn't bring it back.
    let from_b = b.copy();
    a.take(&from_b);
    assert!(a.vault.is_empty());
}
