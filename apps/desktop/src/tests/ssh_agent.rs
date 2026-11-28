//! The SSH agent (controller/ssh_agent.rs), asked as the pipe's threads ask it: the vault's
//! keys listed only while it is open; every signature waits for the person (refused, or
//! approved and checked against the key); "don't ask again" for one key and one program;
//! a key behind the item lock refused until the lock is opened; an unknown key refused at
//! once; and locking refuses what still waits and ends every approval.

use std::{path::PathBuf, sync::mpsc};

use vault_core::{CustomField, GuardCheck, ItemData, ItemKind, KdfParams, SecretKey, Vault, ssh};
use vault_platform::{
    secret_store,
    ssh_agent::{self, Client},
};

use super::{ForgetOnDrop, PASSWORD, app_home, type_into};
use crate::{
    apply_sketches,
    controller::{Controller, Runner},
    ui::{AppWindow, Screen},
};

/// Field numbers (controller.rs `field`) and the notice (`notice`).
const MASTER: i32 = 0;
const REPROMPT: i32 = 11;
const SSH_KEY_USED: i32 = 140;

const DATA: &[u8] = b"a session id and a userauth request";

/// Whether `answer` is the signature of `DATA` by `pair`'s key (Ed25519 signs the same
/// bytes the same way; that the signature checks against the key is vault-core's test).
fn signed_by(answer: &[u8], pair: &ssh::SshKeyPair) -> bool {
    answer == ssh_agent::sign_response(&ssh::agent_sign(&pair.private_key, DATA, 0).unwrap())
}

#[test]
fn the_ssh_agent_asks_before_every_signature() {
    i_slint_backend_testing::init_no_event_loop();
    let dir = tempfile::tempdir().unwrap();
    let _turn = app_home(&dir.path().join("home"));
    let key = SecretKey::generate().unwrap();
    let path = dir.path().join("agent.vault");
    let mut vault = Vault::create(PASSWORD, &key, None, KdfParams::minimum().unwrap()).unwrap();
    // Two test keys made here: one plain, one behind the item lock.
    let mut keys = Vec::new();
    for (title, guarded) in [("Build server", false), ("Production", true)] {
        let pair = ssh::generate_ed25519("test@example.invalid").unwrap();
        let mut item = ItemData::new(ItemKind::SshKey, title);
        item.password = pair.private_key.to_string();
        for (name, value) in [
            (ssh::PUBLIC_KEY_FIELD, pair.public_key.clone()),
            (ssh::FINGERPRINT_FIELD, pair.fingerprint.clone()),
        ] {
            item.custom_fields.push(CustomField {
                name: name.into(),
                value,
                sensitive: false,
            });
        }
        item.reprompt = guarded;
        vault.add_item(&item).unwrap();
        keys.push((ssh::public_key_blob(&pair.public_key).unwrap(), pair));
    }
    // A login is no key.
    vault
        .add_item(&ItemData::new(ItemKind::Login, "Mail"))
        .unwrap();
    vault
        .set_item_guard(false, GuardCheck::Pin, Some("2468"), None)
        .unwrap();
    std::fs::write(&path, vault.to_bytes().unwrap()).unwrap();
    let _cleanup = ForgetOnDrop(vault.id_hex());
    secret_store::store(&vault.id_hex(), &key).unwrap();
    let app = AppWindow::new().unwrap();
    apply_sketches(&app);
    let controller = Controller::install(&app, path.clone(), Runner::Inline, None).unwrap();
    crate::i18n::apply("en");

    let ssh_exe = Client {
        program: Some(PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe")),
        parent: Some(PathBuf::from(r"C:\Program Files\Git\cmd\git.exe")),
    };
    let scp_exe = Client {
        program: Some(PathBuf::from(r"C:\Windows\System32\OpenSSH\scp.exe")),
        parent: None,
    };
    let ask = |controller: &Controller, blob: &[u8], client: &Client| {
        let (reply_to, reply) = mpsc::channel();
        let id = controller.agent_sign(blob.to_vec(), DATA.to_vec(), 0, client, reply_to);
        (id, reply)
    };
    let (plain, plain_pair) = &keys[0];
    let (guarded, _) = &keys[1];

    // Locked: no keys, and a signature refused without a question.
    assert_eq!(controller.agent_identities(), vec![12, 0, 0, 0, 0]);
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    assert_eq!(reply.try_recv().unwrap(), ssh_agent::failure());
    assert!(!app.get_agent_asking());

    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    assert_eq!(
        app.get_screen(),
        Screen::Vault,
        "{}",
        app.get_error_detail()
    );

    // Open: both keys, by their titles, the login not.
    let listed = controller.agent_identities();
    assert_eq!(&listed[..5], &[12, 0, 0, 0, 2]);
    for (blob, _) in &keys {
        assert!(listed.windows(blob.len()).any(|w| w == blob.as_slice()));
    }
    assert!(listed.windows(12).any(|w| w == b"Build server"));

    // Every signature waits for the person; refused, the program gets the failure.
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    assert!(app.get_agent_asking());
    assert_eq!(app.get_agent_key_title(), "Build server");
    assert_eq!(
        app.get_agent_key_fingerprint(),
        plain_pair.fingerprint.as_str()
    );
    assert_eq!(app.get_agent_program(), "ssh.exe");
    assert_eq!(app.get_agent_parent(), "git.exe");
    assert_eq!(app.get_agent_purpose(), 0);
    assert!(!app.get_agent_key_locked());
    assert!(app.get_agent_can_remember());
    assert!(reply.try_recv().is_err(), "nothing before the answer");
    app.invoke_agent_decided(false, false);
    assert_eq!(reply.try_recv().unwrap(), ssh_agent::failure());
    assert!(!app.get_agent_asking());

    // Approved: a signature that checks against the key.
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    app.invoke_agent_decided(true, false);
    assert!(signed_by(&reply.try_recv().unwrap(), plain_pair));
    assert_eq!(app.get_notice_code(), SSH_KEY_USED);
    // Without "don't ask again", the next one asks again.
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    assert!(app.get_agent_asking());
    // With it: this key and this program sign without asking; another program still asks.
    app.invoke_agent_decided(true, true);
    assert!(signed_by(&reply.try_recv().unwrap(), plain_pair));
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    assert!(!app.get_agent_asking());
    assert!(signed_by(&reply.try_recv().unwrap(), plain_pair));
    let (scp_id, scp_reply) = ask(&controller, plain, &scp_exe);
    assert!(app.get_agent_asking());
    assert_eq!(app.get_agent_program(), "scp.exe");
    assert_eq!(app.get_agent_parent(), "");
    // A program Windows didn't name can't be remembered.
    let (_, unnamed) = ask(&controller, plain, &Client::default());
    assert_eq!(app.get_agent_waiting(), 1, "a second question waits");
    // The first stops waiting (its time ran out): the next one shows.
    controller.agent_ask_expired(scp_id);
    assert!(scp_reply.try_recv().is_err());
    assert_eq!(app.get_agent_program(), "");
    assert!(!app.get_agent_can_remember());
    assert_eq!(app.get_agent_waiting(), 0);
    app.invoke_agent_decided(false, false);
    assert_eq!(unnamed.try_recv().unwrap(), ssh_agent::failure());

    // Each signature is in the security log: the key and the program, never a secret.
    app.invoke_open_settings();
    let signed: Vec<_> = slint::Model::iter(&app.get_security_log())
        .filter(|line| line.kind == 18)
        .collect();
    assert_eq!(signed.len(), 3, "two approved, one within the 5 minutes");
    assert!(
        signed
            .iter()
            .all(|line| line.title == "Build server" && line.detail == "ssh.exe")
    );

    // A key nobody has: refused at once.
    let (_, reply) = ask(&controller, b"no such key", &ssh_exe);
    assert_eq!(reply.try_recv().unwrap(), ssh_agent::failure());
    assert!(!app.get_agent_asking());

    // Behind the item lock: the dialog says so and approving signs nothing, even for a
    // program approved "for a while".
    let (_, reply) = ask(&controller, guarded, &ssh_exe);
    assert!(app.get_agent_asking());
    assert!(app.get_agent_key_locked());
    app.invoke_agent_decided(true, true);
    assert_eq!(reply.try_recv().unwrap(), ssh_agent::failure());
    // Opened in the app, it signs once approved.
    app.invoke_select_category(0);
    let index = (0..slint::Model::row_count(&app.get_items()))
        .find(|&i| {
            slint::Model::row_data(&app.get_items(), i).is_some_and(|row| row.title == "Production")
        })
        .unwrap();
    app.invoke_select(i32::try_from(index).unwrap());
    type_into(&app, REPROMPT, "2468");
    app.invoke_unlock_item();
    assert!(app.get_secrets_open());
    let (_, reply) = ask(&controller, guarded, &ssh_exe);
    assert!(!app.get_agent_key_locked());
    app.invoke_agent_decided(true, false);
    assert!(signed_by(&reply.try_recv().unwrap(), &keys[1].1));

    // Locking refuses the question still open, ends "don't ask again" and lists nothing.
    let (_, waiting) = ask(&controller, guarded, &ssh_exe);
    assert!(app.get_agent_asking());
    app.invoke_lock();
    assert_eq!(waiting.try_recv().unwrap(), ssh_agent::failure());
    assert!(!app.get_agent_asking());
    assert_eq!(controller.agent_identities(), vec![12, 0, 0, 0, 0]);
    type_into(&app, MASTER, PASSWORD);
    app.invoke_unlock();
    let (_, reply) = ask(&controller, plain, &ssh_exe);
    assert!(app.get_agent_asking(), "approvals end with the lock");
    assert!(reply.try_recv().is_err());
    app.invoke_agent_decided(false, false);
}
