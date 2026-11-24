//! A running server with real devices (spec: SYNC.md §5.3, §9): two vaults converge through
//! it, and what a stranger, a replay or a confused device sends is refused.

use std::{
    net::SocketAddr,
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use vault_core::{
    ItemData, KdfParams, SecretKey, Unlock, Vault,
    sync::{DeviceId, SeenRevisions},
};
use vault_platform::sync::{self, ServerTarget, Tags, Target};
use vault_sync_wire::{self as wire, DeviceKey, InviteLink};

/// A server on a free local port, stopped when dropped.
struct Running {
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Running {
    fn start(data: &Path) -> Self {
        Self::start_with(data, false)
    }

    /// With the server's own HTTPS; `url` then carries the pin.
    fn start_tls(data: &Path) -> Self {
        Self::start_with(data, true)
    }

    fn start_with(data: &Path, tls: bool) -> Self {
        let data = data.to_owned();
        let tls = tls.then(|| vault_server::Tls::load_or_make(&data, &[]).unwrap());
        let pin = tls.as_ref().map(|tls| tls.pin.clone());
        let (ready, address) = mpsc::channel::<SocketAddr>();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready.send(listener.local_addr().unwrap()).unwrap();
                let stopped = async {
                    let _ = stopped.await;
                };
                match tls {
                    Some(tls) => {
                        vault_server::serve_tls(&data, listener, std::sync::Arc::new(tls), stopped)
                            .await
                    }
                    None => vault_server::serve(&data, listener, stopped).await,
                }
                .unwrap();
            });
        });
        let address = address.recv().unwrap();
        Self {
            url: match pin {
                Some(pin) => format!("https://{address}#pin={pin}"),
                None => format!("http://{address}"),
            },
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

const PASSWORD: &str = "test master password";

fn new_vault() -> (Vec<u8>, SecretKey) {
    let secret_key = SecretKey::generate().unwrap();
    let mut vault =
        Vault::create(PASSWORD, &secret_key, None, KdfParams::minimum().unwrap()).unwrap();
    vault
        .add_item(&ItemData::login(
            "Shared",
            "me",
            "pw-1",
            "https://shared.example",
        ))
        .unwrap();
    (vault.to_bytes().unwrap(), secret_key)
}

fn open(bytes: &[u8], secret_key: &SecretKey) -> Vault {
    Vault::open(
        bytes,
        Unlock::Password {
            password: PASSWORD,
            secret_key,
        },
    )
    .unwrap()
}

/// One device: its vault, its server connection and what it saw.
struct Device {
    id: DeviceId,
    vault: Vault,
    server: ServerTarget,
    seen: SeenRevisions,
}

impl Device {
    fn round(&mut self) -> sync::Round {
        sync::join(&mut self.vault, self.id, "Test device").unwrap();
        let fetched = sync::fetch(&self.server, self.id, &Tags::new()).unwrap();
        assert!(fetched.unreadable.is_empty(), "{:?}", fetched.unreadable);
        let round = sync::merge_all(&mut self.vault, &fetched, &mut self.seen);
        self.server
            .put(self.id, &self.vault.to_bytes().unwrap())
            .unwrap();
        round
    }

    fn titles(&self) -> Vec<String> {
        let mut titles: Vec<String> = self
            .vault
            .summaries()
            .unwrap()
            .into_iter()
            .map(|s| s.title.clone())
            .collect();
        titles.sort();
        titles
    }
}

fn admin_invite(data: &Path) -> String {
    vault_server::admin_invite(data, 1, None).unwrap().0
}

#[test]
fn a_pinned_server_is_reached_over_its_own_https() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start_tls(data.path());
    let (bytes, _) = new_vault();
    let vault_id = Vault::inspect(&bytes).unwrap().id_hex;
    let (base, pin) = running.url.split_once("#pin=").unwrap();
    let (base, pin) = (base.to_owned(), pin.to_owned());

    // Without the pin the certificate is a stranger's; with another pin it's refused before
    // anything but the certificate's path is sent.
    for wrong in [base.to_owned(), format!("{base}#pin={}", "0".repeat(64))] {
        let refused = ServerTarget::join(
            &wrong,
            &vault_id,
            DeviceId::generate().unwrap(),
            "PC",
            &admin_invite(data.path()),
        );
        assert!(refused.is_err(), "{wrong}");
    }

    // With it: the computer joins, invites the phone (the pin travels in the invite), the
    // phone fetches the computer's copy.
    let pc_id = DeviceId::generate().unwrap();
    let pc = ServerTarget::join(
        &running.url,
        &vault_id,
        pc_id,
        "PC",
        &admin_invite(data.path()),
    )
    .unwrap();
    pc.put(pc_id, &bytes).unwrap();
    let link = InviteLink::parse(&pc.invite_link(&pc.invite().unwrap()).to_text()).unwrap();
    assert!(link.server.ends_with(&format!("#pin={pin}")));
    let phone_id = DeviceId::generate().unwrap();
    let phone =
        ServerTarget::join(&link.server, &link.vault, phone_id, "Phone", &link.invite).unwrap();
    let fetched = sync::fetch(&phone, phone_id, &Tags::new()).unwrap();
    assert_eq!(fetched.copies.len(), 1);
    assert_eq!(fetched.copies[0].1, bytes);

    // The same authority (so the same pin) after a restart.
    drop(running);
    let again = vault_server::Tls::load_or_make(data.path(), &[]).unwrap();
    assert_eq!(again.pin, pin);
}

#[test]
fn two_devices_converge_through_the_server() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let (bytes, secret_key) = new_vault();
    let vault_id = Vault::inspect(&bytes).unwrap().id_hex;

    // The computer joins with the admin's invite, then invites the phone.
    let pc_id = DeviceId::generate().unwrap();
    let pc_server = ServerTarget::join(
        &running.url,
        &vault_id,
        pc_id,
        "PC",
        &admin_invite(data.path()),
    )
    .unwrap();
    let invite = pc_server.invite().unwrap();
    let link = InviteLink::parse(&pc_server.invite_link(&invite).to_text()).unwrap();
    assert_eq!(link.vault, vault_id);
    let phone_id = DeviceId::generate().unwrap();
    let phone_server =
        ServerTarget::join(&link.server, &link.vault, phone_id, "Phone", &link.invite).unwrap();
    // An invite works once.
    assert!(
        ServerTarget::join(
            &link.server,
            &link.vault,
            DeviceId::generate().unwrap(),
            "X",
            &link.invite
        )
        .is_err()
    );
    assert_eq!(pc_server.enrolled().unwrap().len(), 2);

    let mut pc = Device {
        id: pc_id,
        vault: open(&bytes, &secret_key),
        server: pc_server,
        seen: SeenRevisions::new(),
    };
    let mut phone = Device {
        id: phone_id,
        vault: open(&bytes, &secret_key),
        server: phone_server,
        seen: SeenRevisions::new(),
    };
    pc.round();
    phone.round();
    pc.round();

    // Each side adds an item; a long-poll on the PC wakes when the phone publishes.
    pc.vault
        .add_item(&ItemData::login("From PC", "p", "x", "https://pc.example"))
        .unwrap();
    phone
        .vault
        .add_item(&ItemData::login(
            "From phone",
            "f",
            "y",
            "https://phone.example",
        ))
        .unwrap();
    let seq = pc.server.wait(0, 0).unwrap().unwrap();
    let waiter = {
        let url = running.url.clone();
        let seed = pc.server.key_seed();
        let (vault_id, id) = (vault_id.clone(), pc.id);
        thread::spawn(move || {
            let server =
                ServerTarget::new(&url, &vault_id, id, DeviceKey::from_seed(&seed)).unwrap();
            let started = Instant::now();
            let after = server.wait(seq, 30).unwrap().unwrap();
            (after, started.elapsed())
        })
    };
    thread::sleep(Duration::from_millis(300));
    phone.round();
    let (after, waited) = waiter.join().unwrap();
    assert!(after > seq, "the counter moved");
    assert!(
        waited < Duration::from_secs(10),
        "woken by the change, not the timeout"
    );

    let back = pc.round();
    assert!(back.changed());
    phone.round();
    let expected = ["From PC", "From phone", "Shared"];
    assert_eq!(pc.titles(), expected);
    assert_eq!(phone.titles(), expected);
    // Settled: another round changes nothing on either side.
    assert!(!pc.round().changed());
    assert!(!phone.round().changed());

    // The server holds only sealed copies: no title, no password in clear.
    let copies = data.path().join("vaults").join(&vault_id).join("copies");
    for entry in std::fs::read_dir(copies).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in ["From PC", "pw-1", "Shared", "shared.example"] {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "{secret} in clear"
            );
        }
    }

    // The phone is lost: the PC takes it out. Its key no longer works there.
    pc.server.remove(phone.id).unwrap();
    assert!(phone.server.list().is_err());
    assert_eq!(pc.server.enrolled().unwrap().len(), 1);
    assert_eq!(pc.server.list().unwrap().len(), 1);
}

/// A signed request as a device would send it, to replay or alter.
fn signed(
    agent: &ureq::Agent,
    url: &str,
    key: &DeviceKey,
    device: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, wire::Signed) {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let signed = key.sign_request(device, method, path, body, time);
    (send(agent, url, method, path, &signed, body), signed)
}

fn send(
    agent: &ureq::Agent,
    url: &str,
    method: &str,
    path: &str,
    signed: &wire::Signed,
    body: &[u8],
) -> u16 {
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{url}{path}"));
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    agent
        .run(request.body(body.to_vec()).unwrap())
        .unwrap()
        .status()
        .as_u16()
}

#[test]
fn strangers_replays_and_confused_devices_are_refused() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let vault = "ab".repeat(16);
    let device = DeviceId::generate().unwrap();
    let server = ServerTarget::join(
        &running.url,
        &vault,
        device,
        "PC",
        &admin_invite(data.path()),
    )
    .unwrap();
    let key = DeviceKey::from_seed(&server.key_seed());
    let me = device.to_hex();
    let list = format!("/v1/vaults/{vault}/devices");

    // Unsigned.
    let status = agent
        .get(format!("{}{list}", running.url))
        .call()
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 401);
    // Signed by a key nobody enrolled.
    let (status, _) = signed(
        &agent,
        &running.url,
        &DeviceKey::generate(),
        &me,
        "GET",
        &list,
        b"",
    );
    assert_eq!(status, 401);
    // Signed properly: fine once, refused when played again.
    let (status, request) = signed(&agent, &running.url, &key, &me, "GET", &list, b"");
    assert_eq!(status, 200);
    assert_eq!(send(&agent, &running.url, "GET", &list, &request, b""), 401);
    // A signature for one body doesn't carry another.
    let own = format!("/v1/vaults/{vault}/devices/{me}");
    let (status, request) = signed(&agent, &running.url, &key, &me, "PUT", &own, b"copy");
    assert_eq!(status, 200);
    let mut fresh = request.clone();
    fresh.nonce = wire::new_nonce();
    assert_eq!(
        send(&agent, &running.url, "PUT", &own, &fresh, b"other"),
        401
    );
    // A device writes only its own copy.
    let other = format!("/v1/vaults/{vault}/devices/{}", "cd".repeat(16));
    let (status, _) = signed(&agent, &running.url, &key, &me, "PUT", &other, b"copy");
    assert_eq!(status, 403);
    // Its key opens nothing in another vault.
    let elsewhere = format!("/v1/vaults/{}/devices", "ef".repeat(16));
    let (status, _) = signed(&agent, &running.url, &key, &me, "GET", &elsewhere, b"");
    assert_eq!(status, 401);
    // Paths that aren't ids.
    let (status, _) = signed(
        &agent,
        &running.url,
        &key,
        &me,
        "GET",
        &format!("/v1/vaults/{vault}/devices/..%2F..%2Fenrolled.json"),
        b"",
    );
    assert_eq!(status, 404);
    // A wrong invite, and the address that tried too often is slowed down.
    let mut refused = Vec::new();
    for _ in 0..25 {
        let attempt = ServerTarget::join(
            &running.url,
            &vault,
            DeviceId::generate().unwrap(),
            "Stranger",
            &"0".repeat(32),
        );
        refused.push(format!("{:#}", attempt.unwrap_err()));
    }
    assert!(refused[0].contains("invite"), "{}", refused[0]);
    assert!(refused.last().unwrap().contains("slow down"), "{refused:?}");
    assert_eq!(server.enrolled().unwrap().len(), 1);
}
