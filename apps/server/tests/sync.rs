//! A running server with real devices (spec: SYNC.md §5.3, §9): two vaults converge through
//! it, and what a stranger, a replay or a confused device sends is refused.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
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

/// N-06: a device taken out by `vault-server remove` (a process of its own, with its own
/// `Store` on the same data folder) is gone from the first listing after it, though the
/// serving server kept the listing from before in memory; the devices waiting for news hear
/// of it.
#[test]
fn an_admin_removal_shows_in_the_next_listing() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let (bytes, _) = new_vault();
    let vault_id = Vault::inspect(&bytes).unwrap().id_hex;
    let pc_id = DeviceId::generate().unwrap();
    let pc = ServerTarget::join(
        &running.url,
        &vault_id,
        pc_id,
        "PC",
        &admin_invite(data.path()),
    )
    .unwrap();
    let invite = pc.invite().unwrap();
    let link = InviteLink::parse(&pc.invite_link(&invite).to_text()).unwrap();
    let phone_id = DeviceId::generate().unwrap();
    let phone =
        ServerTarget::join(&link.server, &link.vault, phone_id, "Phone", &link.invite).unwrap();
    pc.put(pc_id, &bytes).unwrap();
    phone.put(phone_id, &bytes).unwrap();
    assert_eq!(pc.list().unwrap().len(), 2, "listed, and kept in memory");
    let seq = pc.wait(0, 0).unwrap().unwrap();

    // The admin, from another process.
    let admin = vault_server::Store::open(data.path()).unwrap();
    assert!(admin.remove(&vault_id, &phone_id.to_hex()).unwrap());

    // A device that waits for news hears that something changed, before anyone lists again.
    let after = pc.wait(seq, 0).unwrap().unwrap();
    assert!(after > seq, "{after} after {seq}");
    // The first listing after it agrees with the devices and with what can be read.
    let listed: Vec<DeviceId> = pc.list().unwrap().into_iter().map(|l| l.device).collect();
    assert_eq!(listed, [pc_id]);
    assert_eq!(pc.enrolled().unwrap().len(), 1);
    assert!(pc.get(phone_id).is_err(), "its copy is gone");
    assert!(phone.list().is_err(), "its key no longer works");
}

/// The same when the removal finds a listing kept from before and nothing left to delete: one
/// cut short after it deleted the copy, made good by trying again.
#[test]
fn an_admin_removal_tried_again_shows_in_the_next_listing() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let vault = "ab".repeat(16);
    let store = vault_server::Store::open(data.path()).unwrap();
    let (pc, phone) = (TestDevice::new(), TestDevice::new());
    for device in [&pc, &phone] {
        store.enroll(&vault, device.enrolled()).unwrap();
        store.put(&vault, &device.id, b"a copy").unwrap();
    }
    let target = ServerTarget::new(
        &running.url,
        &vault,
        DeviceId::from_hex(&pc.id).unwrap(),
        DeviceKey::from_seed(&pc.key.seed()),
    )
    .unwrap();
    assert_eq!(
        target.list().unwrap().len(),
        2,
        "listed, and kept in memory"
    );
    // As left by `vault-server remove` killed right after it deleted the copy.
    let here = data.path().join("vaults").join(&vault);
    std::fs::write(
        here.join("enrolled.json"),
        serde_json::to_vec(&[pc.enrolled()]).unwrap(),
    )
    .unwrap();
    std::fs::remove_file(here.join("copies").join(format!("{}.vault", phone.id))).unwrap();
    store.remove(&vault, &phone.id).unwrap();
    let listed: Vec<String> = target
        .list()
        .unwrap()
        .into_iter()
        .map(|l| l.device.to_hex())
        .collect();
    assert_eq!(listed, [pc.id]);
}

/// A device enrolled straight in the store, and its key.
struct TestDevice {
    id: String,
    key: DeviceKey,
}

impl TestDevice {
    fn new() -> Self {
        Self {
            id: DeviceId::generate().unwrap().to_hex(),
            key: DeviceKey::generate(),
        }
    }

    /// Never heard from yet, so its first request notes when it was heard.
    fn enrolled(&self) -> vault_server::store::Device {
        vault_server::store::Device {
            device: self.id.clone(),
            key: wire::hex(&self.key.public_key()),
            name: "Test device".into(),
            added_at: 1,
            seen_at: 0,
        }
    }

    fn sign(&self, method: &str, path: &str, body: &[u8]) -> wire::Signed {
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.key.sign_request(&self.id, method, path, body, time)
    }
}

/// What the server answers to a signed request, with the body's digest as a device sends it
/// (or, like an older app, without).
fn answer(
    url: &str,
    method: &str,
    path: &str,
    signed: &wire::Signed,
    body: &[u8],
    digest: bool,
) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .proxy(None)
        .build()
        .into();
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{url}{path}"));
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    if digest {
        request = request.header(wire::header::BODY_SHA256, wire::body_digest(body));
    }
    let mut response = agent.run(request.body(body.to_vec()).unwrap()).unwrap();
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    (status, text)
}

/// A request written to the socket by hand, so its body can be held back. Every read and write
/// has a time limit.
struct ByHand(TcpStream);

impl ByHand {
    fn open(url: &str) -> Self {
        let stream = TcpStream::connect(url.strip_prefix("http://").unwrap()).unwrap();
        let limit = Some(Duration::from_secs(20));
        stream.set_read_timeout(limit).unwrap();
        stream.set_write_timeout(limit).unwrap();
        Self(stream)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).unwrap();
    }

    /// The next head the server sends: its status line and headers.
    fn head(&mut self) -> String {
        let mut head = Vec::new();
        let mut byte = [0];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(self.0.read(&mut byte).unwrap(), 1, "the answer ended");
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    /// What is left of an answer after which the connection closes.
    fn rest(&mut self) -> String {
        let mut rest = String::new();
        self.0.read_to_string(&mut rest).unwrap();
        rest
    }
}

/// PM-11, through the API: a copy whose upload was let in and is still arriving when its device
/// is taken out is refused once it is all there. It doesn't bring the copy back.
#[test]
fn a_copy_still_arriving_when_its_device_is_removed_is_refused() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let vault = "ab".repeat(16);
    let store = vault_server::Store::open(data.path()).unwrap();
    let copies = data.path().join("vaults").join(&vault).join("copies");
    let files = || -> Vec<String> {
        std::fs::read_dir(&copies)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    };
    let copy = b"a sealed copy that takes its time to arrive";
    for removed in [false, true] {
        let device = TestDevice::new();
        store.enroll(&vault, device.enrolled()).unwrap();
        store.put(&vault, &device.id, b"the copy before").unwrap();
        let path = format!("/v1/vaults/{vault}/devices/{}", device.id);
        let mut head = format!(
            "PUT {path} HTTP/1.1\r\nhost: test\r\nconnection: close\r\n\
             content-length: {}\r\nexpect: 100-continue\r\n{}: {}\r\n",
            copy.len(),
            wire::header::BODY_SHA256,
            wire::body_digest(copy),
        );
        for (name, value) in device.sign("PUT", &path, copy).headers() {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        let mut request = ByHand::open(&running.url);
        request.write(head.as_bytes());
        // The server asks for the body, which it does only once it let the request in.
        let go_on = request.head();
        assert!(go_on.starts_with("HTTP/1.1 100"), "{go_on}");
        request.write(&copy[..10]);
        if removed {
            // The admin, from another process.
            let admin = vault_server::Store::open(data.path()).unwrap();
            assert!(admin.remove(&vault, &device.id).unwrap());
            assert!(files().is_empty(), "its copy is gone");
        }
        request.write(&copy[10..]);
        let answered = request.head();
        if removed {
            assert!(answered.starts_with("HTTP/1.1 401"), "{answered}");
            assert!(request.rest().contains("unknown_device"));
            assert!(
                files().is_empty(),
                "{:?}: no copy and no temporary file",
                files()
            );
        } else {
            assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
            assert_eq!(store.get(&vault, &device.id).unwrap().unwrap(), copy);
            store.remove(&vault, &device.id).unwrap();
        }
    }
}

/// PM-11, through the API: every route asks again whether the device is in before it changes
/// or hands over anything. The request is held where the server notes that a device was heard
/// from (it waits for the store's lock there, the signature checked already) while the device
/// is taken out.
#[test]
fn a_request_let_in_before_its_devices_removal_gets_and_changes_nothing() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let vault = "ab".repeat(16);
    let here = data.path().join("vaults").join(&vault);
    let store = vault_server::Store::open(data.path()).unwrap();
    store
        .publish_app(b"PK\x03\x04 a test package", "1.2.3")
        .unwrap();
    let neighbour = TestDevice::new();
    store.enroll(&vault, neighbour.enrolled()).unwrap();
    store.put(&vault, &neighbour.id, b"its copy").unwrap();
    let routes: [(&str, &str, &[u8]); 8] = [
        ("GET", "/devices", b""),
        ("GET", "/devices/NEIGHBOUR", b""),
        ("GET", "/enrolled", b""),
        ("GET", "/app/android", b""),
        ("GET", "/app/android/package", b""),
        ("POST", "/invites", b""),
        ("PUT", "/devices/OWN", b"a copy"),
        ("DELETE", "/devices/NEIGHBOUR", b""),
    ];
    for (method, route, body) in routes {
        for removed in [true, false] {
            let device = TestDevice::new();
            store.enroll(&vault, device.enrolled()).unwrap();
            let path = format!("/v1/vaults/{vault}{route}")
                .replace("OWN", &device.id)
                .replace("NEIGHBOUR", &neighbour.id);
            let signed = device.sign(method, &path, body);
            let lock = std::fs::File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(data.path().join("store.lock"))
                .unwrap();
            lock.lock().unwrap();
            let request = {
                let (url, path) = (running.url.clone(), path.clone());
                thread::spawn(move || answer(&url, method, &path, &signed, body, true))
            };
            thread::sleep(Duration::from_millis(300));
            assert!(!request.is_finished(), "{method} {path} waits for the lock");
            if removed {
                // Taken out by whoever holds the lock.
                let left: Vec<_> = store
                    .devices(&vault)
                    .unwrap()
                    .into_iter()
                    .filter(|d| d.device != device.id)
                    .collect();
                std::fs::write(
                    here.join("enrolled.json"),
                    serde_json::to_vec(&left).unwrap(),
                )
                .unwrap();
            }
            drop(lock);
            let (status, text) = request.join().unwrap();
            if !removed {
                assert!((200..300).contains(&status), "{method} {path}: {status}");
                store.remove(&vault, &device.id).unwrap();
                continue;
            }
            assert_eq!(status, 401, "{method} {path}: {text}");
            assert!(text.contains("unknown_device"), "{method} {path}: {text}");
            assert!(
                store.device(&vault, &neighbour.id).unwrap().is_some(),
                "{method} {path}"
            );
            assert_eq!(
                store.copies(&vault).unwrap().len(),
                1,
                "{method} {path}: the neighbour's copy only"
            );
            let invites = std::fs::read_to_string(here.join("invites.json")).unwrap_or_default();
            assert!(!invites.contains(&device.id), "{method} {path}: {invites}");
        }
    }
}

/// PM-11: the invites a device made before it was taken out let no one in, whoever took it
/// out. The others' do.
#[test]
fn a_removed_devices_invites_let_no_one_in() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let vault = "ab".repeat(16);
    let join = |invite: &str| {
        let id = DeviceId::generate().unwrap();
        ServerTarget::join(&running.url, &vault, id, "Test device", invite).map(|to| (to, id))
    };
    let (pc, _) = join(&admin_invite(data.path())).unwrap();
    let (phone, phone_id) = join(&pc.invite().unwrap().invite).unwrap();
    let before: Vec<String> = (0..2).map(|_| phone.invite().unwrap().invite).collect();
    pc.remove(phone_id).unwrap();
    let refused = format!("{:#}", join(&before[0]).unwrap_err());
    assert!(refused.contains("invite is wrong"), "{refused}");

    let (tablet, tablet_id) = join(&pc.invite().unwrap().invite).unwrap();
    let made = tablet.invite().unwrap().invite;
    let admin = vault_server::Store::open(data.path()).unwrap();
    assert!(admin.remove(&vault, &tablet_id.to_hex()).unwrap());
    for invite in [&made, &before[1]] {
        let refused = format!("{:#}", join(invite).unwrap_err());
        assert!(refused.contains("invite is wrong"), "{refused}");
    }
    assert_eq!(pc.enrolled().unwrap().len(), 1);
    let for_this_vault = vault_server::admin_invite(data.path(), 1, Some(&vault)).unwrap();
    join(&for_this_vault.0).unwrap();
    join(&pc.invite().unwrap().invite).unwrap();
    assert_eq!(pc.enrolled().unwrap().len(), 3);
}

/// Whoever holds no key of a vault gets one answer for a device id that is enrolled there and
/// one that isn't.
#[test]
fn a_stranger_doesnt_learn_which_devices_are_enrolled() {
    let data = tempfile::tempdir().unwrap();
    let running = Running::start(data.path());
    let vault = "ab".repeat(16);
    let store = vault_server::Store::open(data.path()).unwrap();
    let enrolled = TestDevice::new();
    store.enroll(&vault, enrolled.enrolled()).unwrap();
    let requests: [(&str, &str, &[u8], bool); 5] = [
        ("GET", "/devices", b"", true),
        ("GET", "/enrolled", b"", true),
        ("GET", "/changes?after=0&wait=0", b"", true),
        ("PUT", "/devices/OWN", b"a copy", true),
        // Like an older app.
        ("PUT", "/devices/OWN", b"a copy", false),
    ];
    for (method, route, body, digest) in requests {
        let answers = [enrolled.id.clone(), "cd".repeat(16)].map(|id| {
            let stranger = TestDevice {
                id,
                key: DeviceKey::generate(),
            };
            let path = format!("/v1/vaults/{vault}{route}").replace("OWN", &stranger.id);
            let signed = stranger.sign(method, &path, body);
            answer(&running.url, method, &path, &signed, body, digest)
        });
        assert_eq!(answers[0], answers[1], "{method} {route}");
        assert_eq!(answers[0].0, 401, "{method} {route}");
    }
    // A device whose stored key can't be read at all is let in by no signature, and answered
    // the same.
    let unreadable = TestDevice::new();
    store
        .enroll(
            &vault,
            vault_server::store::Device {
                key: "not a key".into(),
                ..unreadable.enrolled()
            },
        )
        .unwrap();
    let path = format!("/v1/vaults/{vault}/devices");
    let (status, text) = answer(
        &running.url,
        "GET",
        &path,
        &unreadable.sign("GET", &path, b""),
        b"",
        true,
    );
    assert_eq!(status, 401, "{text}");
    assert!(text.contains("unknown_device"), "{text}");
    // What a device whose key isn't the one enrolled is told: to join again.
    let other_key = ServerTarget::new(
        &running.url,
        &vault,
        DeviceId::from_hex(&enrolled.id).unwrap(),
        DeviceKey::generate(),
    )
    .unwrap();
    let told = format!("{:#}", other_key.list().unwrap_err());
    assert!(
        told.contains("its key isn't the one it joined with): join it again"),
        "{told}"
    );
}
