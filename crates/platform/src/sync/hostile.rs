//! The HTTP targets against a hostile server written here (THREAT_MODEL A2, A3; SYNC.md
//! §5.3): one that lies in its listing, answers what doesn't fit, hands out an invite that
//! isn't one, sends the device elsewhere, never finishes answering, sends more than any copy
//! can be, or fails half-way through a write. Each ends in an error that says what happened:
//! never a hang, a panic, or a request (or a WebDAV password) sent where it shouldn't go. What
//! a round makes of the copies such a server hands over is in `tests/hostile_sync.rs`.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use vault_core::sync::DeviceId;
use vault_sync_wire::{self as wire, DeviceKey};

use super::{
    MAX_COPIES_READ, Tags, Target, fetch, http, server::ServerTarget, webdav::WebDavTarget,
};

const VAULT: &str = "0123456789abcdef0123456789abcdef";
const DAV_USER: &str = "dav-tester";
const DAV_PASSWORD: &str = "dav test password";

fn device(n: u8) -> DeviceId {
    DeviceId::from_bytes([n; 16])
}

/// One request as the hostile server read it.
#[derive(Debug, Clone)]
struct Asked {
    method: String,
    path: String,
    /// The head, lowercased.
    head: String,
}

/// How the hostile server answers a request.
#[derive(Clone)]
enum Answer {
    /// A whole answer, then the connection is closed.
    Full {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    },
    /// Nothing at all: the connection stays open and silent.
    Silent,
    /// The head of a long answer, then one byte of it every 100 ms, without end.
    Trickle,
    /// A body without end, as fast as it is read.
    Endless,
    /// The connection closed without a word.
    Hangup,
}

fn full(status: u16, body: impl Into<Vec<u8>>) -> Answer {
    Answer::Full {
        status,
        headers: Vec::new(),
        body: body.into(),
    }
}

fn json(body: &str) -> Answer {
    full(200, body.as_bytes())
}

type Script = dyn Fn(&Asked) -> Answer + Send + Sync;

/// A server on a free port of this computer that answers each request as its script says, and
/// keeps what it was asked.
struct Hostile {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<Asked>>>,
    stop: Arc<AtomicBool>,
    accepting: Option<thread::JoinHandle<()>>,
}

impl Hostile {
    fn start(script: impl Fn(&Asked) -> Answer + Send + Sync + 'static) -> Self {
        let script: Arc<Script> = Arc::new(script);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accepting = {
            let (asked, stop) = (asked.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let (script, asked, stop) =
                                (script.clone(), asked.clone(), stop.clone());
                            // Each connection on its own: a silent one holds up no other.
                            thread::spawn(move || answer(stream, &*script, &asked, &stop));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            address,
            asked,
            stop,
            accepting: Some(accepting),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

impl Drop for Hostile {
    fn drop(&mut self) {
        // The connections still open see it too and end.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
    }
}

fn answer(mut stream: TcpStream, script: &Script, asked: &Mutex<Vec<Asked>>, stop: &AtomicBool) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let Some((request, _body)) = read_request(&mut stream, stop) else {
        return;
    };
    asked.lock().unwrap().push(request.clone());
    match script(&request) {
        Answer::Full {
            status,
            headers,
            body,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} Hostile\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.shutdown(std::net::Shutdown::Write);
            // Closing with unread bytes can reset the connection on Windows.
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
        }
        Answer::Silent => {
            let mut piece = [0u8; 1024];
            while !stop.load(Ordering::SeqCst) {
                match stream.read(&mut piece) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(err) if timed_out(&err) => {}
                    Err(_) => return,
                }
            }
        }
        Answer::Trickle => {
            let head = "HTTP/1.1 200 OK\r\ncontent-length: 100000000\r\n\r\n";
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            while !stop.load(Ordering::SeqCst) {
                if stream.write_all(b"x").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        Answer::Endless => {
            let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            let chunk = vec![b'x'; 1 << 20];
            while !stop.load(Ordering::SeqCst) {
                let sent = stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .and_then(|()| stream.write_all(&chunk))
                    .and_then(|()| stream.write_all(b"\r\n"));
                if sent.is_err() {
                    return;
                }
            }
        }
        Answer::Hangup => {}
    }
}

fn timed_out(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Reads one request: its head, then as much body as it says it has (up to 80 MiB).
fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> Option<(Asked, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut piece = [0u8; 64 * 1024];
    let until = Instant::now() + Duration::from_secs(20);
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if stop.load(Ordering::SeqCst) || Instant::now() > until {
            return None;
        }
        match stream.read(&mut piece) {
            Ok(0) => return None,
            Ok(read) => bytes.extend_from_slice(&piece[..read]),
            Err(err) if timed_out(&err) => {}
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
    let mut first = head.lines().next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_uppercase();
    let path = first.next().unwrap_or_default().to_owned();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
        .min(80 << 20);
    let mut body = bytes[end..].to_vec();
    while body.len() < length && !stop.load(Ordering::SeqCst) && Instant::now() < until {
        match stream.read(&mut piece) {
            Ok(0) => break,
            Ok(read) => body.extend_from_slice(&piece[..read]),
            Err(err) if timed_out(&err) => {}
            Err(_) => break,
        }
    }
    Some((Asked { method, path, head }, body))
}

fn server_at(url: &str) -> ServerTarget {
    ServerTarget::new(url, VAULT, device(1), DeviceKey::from_seed(&[7; 32])).unwrap()
}

fn webdav_at(url: &str) -> WebDavTarget {
    WebDavTarget::new(&format!("{url}/dav"), VAULT, DAV_USER, DAV_PASSWORD).unwrap()
}

fn text(err: anyhow::Error) -> String {
    format!("{err:#}")
}

fn listed(device: &str) -> serde_json::Value {
    serde_json::json!({ "device": device, "tag": "t", "size": 1 })
}

/// A listing that names this device, ids that aren't ids, one device twice and far more
/// devices than a vault has: no copy is asked for but real ids, never this device's own, never
/// more than one round allows, and each one that isn't there is said.
#[test]
fn a_listing_that_lies_reads_only_real_copies_and_no_more_than_a_round_allows() {
    let own = device(1);
    let mut copies = vec![
        listed(&own.to_hex()),
        listed("../../../../etc/passwd"),
        listed(&format!("{}/..", "ab".repeat(15))),
        listed("abc"),
        listed(""),
        listed(&format!("{:032x}", 1000)),
    ];
    copies.extend((0..200u32).map(|n| listed(&format!("{:032x}", 1000 + n))));
    let listing = serde_json::json!({ "copies": copies, "seq": 1 }).to_string();
    let hostile = Hostile::start(move |asked| {
        if asked.path.ends_with("/devices") {
            json(&listing)
        } else {
            full(404, "")
        }
    });
    let target = server_at(&hostile.url());
    let fetched = fetch(&target, own, &Tags::new()).unwrap();
    assert!(fetched.copies.is_empty());
    assert_eq!(fetched.unreadable.len(), MAX_COPIES_READ + 1);
    assert!(
        fetched.unreadable[..MAX_COPIES_READ]
            .iter()
            .all(|(_, why)| why.contains("not on the server")),
        "{:?}",
        fetched.unreadable
    );
    let prefix = format!("/v1/vaults/{VAULT}/devices/");
    let gets: Vec<String> = hostile
        .asked()
        .into_iter()
        .filter(|asked| asked.method == "GET" && asked.path.starts_with(&prefix))
        .map(|asked| asked.path)
        .collect();
    assert_eq!(gets.len(), MAX_COPIES_READ, "{gets:?}");
    for path in &gets {
        let id = &path[prefix.len()..];
        assert!(wire::is_id(id) && id != own.to_hex(), "{path}");
    }
}

/// Answers whose status or body doesn't fit what was asked: an error that says so, quickly,
/// whatever the size of the body that came with it.
#[test]
fn answers_that_dont_fit_are_errors_that_say_so() {
    let padded = format!("{}{{}}", " ".repeat(2 << 20));
    let cases: Vec<(Answer, &str)> = vec![
        (json("not json"), "can't be read"),
        (json(r#"{"copies":"none","seq":1}"#), "can't be read"),
        (json(r#"{"copies":[],"seq":1} and more"#), "can't be read"),
        (
            json(r#"{"copies":[{"device":1}],"seq":1}"#),
            "can't be read",
        ),
        (json(&padded), "reading the answer"),
        (full(200, ""), "can't be read"),
        (full(204, ""), "can't be read"),
        (full(304, ""), "another address"),
        (full(500, vec![b'x'; 10 << 20]), "answered 500"),
        (full(401, r#"{"error":"clock"}"#), "clock"),
        (
            full(401, vec![b'{'; 1 << 20]),
            "refused this device's signature",
        ),
        (full(418, r#"{"error":"invite"}"#), "answered 418"),
        (Answer::Hangup, "can't be reached"),
    ];
    for (answer, expected) in cases {
        let hostile = Hostile::start(move |_| answer.clone());
        let started = Instant::now();
        let err = text(server_at(&hostile.url()).list().unwrap_err());
        assert!(err.contains(expected), "{expected}: {err}");
        assert!(started.elapsed() < Duration::from_secs(20), "{expected}");
    }
}

/// A copy a server hands over is the server's bytes, refused or not by the merge (see
/// `tests/hostile_sync.rs`); here, only that anything bigger than a copy can be is cut off,
/// not read to its end.
#[test]
fn an_answer_bigger_than_any_copy_is_cut_off() {
    let hostile = Hostile::start(|_| Answer::Endless);
    let started = Instant::now();
    let err = text(server_at(&hostile.url()).get(device(2)).unwrap_err());
    assert!(
        err.contains("reading the answer") || err.contains("too big"),
        "{err}"
    );
    let dav = text(webdav_at(&hostile.url()).get(device(2)).unwrap_err());
    assert!(
        dav.contains("reading the answer") || dav.contains("too big"),
        "{dav}"
    );
    let listing = text(webdav_at(&hostile.url()).list().unwrap_err());
    assert!(
        listing.contains("reading the answer") || listing.contains("too big"),
        "{listing}"
    );
    assert!(started.elapsed() < Duration::from_secs(60));
}

/// A redirect is never followed, whatever its status: the other address hears nothing, so a
/// WebDAV password never goes there either.
#[test]
fn a_redirect_is_never_followed_and_the_other_address_hears_nothing() {
    let elsewhere = Hostile::start(|_| json(r#"{"copies":[],"seq":1}"#));
    for status in [301, 302, 303, 307, 308] {
        let location = format!("{}/v1/vaults/{VAULT}/devices", elsewhere.url());
        let hostile = Hostile::start(move |_| Answer::Full {
            status,
            headers: vec![("location", location.clone())],
            body: Vec::new(),
        });
        let server = server_at(&hostile.url());
        for err in [
            server.list().unwrap_err(),
            server.get(device(2)).unwrap_err(),
            server.put(device(1), b"sealed copy").unwrap_err(),
            server.invite().unwrap_err(),
        ] {
            assert!(text(err).contains("another address"), "{status}");
        }
        assert!(
            ServerTarget::join(&hostile.url(), VAULT, device(3), "Phone", &"ab".repeat(16))
                .is_err()
        );
        let dav = webdav_at(&hostile.url());
        for err in [
            dav.list().unwrap_err(),
            dav.get(device(2)).unwrap_err(),
            dav.put(device(1), b"sealed copy").unwrap_err(),
        ] {
            assert!(text(err).contains("another address"), "{status}");
        }
        assert!(!hostile.asked().is_empty());
    }
    assert!(elsewhere.asked().is_empty(), "{:?}", elsewhere.asked());
}

/// An address that isn't allowed (plain http:// to anything but this computer, or for the vault
/// server a Tailscale address) is refused before anything is sent, also when it comes inside an
/// invite line.
#[test]
fn plain_http_elsewhere_is_refused_before_anything_is_sent() {
    let hostile = Hostile::start(|_| full(200, ""));
    let port = hostile.address.port();
    for address in [
        format!("http://[::ffff:127.0.0.1]:{port}"),
        format!("http://localhost.:{port}"),
        format!("http://127.0.0.1.example.com:{port}"),
        "http://192.168.1.10:8750".to_owned(),
        "http://example.com".to_owned(),
    ] {
        assert!(
            ServerTarget::new(&address, VAULT, device(1), DeviceKey::generate()).is_err(),
            "{address}"
        );
        let line = wire::InviteLink {
            server: address.clone(),
            vault: VAULT.to_owned(),
            backup: None,
            invite: "ab".repeat(16),
        }
        .to_text();
        let link = wire::InviteLink::parse(&line).unwrap();
        assert!(
            ServerTarget::join(&link.server, &link.vault, device(1), "Phone", &link.invite)
                .is_err(),
            "{address}"
        );
        assert!(
            WebDavTarget::new(&format!("{address}/dav"), VAULT, DAV_USER, DAV_PASSWORD).is_err(),
            "{address}"
        );
    }
    // WebDAV sends its password: plain http:// not even to a Tailscale address.
    assert!(
        WebDavTarget::new(
            &format!("http://100.101.102.103:{port}/dav"),
            VAULT,
            DAV_USER,
            DAV_PASSWORD
        )
        .is_err()
    );
    assert!(hostile.asked().is_empty(), "{:?}", hostile.asked());
}

/// A server that never answers, or answers one byte at a time without end: every call gives up
/// once the request's time is over (here shortened to two seconds).
#[test]
fn a_server_that_never_finishes_answering_is_given_up_on() {
    http::TEST_TIMEOUT.with(|timeout| timeout.set(Some(Duration::from_secs(2))));
    for silent in [true, false] {
        let answer = if silent {
            Answer::Silent
        } else {
            Answer::Trickle
        };
        let hostile = Hostile::start(move |_| answer.clone());
        let server = server_at(&hostile.url());
        let dav = webdav_at(&hostile.url());
        type Call<'a> = (&'static str, Box<dyn Fn() -> bool + 'a>);
        let mut calls: Vec<Call<'_>> = vec![
            ("list", Box::new(|| server.list().is_err())),
            ("get", Box::new(|| server.get(device(2)).is_err())),
            (
                "wait",
                Box::new(|| matches!(server.wait(1, 60), Some(Err(_)))),
            ),
            ("dav list", Box::new(|| dav.list().is_err())),
            ("dav get", Box::new(|| dav.get(device(2)).is_err())),
        ];
        // A trickle starts with "200 OK", all a write needs to hear (its body isn't read).
        if silent {
            calls.push(("put", Box::new(|| server.put(device(1), b"copy").is_err())));
            calls.push(("dav put", Box::new(|| dav.put(device(1), b"copy").is_err())));
        }
        for (name, call) in calls {
            let started = Instant::now();
            assert!(call(), "{name}");
            let took = started.elapsed();
            assert!(took < Duration::from_secs(10), "{name} took {took:?}");
        }
    }
    http::TEST_TIMEOUT.with(|timeout| timeout.set(None));
}

/// The time every request has, as the apps make them: all of it, and the answer's body too.
#[test]
fn every_request_has_an_end_and_follows_no_redirect() {
    for agent in [
        http::agent_for("https://vault.example.com").unwrap(),
        http::agent_for("http://127.0.0.1:8750").unwrap(),
        http::agent_for("http://100.101.102.103:8750").unwrap(),
        http::webdav_agent("https://dav.example.com/dav"),
        http::webdav_agent("http://127.0.0.1:8080/dav"),
    ] {
        let config = agent.config();
        assert_eq!(config.timeouts().global, Some(http::TIMEOUT));
        assert_eq!(config.timeouts().connect, Some(http::CONNECT_TIMEOUT));
        assert_eq!(config.max_redirects(), 0);
    }
}

/// An invite is shown as a QR code and a line another device types: what a server hands back
/// as one must be one (32 lowercase hex), so the line carries nothing the server chose.
#[test]
fn an_invite_that_isnt_one_is_refused() {
    for invite in [
        "x&server=https://elsewhere.example".to_owned(),
        String::new(),
        "AB".repeat(16),
        "ab".repeat(17),
        format!("{}\n", "ab".repeat(16)),
    ] {
        let body = serde_json::json!({ "invite": invite, "expires_at": 0 }).to_string();
        let hostile = Hostile::start(move |_| json(&body));
        let err = text(server_at(&hostile.url()).invite().unwrap_err());
        assert!(err.contains("isn't an invite"), "{invite:?}: {err}");
    }
    let good = serde_json::json!({ "invite": "ab".repeat(16), "expires_at": 0 }).to_string();
    let hostile = Hostile::start(move |_| json(&good));
    assert_eq!(
        server_at(&hostile.url()).invite().unwrap().invite,
        "ab".repeat(16)
    );
}

/// A long-poll answered at once, again and again, with a counter that moves each time (or
/// doesn't): it is asked at most about once a second, so a server can't make this device
/// spin. Answers that aren't a counter are errors.
#[test]
fn a_long_poll_that_doesnt_wait_isnt_asked_again_at_once() {
    let counter = Arc::new(AtomicU64::new(1));
    let hostile = {
        let counter = counter.clone();
        Hostile::start(move |_| {
            let seq = counter.fetch_add(1, Ordering::SeqCst);
            json(&format!(r#"{{"seq":{seq}}}"#))
        })
    };
    let server = server_at(&hostile.url());
    let started = Instant::now();
    let (mut after, mut asked) = (0, 0);
    while started.elapsed() < Duration::from_secs(3) {
        after = server.wait(after, 60).unwrap().unwrap();
        asked += 1;
    }
    assert!(asked <= 5, "asked {asked} times in 3 seconds");
    for body in [
        "",
        "{}",
        r#"{"seq":-1}"#,
        r#"{"seq":"1"}"#,
        r#"{"seq":1.5}"#,
    ] {
        let body = body.to_owned();
        let hostile = Hostile::start(move |_| json(&body));
        assert!(matches!(
            server_at(&hostile.url()).wait(1, 60),
            Some(Err(_))
        ));
    }
}

/// A WebDAV server whose listing and files disagree: a listed copy that isn't there, one that
/// fails, one whose address tries to climb out of the folder or names another host (only its
/// name is taken, and it is read from the vault's own folder). Every request carries the
/// password to this server only, and only to the vault's folder.
#[test]
fn a_webdav_server_whose_listing_and_files_disagree() {
    let (missing, failing, climbing, foreign) = (device(2), device(3), device(4), device(5));
    let listing = format!(
        r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
<d:response><d:href>/dav/{VAULT}/devices/</d:href></d:response>
<d:response><d:href>/dav/{VAULT}/devices/{}.vault</d:href><d:propstat><d:prop><d:getetag>"1"</d:getetag></d:prop></d:propstat></d:response>
<d:response><d:href>/dav/{VAULT}/devices/{}.vault</d:href></d:response>
<d:response><d:href>/dav/{VAULT}/devices/../../../../elsewhere/{}.vault</d:href></d:response>
<d:response><d:href>https://elsewhere.example/{}.vault</d:href></d:response>
<d:response><d:href>/dav/{VAULT}/devices/{}.vault</d:href></d:response>
</d:multistatus>"#,
        missing.to_hex(),
        failing.to_hex(),
        climbing.to_hex(),
        foreign.to_hex(),
        device(1).to_hex(),
    );
    let devices = format!("/dav/{VAULT}/devices/");
    let hostile = {
        let devices = devices.clone();
        Hostile::start(move |asked| match asked.method.as_str() {
            "PROPFIND" => full(207, listing.as_bytes()),
            "GET" if asked.path == format!("{devices}{}.vault", missing.to_hex()) => full(404, ""),
            "GET" if asked.path == format!("{devices}{}.vault", failing.to_hex()) => full(500, ""),
            "GET" => full(200, format!("the server's bytes for {}", asked.path)),
            _ => full(405, ""),
        })
    };
    let dav = webdav_at(&hostile.url());
    let fetched = fetch(&dav, device(1), &Tags::new()).unwrap();
    let read: Vec<DeviceId> = fetched.copies.iter().map(|(d, _)| *d).collect();
    assert_eq!(read, [climbing, foreign]);
    let unreadable: Vec<(DeviceId, bool)> = fetched
        .unreadable
        .iter()
        .map(|(d, why)| (*d, why.contains("doesn't exist") || why.contains("500")))
        .collect();
    assert_eq!(unreadable, [(missing, true), (failing, true)]);
    for asked in hostile.asked() {
        assert!(asked.path.starts_with(&devices), "{asked:?}");
        assert!(asked.head.contains("authorization: basic "), "{asked:?}");
    }
}

/// Listings that aren't one (not XML, cut short, entities that would grow without end, more
/// than a listing can be) are an error or list nothing, quickly.
#[test]
fn a_webdav_listing_that_isnt_one_lists_nothing() {
    let mut laughs = String::from(r#"<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY l0 "lol">"#);
    for n in 1..10 {
        laughs.push_str(&format!(
            "<!ENTITY l{n} \"{}\">",
            format!("&l{};", n - 1).repeat(10)
        ));
    }
    laughs.push_str(
        r#"]><d:multistatus xmlns:d="DAV:"><d:response><d:href>&l9;.vault</d:href></d:response></d:multistatus>"#,
    );
    let cases: Vec<Answer> = vec![
        full(207, "<not xml"),
        full(207, laughs.as_bytes()),
        full(
            207,
            r#"<d:multistatus xmlns:d="DAV:"><d:response><d:href>/x/"#,
        ),
        full(207, vec![b' '; 5 << 20]),
        full(200, ""),
        full(207, "\u{feff}\0\0\0"),
    ];
    for answer in cases {
        let hostile = Hostile::start(move |_| answer.clone());
        let started = Instant::now();
        if let Ok(listed) = webdav_at(&hostile.url()).list() {
            assert!(listed.is_empty(), "{listed:?}");
        }
        assert!(started.elapsed() < Duration::from_secs(20));
    }
}

/// A WebDAV write that fails half-way: the copy is written beside its place and moved over it,
/// so a failed move leaves the old copy where it was (and the temporary one is deleted), and
/// the error says what the server answered. A server that drops the connection while the copy
/// is sent gives an error too.
#[test]
fn a_webdav_write_that_fails_half_way_leaves_the_old_copy() {
    let temp = format!("/dav/{VAULT}/devices/.{}.tmp", device(1).to_hex());
    let script = |moved: u16| {
        move |asked: &Asked| match asked.method.as_str() {
            "MKCOL" => full(405, ""),
            "PUT" => full(201, ""),
            "MOVE" => full(moved, ""),
            "DELETE" => full(204, ""),
            _ => full(500, ""),
        }
    };
    let hostile = Hostile::start(script(500));
    let err = text(
        webdav_at(&hostile.url())
            .put(device(1), b"sealed copy")
            .unwrap_err(),
    );
    assert!(err.contains("answered 500"), "{err}");
    let asked: Vec<(String, String)> = hostile
        .asked()
        .into_iter()
        .map(|a| (a.method, a.path))
        .collect();
    let vault = format!("/dav/{VAULT}/");
    assert_eq!(
        asked,
        [
            ("MKCOL".to_owned(), vault.clone()),
            ("MKCOL".to_owned(), format!("{vault}devices/")),
            ("PUT".to_owned(), temp.clone()),
            ("MOVE".to_owned(), temp.clone()),
            ("DELETE".to_owned(), temp.clone()),
        ],
        "never written over its place"
    );
    // No room for it there (written in place, the server has no MOVE): an error that says so.
    let hostile = Hostile::start(move |asked: &Asked| match asked.method.as_str() {
        "MKCOL" => full(405, ""),
        "PUT" if asked.path.ends_with(".tmp") => full(201, ""),
        "PUT" => full(507, ""),
        "MOVE" => full(501, ""),
        _ => full(204, ""),
    });
    let err = text(
        webdav_at(&hostile.url())
            .put(device(1), b"sealed copy")
            .unwrap_err(),
    );
    assert!(err.contains("no room"), "{err}");
    // The connection dropped while the copy is sent.
    let hostile = Hostile::start(|asked: &Asked| match asked.method.as_str() {
        "MKCOL" => full(405, ""),
        _ => Answer::Hangup,
    });
    assert!(
        webdav_at(&hostile.url())
            .put(device(1), &vec![7u8; 1 << 20])
            .is_err()
    );
    let hostile = Hostile::start(|_| Answer::Hangup);
    assert!(
        server_at(&hostile.url())
            .put(device(1), &vec![7u8; 1 << 20])
            .is_err()
    );
}
