//! The WebDAV target against a small WebDAV server run by the test: the calls a real host
//! (Nextcloud, a NAS) answers, Basic authentication, and two devices syncing through it.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use vault_core::sync::DeviceId;
use vault_platform::sync::{self, Tags, Target, WebDavTarget};

const USER: &str = "dav-tester";
const PASSWORD: &str = "dav test password";

/// Paths (without a trailing `/`) to file contents; a `None` is a collection.
type Files = Arc<Mutex<BTreeMap<String, Option<Vec<u8>>>>>;

async fn dav(files: Files, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    use base64::Engine as _;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{USER}:{PASSWORD}"))
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let path = uri.path().trim_end_matches('/').to_owned();
    let parent = |p: &str| {
        p.rsplit_once('/')
            .map(|(a, _)| a.to_owned())
            .unwrap_or_default()
    };
    let mut files = files.lock().unwrap();
    let has_parent = |files: &BTreeMap<String, Option<Vec<u8>>>, p: &str| {
        let parent = parent(p);
        parent.is_empty() || matches!(files.get(&parent), Some(None))
    };
    match method.as_str() {
        "MKCOL" => {
            if files.contains_key(&path) {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            if !has_parent(&files, &path) {
                return StatusCode::CONFLICT.into_response();
            }
            files.insert(path, None);
            StatusCode::CREATED.into_response()
        }
        "PUT" => {
            if !has_parent(&files, &path) {
                return StatusCode::CONFLICT.into_response();
            }
            files.insert(path, Some(body.to_vec()));
            StatusCode::CREATED.into_response()
        }
        "GET" => match files.get(&path) {
            Some(Some(bytes)) => bytes.clone().into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        },
        "DELETE" => match files.remove(&path) {
            Some(_) => StatusCode::NO_CONTENT.into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        "MOVE" => {
            let Some(destination) = headers
                .get("destination")
                .and_then(|v| v.to_str().ok())
                .and_then(|d| d.parse::<Uri>().ok())
                .map(|d| d.path().trim_end_matches('/').to_owned())
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            match files.remove(&path) {
                Some(content) => {
                    files.insert(destination, content);
                    StatusCode::CREATED.into_response()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
        "PROPFIND" => {
            if !matches!(files.get(&path), Some(None)) {
                return StatusCode::NOT_FOUND.into_response();
            }
            let mut xml = String::from(r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">"#);
            xml.push_str(&format!(
                "<d:response><d:href>{path}/</d:href></d:response>"
            ));
            for (name, content) in files.iter() {
                if parent(name) == path
                    && let Some(bytes) = content
                {
                    let tag = vault_sync_wire::tag(bytes);
                    xml.push_str(&format!(
                        "<d:response><d:href>{name}</d:href><d:propstat><d:prop>\
                         <d:getetag>&quot;{tag}&quot;</d:getetag></d:prop></d:propstat></d:response>"
                    ));
                }
            }
            xml.push_str("</d:multistatus>");
            (StatusCode::MULTI_STATUS, xml).into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// The WebDAV server on a free local port, with `/dav` as the person's folder.
fn start() -> (String, tokio::runtime::Runtime) {
    let files: Files = Arc::new(Mutex::new(BTreeMap::from([("/dav".to_owned(), None)])));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(move |method, uri, headers, body| dav(files.clone(), method, uri, headers, body));
    runtime.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}/dav"), runtime)
}

fn device(n: u8) -> DeviceId {
    DeviceId::from_bytes([n; 16])
}

#[test]
fn copies_go_round_through_webdav() {
    let (url, _runtime) = start();
    let vault = "ab".repeat(16);
    let wrong = WebDavTarget::new(&url, &vault, USER, "not the password").unwrap();
    let refused = format!("{:#}", wrong.list().unwrap_err());
    assert!(refused.contains("user name or password"), "{refused}");

    let one = WebDavTarget::new(&url, &vault, USER, PASSWORD).unwrap();
    assert!(one.list().unwrap().is_empty(), "nothing there yet");
    one.put(device(1), b"first device, first copy").unwrap();
    one.put(device(1), b"first device, second copy").unwrap();
    let two = WebDavTarget::new(&url, &vault, USER, PASSWORD).unwrap();
    two.put(device(2), b"second device").unwrap();

    let listed = one.list().unwrap();
    assert_eq!(
        listed.iter().map(|l| l.device).collect::<Vec<_>>(),
        [device(1), device(2)],
        "one copy per device, no temporary file"
    );
    assert!(listed.iter().all(|l| l.tag.is_some()));
    let fetched = sync::fetch(&one, device(1), &Tags::new()).unwrap();
    assert_eq!(fetched.copies, [(device(2), b"second device".to_vec())]);
    assert_eq!(two.get(device(1)).unwrap(), b"first device, second copy");
    // Unchanged: not read again.
    let again = sync::fetch(&one, device(1), &fetched.tags).unwrap();
    assert_eq!((again.copies.len(), again.unchanged), (0, 1));

    one.remove(device(2)).unwrap();
    one.remove(device(2)).unwrap();
    assert_eq!(one.list().unwrap().len(), 1);
}
