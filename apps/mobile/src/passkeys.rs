//! Passkeys for the browsers and apps on the phone, through Android's Credential Manager
//! (Android 14 on). The Java side (`apps/mobile-android/java/…/VaultCredentialService.java`,
//! `PasskeyActivity.java`) says who asks ([`Asker`]) and hands over the request as the site
//! wrote it (WebAuthn's options, as JSON); this decides which passkeys may answer, and writes
//! the answer a browser would hand the page (`PublicKeyCredential.toJSON()`).
//!
//! - Who asks ([`Caller`]): a browser known by its certificate (the list autofill trusts),
//!   speaking for a web page. Android tells the page's origin only to browsers this app lists
//!   ([`privileged_browsers`], `CallingAppInfo.getOrigin`), and the origin then rules which
//!   site a passkey may be made or used for, as on the desktop
//!   (`vault_browser::origin::passkey_site`). Any other app speaks only for itself: its answer
//!   names the app's own origin (`android:apk-key-hash:` and its certificate's SHA-256), which
//!   the site checks against the apps it trusts, so an app that asks for another site's
//!   passkey gets an answer that site refuses.
//! - Only logins offer passkeys, and none behind the item lock.
//! - Nothing is signed or made before the person confirms with a fingerprint or the phone's
//!   lock (the Java side asks first).
//! - The client data is written here from the caller's origin, or, when a browser sends its
//!   hash (it writes the client data itself), that hash is signed.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vault_browser::origin::{Origin, item_matches, passkey_site, wildcard_base};
use vault_core::passkey::attestation_object;
use vault_core::{ItemData, ItemId, ItemKind, Passkey, Vault};
use zeroize::Zeroizing;

use crate::autofill;
use crate::platform::files;

/// ES256 (COSE algorithm -7): the only kind of passkey made here.
const ES256: i64 = -7;
/// At most this many credential ids are read from a site's list.
const MAX_LISTED: usize = 64;
/// The longest challenge a site may send (WebAuthn asks for at least 16 bytes).
const MAX_CHALLENGE: usize = 1024;
/// The longest request read (a site's options are a few kilobytes).
const MAX_REQUEST: usize = 64 * 1024;

/// What Android says of who asks for a passkey.
#[derive(Clone, Debug, Default)]
pub struct Asker {
    /// The calling app's package (the system's word).
    pub app: String,
    /// SHA-256 of the certificate it is signed with first, then those it was rotated from,
    /// as the package manager proved them. Empty when it has several signers.
    pub signers: Vec<[u8; 32]>,
    /// The web page's origin, which Android gives only to a browser this app lists
    /// ([`privileged_browsers`]); `None` for an app speaking for itself.
    pub origin: Option<String>,
}

/// Who would receive a passkey's answer. Made only by [`Caller::of`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A web page, by its origin, in a browser known by its certificate.
    Page(Origin),
    /// An app, by its package and the SHA-256 of its signing certificate.
    App { package: String, signer: [u8; 32] },
}

impl Caller {
    /// Who `asker` stands for; `None` when no passkey answers there: a page from a browser
    /// this app doesn't know by its certificate, a page that isn't https, or a known browser
    /// asking without a page (it would be every site).
    pub fn of(asker: &Asker) -> Option<Self> {
        let app = asker.app.trim();
        if app.is_empty() {
            return None;
        }
        match &asker.origin {
            Some(origin) => {
                if !autofill::is_known_browser(app, &asker.signers) {
                    return None;
                }
                Origin::of_page(origin).ok().map(Self::Page)
            }
            None if autofill::is_browser_package(app) => None,
            None => Some(Self::App {
                package: app.to_owned(),
                signer: *asker.signers.first()?,
            }),
        }
    }

    /// The origin the answer names: the page's, or the app's own.
    pub fn origin(&self) -> String {
        match self {
            Self::Page(origin) => origin.as_str().to_owned(),
            Self::App { signer, .. } => {
                format!("android:apk-key-hash:{}", URL_SAFE_NO_PAD.encode(signer))
            }
        }
    }

    /// The site (relying party id) a passkey may be made or used for, from the one the
    /// request names ("" = the page's host). A page may speak for its host or a domain it is
    /// under; an app names any site but its answers carry its own origin. Never a public
    /// suffix or an IP address.
    pub fn site(&self, rp_id: &str) -> Option<String> {
        match self {
            Self::Page(origin) => passkey_site(rp_id, origin),
            // The rule a saved `*.example.com` follows: a name with a dot, not a public suffix.
            Self::App { .. } => wildcard_base(&format!("*.{}", rp_id.trim())),
        }
    }

    /// For the prompt: the page's host, or the app's package.
    pub fn name(&self) -> &str {
        match self {
            Self::Page(origin) => origin.host(),
            Self::App { package, .. } => package,
        }
    }
}

/// The browsers Android may tell a page's origin to, in the layout `CallingAppInfo.getOrigin`
/// reads (Google's list of privileged apps): the ones autofill knows by their release
/// certificates.
pub fn privileged_browsers() -> String {
    let apps: Vec<Value> = autofill::browser_certificates()
        .map(|(package, certificates)| {
            let signatures: Vec<Value> = certificates
                .iter()
                .map(|hex| {
                    json!({ "build": "release", "cert_fingerprint_sha256": colon_pairs(hex) })
                })
                .collect();
            json!({ "type": "android", "info": { "package_name": package, "signatures": signatures } })
        })
        .collect();
    json!({ "apps": apps }).to_string()
}

/// `F0FD6C…` as `F0:FD:6C:…`.
fn colon_pairs(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

/// One passkey offered: whose it is, never its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The login it is in (hex id).
    pub item: String,
    /// Its credential id, base64url.
    pub credential: String,
    /// The login's title.
    pub title: String,
    /// The account's name at the site.
    pub user_name: String,
    /// The name the site shows for the account.
    pub display_name: String,
}

/// Why a passkey wasn't made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request couldn't be read, or names nothing usable.
    BadRequest,
    /// The caller may not make passkeys for that site.
    WrongSite,
    /// One of the passkeys the site listed as made already is in the vault.
    Exists,
    /// The site accepts none of the kinds of passkey made here (ES256).
    Unsupported,
    /// The vault couldn't keep it.
    NotKept,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetRequest {
    challenge: String,
    #[serde(default)]
    rp_id: String,
    #[serde(default)]
    allow_credentials: Vec<Descriptor>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRequest {
    challenge: String,
    rp: Party,
    user: User,
    #[serde(default)]
    pub_key_cred_params: Vec<Algorithm>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    id: String,
}

#[derive(Deserialize)]
struct Party {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    display_name: String,
}

#[derive(Deserialize)]
struct Algorithm {
    #[serde(default)]
    alg: i64,
}

fn read<T: for<'de> Deserialize<'de>>(request: &str) -> Option<T> {
    if request.len() > MAX_REQUEST {
        return None;
    }
    serde_json::from_str(request).ok()
}

/// Bytes from base64url, with or without padding.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

fn base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The credential ids a site listed, decoded (at most [`MAX_LISTED`]).
fn listed(descriptors: &[Descriptor]) -> Vec<Vec<u8>> {
    descriptors
        .iter()
        .take(MAX_LISTED)
        .filter_map(|d| unbase64(&d.id))
        .collect()
}

/// Whether `item` may offer passkeys: a login, not behind the item lock.
fn usable(vault: &Vault, item: &ItemData) -> bool {
    item.kind == ItemKind::Login && item.is_active() && !autofill::behind_lock(vault, item)
}

/// The passkeys of `vault` that may answer `request` (a site's request options, JSON) from
/// `caller`, by account name. None behind the item lock.
pub fn offers(vault: &Vault, caller: &Caller, request: &str) -> Vec<Offer> {
    let Some(request) = read::<GetRequest>(request) else {
        return Vec::new();
    };
    let Some(site) = caller.site(&request.rp_id) else {
        return Vec::new();
    };
    let allow = listed(&request.allow_credentials);
    let mut found = Vec::new();
    for id in vault.item_ids() {
        let Ok(item) = vault.get_item(&id) else {
            continue;
        };
        if !usable(vault, &item) {
            continue;
        }
        for passkey in item
            .passkeys
            .iter()
            .filter(|p| p.rp_id == site && (allow.is_empty() || allow.contains(&p.credential_id)))
        {
            found.push(Offer {
                item: id.to_hex(),
                credential: base64(&passkey.credential_id),
                title: item.title.clone(),
                user_name: passkey.user_name.clone(),
                display_name: passkey.display_name.clone(),
            });
        }
    }
    found.sort_by_key(|o| (o.user_name.to_lowercase(), o.title.to_lowercase()));
    found
}

/// The client data a passkey signs (WebAuthn §5.8.1), in the order the specification
/// writes it.
#[derive(Serialize)]
struct ClientData<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
    /// For an app: its package, as Android's own passkeys write it.
    #[serde(rename = "androidPackageName", skip_serializing_if = "Option::is_none")]
    android_package: Option<&'a str>,
}

/// The client data for `caller` and its hash: the one a browser sent (it writes the client
/// data itself), or that of the client data written here. `None` for a challenge that isn't
/// base64url, is empty or too long, or a hash that isn't 32 bytes.
fn client_data(
    caller: &Caller,
    kind: &str,
    challenge: &str,
    sent_hash: Option<&[u8]>,
) -> Option<(Vec<u8>, [u8; 32])> {
    let challenge = unbase64(challenge).filter(|c| !c.is_empty() && c.len() <= MAX_CHALLENGE)?;
    let text = serde_json::to_vec(&ClientData {
        kind,
        challenge: base64(&challenge),
        origin: caller.origin(),
        cross_origin: false,
        android_package: match caller {
            Caller::App { package, .. } => Some(package),
            Caller::Page(_) => None,
        },
    })
    .ok()?;
    let hash = match sent_hash {
        Some(hash) => <[u8; 32]>::try_from(hash).ok()?,
        None => Sha256::digest(&text).into(),
    };
    Some((text, hash))
}

/// The answer of `passkey` to a sign-in, signed over the client data's hash.
fn assertion_of(
    passkey: &Passkey,
    caller: &Caller,
    request: &GetRequest,
    sent_hash: Option<&[u8]>,
) -> Option<Zeroizing<String>> {
    let (client, hash) = client_data(caller, "webauthn.get", &request.challenge, sent_hash)?;
    // Verified for this request: the activity asks for the fingerprint or the phone's lock
    // before any passkey answers.
    let data = passkey.authenticator_data(false, true).ok()?;
    let signature = passkey.sign(&data, &hash).ok()?;
    let id = base64(&passkey.credential_id);
    let answer = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": base64(&client),
            "authenticatorData": base64(&data),
            "signature": base64(&signature),
            "userHandle": base64(&passkey.user_handle),
        },
        "clientExtensionResults": {},
    });
    Some(Zeroizing::new(answer.to_string()))
}

/// Signs in with passkey `credential` (base64url) of login `item` (hex id): the answer to
/// `request`, or `None` when that passkey doesn't answer this caller and request (another
/// site, not in the site's list, behind the item lock, gone).
pub fn assertion(
    vault: &Vault,
    caller: &Caller,
    item: &str,
    credential: &str,
    request: &str,
    sent_hash: Option<&[u8]>,
) -> Option<Zeroizing<String>> {
    let request = read::<GetRequest>(request)?;
    let site = caller.site(&request.rp_id)?;
    let credential = unbase64(credential)?;
    let allow = listed(&request.allow_credentials);
    if !allow.is_empty() && !allow.contains(&credential) {
        return None;
    }
    let login = vault.get_item(&ItemId::from_hex(item)?).ok()?;
    if !usable(vault, &login) {
        return None;
    }
    let passkey = login
        .passkeys
        .iter()
        .find(|p| p.rp_id == site && p.credential_id == credential)?;
    assertion_of(passkey, caller, &request, sent_hash)
}

/// A passkey made: the answer for the site, and the login that keeps it.
#[derive(Debug)]
pub struct Made {
    /// The answer a browser hands the page (`PublicKeyCredential.toJSON()`).
    pub answer: String,
    /// The title of the login it went into.
    pub title: String,
}

/// Makes a passkey for `request` (a site's creation options, JSON) and keeps it in the login
/// for that site and account, a new login when there is none (or when that one is behind the
/// item lock). A passkey of the same site and account already there is replaced, as an
/// authenticator does. The vault is changed, not saved: the caller saves it.
pub fn create(
    vault: &mut Vault,
    caller: &Caller,
    request: &str,
    sent_hash: Option<&[u8]>,
) -> Result<Made, Refusal> {
    let request = read::<CreateRequest>(request).ok_or(Refusal::BadRequest)?;
    let site = caller.site(&request.rp.id).ok_or(Refusal::WrongSite)?;
    if !request.pub_key_cred_params.is_empty()
        && !request.pub_key_cred_params.iter().any(|p| p.alg == ES256)
    {
        return Err(Refusal::Unsupported);
    }
    let user_handle = unbase64(&request.user.id)
        .filter(|h| !h.is_empty() && h.len() <= Passkey::MAX_USER_HANDLE)
        .ok_or(Refusal::BadRequest)?;
    let user_name = request.user.name.trim();
    let display_name = request.user.display_name.trim();
    let (client, _) = client_data(caller, "webauthn.create", &request.challenge, sent_hash)
        .ok_or(Refusal::BadRequest)?;
    let exclude = listed(&request.exclude_credentials);
    // Where it goes: the login with this account for this site, unless it is behind the lock.
    let site_origin = match caller {
        Caller::Page(origin) => origin.clone(),
        Caller::App { .. } => {
            Origin::of_page(&format!("https://{site}")).map_err(|_| Refusal::WrongSite)?
        }
    };
    let mut target = None;
    for id in vault.item_ids() {
        let Ok(item) = vault.get_item(&id) else {
            continue;
        };
        if item.kind != ItemKind::Login {
            continue;
        }
        if item
            .passkeys
            .iter()
            .any(|p| p.rp_id == site && exclude.contains(&p.credential_id))
        {
            return Err(Refusal::Exists);
        }
        if target.is_none()
            && usable(vault, &item)
            && item.username == user_name
            && item_matches(&item.urls, &site_origin)
        {
            target = Some((id, item));
        }
    }
    let passkey = Passkey::new(&site, &user_handle, user_name, display_name)
        .map_err(|_| Refusal::BadRequest)?;
    // Verified for this request, as a sign-in is (the fingerprint or the phone's lock first).
    let data = passkey
        .authenticator_data(true, true)
        .map_err(|_| Refusal::BadRequest)?;
    let public_key = passkey.spki().map_err(|_| Refusal::BadRequest)?;
    let title = match target {
        Some((id, mut item)) => {
            item.passkeys
                .retain(|p| !(p.rp_id == passkey.rp_id && p.user_handle == passkey.user_handle));
            if item.passkeys.len() >= Passkey::MAX_PER_ITEM {
                return Err(Refusal::NotKept);
            }
            item.passkeys.push(passkey.clone());
            item.touch();
            vault
                .update_item(&id, &item)
                .map_err(|_| Refusal::NotKept)?;
            item.title.clone()
        }
        None => {
            let host = site_origin.host();
            let title = host.strip_prefix("www.").unwrap_or(host);
            // A login for the passkey alone: no password.
            let mut item = ItemData::new(ItemKind::Login, title);
            item.username = user_name.to_owned();
            item.urls.push(site_origin.as_str().to_owned());
            item.passkeys.push(passkey.clone());
            vault.add_item(&item).map_err(|_| Refusal::NotKept)?;
            item.title.clone()
        }
    };
    let id = base64(&passkey.credential_id);
    let answer = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": base64(&client),
            "attestationObject": base64(&attestation_object(&data)),
            "authenticatorData": base64(&data),
            "publicKey": base64(&public_key),
            "publicKeyAlgorithm": ES256,
            "transports": ["internal", "hybrid"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });
    Ok(Made {
        answer: answer.to_string(),
        title,
    })
}

/// With the app's vault locked: opens the vault file with the device secret the fingerprint
/// released, makes the passkey in it ([`create`]) and writes the file back, only over the very
/// file it read (one changed since is left alone and the passkey not made). The app syncs it
/// at its next unlock.
pub fn create_with_secret(
    home: &std::path::Path,
    secret: &[u8],
    caller: &Caller,
    request: &str,
    sent_hash: Option<&[u8]>,
    now: i64,
) -> Result<Made, Refusal> {
    let (mut vault, path, read) =
        autofill::open_locked_file(home, secret, now).ok_or(Refusal::NotKept)?;
    let made = create(&mut vault, caller, request, sent_hash)?;
    let bytes = vault.to_bytes().map_err(|_| Refusal::NotKept)?;
    if files::read(&path).ok().as_deref() != Some(read.as_slice()) {
        return Err(Refusal::NotKept);
    }
    files::write_atomic(&path, &bytes).map_err(|_| Refusal::NotKept)?;
    // Best effort: without the app's folder set (Android started only the provider), the
    // next unlock records the newer revision instead.
    let _ = crate::platform::device::record_revision(&vault.id_hex(), vault.revision());
    Ok(made)
}

/// The passkeys for one sign-in, read from the vault file with the device secret the
/// fingerprint released while the app was locked ([`Held::open`]). They stay in memory only
/// until the person picks one or [`Held::FOR_SECONDS`] pass, so that picking one doesn't ask
/// for the fingerprint a second time; their keys are wiped when this is dropped.
pub struct Held {
    caller: Caller,
    at: i64,
    passkeys: Vec<(String, Passkey)>,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Held")
            .field("caller", &self.caller)
            .field("at", &self.at)
            .field("passkeys", &self.passkeys.len())
            .finish()
    }
}

impl Held {
    /// How long passkeys read with a fingerprint stay ready for the pick that follows.
    pub const FOR_SECONDS: i64 = 60;

    /// Opens the vault at `home` with the device secret and keeps the passkeys that may
    /// answer `request` from `caller`; `None` when the vault doesn't open that way.
    pub fn open(
        home: &std::path::Path,
        secret: &[u8],
        caller: &Caller,
        request: &str,
        now: i64,
    ) -> Option<(Self, Vec<Offer>)> {
        let vault = autofill::open_locked(home, secret, now)?;
        let found = offers(&vault, caller, request);
        let mut passkeys = Vec::with_capacity(found.len());
        for offer in &found {
            let item = vault.get_item(&ItemId::from_hex(&offer.item)?).ok()?;
            let credential = unbase64(&offer.credential)?;
            if let Some(passkey) = item.passkeys.iter().find(|p| p.credential_id == credential) {
                passkeys.push((offer.item.clone(), passkey.clone()));
            }
        }
        Some((
            Self {
                caller: caller.clone(),
                at: now,
                passkeys,
            },
            found,
        ))
    }

    /// Whether `now` is within [`Held::FOR_SECONDS`] of the fingerprint (and not before it).
    pub fn fresh(&self, now: i64) -> bool {
        now >= self.at && now - self.at <= Self::FOR_SECONDS
    }

    /// Signs in with one of the held passkeys, for the same caller, while [`Held::fresh`].
    pub fn assertion(
        &self,
        caller: &Caller,
        item: &str,
        credential: &str,
        request: &str,
        sent_hash: Option<&[u8]>,
        now: i64,
    ) -> Option<Zeroizing<String>> {
        if *caller != self.caller || !self.fresh(now) {
            return None;
        }
        let request = read::<GetRequest>(request)?;
        let site = caller.site(&request.rp_id)?;
        let credential = unbase64(credential)?;
        let allow = listed(&request.allow_credentials);
        if !allow.is_empty() && !allow.contains(&credential) {
            return None;
        }
        let (_, passkey) = self.passkeys.iter().find(|(held_item, p)| {
            held_item == item && p.rp_id == site && p.credential_id == credential
        })?;
        assertion_of(passkey, caller, &request, sent_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, SecretKey};

    /// Chrome's release certificate (autofill's list), as the package manager hands it.
    fn chrome_signer() -> [u8; 32] {
        let hex = "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83";
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn page(origin: &str) -> Caller {
        Caller::of(&Asker {
            app: "com.android.chrome".into(),
            signers: vec![chrome_signer()],
            origin: Some(origin.into()),
        })
        .unwrap()
    }

    fn app(package: &str) -> Caller {
        Caller::of(&Asker {
            app: package.into(),
            signers: vec![[9; 32]],
            origin: None,
        })
        .unwrap()
    }

    fn vault() -> Vault {
        Vault::create(
            "passkeys test passphrase",
            &SecretKey::generate().unwrap(),
            None,
            KdfParams::minimum().unwrap(),
        )
        .unwrap()
    }

    const CHALLENGE: &str = "AAECAwQFBgcICQoLDA0ODw";

    fn create_request(rp: &str, user: &str) -> String {
        json!({
            "challenge": CHALLENGE,
            "rp": { "id": rp, "name": "Shop" },
            "user": { "id": "dXNlci0x", "name": user, "displayName": "Me" },
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        })
        .to_string()
    }

    fn get_request(rp: &str) -> String {
        json!({ "challenge": CHALLENGE, "rpId": rp }).to_string()
    }

    fn decoded(answer: &str) -> Value {
        serde_json::from_str(answer).unwrap()
    }

    fn field(answer: &Value, key: &str) -> Vec<u8> {
        unbase64(answer["response"][key].as_str().unwrap()).unwrap()
    }

    #[test]
    fn who_asks_is_a_known_browser_with_its_page_or_an_app_for_itself() {
        assert!(matches!(page("https://shop.example"), Caller::Page(_)));
        // A browser not known by its certificate, or a known name signed by someone else.
        for (package, signer) in [
            ("com.example.browser", chrome_signer()),
            ("com.android.chrome", [9; 32]),
        ] {
            let asker = Asker {
                app: package.into(),
                signers: vec![signer],
                origin: Some("https://shop.example".into()),
            };
            assert!(Caller::of(&asker).is_none(), "{package}");
        }
        // Plain http pages get nothing; a known browser without a page is no app of its own.
        let http = Asker {
            app: "com.android.chrome".into(),
            signers: vec![chrome_signer()],
            origin: Some("http://shop.example".into()),
        };
        assert!(Caller::of(&http).is_none());
        let no_page = Asker {
            origin: None,
            ..http
        };
        assert!(Caller::of(&no_page).is_none());
        // An app without one signer it can be told by.
        let unsigned = Asker {
            app: "com.example.shop".into(),
            signers: Vec::new(),
            origin: None,
        };
        assert!(Caller::of(&unsigned).is_none());

        let shop = app("com.example.shop");
        assert_eq!(
            shop.origin(),
            format!("android:apk-key-hash:{}", base64(&[9; 32]))
        );
        assert_eq!(shop.name(), "com.example.shop");
    }

    #[test]
    fn a_page_speaks_for_its_own_site_only() {
        let login = page("https://login.shop.example");
        assert_eq!(login.site("").as_deref(), Some("login.shop.example"));
        assert_eq!(login.site("shop.example").as_deref(), Some("shop.example"));
        for other in ["evil.example", "example", "com", "co.uk", "127.0.0.1"] {
            assert!(login.site(other).is_none(), "{other}");
        }
        // An app may name a site (its answers carry its own origin), never a public suffix.
        let shop = app("com.example.shop");
        assert_eq!(shop.site("Shop.Example").as_deref(), Some("shop.example"));
        for other in ["", "com", "github.io", "127.0.0.1", "a b"] {
            assert!(shop.site(other).is_none(), "{other:?}");
        }
    }

    #[test]
    fn a_passkey_made_in_a_browser_signs_in_there_and_nowhere_else() {
        let mut vault = vault();
        let shop = page("https://shop.example");
        let made = create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        assert_eq!(made.title, "shop.example");
        let answer = decoded(&made.answer);
        let client: Value = serde_json::from_slice(&field(&answer, "clientDataJSON")).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://shop.example");
        assert_eq!(client["challenge"], CHALLENGE);
        assert!(client.get("androidPackageName").is_none());
        assert_eq!(answer["response"]["publicKeyAlgorithm"], -7);
        assert_eq!(answer["id"], answer["rawId"]);
        // The attestation's authenticator data is the one given apart.
        let data = field(&answer, "authenticatorData");
        assert_eq!(&data[..32], Sha256::digest(b"shop.example").as_slice());
        assert!(
            field(&answer, "attestationObject")
                .windows(data.len())
                .any(|w| w == data)
        );

        // Kept in a new login for the site, with the account's name.
        let item = vault
            .item_ids()
            .map(|id| vault.get_item(&id).unwrap())
            .find(|i| i.title == "shop.example")
            .unwrap();
        assert_eq!(item.username, "me");
        assert_eq!(item.urls, ["https://shop.example"]);
        assert_eq!(item.passkeys.len(), 1);

        // Offered to the page, signs, and the site's public key checks it.
        let found = offers(&vault, &shop, &get_request("shop.example"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user_name, "me");
        let signed = assertion(
            &vault,
            &shop,
            &found[0].item,
            &found[0].credential,
            &get_request("shop.example"),
            None,
        )
        .unwrap();
        let signed = decoded(&signed);
        let client_json = field(&signed, "clientDataJSON");
        let client: Value = serde_json::from_slice(&client_json).unwrap();
        assert_eq!(client["type"], "webauthn.get");
        let mut message = field(&signed, "authenticatorData");
        message.extend_from_slice(&Sha256::digest(&client_json));
        let public_key = item.passkeys[0].public_key().unwrap();
        assert!(vault_core::passkey::verify(
            &public_key,
            &message,
            &field(&signed, "signature")
        ));
        assert_eq!(field(&signed, "userHandle"), b"user-1");

        // Another site, and an app naming this one, see nothing usable.
        let evil = page("https://evil.example");
        assert!(offers_for(&vault, &evil, "shop.example").is_empty());
        assert!(
            assertion(
                &vault,
                &evil,
                &found[0].item,
                &found[0].credential,
                &get_request("shop.example"),
                None
            )
            .is_none()
        );
        // An app gets an answer, but one that names the app: the site refuses it.
        let other = app("com.example.other");
        let foreign = assertion(
            &vault,
            &other,
            &found[0].item,
            &found[0].credential,
            &get_request("shop.example"),
            None,
        )
        .unwrap();
        let client: Value =
            serde_json::from_slice(&field(&decoded(&foreign), "clientDataJSON")).unwrap();
        assert_eq!(client["origin"], other.origin());
        assert_eq!(client["androidPackageName"], "com.example.other");
    }

    fn offers_for(vault: &Vault, caller: &Caller, rp: &str) -> Vec<Offer> {
        offers(vault, caller, &get_request(rp))
    }

    #[test]
    fn a_hash_the_browser_sends_is_what_gets_signed() {
        let mut vault = vault();
        let shop = page("https://shop.example");
        create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        let offer = offers_for(&vault, &shop, "shop.example").remove(0);
        let hash = [5u8; 32];
        let signed = assertion(
            &vault,
            &shop,
            &offer.item,
            &offer.credential,
            &get_request("shop.example"),
            Some(&hash),
        )
        .unwrap();
        let signed = decoded(&signed);
        let mut message = field(&signed, "authenticatorData");
        message.extend_from_slice(&hash);
        let item = vault
            .get_item(&ItemId::from_hex(&offer.item).unwrap())
            .unwrap();
        assert!(vault_core::passkey::verify(
            &item.passkeys[0].public_key().unwrap(),
            &message,
            &field(&signed, "signature")
        ));
        // A hash of any other length is refused.
        assert!(
            assertion(
                &vault,
                &shop,
                &offer.item,
                &offer.credential,
                &get_request("shop.example"),
                Some(&[5; 31])
            )
            .is_none()
        );
    }

    #[test]
    fn a_site_s_lists_and_algorithms_are_followed() {
        let mut vault = vault();
        let shop = page("https://shop.example");
        let first = create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        let credential = decoded(&first.answer)["id"].as_str().unwrap().to_owned();

        // The same account again replaces the passkey in the same login.
        create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        let found = offers_for(&vault, &shop, "shop.example");
        assert_eq!(found.len(), 1);
        assert_ne!(found[0].credential, credential);

        // A passkey the site lists as made already: refused.
        let mut excluded: Value =
            serde_json::from_str(&create_request("shop.example", "you")).unwrap();
        excluded["excludeCredentials"] =
            json!([{ "type": "public-key", "id": found[0].credential }]);
        assert_eq!(
            create(&mut vault, &shop, &excluded.to_string(), None).unwrap_err(),
            Refusal::Exists
        );
        // Only RSA asked for: none of the kinds made here.
        let mut rsa: Value = serde_json::from_str(&create_request("shop.example", "you")).unwrap();
        rsa["pubKeyCredParams"] = json!([{ "type": "public-key", "alg": -257 }]);
        assert_eq!(
            create(&mut vault, &shop, &rsa.to_string(), None).unwrap_err(),
            Refusal::Unsupported
        );
        // Another site's name from this page, or an unreadable request.
        assert_eq!(
            create(
                &mut vault,
                &shop,
                &create_request("evil.example", "me"),
                None
            )
            .unwrap_err(),
            Refusal::WrongSite
        );
        assert_eq!(
            create(&mut vault, &shop, "{", None).unwrap_err(),
            Refusal::BadRequest
        );

        // A sign-in that lists other credentials gets nothing from this vault.
        let mut listing: Value = serde_json::from_str(&get_request("shop.example")).unwrap();
        listing["allowCredentials"] = json!([{ "type": "public-key", "id": "AQID" }]);
        assert!(offers(&vault, &shop, &listing.to_string()).is_empty());
        listing["allowCredentials"] = json!([{ "type": "public-key", "id": found[0].credential }]);
        assert_eq!(offers(&vault, &shop, &listing.to_string()).len(), 1);
    }

    #[test]
    fn passkeys_behind_the_item_lock_are_not_offered() {
        let mut vault = vault();
        let shop = page("https://shop.example");
        create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        vault
            .set_item_guard(
                true,
                vault_core::GuardCheck::Pin,
                Some("2468"),
                Some("passkeys test passphrase"),
            )
            .unwrap();
        vault.lock_secrets();
        assert!(offers_for(&vault, &shop, "shop.example").is_empty());
        // Made again while locked: a login of its own, beside the locked one.
        create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        assert_eq!(vault.item_ids().count(), 2);
    }

    #[test]
    fn passkeys_read_with_the_fingerprint_answer_only_that_caller_for_a_minute() {
        let mut vault = vault();
        let shop = page("https://shop.example");
        create(
            &mut vault,
            &shop,
            &create_request("shop.example", "me"),
            None,
        )
        .unwrap();
        let offer = offers_for(&vault, &shop, "shop.example").remove(0);
        let item = vault
            .get_item(&ItemId::from_hex(&offer.item).unwrap())
            .unwrap();
        let held = Held {
            caller: shop.clone(),
            at: 1_000,
            passkeys: vec![(offer.item.clone(), item.passkeys[0].clone())],
        };
        let sign = |caller: &Caller, now: i64| {
            held.assertion(
                caller,
                &offer.item,
                &offer.credential,
                &get_request("shop.example"),
                None,
                now,
            )
        };
        assert!(sign(&shop, 1_000 + Held::FOR_SECONDS).is_some());
        assert!(sign(&shop, 1_001 + Held::FOR_SECONDS).is_none(), "too late");
        assert!(sign(&shop, 999).is_none(), "a clock gone back");
        assert!(sign(&page("https://evil.example"), 1_010).is_none());
        assert!(sign(&app("com.example.shop"), 1_010).is_none());
        // What it holds is counted, never shown.
        assert!(format!("{held:?}").ends_with("passkeys: 1 }"), "{held:?}");
    }

    #[test]
    fn the_browsers_android_may_tell_a_page_to_are_listed_with_their_certificates() {
        let list: Value = serde_json::from_str(&privileged_browsers()).unwrap();
        let chrome = list["apps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|app| app["info"]["package_name"] == "com.android.chrome")
            .unwrap();
        assert_eq!(chrome["type"], "android");
        assert_eq!(
            chrome["info"]["signatures"][0]["cert_fingerprint_sha256"],
            "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83"
        );
        assert_eq!(chrome["info"]["signatures"][0]["build"], "release");
    }
}
