//! Android autofill's questions, answered from the vault. The Java side
//! (`apps/mobile-android/java/…/VaultAutofillService.java`, `AutofillActivity.java`) finds a
//! form's fields and says what Android knows of who asks ([`Asker`]): the app's package and
//! signing certificate, and, for fields inside a web page, that page's own domain and scheme.
//!
//! - Who would receive a login ([`Recipient`]): a website only when a browser this app knows
//!   by its certificate names it, over https; else the app itself, by its package and signing
//!   identity; else nobody. A domain in any other app's view tree is only that app's word
//!   (Digital Asset Links, which tie an app to a site, can't be checked offline), so it counts
//!   for nothing.
//! - Which logins belong there: the website's exact domain (or everything under a saved
//!   `*.example.com`), or an app by the `androidapp://<certificate>@<package>` address saved in
//!   the login.
//! - A login behind the item lock is neither offered nor changed ([`behind_lock`]).
//! - Before anything is filled, the person confirms with a fingerprint or the phone's own lock
//!   (the Java side asks). With the vault locked, fingerprint unlock opens the vault file here
//!   just long enough to read the logins for that place.
//! - A login saved from another app while the vault is locked is sealed to the vault's drop box
//!   (CRYPTO.md §3.5: only the open vault reads it) and added at the next unlock.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_core::{
    ItemData, ItemId, ItemKind, Vault,
    drop_box::{self, DropBoxKey, PUBLIC_KEY_LEN},
    generator::{PasswordOptions, generate_password},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{bio, platform::files, prefs};

/// A login offered to a form.
#[derive(Clone)]
pub struct Login {
    /// The item's id (hex).
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

// ---- who asks ----

/// What Android says of a form that asks for a login, or saves one. All of it is about one
/// request: the fields are of the page (or the app) it names, and of no other.
#[derive(Debug, Clone, Default)]
pub struct Asker {
    /// The app the form is in, which gets what is filled (the system's word, not the app's).
    pub app: String,
    /// SHA-256 of the certificate it is signed with first, then those it was rotated from, as
    /// the package manager proved them. Empty when it has several signers or isn't known.
    pub signers: Vec<[u8; 32]>,
    /// It opens any https link: a browser, whether this app knows it or not.
    pub browser: bool,
    /// For fields inside a web page: the page's domain, as the web view around exactly these
    /// fields gives it ("" when it gives none that can be read). `None` for the app's own.
    pub domain: Option<String>,
    /// The page's scheme, when the web view gives it.
    pub scheme: Option<String>,
}

/// Who would receive a login. Made only by [`Recipient::of`], so a website here was always
/// vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient(To);

#[derive(Debug, Clone, PartialEq, Eq)]
enum To {
    /// A website, named by a browser this app knows.
    Site(String),
    /// An app, by its package and Android-verified signing lineage.
    App(App),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct App {
    package: String,
    /// Always nonempty: the current signer first, then the verified rotation history.
    signers: Vec<[u8; 32]>,
}

impl App {
    fn of(package: &str, signers: &[[u8; 32]]) -> Option<Self> {
        signers.first()?;
        Some(Self {
            package: package.to_owned(),
            signers: signers.to_vec(),
        })
    }

    fn matches(&self, url: &str) -> bool {
        app_matches(url, &self.package, &self.signers)
    }

    fn address(&self) -> String {
        format!(
            "{APP_ADDRESS}{}@{}",
            certificate_hex(&self.signers[0]),
            self.package
        )
    }

    /// Replaces package-only facets after Android's explicit save confirmation. They are never
    /// considered by [`Self::matches`], so this cannot happen as part of a fill.
    fn bind_legacy(&self, item: &mut ItemData) -> bool {
        let address = self.address();
        let mut rebound = false;
        for url in &mut item.urls {
            if legacy_app_matches(url, &self.package) {
                url.clone_from(&address);
                rebound = true;
            }
        }
        rebound
    }
}

impl To {
    /// The place an address made by [`place_of`] stands for.
    fn of_saved(url: &str, history: &[[u8; 32]]) -> Option<Self> {
        if let Some((package, signer)) = app_facet(url) {
            let mut signers = vec![signer];
            signers.extend_from_slice(history);
            return Some(Self::App(App {
                package: package.to_owned(),
                signers,
            }));
        }
        url.strip_prefix("https://")
            .map(|domain| Self::Site(domain.to_owned()))
    }

    /// Whether `item` is saved for this place.
    fn fits(&self, item: &ItemData) -> bool {
        item.urls.iter().any(|url| match self {
            Self::Site(domain) => site_matches(url, domain),
            Self::App(app) => app.matches(url),
        })
    }

    /// Whether `item` has the old package-only facet for this app. This is used only after the
    /// person explicitly accepts Android's save prompt, never when choosing what to fill.
    fn fits_legacy(&self, item: &ItemData) -> bool {
        match self {
            Self::Site(_) => false,
            Self::App(app) => item
                .urls
                .iter()
                .any(|url| legacy_app_matches(url, &app.package)),
        }
    }
}

/// Includes guarded logins so saving a second copy can preserve their protection.
fn account_logins<'a>(
    vault: &'a Vault,
    username: &'a str,
) -> impl Iterator<Item = (ItemId, ItemData)> + 'a {
    vault
        .item_ids()
        .filter_map(|id| Some((id, vault.get_item(&id).ok()?)))
        .filter(move |(_, item)| item.kind == ItemKind::Login && item.username == username)
}

impl Recipient {
    /// Who `asker` stands for; `None` when nothing is offered, filled or saved there.
    ///
    /// - A page that isn't https gets nothing, in any app: anyone on the network could read
    ///   what is filled in it.
    /// - A website counts only from a browser known by package and certificate.
    /// - Any other browser gets nothing: its package says nothing about the page, so a login
    ///   saved "for the browser" would be offered on every site in it. The same goes for an
    ///   app that has a known browser's name and somebody else's certificate.
    /// - Any other app is only itself, whatever domain its view tree gives, and only when
    ///   Android supplies one current signer and its verified signing history.
    pub fn of(asker: &Asker) -> Option<Self> {
        let app = asker.app.trim();
        if app.is_empty() {
            return None;
        }
        if let Some(scheme) = &asker.scheme
            && !scheme.eq_ignore_ascii_case("https")
        {
            return None;
        }
        // A web page whose address can't be read belongs to nobody.
        let site = match &asker.domain {
            Some(domain) => Some(plain_host(domain)?),
            None => None,
        };
        match (known_browser(app), site) {
            (Some(certificates), Some(site)) if signed_with(asker, certificates) => {
                Some(Self(To::Site(site)))
            }
            (Some(_), _) => None,
            (None, _) if asker.browser => None,
            (None, _) => Some(Self(To::App(App::of(app, &asker.signers)?))),
        }
    }

    /// The website's domain or the app's package, for the prompt that asks the person.
    pub fn name(&self) -> &str {
        match &self.0 {
            To::Site(domain) => domain,
            To::App(app) => &app.package,
        }
    }
}

/// `domain` as a plain host name (or an IPv4 address), lower case; `None` for anything else.
/// It goes into a saved address, so nothing that could end a host or start another one.
fn plain_host(domain: &str) -> Option<String> {
    let host = domain.trim().trim_end_matches('.').to_lowercase();
    let plain = |c: char| c.is_alphanumeric() || matches!(c, '.' | '-' | '_');
    (!host.is_empty() && host.chars().all(plain)).then_some(host)
}

/// Whether `asker` is signed with one of `certificates` (SHA-256, in hex).
fn signed_with(asker: &Asker, certificates: &[&str]) -> bool {
    asker.signers.iter().any(|signer| {
        let hex = certificate_hex(signer);
        certificates.contains(&hex.as_str())
    })
}

/// The certificates a browser's releases are signed with, when `package` is one known here.
fn known_browser(package: &str) -> Option<&'static [&'static str]> {
    BROWSERS
        .iter()
        .find(|(known, _)| *known == package)
        .map(|(_, certificates)| *certificates)
}

const CHROME: &str = "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83";
const CHROME_BETA: &str = "DA633D34B69E63AE2103B49D53CE052FC5F7F3C53AAB94FDC2A208BDFD14249C";
const CHROME_DEV: &str = "9044EE5FEE4BBC5E21DD44665431C4EB1F1F71A32716A0BC927BCBB39233CABF";
/// Chrome beta and dev: their other certificate.
const CHROME_CHANNELS: &str = "3D7A1223019AA39D9EA0E3436AB7C0896BFB4FB679F4DE5FE7C23F326C8F994A";
const CHROME_CANARY: &str = "2019DFA1FB23EFBF70C5BCD1443C5BEAB04F3F2FF4366E9AC1E3457639A24CFC";
const FIREFOX: &str = "A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04";
const FIREFOX_NIGHTLY: &str = "5004779088E7F988D5BC5CC5F8798FEBF4F8CD084A1B2A46EFD4C8EE4AEAF211";
const FIREFOX_FOCUS: &str = "6203A473BE36D64EE37F87FA500EDBC79EAB930610AB9B9FA4CA7D5C1F1B4FFC";
const EDGE: &str = "01E1999710A82C2749B4D50C445DC85D670B6136089D0A766A73827C82A1EAC9";
const BRAVE: &str = "9C2DB70513515FDBFBBC585B3EDF3D7123D4DC67C94FFD306361C1D79BBF18AC";
const SAMSUNG: &str = "34DF0E7A9F1CF1892E45C056B4973CD81CCF148A4050D11AEA4AC5A65F900A42";
const OPERA: &str = "5D6AFBF87F652AF04647ADA0DF634CF22370900B164B09D50BD23AA2CB5285B8";
const VIVALDI: &str = "E8A78544655BA8C09817F732768F5689B1662EC4B2BC5A0BC0EC138D33CA3D1E";
const DUCKDUCKGO: &str = "BB7BB31C573C46A1DA7FC5C528A6ACF432108456FEEC50810C7F33694EB3D2D4";
const VANADIUM: &str = "C6ADB8B83C6D4C17D292AFDE56FD488A51D316FF8F2C11C5410223BFF8A7DBB3";

/// The browsers whose word about the page counts: package, and SHA-256 of the certificates
/// its releases are signed with. They are the ones Google publishes for passkeys
/// (<https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json>), release keys only.
/// Adding one means comparing its certificate with a second source.
const BROWSERS: [(&str, &[&str]); 23] = [
    ("com.android.chrome", &[CHROME]),
    ("com.chrome.beta", &[CHROME_BETA, CHROME_CHANNELS]),
    ("com.chrome.dev", &[CHROME_DEV, CHROME_CHANNELS]),
    ("com.chrome.canary", &[CHROME_CANARY]),
    ("org.mozilla.firefox", &[FIREFOX]),
    ("org.mozilla.firefox_beta", &[FIREFOX]),
    ("org.mozilla.fenix", &[FIREFOX_NIGHTLY]),
    ("org.mozilla.focus", &[FIREFOX_FOCUS]),
    ("com.microsoft.emmx", &[EDGE]),
    ("com.microsoft.emmx.beta", &[EDGE]),
    ("com.microsoft.emmx.dev", &[EDGE]),
    ("com.microsoft.emmx.canary", &[EDGE]),
    ("com.brave.browser", &[BRAVE]),
    ("com.brave.browser_beta", &[BRAVE]),
    ("com.brave.browser_nightly", &[BRAVE]),
    ("com.sec.android.app.sbrowser", &[SAMSUNG]),
    ("com.sec.android.app.sbrowser.beta", &[SAMSUNG]),
    ("com.opera.browser", &[OPERA]),
    ("com.opera.browser.beta", &[OPERA]),
    ("com.vivaldi.browser", &[VIVALDI]),
    ("com.vivaldi.browser.snapshot", &[VIVALDI]),
    ("com.duckduckgo.mobile.android", &[DUCKDUCKGO]),
    ("app.vanadium.browser", &[VANADIUM]),
];

// ---- which logins belong there ----

/// A saved address's host, lower case, without scheme, user, port or path; `None` for an app's
/// address or nothing usable.
fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = match url.split_once("://") {
        Some((scheme, _)) if scheme.eq_ignore_ascii_case("androidapp") => return None,
        Some((_, rest)) => rest,
        None => url,
    };
    // A backslash ends the host too, as a browser reads a web address (`https://a\@b` is `a`).
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Whether a login's saved address `url` is the website `domain`: the same host, or `domain`
/// is under a saved `*.example.com`.
///
/// A `*.` entry follows the browser extension's rule (`vault_browser::origin`), decided again
/// each time a form asks: one over a public suffix (`*.co.uk`, `*.github.io`, `*.com`), where
/// anyone can have a site, covers nothing, whether it was typed or came in with an import.
pub fn site_matches(url: &str, domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    let Some(host) = host_of(url) else {
        return false;
    };
    // A `*` in the host makes it a wildcard entry, decided by that rule alone: never a plain
    // name. One only in the path (`https://example.com/*`) is the host's, as in the extension.
    if host.contains('*') {
        return wildcard_covers(url, &domain);
    }
    host == domain
}

#[cfg(not(target_arch = "wasm32"))]
fn wildcard_covers(saved: &str, domain: &str) -> bool {
    vault_browser::origin::wildcard_covers_host(saved, domain)
}

/// The browser preview fills nothing, and has no list of public suffixes: no `*.` entry
/// covers anything there.
#[cfg(target_arch = "wasm32")]
fn wildcard_covers(_saved: &str, _domain: &str) -> bool {
    false
}

/// Whether the saved website `url` is a `*` rule that covers no site at all, so autofill
/// skips it (the item page says so): one over a public suffix (`*.co.uk`, `*.github.io`,
/// where anyone can have a site), or one that isn't a plain name (`*.example.com/login`,
/// `http://*.example.com`). Judged by the same rule as [`site_matches`], each time, so a rule
/// typed or imported before is caught as well.
pub fn wildcard_unused(url: &str) -> bool {
    host_of(url).is_some_and(|host| host.contains('*')) && !wildcard_is_rule(url)
}

#[cfg(not(target_arch = "wasm32"))]
fn wildcard_is_rule(saved: &str) -> bool {
    vault_browser::origin::wildcard_base(saved).is_some()
}

#[cfg(target_arch = "wasm32")]
fn wildcard_is_rule(_saved: &str) -> bool {
    false
}

const APP_ADDRESS: &str = "androidapp://";

fn certificate_hex(certificate: &[u8; 32]) -> String {
    certificate
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

fn app_facet(url: &str) -> Option<(&str, [u8; 32])> {
    let url = url.trim();
    let scheme = url.get(..APP_ADDRESS.len())?;
    let facet = url.get(APP_ADDRESS.len()..)?.trim_end_matches('/');
    if !scheme.eq_ignore_ascii_case(APP_ADDRESS) {
        return None;
    }
    let (digest, package) = facet.split_once('@')?;
    if digest.len() != 64 || package.is_empty() || package.contains('@') {
        return None;
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut signer = [0; 32];
    let (pairs, _) = digest.as_bytes().as_chunks::<2>();
    for (to, pair) in signer.iter_mut().zip(pairs) {
        *to = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some((package, signer))
}

/// Whether a login's signed app facet names `package` and one of Android's verified `signers`.
pub fn app_matches(url: &str, package: &str, signers: &[[u8; 32]]) -> bool {
    app_facet(url).is_some_and(|(saved_package, signer)| {
        saved_package == package && signers.contains(&signer)
    })
}

/// Package-only app facets from older versions. These are deliberately separate from
/// [`app_matches`]: they can be rebound after an explicit save, but can never authorize a fill.
fn legacy_app_matches(url: &str, package: &str) -> bool {
    legacy_package(url) == Some(package)
}

fn legacy_package(url: &str) -> Option<&str> {
    let url = url.trim();
    let scheme = url.get(..APP_ADDRESS.len())?;
    let package = url.get(APP_ADDRESS.len()..)?.trim_end_matches('/');
    (scheme.eq_ignore_ascii_case(APP_ADDRESS) && !package.is_empty() && !package.contains('@'))
        .then_some(package)
}

/// Whether `item` is behind the item lock: its secrets are sealed, or they wait for the lock's
/// check (a PIN, a password, the master password), sealed already or not yet
/// ([`Vault::pending_seal`]), and whether or not that check was just passed on the item's page.
///
/// The one rule of autofill, both ways: such a login is not offered to another app, and its
/// password isn't changed from one. Only the app itself does that, after the item's check.
fn behind_lock(vault: &Vault, item: &ItemData) -> bool {
    item.is_locked() || vault.guards(item)
}

/// The logins of `vault` saved for `to`, by title. None behind the item lock.
pub fn logins_for(vault: &Vault, to: &Recipient) -> Vec<Login> {
    let mut found: Vec<Login> = vault
        .item_ids()
        .filter_map(|id| {
            let item = vault.get_item(&id).ok()?;
            let usable = item.kind == ItemKind::Login
                && !behind_lock(vault, &item)
                && !(item.password.is_empty() && item.username.is_empty())
                && to.0.fits(&item);
            usable.then(|| Login {
                id: id.to_hex(),
                title: item.title.clone(),
                username: item.username.clone(),
                password: Zeroizing::new(item.password.clone()),
            })
        })
        .collect();
    found.sort_by_key(|login| login.title.to_lowercase());
    found
}

/// One login of `vault` by its id, only if it still belongs to `to`.
pub fn login_by_id(vault: &Vault, id: &str, to: &Recipient) -> Option<Login> {
    let id = ItemId::from_hex(id)?;
    logins_for(vault, to)
        .into_iter()
        .find(|login| ItemId::from_hex(&login.id) == Some(id))
}

/// A strong password for a new-password field (the generator's defaults: 20 characters of
/// every kind).
pub fn suggest() -> Option<Zeroizing<String>> {
    generate_password(&PasswordOptions::default()).ok()
}

// ---- the locked app ----

/// The phone's vault file in `home` that the app opened last.
fn current_vault(home: &Path) -> PathBuf {
    let prefs = prefs::Prefs::load(&prefs::path_for(&home.join(prefs::FIRST_VAULT)));
    let file = if prefs::is_vault_file(&prefs.current) {
        prefs.current
    } else {
        prefs::FIRST_VAULT.to_owned()
    };
    home.join(file)
}

/// The vault the app opened last, when fingerprint unlock is on for it and the master password
/// isn't due: its id and its device secret as the secure hardware sealed it.
pub fn locked_unlock(home: &Path, now: i64) -> Option<(String, Vec<u8>)> {
    let bytes = files::read(&current_vault(home)).ok()?;
    let id = Vault::inspect(&bytes).ok()?.id_hex;
    let unlock = bio::read(home, &id).filter(|b| b.fresh(now))?;
    Some((id, unlock.hardware))
}

/// Opens that vault with the device secret the fingerprint released and reads the logins for
/// `to`. The vault leaves memory when this returns.
pub fn open_with_secret(
    home: &Path,
    secret: &[u8],
    to: &Recipient,
    now: i64,
) -> Option<Vec<Login>> {
    let bytes = files::read(&current_vault(home)).ok()?;
    let id = Vault::inspect(&bytes).ok()?.id_hex;
    let unlock = bio::read(home, &id).filter(|b| b.fresh(now))?;
    let vault = Vault::open_with_device(&bytes, secret, &unlock.sealed_key).ok()?;
    Some(logins_for(&vault, to))
}

// ---- the drop box: logins saved while the vault is locked ----

/// Entries kept at most while locked; later saves are refused.
const MAX_ENTRIES: usize = 200;

/// `autofill-drop-<vault id>.json` next to the vault: the drop box's public key, its private key
/// sealed with the vault key, and the logins sealed to the public key since the last unlock.
#[derive(Serialize, Deserialize)]
struct DropFile {
    public_key: [u8; PUBLIC_KEY_LEN],
    sealed_key: Vec<u8>,
    entries: Vec<Vec<u8>>,
}

/// One login, as sealed in an entry.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Dropped {
    url: String,
    title: String,
    username: String,
    password: String,
    /// Needed only to preserve key-rotation matching while this signed app login is waiting.
    #[serde(default)]
    app_signer_history: Vec<[u8; 32]>,
}

fn drop_path(folder: &Path, vault_id: &str) -> PathBuf {
    folder.join(format!("autofill-drop-{vault_id}.json"))
}

/// After a renewal of the vault key: the drop box's key sealed again under the new one (the
/// key itself stays, so the logins sealed to it while locked still open).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn reseal_drop_box(folder: &Path, vault: &Vault, former: &vault_core::FormerKey) {
    let id = vault.id_hex();
    let Some(mut file) = read_drop(folder, &id) else {
        return;
    };
    let Ok(sealed_key) = DropBoxKey::reseal_with(vault, former, &file.sealed_key) else {
        return;
    };
    file.sealed_key = sealed_key;
    let _ = write_drop(folder, &id, &file);
}

fn read_drop(folder: &Path, vault_id: &str) -> Option<DropFile> {
    let bytes = files::read_any(&drop_path(folder, vault_id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_drop(folder: &Path, vault_id: &str, file: &DropFile) -> bool {
    serde_json::to_vec(file)
        .ok()
        .is_some_and(|bytes| files::write_atomic(&drop_path(folder, vault_id), &bytes).is_ok())
}

/// The title and address a login saved from `from` gets.
fn place_of(from: &Recipient) -> (String, String) {
    match &from.0 {
        To::Site(domain) => {
            let title = domain.strip_prefix("www.").unwrap_or(domain).to_owned();
            (title, format!("https://{domain}"))
        }
        To::App(app) => (app.package.clone(), app.address()),
    }
}

/// Seals a login saved from another app while the vault the app opened last is locked, for
/// the next unlock, when it becomes a login of its own (none is changed). `false` when that
/// vault has no drop box yet (it is made at an unlock) or it is full.
pub fn keep_locked(home: &Path, from: &Recipient, username: &str, password: &str) -> bool {
    let Ok(bytes) = files::read(&current_vault(home)) else {
        return false;
    };
    let Ok(info) = Vault::inspect(&bytes) else {
        return false;
    };
    let Some(mut file) = read_drop(home, &info.id_hex) else {
        return false;
    };
    if file.entries.len() >= MAX_ENTRIES {
        return false;
    }
    let (title, url) = place_of(from);
    let dropped = Dropped {
        url,
        title,
        username: username.to_owned(),
        password: password.to_owned(),
        app_signer_history: match &from.0 {
            To::Site(_) => Vec::new(),
            To::App(app) => app.signers[1..].to_vec(),
        },
    };
    let Ok(plain) = serde_json::to_vec(&dropped).map(Zeroizing::new) else {
        return false;
    };
    let Ok(entry) = drop_box::seal_entry(&file.public_key, &info.id_hex, &plain) else {
        return false;
    };
    file.entries.push(entry);
    write_drop(home, &info.id_hex, &file)
}

/// At unlock: the logins saved while the vault was locked, as items to add (the drop box is
/// made when there is none). One whose account has a login behind the item lock goes behind it
/// too. Call [`empty_drop_box`] once they are safely saved.
pub(crate) fn dropped_logins(folder: &Path, vault: &Vault) -> Vec<ItemData> {
    let id = vault.id_hex();
    let Some(file) = read_drop(folder, &id) else {
        make_drop_box(folder, vault);
        return Vec::new();
    };
    let Ok(key) = DropBoxKey::open_with(vault, &file.sealed_key) else {
        // Another vault's key under this id, or a damaged file: start over.
        make_drop_box(folder, vault);
        return Vec::new();
    };
    file.entries
        .iter()
        .filter_map(|entry| {
            let plain = key.open_entry(vault, entry).ok()?;
            let dropped: Dropped = serde_json::from_slice(&plain).ok()?;
            let mut item = ItemData::new(ItemKind::Login, &dropped.title);
            item.username.clone_from(&dropped.username);
            item.password.clone_from(&dropped.password);
            item.urls = vec![dropped.url.clone()];
            let place = To::of_saved(&dropped.url, &dropped.app_signer_history);
            item.reprompt = account_logins(vault, &dropped.username).any(|(_, saved)| {
                saved.reprompt
                    && match &place {
                        Some(place) => place.fits(&saved) || place.fits_legacy(&saved),
                        // Queued before the upgrade: keep the old guard and leave the facet unbound.
                        None => legacy_package(&dropped.url).is_some_and(|package| {
                            saved
                                .urls
                                .iter()
                                .any(|url| legacy_app_matches(url, package))
                        }),
                    }
            });
            Some(item)
        })
        .collect()
}

/// Empties the drop box once its logins are in the saved vault.
pub(crate) fn empty_drop_box(folder: &Path, vault_id: &str) {
    if let Some(file) = read_drop(folder, vault_id)
        && !file.entries.is_empty()
    {
        write_drop(
            folder,
            vault_id,
            &DropFile {
                entries: Vec::new(),
                ..file
            },
        );
    }
}

fn make_drop_box(folder: &Path, vault: &Vault) {
    let Ok(key) = DropBoxKey::generate() else {
        return;
    };
    let Ok(sealed_key) = key.seal_with(vault) else {
        return;
    };
    write_drop(
        folder,
        &vault.id_hex(),
        &DropFile {
            public_key: key.public_key(),
            sealed_key,
            entries: Vec::new(),
        },
    );
}

/// What a login saved from another app did to the open vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// It was there already.
    Same,
    /// The login saved there for the same place and username has the new password (the old
    /// one went into its history), or its legacy app facet was explicitly rebound.
    Replaced,
    /// A new login.
    Added,
    /// A new login, beside one for the same place and username that is behind the item lock:
    /// that one stays as it is, and the new one is behind the lock as well.
    AddedBeside,
}

/// Adds a login saved from another app to the open `vault`: the password of a login already
/// saved there for the same place and username changes, else a new login is made. Android's
/// save confirmation may also rebind a legacy package-only app facet to the verified signer
/// shown in that confirmation; fills never use or change a legacy facet.
///
/// A login behind the item lock is never changed here ([`behind_lock`]), nor is its password
/// compared with the new one: the person's "Save" in another app isn't the item's check. The
/// new password is kept as a login of its own, so it isn't lost, and the person sorts the two
/// out in the app.
pub(crate) fn save_into(
    vault: &mut Vault,
    from: &Recipient,
    username: &str,
    password: &str,
) -> vault_core::Result<Kept> {
    if password.is_empty() {
        return Ok(Kept::Same);
    }
    let mut current = Vec::new();
    let mut legacy = Vec::new();
    for (id, item) in account_logins(vault, username) {
        if from.0.fits(&item) {
            current.push((id, item));
        } else if from.0.fits_legacy(&item) {
            legacy.push((id, item));
        }
    }
    let (mut locked, open): (Vec<_>, Vec<_>) = current
        .into_iter()
        .partition(|(_, item)| behind_lock(vault, item));
    match open.into_iter().next() {
        Some((_, item)) if item.password == password => Ok(Kept::Same),
        Some((id, mut item)) => {
            item.password = password.to_owned();
            vault.update_item(&id, &item)?;
            Ok(Kept::Replaced)
        }
        None => {
            let (legacy_locked, mut legacy_open): (Vec<_>, Vec<_>) = legacy
                .into_iter()
                .partition(|(_, item)| behind_lock(vault, item));
            locked.extend(legacy_locked);
            // A save confirms the package and signer, but does not select among legacy items.
            if locked.is_empty()
                && legacy_open.len() == 1
                && let Some((id, mut item)) = legacy_open.pop()
                && let To::App(app) = &from.0
                && app.bind_legacy(&mut item)
            {
                item.password = password.to_owned();
                vault.update_item(&id, &item)?;
                return Ok(Kept::Replaced);
            }
            let (title, url) = place_of(from);
            let mut item = ItemData::new(ItemKind::Login, &title);
            item.username = username.to_owned();
            item.password = password.to_owned();
            item.urls = vec![url];
            // The account is one the person keeps behind the item lock: so is its new password.
            item.reprompt = locked.iter().any(|(_, item)| item.reprompt);
            vault.add_item(&item)?;
            Ok(if locked.is_empty() {
                Kept::Added
            } else {
                Kept::AddedBeside
            })
        }
    }
}

#[cfg(test)]
mod tests;
