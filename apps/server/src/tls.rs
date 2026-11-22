//! HTTPS of the server's own (`serve --tls`), for a home network with no domain name and no
//! Tailscale.
//!
//! On first start the server makes a small certificate authority and keeps it in
//! `<data>/tls/`. Devices pin it: its SHA-256 travels in the server's address
//! (`https://192.168.1.10:8750#pin=<hex>`), a device fetches it from `/v1/certificate`,
//! checks the hash and then verifies the server's certificate against it as its only root.
//! The server's own certificate is made at each start for this computer's addresses, and
//! again for any other address of this computer a device connects to (one Windows calls
//! deprecated, one handed out since), signed by that authority, so the pin stays the same
//! when an address changes.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// Handshakes in flight at once; more connections wait in the kernel's queue.
const HANDSHAKES: usize = 64;
/// A client that hasn't finished its handshake by then is dropped.
const HANDSHAKE_TIME: Duration = Duration::from_secs(10);

/// Certificates made for addresses found only when a device connected to them. Only this
/// computer's own addresses get there, so a handful at most; the cap is a backstop.
const MAX_EXTRA_ADDRESSES: usize = 64;

/// The server's HTTPS: the rustls setup, the authority devices fetch and its pin.
pub struct Tls {
    /// For this computer's addresses at start, `localhost` and the names asked for.
    pub config: Arc<ServerConfig>,
    /// The authority's certificate (DER), served at `/v1/certificate`.
    pub authority: Vec<u8>,
    /// Hex SHA-256 of `authority`: what goes after `#pin=` in the address.
    pub pin: String,
    issuer: Issuer<'static, KeyPair>,
    names: Vec<String>,
    covered: Vec<IpAddr>,
    extra: Mutex<HashMap<IpAddr, Arc<ServerConfig>>>,
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("pin", &self.pin)
            .field("covered", &self.covered)
            .finish_non_exhaustive()
    }
}

impl Tls {
    /// Loads the authority from `<data>/tls/` (making it the first time) and makes this
    /// start's certificate for `localhost`, this computer's addresses and `names`.
    pub fn load_or_make(data: &Path, names: &[String]) -> Result<Self> {
        let dir = data.join("tls");
        let cert_path = dir.join("authority.der");
        let key_path = dir.join("authority-key.pem");
        let (authority, authority_key) = if cert_path.exists() || key_path.exists() {
            let der = std::fs::read(&cert_path)
                .with_context(|| format!("reading {}", cert_path.display()))?;
            let pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("reading {}", key_path.display()))?;
            (
                der,
                KeyPair::from_pem(&pem).context("reading the authority's key")?,
            )
        } else {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            let key = KeyPair::generate().context("making the authority's key")?;
            let der = authority_params()
                .self_signed(&key)
                .context("making the authority")?
                .der()
                .to_vec();
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, &der)
                .with_context(|| format!("writing {}", cert_path.display()))?;
            (der, key)
        };
        // The leaf names its issuer by the authority's subject and key id, both of which come
        // from these same parameters and key.
        let issuer = Issuer::new(authority_params(), authority_key);
        let mut covered: Vec<IpAddr> = vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
        covered.extend(local_addresses());
        covered.extend(
            names
                .iter()
                .filter_map(|name| name.trim().parse::<IpAddr>().ok()),
        );
        covered.sort();
        covered.dedup();
        let config = server_config(&issuer, &authority, &covered, names)?;
        let pin = hex(&Sha256::digest(&authority));
        Ok(Self {
            config,
            authority,
            pin,
            issuer,
            names: names.to_vec(),
            covered,
            extra: Mutex::default(),
        })
    }

    /// The setup for a connection that came in on `local` (the address the device dialled):
    /// one whose certificate names it.
    pub fn config_for(&self, local: IpAddr) -> Arc<ServerConfig> {
        let local = local.to_canonical();
        if self.covered.contains(&local) {
            return self.config.clone();
        }
        let mut extra = self.extra.lock().unwrap();
        if let Some(config) = extra.get(&local) {
            return config.clone();
        }
        if extra.len() >= MAX_EXTRA_ADDRESSES {
            return self.config.clone();
        }
        let mut addresses = self.covered.clone();
        addresses.push(local);
        match server_config(&self.issuer, &self.authority, &addresses, &self.names) {
            Ok(config) => {
                extra.insert(local, config.clone());
                config
            }
            Err(_) => self.config.clone(),
        }
    }
}

/// A server certificate for `addresses`, `localhost` and `names`, signed by the authority.
fn server_config(
    issuer: &Issuer<'_, KeyPair>,
    authority: &[u8],
    addresses: &[IpAddr],
    names: &[String],
) -> Result<Arc<ServerConfig>> {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "vault-server");
    params.subject_alt_names = alt_names(addresses, names)?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate().context("making the server's key")?;
    let leaf = params
        .signed_by(&leaf_key, issuer)
        .context("making the server's certificate")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("setting up TLS")?
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), CertificateDer::from(authority.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .context("setting up TLS")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn authority_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "vault-server certificate authority");
    // Signs server certificates only, never another authority.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// The addresses, `localhost` and the names asked for that aren't addresses.
fn alt_names(addresses: &[IpAddr], names: &[String]) -> Result<Vec<SanType>> {
    let mut dns = vec!["localhost".to_owned()];
    for name in names {
        let name = name.trim();
        if !name.is_empty() && name.parse::<IpAddr>().is_err() {
            dns.push(name.to_owned());
        }
    }
    let mut out: Vec<SanType> = addresses.iter().copied().map(SanType::IpAddress).collect();
    for name in dns {
        let Ok(name) = name.clone().try_into() else {
            bail!("not a host name: {name}");
        };
        out.push(SanType::DnsName(name));
    }
    Ok(out)
}

/// This computer's addresses (none if they can't be read).
pub fn local_addresses() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .map(|all| all.into_iter().map(|i| i.ip()).collect())
        .unwrap_or_default()
}

/// Writes the authority's key so only this user can read it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A listener that hands axum connections once their TLS handshake is done. Handshakes run
/// side by side (a slow client holds up no one) with a time limit and a cap.
#[derive(Debug)]
pub struct TlsListener {
    incoming: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, tls: Arc<Tls>) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let (sender, incoming) = mpsc::channel(HANDSHAKES);
        let slots = Arc::new(Semaphore::new(HANDSHAKES));
        tokio::spawn(async move {
            loop {
                if sender.is_closed() {
                    return;
                }
                let Ok(permit) = slots.clone().acquire_owned().await else {
                    return;
                };
                let (stream, address) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        // Out of file handles and the like: wait instead of spinning.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // The certificate names the address this connection was made to.
                let config = match stream.local_addr() {
                    Ok(dialled) => tls.config_for(dialled.ip()),
                    Err(_) => tls.config.clone(),
                };
                let acceptor = TlsAcceptor::from(config);
                let sender = sender.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(HANDSHAKE_TIME, acceptor.accept(stream)).await
                    {
                        let _ = sender.send((stream, address)).await;
                    }
                });
            }
        });
        Ok(Self { incoming, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.incoming.recv().await {
            Some(connection) => connection,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_found_at_connection_gets_a_certificate_of_its_own() {
        let data = tempfile::tempdir().unwrap();
        let tls = Tls::load_or_make(data.path(), &["vault.home.arpa".to_owned()]).unwrap();
        assert!(Arc::ptr_eq(
            &tls.config_for(Ipv4Addr::LOCALHOST.into()),
            &tls.config
        ));
        // An IPv4 address seen through an IPv6 socket counts as itself.
        let mapped: IpAddr = Ipv4Addr::LOCALHOST.to_ipv6_mapped().into();
        assert!(Arc::ptr_eq(&tls.config_for(mapped), &tls.config));
        let unseen: IpAddr = "192.0.2.77".parse().unwrap();
        let first = tls.config_for(unseen);
        assert!(!Arc::ptr_eq(&first, &tls.config));
        assert!(Arc::ptr_eq(&first, &tls.config_for(unseen)));
        // The pin is the authority's, whichever certificate a connection gets.
        assert_eq!(tls.pin, hex(&Sha256::digest(&tls.authority)));
    }
}
