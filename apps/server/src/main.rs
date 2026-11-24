//! The `vault-server` command: serve, make an invite, list or remove devices, publish an
//! update of the phone app.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use vault_server::{Store, Tls};

#[derive(Debug, Parser)]
#[command(version, about = "Self-hosted sync server for the password manager")]
struct Cli {
    /// Where the copies, device keys and invites are kept.
    #[arg(long, env = "VAULT_SERVER_DATA", default_value = "data", global = true)]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the API. Put HTTPS in front (tailscale serve, Caddy) or use `--tls`, and keep it
    /// off the open internet: see docs/SERVER.md.
    Serve {
        #[arg(long, env = "VAULT_SERVER_LISTEN", default_value = "127.0.0.1:8750")]
        listen: SocketAddr,
        /// HTTPS of the server's own, with a certificate the devices pin (for a home network
        /// with no domain name). It prints the addresses to give the app.
        #[arg(long, env = "VAULT_SERVER_TLS")]
        tls: bool,
        /// More names or addresses for the certificate (this computer's addresses are always
        /// in it).
        #[arg(long = "tls-name", value_name = "NAME")]
        tls_names: Vec<String>,
    },
    /// Make a one-time invite for a device to join a vault. Without `--vault` it starts a new
    /// vault only (the first device of a vault); a device of a vault already here joins with
    /// `--vault <id>`, or better with an invite from a device already in (Add a device).
    /// With `--address` it also prints the whole link (the address, the certificate's pin and
    /// the invite in one line) and its QR code, to paste or scan in the app.
    Invite {
        /// How long it stays good.
        #[arg(long, default_value_t = 24)]
        hours: i64,
        /// Where the devices reach this server, as the app would be given it.
        #[arg(long, env = "VAULT_SERVER_URL")]
        address: Option<String>,
        /// For this vault (its id, from `vault-server list`), which may have devices already:
        /// the link then also sets up a phone that has no vault yet.
        #[arg(long)]
        vault: Option<String>,
        /// Leave the certificate's pin out of the link (the server is reached through
        /// Tailscale or a proxy with a certificate of its own).
        #[arg(long)]
        no_pin: bool,
    },
    /// List the vaults and their devices.
    List,
    /// Take a device out of a vault: its key and its copy.
    Remove { vault: String, device: String },
    /// Put an update of the phone app here (the APK `apps/mobile-android/build.ps1` made).
    /// Phones that sync through this server offer it in Settings, Updates.
    PublishApp {
        /// The APK.
        package: PathBuf,
        /// Its version, as in the app (`0.2.0`).
        #[arg(long)]
        version: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            listen,
            tls,
            tls_names,
        } => {
            if !listen.ip().is_loopback() && !tls {
                eprintln!(
                    "vault-server: listening on {listen}. Keep this port off the open internet \
                     (a Tailscale or WireGuard network, HTTPS in front)."
                );
            }
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("listening on {listen}"))?;
            eprintln!("vault-server: serving {} on {listen}", cli.data.display());
            let stop = stopped();
            if !tls {
                return vault_server::serve(&cli.data, listener, stop).await;
            }
            let tls = Tls::load_or_make(&cli.data, &tls_names)?;
            eprintln!(
                "vault-server: HTTPS on. The address for the app (Settings, Sync, Use a server):"
            );
            for address in app_addresses(listen, &tls.pin) {
                println!("  {address}");
            }
            eprintln!(
                "vault-server: or, typed apart, the address before # and this pin (the app's \
                 Certificate pin field): {}",
                tls.pin
            );
            eprintln!(
                "vault-server: vault-server invite --address <one of the addresses> prints one \
                 link (address, pin and invite) and its QR code."
            );
            vault_server::serve_tls(&cli.data, listener, std::sync::Arc::new(tls), stop).await
        }
        Command::Invite {
            hours,
            address,
            vault,
            no_pin,
        } => {
            let (invite, expires_at) =
                vault_server::admin_invite(&cli.data, hours, vault.as_deref())?;
            println!("{invite}");
            if vault.is_none() {
                let store = Store::open(&cli.data)?;
                let here = store.vaults()?;
                if !here.is_empty() {
                    eprintln!(
                        "This invite starts a new vault. For a device of a vault already here, \
                         use Add a device on a device that syncs it, or make the invite with \
                         --vault and one of these:"
                    );
                    for id in here {
                        let names: Vec<String> =
                            store.devices(&id)?.into_iter().map(|d| d.name).collect();
                        eprintln!("  {id}  ({})", names.join(", "));
                    }
                }
            }
            match address {
                Some(address) => {
                    let server = vault_server::link_address(&cli.data, &address, !no_pin)?;
                    let link = vault_sync_wire::InviteLink {
                        server,
                        vault: vault.unwrap_or_default(),
                        invite: invite.clone(),
                        backup: None,
                    };
                    let text = link.to_text();
                    eprintln!(
                        "\nThe link: it holds the address, the certificate's pin and the invite. \
                         Paste it in the app (Settings, Sync, Use a server), or scan the code \
                         with the phone."
                    );
                    println!("{}", *text);
                    eprintln!("{}", vault_server::terminal_qr(&text));
                }
                None => eprintln!(
                    "Add --address <where the devices reach this server> for a link and a QR code \
                     that hold the address, the pin and the invite."
                ),
            }
            eprintln!(
                "Good once, until Unix time {expires_at}. Type it in the app with this \
                 server's address: Settings, Sync, Use a server."
            );
            Ok(())
        }
        Command::List => {
            let store = Store::open(&cli.data)?;
            for vault in store.vaults()? {
                println!("vault {vault}");
                for device in store.devices(&vault)? {
                    println!(
                        "  {}  {}  added {}  last seen {}",
                        device.device, device.name, device.added_at, device.seen_at
                    );
                }
            }
            Ok(())
        }
        Command::PublishApp { package, version } => {
            let store = Store::open(&cli.data)?;
            let bytes = std::fs::read(&package)
                .with_context(|| format!("reading {}", package.display()))?;
            let release = store.publish_app(&bytes, &version)?;
            println!(
                "Published version {} ({} bytes, SHA-256 {}) in {}. A server started with this \
                 data folder offers it to the phones.",
                release.version,
                release.size,
                release.sha256,
                cli.data.display()
            );
            Ok(())
        }
        Command::Remove { vault, device } => {
            let store = Store::open(&cli.data)?;
            if store.remove(&vault, &device)? {
                println!("Removed.");
            } else {
                println!("No such device in that vault.");
            }
            Ok(())
        }
    }
}

/// Ctrl+C, or (on Unix) the SIGTERM a container or service manager sends: requests under way
/// finish first, nothing new is taken.
async fn stopped() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The addresses another device reaches this server at, each with the certificate's pin:
/// every non-loopback address when listening on all of them, else the one listened on.
fn app_addresses(listen: SocketAddr, pin: &str) -> Vec<String> {
    let ips = if listen.ip().is_unspecified() {
        let mut ips: Vec<_> = vault_server::tls::local_addresses()
            .into_iter()
            .filter(|ip| !ip.is_loopback() && ip.is_ipv4() == listen.is_ipv4())
            .collect();
        ips.sort();
        ips
    } else {
        vec![listen.ip()]
    };
    ips.into_iter()
        .map(|ip| format!("https://{}#pin={pin}", SocketAddr::new(ip, listen.port())))
        .collect()
}
