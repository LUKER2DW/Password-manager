//! The `vault-server` command: serve, make an invite, list or remove devices.

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
    /// Make a one-time invite for a device to join a vault (the first device of a new vault,
    /// or one that lost its key). More devices are better invited from a device already in.
    Invite {
        /// How long it stays good.
        #[arg(long, default_value_t = 24)]
        hours: i64,
    },
    /// List the vaults and their devices.
    List,
    /// Take a device out of a vault: its key and its copy.
    Remove { vault: String, device: String },
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
            let stop = async {
                let _ = tokio::signal::ctrl_c().await;
            };
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
            vault_server::serve_tls(&cli.data, listener, std::sync::Arc::new(tls), stop).await
        }
        Command::Invite { hours } => {
            let (invite, expires_at) = vault_server::admin_invite(&cli.data, hours)?;
            println!("{invite}");
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
