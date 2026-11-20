//! The `vault-server` command: serve, make an invite, list or remove devices.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use vault_server::Store;

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
    /// Serve the API. Put HTTPS in front (tailscale serve, Caddy) and keep it off the open
    /// internet: see docs/SERVER.md.
    Serve {
        #[arg(long, env = "VAULT_SERVER_LISTEN", default_value = "127.0.0.1:8750")]
        listen: SocketAddr,
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
        Command::Serve { listen } => {
            if !listen.ip().is_loopback() {
                eprintln!(
                    "vault-server: listening on {listen}. Keep this port off the open internet \
                     (a Tailscale or WireGuard network, HTTPS in front)."
                );
            }
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("listening on {listen}"))?;
            eprintln!("vault-server: serving {} on {listen}", cli.data.display());
            vault_server::serve(&cli.data, listener, async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
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
