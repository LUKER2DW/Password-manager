//! What a device reads back from a sync place and from GitHub's release list (THREAT_MODEL
//! A2): a vault server's JSON answers, a WebDAV host's PROPFIND listing, a release and the
//! versions it names. A server that lies gets an error or nothing, never a panic; a release
//! taken always names a version and github.com.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_sync_wire::{
    self as wire, AppRelease, Changes, Copies, EnrolledDevice, Invite, Refusal, releases::Release,
};

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else {
        return;
    };
    match pick % 4 {
        0 => {
            if let Ok(copies) = serde_json::from_slice::<Copies>(rest) {
                for copy in &copies.copies {
                    let _ = vault_core::sync::DeviceId::from_hex(&copy.device);
                }
            }
            let _ = serde_json::from_slice::<Changes>(rest);
            let _ = serde_json::from_slice::<Vec<EnrolledDevice>>(rest);
            let _ = serde_json::from_slice::<Refusal>(rest);
            let _ = serde_json::from_slice::<AppRelease>(rest);
            if let Ok(invite) = serde_json::from_slice::<Invite>(rest) {
                let _ = wire::is_id(&invite.invite);
            }
        }
        1 => {
            if let Some(release) = Release::parse(rest) {
                assert!(wire::parse_version(&release.version).is_some());
                assert!(release.page.starts_with("https://github.com/"));
                let _ = release.phone_package();
                let _ = release.extension_package();
                let _ = release.is_newer_than("0.4.7");
            }
        }
        2 => {
            if let Ok(listed) = vault_platform::sync::webdav::parse_listing(rest) {
                for copy in listed {
                    assert_eq!(copy.device.to_hex().len(), 32);
                }
            }
        }
        _ => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return;
            };
            let (a, b) = text.split_once(' ').unwrap_or((text, ""));
            let _ = wire::parse_version(a);
            let _ = wire::is_newer(a, b);
        }
    }
});
