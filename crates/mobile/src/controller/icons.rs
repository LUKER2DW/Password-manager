//! Website icons on the phone, when turned on in Settings: the desktop's fetcher and cache
//! (`vault_platform::website_icons`, where its privacy model is written down). Each saved
//! site is asked once, directly, for its icon; what was found is kept in a file sealed with
//! the vault's key, next to the phone's copy of the vault. In a browser (the web preview)
//! there are none.

use slint::Image;

use super::Controller;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::{collections::HashMap, path::PathBuf};

    use slint::{Image, Rgba8Pixel, SharedPixelBuffer};
    use vault_core::storage;
    use vault_platform::website_icons::{self as icons, Fetched, IconCache};

    use super::super::{CURRENT, Controller};

    #[derive(Debug, Default)]
    pub(in crate::controller) struct Icons {
        cache: IconCache,
        images: HashMap<String, Image>,
        fetching: bool,
    }

    /// The cache key of a website (`www.` and the scheme left out), if it is one.
    pub(in crate::controller) fn key(url: &str) -> Option<String> {
        icons::host_of(url).map(|host| icons::cache_key(&host))
    }

    impl Controller {
        fn icon_cache_path(&self) -> Option<PathBuf> {
            let state = self.state.borrow();
            let id = state.vault.as_ref()?.id_hex();
            Some(state.path.with_file_name(format!("icons-{id}.cache")))
        }

        /// Reads the sealed cache once the vault is open (nothing, if icons are off).
        pub(in crate::controller) fn load_icons(&self) {
            let loaded = self.icon_cache_path().and_then(|path| {
                let sealed = std::fs::read(path).ok()?;
                let state = self.state.borrow();
                let plain = state.vault.as_ref()?.open_local("icons", &sealed).ok()?;
                IconCache::from_bytes(&plain)
            });
            let mut icons = self.icons.borrow_mut();
            icons.cache = loaded.unwrap_or_default();
            icons.images.clear();
        }

        fn save_icons(&self) {
            let Some(path) = self.icon_cache_path() else {
                return;
            };
            let sealed = {
                let state = self.state.borrow();
                let Some(vault) = state.vault.as_ref() else {
                    return;
                };
                vault.seal_local("icons", &self.icons.borrow().cache.to_bytes())
            };
            if let Ok(sealed) = sealed {
                let _ = storage::write_atomic(&path, &sealed);
            }
        }

        /// Turning icons off forgets them on this phone too.
        pub(in crate::controller) fn forget_icons(&self) {
            if let Some(path) = self.icon_cache_path() {
                let _ = std::fs::remove_file(storage::backup_path(&path));
                let _ = std::fs::remove_file(path);
            }
            let mut icons = self.icons.borrow_mut();
            icons.cache = IconCache::default();
            icons.images.clear();
        }

        /// The icon of a website, when icons are on and one was found for it.
        pub(in crate::controller) fn icon_for(&self, url: &str) -> Option<Image> {
            if !self.state.borrow().prefs.website_icons {
                return None;
            }
            let key = key(url)?;
            let mut icons = self.icons.borrow_mut();
            if let Some(image) = icons.images.get(&key) {
                return Some(image.clone());
            }
            let pixels = icons.cache.get(&key)?.to_vec();
            let image = Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
                &pixels,
                icons::ICON_SIZE,
                icons::ICON_SIZE,
            ));
            icons.images.insert(key, image.clone());
            Some(image)
        }

        /// Asks the sites that have no icon yet, one after the other, off the UI thread. Not
        /// while testing (`inline`): tests never go out to the network.
        pub(in crate::controller) fn fetch_icons(&self) {
            let sites: Vec<String> = {
                let state = self.state.borrow();
                let Some(vault) = state.vault.as_ref() else {
                    return;
                };
                if !state.prefs.website_icons || state.inline || self.icons.borrow().fetching {
                    return;
                }
                let icons = self.icons.borrow();
                let mut sites: Vec<String> = vault
                    .summaries()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|item| key(&item.url))
                    .filter(|key| icons.cache.needs_fetch(key))
                    .collect();
                sites.sort();
                sites.dedup();
                sites
            };
            if sites.is_empty() {
                return;
            }
            self.icons.borrow_mut().fetching = true;
            std::thread::spawn(move || {
                for site in sites {
                    let icon = icons::fetch(&site);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(c) = CURRENT.with(|current| current.borrow().upgrade()) {
                            c.icon_fetched(site, icon);
                        }
                    });
                }
                let _ = slint::invoke_from_event_loop(|| {
                    if let Some(c) = CURRENT.with(|current| current.borrow().upgrade()) {
                        c.icons.borrow_mut().fetching = false;
                        c.save_icons();
                    }
                });
            });
        }

        fn icon_fetched(&self, site: String, icon: Fetched) {
            if self.state.borrow().vault.is_none() {
                return; // locked meanwhile
            }
            let shows = icon.shows();
            {
                let mut icons = self.icons.borrow_mut();
                icons.images.remove(&site);
                icons.cache.insert(site, icon);
            }
            if shows {
                self.refresh_list();
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod native {
    use slint::Image;

    use super::super::Controller;

    #[derive(Debug, Default)]
    pub(in crate::controller) struct Icons;

    impl Controller {
        pub(in crate::controller) fn load_icons(&self) {}
        pub(in crate::controller) fn forget_icons(&self) {}
        pub(in crate::controller) fn fetch_icons(&self) {}
        pub(in crate::controller) fn icon_for(&self, _url: &str) -> Option<Image> {
            None
        }
    }
}

pub(super) use native::Icons;

impl Controller {
    /// An item's picture: its website's icon, or (`None`) its initial on a colour.
    pub(super) fn picture(&self, url: &str) -> (Image, bool) {
        match self.icon_for(url) {
            Some(image) => (image, true),
            None => (Image::default(), false),
        }
    }
}
