//! The vault's file type: on Windows, `.vault` files show the app's icon and open in it
//! (a double-click, "Open with").
//!
//! Registered for the signed-in user only (`HKEY_CURRENT_USER\Software\Classes`), so no
//! administrator rights are needed and other accounts are left alone. The desktop app does it
//! when it starts, pointing at itself, so a moved app fixes its entry the next time it runs.
//! Nothing is written when the entry is already right; the extension's default program is
//! taken only when no other program has it (otherwise the app is only offered under
//! "Open with").

use std::path::Path;

use anyhow::Result;

/// A vault file's extension (without the dot).
pub const VAULT_EXTENSION: &str = "vault";
/// The file type the extension points at.
pub const PROG_ID: &str = "PasswordVault.Vault";

/// Whether `path` names a vault file, by its extension (its header says for sure, when it is
/// opened).
pub fn is_vault_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(VAULT_EXTENSION))
}

/// One registry value the file type needs: the key under `Classes`, the value's name (`None`
/// for the key's default value) and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub name: Option<String>,
    pub data: String,
}

/// What makes `.vault` open in `exe` with its icon: the file type (its name in Explorer, its
/// icon, how it opens), the extension's "Open with" list, and the app's own entry. The
/// extension's default program is set apart ([`register_vault_files`]).
pub fn entries(exe: &Path, type_name: &str) -> Vec<Entry> {
    let exe_text = exe.display().to_string();
    let exe_name = exe.file_name().map_or_else(
        || "vault-desktop.exe".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let entry = |key: String, name: Option<&str>, data: String| Entry {
        key,
        name: name.map(str::to_owned),
        data,
    };
    vec![
        entry(PROG_ID.to_owned(), None, type_name.to_owned()),
        entry(
            format!(r"{PROG_ID}\DefaultIcon"),
            None,
            format!("\"{exe_text}\",0"),
        ),
        entry(
            format!(r"{PROG_ID}\shell\open\command"),
            None,
            format!("\"{exe_text}\" \"%1\""),
        ),
        entry(
            format!(r".{VAULT_EXTENSION}\OpenWithProgids"),
            Some(PROG_ID),
            String::new(),
        ),
        entry(
            format!(r"Applications\{exe_name}\SupportedTypes"),
            Some(&format!(".{VAULT_EXTENSION}")),
            String::new(),
        ),
    ]
}

/// Makes `.vault` files show the app's icon and open in `exe`, for this user. `type_name` is
/// what Explorer calls the files ("Password vault", in the app's language). Answers whether
/// anything changed; Explorer is then told to redraw its icons.
pub fn register_vault_files(exe: &Path, type_name: &str) -> Result<bool> {
    imp::register(r"Software\Classes", exe, type_name, true)
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use anyhow::{Result, bail};
    use windows_sys::Win32::{
        System::Registry::{
            HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ, RegGetValueW,
            RegSetKeyValueW,
        },
        UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify},
    };

    use super::{PROG_ID, VAULT_EXTENSION, entries};

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A text value, or `None` when the key or the value is missing (or not text).
    pub(super) fn read(root: HKEY, key: &str, name: Option<&str>) -> Option<String> {
        let key = wide(key);
        let name = name.map(wide);
        let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
        let mut buffer = vec![0u16; 1024];
        let mut bytes = u32::try_from(buffer.len() * 2).ok()?;
        // SAFETY: `key` and `name` are NUL-terminated UTF-16 buffers that outlive the call (a
        // null name reads the key's default value); `buffer` has room for `bytes` bytes, and
        // the call writes at most that many and sets `bytes` to what it wrote.
        #[allow(unsafe_code)]
        let status = unsafe {
            RegGetValueW(
                root,
                key.as_ptr(),
                name_ptr,
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &raw mut bytes,
            )
        };
        if status != 0 {
            return None;
        }
        let chars = (bytes as usize / 2).min(buffer.len());
        let text = &buffer[..chars];
        let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        Some(String::from_utf16_lossy(&text[..end]))
    }

    pub(super) fn write(key: &str, name: Option<&str>, data: &str) -> Result<()> {
        let key_w = wide(key);
        let name = name.map(wide);
        let name_ptr = name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr());
        let value = wide(data);
        let Ok(bytes) = u32::try_from(value.len() * 2) else {
            bail!("registry value too long");
        };
        // SAFETY: `key_w`, `name` and `value` are NUL-terminated UTF-16 buffers that outlive
        // the call; `bytes` is the size of `value` in bytes. The call creates the key when it
        // is missing; a null name sets the key's default value.
        #[allow(unsafe_code)]
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key_w.as_ptr(),
                name_ptr,
                REG_SZ,
                value.as_ptr().cast(),
                bytes,
            )
        };
        if status != 0 {
            bail!("registering the vault file type failed (Windows error {status})");
        }
        Ok(())
    }

    /// Writes the entries under `base` (in `HKEY_CURRENT_USER`) that aren't right yet. With
    /// `live`, the extension's current program is read as Windows sees it (the user's and the
    /// computer's entries together) and Explorer is told when something changed.
    pub(super) fn register(base: &str, exe: &Path, type_name: &str, live: bool) -> Result<bool> {
        let mut changed = false;
        for entry in entries(exe, type_name) {
            let key = format!(r"{base}\{}", entry.key);
            let name = entry.name.as_deref();
            if read(HKEY_CURRENT_USER, &key, name).as_deref() != Some(entry.data.as_str()) {
                write(&key, name, &entry.data)?;
                changed = true;
            }
        }
        // The extension's default program: this app, unless another program has it.
        let extension = format!(".{VAULT_EXTENSION}");
        let current = if live {
            read(HKEY_CLASSES_ROOT, &extension, None)
        } else {
            read(HKEY_CURRENT_USER, &format!(r"{base}\{extension}"), None)
        };
        if current.as_deref().is_none_or(str::is_empty) {
            write(&format!(r"{base}\{extension}"), None, PROG_ID)?;
            changed = true;
        }
        if changed && live {
            // SAFETY: SHCNE_ASSOCCHANGED takes no items; both pointers may be null.
            // The event id is 0x0800_0000, which fits in the i32 the function takes.
            #[allow(unsafe_code)]
            unsafe {
                SHChangeNotify(
                    SHCNE_ASSOCCHANGED as i32,
                    SHCNF_IDLIST,
                    std::ptr::null(),
                    std::ptr::null(),
                );
            }
        }
        Ok(changed)
    }

    #[cfg(test)]
    pub(super) fn delete_tree(key: &str) {
        use windows_sys::Win32::System::Registry::RegDeleteTreeW;
        let key = wide(key);
        // SAFETY: `key` is a NUL-terminated UTF-16 buffer that outlives the call; the tests
        // only remove the throwaway key they made.
        #[allow(unsafe_code)]
        unsafe {
            RegDeleteTreeW(HKEY_CURRENT_USER, key.as_ptr());
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use anyhow::Result;

    /// Only Windows keeps file types this way; elsewhere nothing is written.
    pub(super) fn register(
        _base: &str,
        _exe: &Path,
        _type_name: &str,
        _live: bool,
    ) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn vault_files_by_their_extension() {
        assert!(is_vault_file(Path::new(r"C:\vaults\demo.vault")));
        assert!(is_vault_file(Path::new("Demo.VAULT")));
        assert!(!is_vault_file(Path::new("export.vaultx")));
        assert!(!is_vault_file(Path::new("vault")));
        assert!(!is_vault_file(Path::new("notes.txt")));
    }

    #[test]
    fn the_entries_point_at_the_app() {
        let exe = Path::new(r"C:\Program Files\Vault\vault-desktop.exe");
        let all = entries(exe, "Password vault");
        let find = |key: &str| all.iter().find(|e| e.key == key).unwrap();
        assert_eq!(find(PROG_ID).data, "Password vault");
        assert_eq!(
            find(r"PasswordVault.Vault\shell\open\command").data,
            r#""C:\Program Files\Vault\vault-desktop.exe" "%1""#,
            "the path and the file both quoted (spaces)"
        );
        assert_eq!(
            find(r"PasswordVault.Vault\DefaultIcon").data,
            r#""C:\Program Files\Vault\vault-desktop.exe",0"#
        );
        assert_eq!(
            find(r".vault\OpenWithProgids").name.as_deref(),
            Some(PROG_ID)
        );
        assert!(
            all.iter()
                .any(|e| e.key == r"Applications\vault-desktop.exe\SupportedTypes")
        );
    }

    /// Written under a throwaway key of this user's, then removed: what is written, that a
    /// second run writes nothing, that a moved app is fixed, and that another program's
    /// extension is left alone.
    #[cfg(windows)]
    #[test]
    fn registers_once_and_follows_the_app() {
        use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let root = format!(
            r"Software\vault-file-types-test-{}-{nanos}",
            std::process::id()
        );
        let base = format!(r"{root}\Classes");
        let exe = Path::new(r"C:\Apps\vault-desktop.exe");
        let outcome = (|| -> Result<()> {
            assert!(imp::register(&base, exe, "Password vault", false)?);
            assert_eq!(
                imp::read(HKEY_CURRENT_USER, &format!(r"{base}\.vault"), None).as_deref(),
                Some(PROG_ID)
            );
            assert_eq!(
                imp::read(
                    HKEY_CURRENT_USER,
                    &format!(r"{base}\{PROG_ID}\shell\open\command"),
                    None
                )
                .as_deref(),
                Some(r#""C:\Apps\vault-desktop.exe" "%1""#)
            );
            assert!(
                !imp::register(&base, exe, "Password vault", false)?,
                "nothing to change the second time"
            );
            let moved = Path::new(r"D:\Vault\vault-desktop.exe");
            assert!(imp::register(&base, moved, "Password vault", false)?);
            assert_eq!(
                imp::read(
                    HKEY_CURRENT_USER,
                    &format!(r"{base}\{PROG_ID}\DefaultIcon"),
                    None
                )
                .as_deref(),
                Some(r#""D:\Vault\vault-desktop.exe",0"#)
            );
            Ok(())
        })();
        imp::delete_tree(&root);
        outcome.unwrap();

        // Another program's extension stays its own; the app is only offered.
        let other_root = format!("{root}-other");
        let other = format!(r"{other_root}\Classes");
        let outcome = (|| -> Result<()> {
            imp::write(&format!(r"{other}\.vault"), None, "Another.Program")?;
            imp::register(&other, exe, "Password vault", false)?;
            assert_eq!(
                imp::read(HKEY_CURRENT_USER, &format!(r"{other}\.vault"), None).as_deref(),
                Some("Another.Program")
            );
            assert_eq!(
                imp::read(
                    HKEY_CURRENT_USER,
                    &format!(r"{other}\.vault\OpenWithProgids"),
                    Some(PROG_ID)
                )
                .as_deref(),
                Some(""),
                "offered under Open with"
            );
            Ok(())
        })();
        imp::delete_tree(&other_root);
        outcome.unwrap();
    }
}
