//! Starting the desktop app when the person signs in to Windows (Settings → Appearance).
//!
//! One value in this user's `Run` key (`HKEY_CURRENT_USER\Software\Microsoft\Windows\
//! CurrentVersion\Run`): no administrator rights, other accounts are left alone, and Task
//! Manager's Startup apps (and Settings → Apps → Startup) list it like any other. The registry
//! is the only record of the setting, so the app shows what Windows will do: an entry turned
//! off there (Windows marks it in `…\Explorer\StartupApproved\Run`) shows as off in the app,
//! and turning it on in the app clears that mark.
//!
//! The command ends with [`ARG`]: the app then knows Windows started it and, when the person
//! chose so, stays in the notification area instead of opening its window. It starts locked
//! like any start; nothing is unlocked at sign-in.

use std::{ffi::OsStr, path::Path};

use anyhow::Result;

/// The argument the start at sign-in passes to the app.
pub const ARG: &str = "--at-sign-in";
/// The entry's name in the `Run` key.
pub const NAME: &str = "PasswordVault";

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

/// The command Windows runs: the program, quoted (its path may have spaces), then [`ARG`].
pub fn command(exe: &Path) -> String {
    format!("\"{}\" {ARG}", exe.display())
}

/// Whether the program's arguments (without its own name) say Windows started it at sign-in.
pub fn is_sign_in_start<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter().any(|arg| arg.as_ref() == OsStr::new(ARG))
}

/// Whether Windows starts the app at sign-in: the entry is there and not turned off.
pub fn is_on() -> bool {
    imp::is_on(RUN, APPROVED)
}

/// Turns the start at sign-in on (starting `exe`) or off.
pub fn set(exe: &Path, on: bool) -> Result<()> {
    imp::set(RUN, APPROVED, exe, on)
}

/// Points an existing entry at `exe` when it names another program file: the app was moved,
/// or a newer copy downloaded and run (or another program put itself there: the app tells the
/// person which program it replaced). Whether it is turned on stays as it was; without an entry
/// nothing is written. Answers the program the entry started before, when it changed.
pub fn follow(exe: &Path) -> Result<Option<String>> {
    imp::follow(RUN, exe)
}

/// The program a command starts: its first part, without the quotes around it.
pub fn program_of(command: &str) -> &str {
    let command = command.trim();
    if let Some(quoted) = command.strip_prefix('"') {
        quoted.split('"').next().unwrap_or_default()
    } else {
        command.split_whitespace().next().unwrap_or_default()
    }
}

/// Whether a `StartupApproved` value says the entry is turned off. Windows writes 12 bytes:
/// the first is even while the entry is on (2, or 6) and odd once turned off (3, or 7),
/// followed by the time it was turned off. A missing value means on.
fn turned_off(data: &[u8]) -> bool {
    data.first().is_some_and(|first| first & 1 == 1)
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use anyhow::Result;
    use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;

    use super::{NAME, command, program_of, turned_off};
    use crate::registry;

    pub(super) fn is_on(run: &str, approved: &str) -> bool {
        registry::read_text(HKEY_CURRENT_USER, run, Some(NAME))
            .is_some_and(|command| !command.trim().is_empty())
            && !registry::read_bytes(approved, NAME).is_some_and(|data| turned_off(&data))
    }

    pub(super) fn set(run: &str, approved: &str, exe: &Path, on: bool) -> Result<()> {
        if on {
            registry::write_text(run, Some(NAME), &command(exe))?;
        } else {
            registry::delete_value(run, NAME)?;
        }
        // Turned off in Task Manager before: turning it on here means on. Turned off here, the
        // mark has nothing left to mark.
        registry::delete_value(approved, NAME)
    }

    pub(super) fn follow(run: &str, exe: &Path) -> Result<Option<String>> {
        let wanted = command(exe);
        match registry::read_text(HKEY_CURRENT_USER, run, Some(NAME)) {
            Some(current) if !current.trim().is_empty() && current != wanted => {
                registry::write_text(run, Some(NAME), &wanted)?;
                Ok(Some(program_of(&current).to_owned()))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use anyhow::{Result, bail};

    /// Only the Windows app starts at sign-in for now.
    pub(super) fn is_on(_run: &str, _approved: &str) -> bool {
        false
    }

    pub(super) fn set(_run: &str, _approved: &str, _exe: &Path, on: bool) -> Result<()> {
        if on {
            bail!("starting at sign-in is set up only on Windows for now");
        }
        Ok(())
    }

    pub(super) fn follow(_run: &str, _exe: &Path) -> Result<Option<String>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn the_command_quotes_the_program() {
        assert_eq!(
            command(Path::new(r"C:\Program Files\Vault\vault-desktop.exe")),
            r#""C:\Program Files\Vault\vault-desktop.exe" --at-sign-in"#
        );
    }

    #[test]
    fn a_start_at_sign_in_by_its_argument() {
        assert!(is_sign_in_start(["--at-sign-in"]));
        assert!(!is_sign_in_start(Vec::<String>::new()));
        assert!(!is_sign_in_start([r"C:\vaults\home.vault"]));
        assert!(
            !is_sign_in_start(["--at-sign-in-later"]),
            "the whole argument, not a prefix"
        );
    }

    #[test]
    fn the_program_of_a_command() {
        assert_eq!(
            program_of(r#""C:\Program Files\Vault\vault-desktop.exe" --at-sign-in"#),
            r"C:\Program Files\Vault\vault-desktop.exe"
        );
        assert_eq!(
            program_of(r"C:\Apps\other.exe --hidden"),
            r"C:\Apps\other.exe"
        );
        assert_eq!(program_of("  "), "");
    }

    #[test]
    fn task_managers_mark() {
        assert!(!turned_off(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!turned_off(&[6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(turned_off(&[3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]));
        assert!(turned_off(&[7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!turned_off(&[]), "no mark: on");
    }

    /// Written under throwaway keys of this user's, then removed: on, turned off in Task
    /// Manager, on again, following a moved app, and off.
    #[cfg(windows)]
    #[test]
    fn on_off_and_follows_the_app() {
        use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;

        use crate::registry;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let root = format!(
            r"Software\vault-autostart-test-{}-{nanos}",
            std::process::id()
        );
        let run = format!(r"{root}\Run");
        let approved = format!(r"{root}\StartupApproved");
        let exe = Path::new(r"C:\Apps\vault-desktop.exe");
        let outcome = (|| -> Result<()> {
            assert!(!imp::is_on(&run, &approved));
            assert_eq!(imp::follow(&run, exe)?, None, "no entry: nothing written");
            assert!(registry::read_text(HKEY_CURRENT_USER, &run, Some(NAME)).is_none());

            imp::set(&run, &approved, exe, true)?;
            assert!(imp::is_on(&run, &approved));
            assert_eq!(
                registry::read_text(HKEY_CURRENT_USER, &run, Some(NAME)).as_deref(),
                Some(r#""C:\Apps\vault-desktop.exe" --at-sign-in"#)
            );

            // Turned off in Task Manager: off here too, until turned on here.
            write_mark(&approved, &[3, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
            assert!(!imp::is_on(&run, &approved));
            imp::set(&run, &approved, exe, true)?;
            assert!(imp::is_on(&run, &approved));
            assert!(registry::read_bytes(&approved, NAME).is_none());

            assert_eq!(imp::follow(&run, exe)?, None, "already this program");
            let moved = Path::new(r"D:\Vault\vault-desktop.exe");
            assert_eq!(
                imp::follow(&run, moved)?.as_deref(),
                Some(r"C:\Apps\vault-desktop.exe"),
                "what it started before, to tell the person"
            );
            assert_eq!(
                registry::read_text(HKEY_CURRENT_USER, &run, Some(NAME)).as_deref(),
                Some(r#""D:\Vault\vault-desktop.exe" --at-sign-in"#)
            );

            imp::set(&run, &approved, moved, false)?;
            assert!(!imp::is_on(&run, &approved));
            assert!(registry::read_text(HKEY_CURRENT_USER, &run, Some(NAME)).is_none());
            imp::set(&run, &approved, moved, false)?;
            Ok(())
        })();
        registry::delete_tree(&root);
        outcome.unwrap();
    }

    /// Writes a binary value the way Task Manager does.
    #[cfg(windows)]
    fn write_mark(key: &str, data: &[u8]) {
        use windows_sys::Win32::System::Registry::{
            HKEY_CURRENT_USER, REG_BINARY, RegSetKeyValueW,
        };

        let key: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let name: Vec<u16> = NAME.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `key` and `name` are NUL-terminated UTF-16 buffers and `data` is `data.len()`
        // bytes, all alive for the call; it writes under the test's throwaway key.
        #[allow(unsafe_code)]
        let status = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                REG_BINARY,
                data.as_ptr().cast(),
                u32::try_from(data.len()).unwrap(),
            )
        };
        assert_eq!(status, 0);
    }
}
