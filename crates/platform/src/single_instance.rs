//! One running copy of the desktop app per person: started again (Explorer, a shortcut, the
//! Start menu), it brings the running copy's window to the front and ends, instead of a second
//! copy with its own icon by the clock, its own extension channel and its own timers. That
//! matters most once the app starts at sign-in and waits in the notification area.
//!
//! A named event in this sign-in session (`Local\`) marks the running copy and carries the
//! call to show itself. Its name holds a digest of the app's folder, so a test run with a
//! `VAULT_HOME` of its own is a copy of its own. Malware running as the same user could make
//! that event first and so keep the app from opening; it could as well end the app, so this
//! adds nothing it couldn't already do (THREAT_MODEL.md).

use std::path::Path;

use sha2::{Digest, Sha256};

/// What [`claim`] found.
#[allow(missing_debug_implementations)]
pub enum Claim {
    /// This is the only copy: keep the [`Instance`] for as long as the app runs.
    First(Instance),
    /// Another copy runs, and was asked to show its window: this one should end.
    Running,
}

/// The running copy's mark; [`Instance::when_called`] answers the next copies.
#[allow(missing_debug_implementations)]
pub struct Instance {
    #[cfg(windows)]
    event: Option<imp::Event>,
}

/// The event's name for the app folder `app_dir`.
pub fn event_name(app_dir: &Path) -> String {
    let folder = app_dir.to_string_lossy().to_lowercase();
    let digest = Sha256::digest(folder.as_bytes());
    let short: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!(r"Local\PasswordVault.Running.{short}")
}

/// Marks this copy as the running one, or asks the copy already running to show itself.
pub fn claim(app_dir: &Path) -> Claim {
    imp::claim(&event_name(app_dir))
}

impl Instance {
    /// Calls `on_call` (on a thread of its own) each time another copy asks this one to show
    /// itself.
    pub fn when_called(self, on_call: impl Fn() + Send + 'static) {
        #[cfg(windows)]
        if let Some(event) = self.event {
            imp::listen(event, on_call);
        }
        #[cfg(not(windows))]
        let _ = on_call;
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, WAIT_OBJECT_0},
        System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForSingleObject},
        UI::WindowsAndMessaging::{ASFW_ANY, AllowSetForegroundWindow},
    };

    use super::{Claim, Instance};

    /// The event's handle, closed when dropped.
    pub(super) struct Event(HANDLE);

    // SAFETY: a kernel object's handle is valid on every thread of the process; only the
    // waiting thread uses it once it is handed over.
    #[allow(unsafe_code)]
    unsafe impl Send for Event {}

    impl Event {
        /// The handle, for a call (the closure then holds the whole `Event`, which closes it).
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateEventW and is closed only here, once.
            #[allow(unsafe_code)]
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub(super) fn claim(name: &str) -> Claim {
        let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `name` is a NUL-terminated UTF-16 buffer that outlives the call; no security
        // attributes (the session's defaults), an auto-reset event, not signalled.
        #[allow(unsafe_code)]
        let (handle, error) = unsafe {
            let handle = CreateEventW(std::ptr::null(), 0, 0, name.as_ptr());
            (handle, GetLastError())
        };
        if handle.is_null() {
            // The mark couldn't be made: run as before, without it.
            return Claim::First(Instance { event: None });
        }
        let event = Event(handle);
        if error != ERROR_ALREADY_EXISTS {
            return Claim::First(Instance { event: Some(event) });
        }
        // SAFETY: the handle is open (closed when `event` drops); ASFW_ANY lets the running
        // copy bring its window to the front, which Windows allows only with this copy's leave.
        #[allow(unsafe_code)]
        unsafe {
            AllowSetForegroundWindow(ASFW_ANY);
            SetEvent(event.raw());
        }
        Claim::Running
    }

    pub(super) fn listen(event: Event, on_call: impl Fn() + Send + 'static) {
        std::thread::spawn(move || {
            loop {
                // SAFETY: the handle stays open while this thread owns `event`.
                #[allow(unsafe_code)]
                let woke = unsafe { WaitForSingleObject(event.raw(), INFINITE) };
                if woke != WAIT_OBJECT_0 {
                    return;
                }
                on_call();
            }
        });
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Claim, Instance};

    /// Only the Windows app keeps to one copy for now.
    pub(super) fn claim(_name: &str) -> Claim {
        Claim::First(Instance {})
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn one_name_per_app_folder() {
        let home = event_name(Path::new(r"C:\Users\Test\AppData\Local\vault"));
        assert!(home.starts_with(r"Local\PasswordVault.Running."));
        assert_eq!(home.len(), r"Local\PasswordVault.Running.".len() + 16);
        assert_eq!(
            home,
            event_name(Path::new(r"c:\users\test\appdata\local\VAULT")),
            "Windows paths ignore case"
        );
        assert_ne!(home, event_name(Path::new(r"D:\portable\vault")));
        assert!(!home[r"Local\".len()..].contains('\\'));
    }

    /// The second copy finds the first and asks it to show itself; the first hears it.
    #[cfg(windows)]
    #[test]
    fn the_second_copy_calls_the_first() {
        let folder = std::env::temp_dir().join(format!(
            "vault-single-instance-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let Claim::First(first) = claim(&folder) else {
            panic!("nothing else runs with this folder");
        };
        let (calls, heard) = std::sync::mpsc::channel();
        first.when_called(move || {
            let _ = calls.send(());
        });
        assert!(matches!(claim(&folder), Claim::Running));
        heard
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the first copy was called");
        assert!(matches!(claim(&folder), Claim::Running), "still running");
        heard
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("called again");
    }
}
