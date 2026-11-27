//! Locking with Windows: the session locked (Win+L, a screen saver or a closed lid set to
//! lock), another user taking the console or a remote session disconnected, signing out, and
//! the computer going to sleep or hibernating.
//!
//! Slint owns the app window's messages, so a hidden window of this module's own, on a thread
//! of its own, hears them: `WTSRegisterSessionNotification` for the session, and
//! `WM_POWERBROADCAST` (with `RegisterSuspendResumeNotification`, which also covers Modern
//! Standby) for sleep. The callback runs on that thread before the message is answered, so the
//! app can lock before Windows suspends: Windows gives a suspend about two seconds.

/// What Windows told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The session was locked.
    Locked,
    /// Another user took the console, or a remote session was disconnected.
    Disconnected,
    /// The person is signing out.
    SigningOut,
    /// The computer is going to sleep or hibernate.
    Suspending,
}

/// Starts hearing these for the rest of the process; `on_event` runs on the watching thread.
/// Answers whether it started (once per process: a second call answers `false`).
pub fn watch(on_event: impl Fn(SessionEvent) + Send + Sync + 'static) -> bool {
    imp::watch(Box::new(on_event))
}

#[cfg(windows)]
mod imp {
    use std::sync::{OnceLock, mpsc};

    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Power::RegisterSuspendResumeNotification,
            RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification},
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DispatchMessageW,
            GetMessageW, MSG, PBT_APMSUSPEND, RegisterClassExW, TranslateMessage,
            WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSEXW, WS_OVERLAPPED,
            WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
        },
    };

    use super::SessionEvent;

    type Handler = Box<dyn Fn(SessionEvent) + Send + Sync>;

    /// The one handler of this process.
    static HANDLER: OnceLock<Handler> = OnceLock::new();

    /// The hidden window's class (and title), one per process: nothing else ever finds it by
    /// a fixed name, and a test reaches only its own.
    pub(super) fn class_name() -> String {
        format!("PasswordVault.SessionWatch.{}", std::process::id())
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// What a window message says, if it is one of these.
    pub(super) fn event_of(message: u32, wparam: WPARAM) -> Option<SessionEvent> {
        let code = u32::try_from(wparam).ok()?;
        match (message, code) {
            (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK) => Some(SessionEvent::Locked),
            (WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT) => {
                Some(SessionEvent::Disconnected)
            }
            (WM_WTSSESSION_CHANGE, WTS_SESSION_LOGOFF) => Some(SessionEvent::SigningOut),
            (WM_POWERBROADCAST, PBT_APMSUSPEND) => Some(SessionEvent::Suspending),
            _ => None,
        }
    }

    pub(super) fn watch(handler: Handler) -> bool {
        if HANDLER.set(handler).is_err() {
            return false;
        }
        let (started, answer) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("session-watch".into())
            .spawn(move || run(&started));
        spawned.is_ok() && answer.recv().unwrap_or(false)
    }

    /// Makes the hidden window, signs it up, tells `started` whether that worked, then
    /// dispatches its messages for as long as the process runs.
    fn run(started: &mpsc::Sender<bool>) {
        let class = wide(&class_name());
        // SAFETY: every pointer handed over is either null where the API allows it or points
        // into `class`, `window_class` or `message`, which outlive the calls. The window is
        // this thread's, so its messages are dispatched by the loop below on this thread.
        #[allow(unsafe_code)]
        unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            let mut window_class: WNDCLASSEXW = std::mem::zeroed();
            window_class.cbSize = u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0);
            window_class.lpfnWndProc = Some(window_proc);
            window_class.hInstance = instance;
            window_class.lpszClassName = class.as_ptr();
            if RegisterClassExW(&raw const window_class) == 0 {
                let _ = started.send(false);
                return;
            }
            // A top-level window that is never shown: unlike a message-only window it also
            // gets the broadcast WM_POWERBROADCAST.
            let window = CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null(),
            );
            if window.is_null() {
                let _ = started.send(false);
                return;
            }
            let session = WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) != 0;
            // Kept for the life of the process, like the window.
            let _ = RegisterSuspendResumeNotification(window, DEVICE_NOTIFY_WINDOW_HANDLE);
            let _ = started.send(session);
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&raw mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
    }

    /// The hidden window's messages: the handler runs before the answer goes back. A safe
    /// function, which the class's `unsafe` procedure pointer takes as it is.
    extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if let Some(event) = event_of(message, wparam)
            && let Some(handler) = HANDLER.get()
        {
            // A panic must not unwind into Windows.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(event)));
        }
        if message == WM_POWERBROADCAST {
            return 1;
        }
        // SAFETY: the arguments are the ones Windows passed for this window.
        #[allow(unsafe_code)]
        unsafe {
            DefWindowProcW(window, message, wparam, lparam)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::SessionEvent;

    /// Only the Windows app listens for now; the phone locks when it leaves the screen.
    pub(super) fn watch(_handler: Box<dyn Fn(SessionEvent) + Send + Sync>) -> bool {
        false
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND, SendMessageW, WM_POWERBROADCAST,
        WM_WTSSESSION_CHANGE, WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT,
        WTS_SESSION_LOCK, WTS_SESSION_LOGOFF, WTS_SESSION_UNLOCK,
    };

    use super::*;

    #[test]
    fn what_each_message_means() {
        let session = |code: u32| imp::event_of(WM_WTSSESSION_CHANGE, code as usize);
        assert_eq!(session(WTS_SESSION_LOCK), Some(SessionEvent::Locked));
        assert_eq!(
            session(WTS_CONSOLE_DISCONNECT),
            Some(SessionEvent::Disconnected)
        );
        assert_eq!(
            session(WTS_REMOTE_DISCONNECT),
            Some(SessionEvent::Disconnected)
        );
        assert_eq!(session(WTS_SESSION_LOGOFF), Some(SessionEvent::SigningOut));
        assert_eq!(
            session(WTS_SESSION_UNLOCK),
            None,
            "coming back locks nothing"
        );
        assert_eq!(session(WTS_CONSOLE_CONNECT), None);
        assert_eq!(
            imp::event_of(WM_POWERBROADCAST, PBT_APMSUSPEND as usize),
            Some(SessionEvent::Suspending)
        );
        assert_eq!(
            imp::event_of(WM_POWERBROADCAST, PBT_APMRESUMEAUTOMATIC as usize),
            None
        );
        assert_eq!(imp::event_of(0x0010, WTS_SESSION_LOCK as usize), None);
    }

    /// The hidden window is made and hears what Windows would send it (sent here by hand),
    /// and the handler runs before the message is answered.
    #[test]
    fn the_hidden_window_hears_a_lock_and_a_suspend() {
        let (heard, events) = mpsc::channel();
        assert!(watch(move |event| {
            let _ = heard.send(event);
        }));
        assert!(!watch(|_| {}), "one watch per process");
        let class: Vec<u16> = imp::class_name()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `class` is a NUL-terminated UTF-16 buffer that outlives the calls; the
        // window found is this test's hidden window, and SendMessageW returns once its
        // procedure has run.
        #[allow(unsafe_code)]
        let answer = unsafe {
            let window = FindWindowW(class.as_ptr(), std::ptr::null());
            assert!(!window.is_null(), "the hidden window exists");
            SendMessageW(window, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize, 0);
            SendMessageW(window, WM_POWERBROADCAST, PBT_APMSUSPEND as usize, 0)
        };
        assert_eq!(answer, 1, "a suspend is answered TRUE");
        let wait = Duration::from_secs(5);
        assert_eq!(events.recv_timeout(wait), Ok(SessionEvent::Locked));
        assert_eq!(events.recv_timeout(wait), Ok(SessionEvent::Suspending));
    }
}
