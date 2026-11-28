//! Shortcuts that work from any program (Windows): the desktop app's quick search and its lock,
//! each one of a few fixed key combinations the person picks in Settings (none taken by
//! Windows itself). Windows hands a pressed combination to the one program that registered it
//! (`RegisterHotKey`); one already taken by another program can't be registered, and the app
//! says so.
//!
//! A thread of its own registers them and waits for them; dropping [`Hotkeys`] ends it, and the
//! combinations are free again. A program running as the person could press them too, which
//! only shows the app's window or locks it.

/// A combination a shortcut can be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Combo {
    CtrlShiftSpace,
    CtrlAltSpace,
    CtrlAltL,
    CtrlShiftL,
}

impl Combo {
    /// The combinations Settings offers for the quick search (after "Off"), in order.
    pub const QUICK: [Combo; 2] = [Combo::CtrlShiftSpace, Combo::CtrlAltSpace];
    /// The combinations Settings offers for locking (after "Off"), in order.
    pub const LOCK: [Combo; 2] = [Combo::CtrlAltL, Combo::CtrlShiftL];

    /// How the keys are written on screen (the same in every language).
    pub fn label(self) -> &'static str {
        match self {
            Combo::CtrlShiftSpace => "Ctrl+Shift+Space",
            Combo::CtrlAltSpace => "Ctrl+Alt+Space",
            Combo::CtrlAltL => "Ctrl+Alt+L",
            Combo::CtrlShiftL => "Ctrl+Shift+L",
        }
    }

    /// Windows' modifier flags and virtual key.
    #[cfg(windows)]
    fn keys(self) -> (u32, u32) {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, VK_L, VK_SPACE,
        };
        let (mods, key) = match self {
            Combo::CtrlShiftSpace => (MOD_CONTROL | MOD_SHIFT, VK_SPACE),
            Combo::CtrlAltSpace => (MOD_CONTROL | MOD_ALT, VK_SPACE),
            Combo::CtrlAltL => (MOD_CONTROL | MOD_ALT, VK_L),
            Combo::CtrlShiftL => (MOD_CONTROL | MOD_SHIFT, VK_L),
        };
        (mods | MOD_NOREPEAT, u32::from(key))
    }
}

/// The choice Settings stores (0 off, then the list's combinations from 1) as a combination.
pub fn chosen(list: &[Combo], choice: u8) -> Option<Combo> {
    usize::from(choice)
        .checked_sub(1)
        .and_then(|i| list.get(i).copied())
}

/// The shortcuts registered, until dropped.
#[allow(missing_debug_implementations)]
pub struct Hotkeys {
    #[cfg(windows)]
    thread: u32,
    #[cfg(windows)]
    join: Option<std::thread::JoinHandle<()>>,
}

/// Registers each `(id, combination)` and calls `on_press(id)` (on the hotkeys' thread) each time
/// one is pressed, in any program. Returns the ids that couldn't be registered (another program
/// holds that combination) with the handle that keeps the others.
pub fn register(
    shortcuts: &[(i32, Combo)],
    on_press: impl Fn(i32) + Send + 'static,
) -> (Hotkeys, Vec<i32>) {
    imp::register(shortcuts, on_press)
}

#[cfg(windows)]
mod imp {
    use std::sync::mpsc;

    use windows_sys::Win32::{
        System::Threading::GetCurrentThreadId,
        UI::{
            Input::KeyboardAndMouse::{RegisterHotKey, UnregisterHotKey},
            WindowsAndMessaging::{
                GetMessageW, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, WM_HOTKEY, WM_QUIT,
            },
        },
    };

    use super::{Combo, Hotkeys};

    pub(super) fn register(
        shortcuts: &[(i32, Combo)],
        on_press: impl Fn(i32) + Send + 'static,
    ) -> (Hotkeys, Vec<i32>) {
        let every: Vec<i32> = shortcuts.iter().map(|(id, _)| *id).collect();
        let shortcuts = shortcuts.to_vec();
        let (ready, started) = mpsc::channel();
        let join = std::thread::spawn(move || {
            // SAFETY: a zeroed MSG is a valid value to be written into.
            #[allow(unsafe_code)]
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            // SAFETY: `msg` is valid for writes; PM_NOREMOVE only makes the thread's message
            // queue, so the thread can be sent WM_QUIT from the moment its id is known.
            #[allow(unsafe_code)]
            let thread = unsafe {
                PeekMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0, PM_NOREMOVE);
                GetCurrentThreadId()
            };
            let mut held = Vec::new();
            let mut taken = Vec::new();
            for (id, combo) in &shortcuts {
                let (mods, key) = combo.keys();
                // SAFETY: no window: the shortcut is posted to this thread's queue; plain values.
                #[allow(unsafe_code)]
                let ok = unsafe { RegisterHotKey(std::ptr::null_mut(), *id, mods, key) } != 0;
                if ok {
                    held.push(*id);
                } else {
                    taken.push(*id);
                }
            }
            if ready.send((thread, taken)).is_err() {
                return;
            }
            loop {
                // SAFETY: `msg` is valid for writes; every message of this thread's queue.
                #[allow(unsafe_code)]
                let got = unsafe { GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) };
                if got <= 0 {
                    break; // WM_QUIT, or an error
                }
                if msg.message == WM_HOTKEY {
                    on_press(i32::try_from(msg.wParam).unwrap_or(-1));
                }
            }
            for id in held {
                // SAFETY: registered above by this thread, without a window.
                #[allow(unsafe_code)]
                unsafe {
                    UnregisterHotKey(std::ptr::null_mut(), id);
                }
            }
        });
        let (thread, taken) = started.recv().unwrap_or((0, every));
        let join = (thread != 0).then_some(join);
        (Hotkeys { thread, join }, taken)
    }

    impl Drop for Hotkeys {
        /// Ends the thread and waits for it, so the combinations are free again on return (to
        /// be registered anew at once, with other choices).
        fn drop(&mut self) {
            if self.thread != 0 {
                // SAFETY: plain values; a thread that ended already just makes this fail.
                #[allow(unsafe_code)]
                unsafe {
                    PostThreadMessageW(self.thread, WM_QUIT, 0, 0);
                }
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{Combo, Hotkeys};

    /// Other systems have no shortcuts from other programs yet: none is registered.
    pub(super) fn register(
        shortcuts: &[(i32, Combo)],
        _on_press: impl Fn(i32) + Send + 'static,
    ) -> (Hotkeys, Vec<i32>) {
        (Hotkeys {}, shortcuts.iter().map(|(id, _)| *id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_choices_map_to_combinations() {
        assert_eq!(chosen(&Combo::QUICK, 0), None, "off");
        assert_eq!(chosen(&Combo::QUICK, 1), Some(Combo::CtrlShiftSpace));
        assert_eq!(chosen(&Combo::LOCK, 2), Some(Combo::CtrlShiftL));
        assert_eq!(chosen(&Combo::LOCK, 3), None, "past the list");
        assert_eq!(Combo::CtrlAltSpace.label(), "Ctrl+Alt+Space");
    }

    /// Registered and freed again: a second registration of the same combination works once
    /// the first is dropped (the combination may be another program's on this computer: then
    /// both say so the same way).
    #[cfg(windows)]
    #[test]
    fn registered_until_dropped() {
        let (first, taken) = register(&[(7, Combo::CtrlAltSpace)], |_| {});
        let held = taken.is_empty();
        if held {
            let (_second, taken_again) = register(&[(8, Combo::CtrlAltSpace)], |_| {});
            assert_eq!(taken_again, [8], "one program at a time");
        }
        drop(first);
        let (_third, taken) = register(&[(9, Combo::CtrlAltSpace)], |_| {});
        assert_eq!(taken.is_empty(), held, "freed when dropped");
    }
}
