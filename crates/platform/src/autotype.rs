//! Auto-type (M10 F11): a login's username, Tab, password and Enter typed into the window
//! the person was in before this app, as if typed on the keyboard (`SendInput` with Unicode
//! characters, so the keyboard layout doesn't change them).
//!
//! The window is the one right behind the app's own (Windows keeps top-level windows in the
//! order they were last active). Before typing, the app shows that window's title and counts
//! down; then it brings the window forward and types only while that same window (same
//! handle, same program, same title) has the keyboard, looked at again before each step, and
//! never into the app's own window. A step that finds anything else stops everything after
//! it.
//!
//! What it can't protect against (THREAT_MODEL.md §2.5): keys typed this way are seen by a
//! keylogger and by any program that hooks the keyboard, as typed ones are; and Windows
//! doesn't say when it drops typed keys for a window of an administrator's program (UIPI),
//! so nothing reaches such a window and the app can't tell.

/// A window that may be typed into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The window's handle, as a number.
    pub window: isize,
    /// Its process.
    pub process: u32,
    /// Its title when it was chosen, shown to the person.
    pub title: String,
}

/// One step of what is typed.
#[derive(Clone, Copy)]
pub enum Step<'a> {
    Text(&'a str),
    Tab,
    Enter,
}

impl std::fmt::Debug for Step<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(_) => f.write_str("Text(<redacted>)"),
            Self::Tab => f.write_str("Tab"),
            Self::Enter => f.write_str("Enter"),
        }
    }
}

/// One key press or release, as handed to Windows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    /// A UTF-16 unit typed as itself.
    Unicode { unit: u16, up: bool },
    /// A key by its virtual-key code (Tab, Enter).
    Virtual { key: u16, up: bool },
}

impl std::fmt::Debug for KeyEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicode { up, .. } => write!(f, "Unicode(<redacted>, up: {up})"),
            Self::Virtual { key, up } => write!(f, "Virtual({key}, up: {up})"),
        }
    }
}

pub const VK_TAB: u16 = 0x09;
pub const VK_RETURN: u16 = 0x0D;

/// The key presses and releases for one step. Line breaks in a text are left out: they would
/// press Enter in the middle of it.
pub fn key_events(step: Step<'_>) -> Vec<KeyEvent> {
    let press = |key| {
        vec![
            KeyEvent::Virtual { key, up: false },
            KeyEvent::Virtual { key, up: true },
        ]
    };
    match step {
        Step::Tab => press(VK_TAB),
        Step::Enter => press(VK_RETURN),
        Step::Text(text) => text
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .flat_map(|c| {
                let mut units = [0u16; 2];
                let units = c.encode_utf16(&mut units).to_vec();
                units.into_iter().flat_map(|unit| {
                    [
                        KeyEvent::Unicode { unit, up: false },
                        KeyEvent::Unicode { unit, up: true },
                    ]
                })
            })
            .collect(),
    }
}

/// What a login types: username, Tab, password, Enter (a part that is empty is left out
/// with the Tab after it).
pub fn login_steps<'a>(username: &'a str, password: &'a str) -> Vec<Step<'a>> {
    let mut steps = Vec::new();
    if !username.is_empty() {
        steps.push(Step::Text(username));
        if !password.is_empty() {
            steps.push(Step::Tab);
        }
    }
    if !password.is_empty() {
        steps.push(Step::Text(password));
    }
    steps.push(Step::Enter);
    steps
}

/// What touches the desktop, behind a trait so the app's tests type into nothing.
pub trait Desktop {
    /// The window right behind `own` (the app's window): visible, with a title, not a tool
    /// window, not the app's.
    fn window_behind(&self, own: isize) -> Option<Target>;
    /// Whether `target` still is that window: same handle, program and title.
    fn still_there(&self, target: &Target) -> bool;
    /// Brings `target` forward and waits (briefly) until it has the keyboard.
    fn activate(&self, target: &Target) -> bool;
    /// The window that has the keyboard now (its handle).
    fn foreground(&self) -> Option<isize>;
    /// Whether Ctrl, Alt, Shift or the Windows key is held (typing then would turn letters
    /// into shortcuts).
    fn modifiers_held(&self) -> bool;
    /// Hands one step's keys to Windows.
    fn send(&self, events: &[KeyEvent]) -> bool;
}

/// Types `steps` into `target`, looking before each step that `target` has the keyboard and
/// that it isn't `own`.
pub fn type_into(
    desktop: &dyn Desktop,
    own: isize,
    target: &Target,
    steps: &[Step<'_>],
) -> Result<(), Problem> {
    if target.window == own {
        return Err(Problem::OwnWindow);
    }
    if !desktop.still_there(target) {
        return Err(Problem::WindowChanged);
    }
    if !desktop.activate(target) {
        return Err(Problem::WindowChanged);
    }
    for step in steps {
        if desktop.foreground() != Some(target.window) || !desktop.still_there(target) {
            return Err(Problem::WindowChanged);
        }
        if desktop.modifiers_held() {
            return Err(Problem::KeysHeld);
        }
        let mut events = key_events(*step);
        let sent = desktop.send(&events);
        // The characters of a password were in there.
        events.fill(KeyEvent::Virtual { key: 0, up: true });
        if !sent {
            return Err(Problem::NotSent);
        }
    }
    Ok(())
}

/// Why auto-type stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The window to type into is the app's own.
    OwnWindow,
    /// The window closed, changed its title, or something else took the keyboard.
    WindowChanged,
    /// Ctrl, Alt, Shift or the Windows key was held.
    KeysHeld,
    /// Windows refused the keys.
    NotSent,
}

/// The real desktop.
#[derive(Debug, Default)]
pub struct System;

#[cfg(windows)]
impl Desktop for System {
    fn window_behind(&self, own: isize) -> Option<Target> {
        imp::window_behind(own)
    }
    fn still_there(&self, target: &Target) -> bool {
        imp::describe(target.window)
            .is_some_and(|(process, title)| process == target.process && title == target.title)
    }
    fn activate(&self, target: &Target) -> bool {
        imp::activate(target.window)
    }
    fn foreground(&self) -> Option<isize> {
        imp::foreground()
    }
    fn modifiers_held(&self) -> bool {
        imp::modifiers_held()
    }
    fn send(&self, events: &[KeyEvent]) -> bool {
        imp::send(events)
    }
}

#[cfg(not(windows))]
impl Desktop for System {
    fn window_behind(&self, _own: isize) -> Option<Target> {
        None
    }
    fn still_there(&self, _target: &Target) -> bool {
        false
    }
    fn activate(&self, _target: &Target) -> bool {
        false
    }
    fn foreground(&self) -> Option<isize> {
        None
    }
    fn modifiers_held(&self) -> bool {
        false
    }
    fn send(&self, _events: &[KeyEvent]) -> bool {
        false
    }
}

#[cfg(windows)]
mod imp {
    use std::time::{Duration, Instant};

    use windows_sys::Win32::{
        Foundation::HWND,
        UI::{
            Input::KeyboardAndMouse::{
                GetAsyncKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
                KEYEVENTF_UNICODE, SendInput, VK_CONTROL, VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
            },
            WindowsAndMessaging::{
                GA_ROOTOWNER, GW_HWNDNEXT, GWL_EXSTYLE, GetAncestor, GetForegroundWindow,
                GetWindow, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW,
                GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, SW_RESTORE,
                SetForegroundWindow, ShowWindow, WS_EX_TOOLWINDOW,
            },
        },
    };

    use super::{KeyEvent, Target};

    fn hwnd(window: isize) -> HWND {
        window as HWND
    }

    /// The process and title of `window`, while it is a window.
    pub(super) fn describe(window: isize) -> Option<(u32, String)> {
        let handle = hwnd(window);
        // SAFETY: plain calls on a window handle; Windows checks it (a stale one fails).
        #[allow(unsafe_code)]
        unsafe {
            if IsWindow(handle) == 0 {
                return None;
            }
            let mut process = 0u32;
            GetWindowThreadProcessId(handle, &mut process);
            let len = GetWindowTextLengthW(handle).clamp(0, 1024) as usize;
            let mut buffer = vec![0u16; len + 1];
            let read = GetWindowTextW(handle, buffer.as_mut_ptr(), buffer.len() as i32);
            let title = String::from_utf16_lossy(&buffer[..read.clamp(0, len as i32) as usize]);
            Some((process, title))
        }
    }

    pub(super) fn window_behind(own: isize) -> Option<Target> {
        let own = hwnd(own);
        // SAFETY: plain calls on window handles Windows hands out; each is checked by it.
        #[allow(unsafe_code)]
        unsafe {
            let mut own_process = 0u32;
            GetWindowThreadProcessId(own, &mut own_process);
            let mut next = GetWindow(own, GW_HWNDNEXT);
            let mut looked = 0;
            while !next.is_null() && looked < 512 {
                looked += 1;
                let window = next;
                next = GetWindow(window, GW_HWNDNEXT);
                let tool = (GetWindowLongPtrW(window, GWL_EXSTYLE) as u32) & WS_EX_TOOLWINDOW != 0;
                if IsWindowVisible(window) == 0
                    || tool
                    || GetAncestor(window, GA_ROOTOWNER) != window
                {
                    continue;
                }
                let Some((process, title)) = describe(window as isize) else {
                    continue;
                };
                // Not the app's own windows (its tray menu), and something with a name.
                if process == own_process || title.trim().is_empty() {
                    continue;
                }
                return Some(Target {
                    window: window as isize,
                    process,
                    title,
                });
            }
            None
        }
    }

    pub(super) fn foreground() -> Option<isize> {
        // SAFETY: plain call.
        #[allow(unsafe_code)]
        let window = unsafe { GetForegroundWindow() };
        (!window.is_null()).then_some(window as isize)
    }

    pub(super) fn activate(window: isize) -> bool {
        let handle = hwnd(window);
        // SAFETY: plain calls on a window handle Windows checks. This app is in front (the
        // person just clicked in it), so Windows lets it hand the front over.
        #[allow(unsafe_code)]
        unsafe {
            if IsIconic(handle) != 0 {
                ShowWindow(handle, SW_RESTORE);
            }
            SetForegroundWindow(handle);
        }
        let until = Instant::now() + Duration::from_millis(700);
        while Instant::now() < until {
            if foreground() == Some(window) {
                // Lets the window take the keyboard before the first key.
                std::thread::sleep(Duration::from_millis(80));
                return foreground() == Some(window);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    pub(super) fn modifiers_held() -> bool {
        [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN]
            .into_iter()
            .any(|key| {
                // SAFETY: plain call with a virtual-key code.
                #[allow(unsafe_code)]
                let state = unsafe { GetAsyncKeyState(i32::from(key)) };
                state < 0
            })
    }

    pub(super) fn send(events: &[KeyEvent]) -> bool {
        if events.is_empty() {
            return true;
        }
        let mut inputs: Vec<INPUT> = events
            .iter()
            .map(|event| {
                let (vk, scan, flags) = match *event {
                    KeyEvent::Unicode { unit, up } => (
                        0,
                        unit,
                        KEYEVENTF_UNICODE | if up { KEYEVENTF_KEYUP } else { 0 },
                    ),
                    KeyEvent::Virtual { key, up } => (key, 0, if up { KEYEVENTF_KEYUP } else { 0 }),
                };
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: vk,
                            wScan: scan,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            })
            .collect();
        // SAFETY: `inputs` is a valid array of INPUT of the length given, alive for the call.
        #[allow(unsafe_code)]
        let sent = unsafe {
            SendInput(
                inputs.len() as u32,
                inputs.as_ptr(),
                std::mem::size_of::<INPUT>() as i32,
            )
        };
        let all = sent as usize == inputs.len();
        // The characters typed are wiped from the copy handed to Windows.
        for input in &mut inputs {
            input.Anonymous = INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: 0,
                    dwFlags: 0,
                    time: 0,
                    dwExtraInfo: 0,
                },
            };
        }
        std::hint::black_box(&inputs);
        all
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[test]
    fn a_login_types_username_tab_password_enter_as_unicode() {
        let steps = login_steps("me@example.com", "pässwörd 🔑");
        assert_eq!(steps.len(), 4);
        let events: Vec<KeyEvent> = steps.iter().flat_map(|s| key_events(*s)).collect();
        let typed: Vec<u16> = events
            .iter()
            .filter_map(|e| match e {
                KeyEvent::Unicode { unit, up: false } => Some(*unit),
                _ => None,
            })
            .collect();
        assert_eq!(
            String::from_utf16(&typed).unwrap(),
            "me@example.compässwörd 🔑",
            "every character as itself, the key as two units"
        );
        let keys: Vec<(u16, bool)> = events
            .iter()
            .filter_map(|e| match e {
                KeyEvent::Virtual { key, up } => Some((*key, *up)),
                _ => None,
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                (VK_TAB, false),
                (VK_TAB, true),
                (VK_RETURN, false),
                (VK_RETURN, true)
            ]
        );
        // Each press is released.
        assert_eq!(events.len() % 2, 0);
        // An empty part is left out with its Tab; a line break never presses Enter.
        assert_eq!(login_steps("", "pw").len(), 2);
        assert_eq!(login_steps("me", "").len(), 2);
        assert_eq!(key_events(Step::Text("a\r\nb")).len(), 4);
        assert!(format!("{:?}", Step::Text("secret")).contains("redacted"));
        // The unit typed (`Q`, 81) shows nowhere in what is printed.
        let printed = format!("{:?}", key_events(Step::Text("Q")));
        assert!(!printed.contains('Q') && !printed.contains("81"));
    }

    /// A desktop in memory: which window is in front, and what reached it.
    struct Fake {
        front: RefCell<isize>,
        title: RefCell<String>,
        /// After this many steps, another window takes the keyboard.
        steal_after: Option<usize>,
        held: bool,
        sent: RefCell<Vec<Vec<KeyEvent>>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                front: RefCell::new(1),
                title: RefCell::new("Notepad".into()),
                steal_after: None,
                held: false,
                sent: RefCell::new(Vec::new()),
            }
        }
    }

    impl Desktop for Fake {
        fn window_behind(&self, _own: isize) -> Option<Target> {
            Some(target())
        }
        fn still_there(&self, target: &Target) -> bool {
            *self.title.borrow() == target.title
        }
        fn activate(&self, target: &Target) -> bool {
            *self.front.borrow_mut() = target.window;
            true
        }
        fn foreground(&self) -> Option<isize> {
            Some(*self.front.borrow())
        }
        fn modifiers_held(&self) -> bool {
            self.held
        }
        fn send(&self, events: &[KeyEvent]) -> bool {
            self.sent.borrow_mut().push(events.to_vec());
            if self.steal_after == Some(self.sent.borrow().len()) {
                *self.front.borrow_mut() = 99;
            }
            true
        }
    }

    fn target() -> Target {
        Target {
            window: 7,
            process: 4,
            title: "Notepad".into(),
        }
    }

    #[test]
    fn typing_goes_only_to_the_window_shown_and_stops_when_it_changes() {
        let steps = login_steps("me", "pw");
        // All of it, into the window shown.
        let fake = Fake::new();
        type_into(&fake, 1, &target(), &steps).unwrap();
        assert_eq!(fake.sent.borrow().len(), 4);
        // Never into the app's own window.
        let fake = Fake::new();
        assert_eq!(
            type_into(&fake, 7, &target(), &steps),
            Err(Problem::OwnWindow)
        );
        assert!(fake.sent.borrow().is_empty());
        // Its title changed (another tab, another page) since it was shown: nothing.
        let fake = Fake::new();
        *fake.title.borrow_mut() = "Other".into();
        assert_eq!(
            type_into(&fake, 1, &target(), &steps),
            Err(Problem::WindowChanged)
        );
        assert!(fake.sent.borrow().is_empty());
        // Another window takes the keyboard after the username: the password never goes.
        let fake = Fake {
            steal_after: Some(1),
            ..Fake::new()
        };
        assert_eq!(
            type_into(&fake, 1, &target(), &steps),
            Err(Problem::WindowChanged)
        );
        assert_eq!(fake.sent.borrow().len(), 1);
        // A held Ctrl would make shortcuts of the letters: nothing.
        let fake = Fake {
            held: true,
            ..Fake::new()
        };
        assert_eq!(
            type_into(&fake, 1, &target(), &steps),
            Err(Problem::KeysHeld)
        );
        assert!(fake.sent.borrow().is_empty());
    }
}
