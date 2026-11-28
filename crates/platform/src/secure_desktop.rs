//! The master password typed on a secure desktop (Windows): a small window of its own on a
//! separate desktop, the way Windows' own credential prompts keep other programs out
//! (THREAT_MODEL.md §3, the secure desktop).
//!
//! A program on the person's normal desktop can't hook the keyboard of another desktop
//! (`SetWindowsHookEx`, raw input and `GetAsyncKeyState` see only their own), can't send it
//! keys or messages, and captures only its own desktop's screen. The window is plain Win32,
//! not Slint (Slint's windows belong to the UI thread's desktop): each character typed goes
//! straight from `WM_CHAR` into a [`SecretBuffer`], and the window only ever draws how many
//! there are. No edit control holds the text.
//!
//! Getting back is never left to chance: the thread that switched restores the desktop it
//! came from when the prompt ends, on Enter, Escape, the time limit ([`TIME_LIMIT`]) or a
//! panic (the guard's `Drop`); if the process dies, its desktop goes with its last handle and
//! Windows shows the default desktop again; and Ctrl+Alt+Del works on every desktop. The
//! prompt doesn't start unless the desktop to come back to is known.

use std::time::Duration;

use crate::SecretBuffer;

/// How long the prompt waits for the password before it gives up and switches back.
pub const TIME_LIMIT: Duration = Duration::from_secs(120);

/// The prompt's words, in the person's language (the apps word them, `Messages`).
#[derive(Debug, Clone, Default)]
pub struct PromptWords {
    pub title: String,
    /// What this screen is, and that the normal desktop comes back after.
    pub lead: String,
    /// What Enter and Escape do.
    pub keys: String,
}

/// How the prompt ended.
#[derive(Debug)]
pub enum Prompted {
    /// Enter, with what was typed.
    Typed(SecretBuffer),
    /// Escape, or the time limit: nothing typed is kept.
    Cancelled,
}

/// What one key does to the typing.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Go,
    Done,
    Cancel,
}

/// The typing, one UTF-16 unit of `WM_CHAR` at a time, into a [`SecretBuffer`].
#[derive(Default)]
struct Typing {
    buffer: SecretBuffer,
    /// The first half of a character outside the Basic Multilingual Plane.
    high: Option<u16>,
}

impl Typing {
    fn unit(&mut self, unit: u16) -> Step {
        match unit {
            0x0D => return Step::Done,
            0x1B => return Step::Cancel,
            0x08 => {
                self.high = None;
                self.buffer.backspace();
                return Step::Go;
            }
            _ => {}
        }
        let c = if (0xD800..0xDC00).contains(&unit) {
            self.high = Some(unit);
            return Step::Go;
        } else if (0xDC00..0xE000).contains(&unit) {
            let Some(high) = self.high.take() else {
                return Step::Go;
            };
            let code = 0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
            char::from_u32(code)
        } else {
            self.high = None;
            char::from_u32(u32::from(unit))
        };
        if let Some(c) = c.filter(|c| SecretBuffer::takes(*c)) {
            let mut bytes = [0u8; 4];
            let text = c.encode_utf8(&mut bytes);
            self.buffer.push_str(text);
            zeroize::Zeroize::zeroize(&mut bytes);
        }
        Step::Go
    }
}

#[cfg(windows)]
pub use windows_impl::ask;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_impl {
    use std::{cell::RefCell, ptr::null, time::Duration};

    use anyhow::{Result, anyhow, bail};
    use windows_sys::Win32::{
        Foundation::{COLORREF, GetLastError, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::{
            BeginPaint, CreateFontW, CreateSolidBrush, DT_CENTER, DT_NOPREFIX, DT_WORDBREAK,
            DeleteObject, DrawTextW, EndPaint, FillRect, HGDIOBJ, InvalidateRect, PAINTSTRUCT,
            SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
        },
        System::{
            LibraryLoader::GetModuleHandleW,
            StationsAndDesktops::{
                CloseDesktop, CreateDesktopW, DESKTOP_CREATEWINDOW, DESKTOP_READOBJECTS,
                DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS, GetThreadDesktop, HDESK,
                OpenInputDesktop, SetThreadDesktop, SwitchDesktop,
            },
            Threading::GetCurrentThreadId,
        },
        UI::{
            HiDpi::GetDpiForSystem,
            Input::KeyboardAndMouse::SetFocus,
            WindowsAndMessaging::{
                CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
                DispatchMessageW, GetMessageW, GetSystemMetrics, IDC_ARROW, KillTimer, LoadCursorW,
                MSG, PostMessageW, PostQuitMessage, RegisterClassExW, SM_CXSCREEN,
                SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
                SM_YVIRTUALSCREEN, SetForegroundWindow, SetTimer, TranslateMessage, WM_CHAR,
                WM_CLOSE, WM_DESTROY, WM_PAINT, WM_TIMER, WNDCLASSEXW, WS_EX_TOPMOST, WS_POPUP,
                WS_VISIBLE,
            },
        },
    };

    use super::{PromptWords, Prompted, Step, TIME_LIMIT, Typing};

    const CLASS: &str = "VaultSecurePrompt";
    const TIMER: usize = 1;

    fn last_error() -> u32 {
        // SAFETY: reads this thread's last error code.
        unsafe { GetLastError() }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// What the window procedure works on: one prompt per thread, on its own desktop.
    struct Prompt {
        words: PromptWords,
        typing: Typing,
        ended: Option<bool>,
    }

    thread_local! {
        static PROMPT: RefCell<Option<Prompt>> = const { RefCell::new(None) };
    }

    /// The desktop the person came from, shown again when this is dropped (also on a panic),
    /// and the prompt's own desktop closed.
    struct Desktops {
        back_to: HDESK,
        thread_had: HDESK,
        own: HDESK,
        switched: bool,
    }

    impl Drop for Desktops {
        fn drop(&mut self) {
            // SAFETY: the handles were opened by this thread and are closed once, here; the
            // thread's own windows are gone (the message loop ended) before it leaves the
            // desktop.
            unsafe {
                if self.switched {
                    SwitchDesktop(self.back_to);
                }
                SetThreadDesktop(self.thread_had);
                CloseDesktop(self.own);
                if !self.back_to.is_null() {
                    CloseDesktop(self.back_to);
                }
            }
        }
    }

    /// Asks for the master password on a desktop of its own, then shows the person's desktop
    /// again. Runs on a thread of its own (a thread with windows can't change desktops); the
    /// caller waits for it, off the UI thread.
    pub fn ask(words: &PromptWords) -> Result<Prompted> {
        let words = words.clone();
        std::thread::Builder::new()
            .name("secure desktop".into())
            .spawn(move || prompt(words, true, TIME_LIMIT, None))
            .map_err(|err| anyhow!("{err}"))?
            .join()
            .map_err(|_| anyhow!("the secure desktop's prompt stopped"))?
    }

    /// The prompt. `switch`: show its desktop (tests leave it hidden and send `keys` to the
    /// window instead of a person typing).
    pub(super) fn prompt(
        words: PromptWords,
        switch: bool,
        limit: Duration,
        keys: Option<Vec<u16>>,
    ) -> Result<Prompted> {
        let name = {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|e| anyhow!("no randomness: {e}"))?;
            wide(&format!("VaultPrompt-{}", vault_sync_wire::hex(&random)))
        };
        let access = DESKTOP_CREATEWINDOW
            | DESKTOP_READOBJECTS
            | DESKTOP_WRITEOBJECTS
            | DESKTOP_SWITCHDESKTOP;
        // SAFETY: plain calls with valid arguments; each handle is checked and closed by the
        // `Desktops` guard.
        let mut desktops = unsafe {
            // The desktop to come back to (only needed when the prompt's is shown).
            let back_to = if switch {
                OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP)
            } else {
                std::ptr::null_mut()
            };
            if switch && back_to.is_null() {
                // Another desktop has the input (a UAC prompt, the lock screen): without the
                // way back, the prompt doesn't start.
                bail!(
                    "the desktop in use can't be told apart ({})",
                    GetLastError()
                );
            }
            let thread_had = GetThreadDesktop(GetCurrentThreadId());
            let own = CreateDesktopW(name.as_ptr(), null(), null(), 0, access, null());
            if own.is_null() {
                if !back_to.is_null() {
                    CloseDesktop(back_to);
                }
                bail!("no secure desktop could be made ({})", GetLastError());
            }
            Desktops {
                back_to,
                thread_had,
                own,
                switched: false,
            }
        };
        // SAFETY: this thread has no windows or hooks yet, so it may move to the new desktop.
        if unsafe { SetThreadDesktop(desktops.own) } == 0 {
            bail!("couldn't move to the secure desktop ({})", last_error());
        }
        if switch {
            // SAFETY: a desktop handle with DESKTOP_SWITCHDESKTOP access.
            if unsafe { SwitchDesktop(desktops.own) } == 0 {
                bail!("couldn't show the secure desktop ({})", last_error());
            }
            desktops.switched = true;
        }
        PROMPT.with(|p| {
            *p.borrow_mut() = Some(Prompt {
                words,
                typing: Typing::default(),
                ended: None,
            });
        });
        let shown = show_window(limit, keys);
        let prompt = PROMPT.with(|p| p.borrow_mut().take());
        drop(desktops);
        shown?;
        match prompt {
            Some(Prompt {
                typing,
                ended: Some(true),
                ..
            }) => Ok(Prompted::Typed(typing.buffer)),
            _ => Ok(Prompted::Cancelled),
        }
    }

    /// The window, over every screen, until Enter, Escape or the time limit.
    fn show_window(limit: Duration, keys: Option<Vec<u16>>) -> Result<()> {
        let class = wide(CLASS);
        // SAFETY: the class and window are made and destroyed on this thread; the window
        // procedure only touches this thread's `PROMPT`.
        unsafe {
            let instance = GetModuleHandleW(null());
            let wc = WNDCLASSEXW {
                cbSize: u32::try_from(std::mem::size_of::<WNDCLASSEXW>()).unwrap_or(0),
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(procedure),
                hInstance: instance,
                hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            // Registered once per process; a second time fails harmlessly.
            RegisterClassExW(&raw const wc);
            let window = CreateWindowExW(
                WS_EX_TOPMOST,
                class.as_ptr(),
                class.as_ptr(),
                WS_POPUP | WS_VISIBLE,
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                null(),
            );
            if window.is_null() {
                bail!("the prompt's window couldn't be made ({})", GetLastError());
            }
            SetForegroundWindow(window);
            SetFocus(window);
            let millis = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);
            SetTimer(window, TIMER, millis, None);
            if let Some(keys) = keys {
                for unit in keys {
                    PostMessageW(window, WM_CHAR, WPARAM::from(unit), 0);
                }
            }
            let mut message: MSG = std::mem::zeroed();
            while GetMessageW(&raw mut message, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
        Ok(())
    }

    fn end(window: HWND, typed: bool) {
        PROMPT.with(|p| {
            if let Some(prompt) = p.borrow_mut().as_mut() {
                prompt.ended = Some(typed);
            }
        });
        // SAFETY: the window is this thread's own.
        unsafe {
            KillTimer(window, TIMER);
            DestroyWindow(window);
        }
    }

    unsafe extern "system" fn procedure(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_CHAR => {
                let step = PROMPT.with(|p| {
                    p.borrow_mut().as_mut().map_or(Step::Cancel, |prompt| {
                        prompt
                            .typing
                            .unit(u16::try_from(wparam & 0xFFFF).unwrap_or(0))
                    })
                });
                match step {
                    Step::Go => {
                        // SAFETY: the window is this thread's own.
                        unsafe { InvalidateRect(window, null(), 1) };
                    }
                    Step::Done => end(window, true),
                    Step::Cancel => end(window, false),
                }
                0
            }
            WM_TIMER | WM_CLOSE => {
                end(window, false);
                0
            }
            WM_PAINT => {
                paint(window);
                0
            }
            WM_DESTROY => {
                // SAFETY: ends this thread's message loop.
                unsafe { PostQuitMessage(0) };
                0
            }
            // SAFETY: what the window doesn't handle goes to Windows' own procedure.
            _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
        }
    }

    const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
        r as u32 | ((g as u32) << 8) | ((b as u32) << 16)
    }

    /// A dark screen, and in the middle of the main screen the title, what this is, the
    /// typed length as dots and the keys. Nothing typed is ever drawn.
    fn paint(window: HWND) {
        let (words, count) = PROMPT.with(|p| {
            p.borrow()
                .as_ref()
                .map(|prompt| (prompt.words.clone(), prompt.typing.buffer.char_count()))
                .unwrap_or_default()
        });
        // SAFETY: painting this thread's window between BeginPaint and EndPaint; every GDI
        // object made here is selected out and deleted before returning.
        unsafe {
            let mut paint: PAINTSTRUCT = std::mem::zeroed();
            let dc = BeginPaint(window, &raw mut paint);
            let background = CreateSolidBrush(rgb(0x1B, 0x1A, 0x17));
            FillRect(dc, &raw const paint.rcPaint, background);
            DeleteObject(background as HGDIOBJ);
            let scale = i32::try_from(GetDpiForSystem()).unwrap_or(96);
            let px = |n: i32| n * scale / 96;
            // The main screen, in the window's coordinates (it starts at the virtual screen's
            // corner).
            let left = -GetSystemMetrics(SM_XVIRTUALSCREEN);
            let top = -GetSystemMetrics(SM_YVIRTUALSCREEN);
            let (width, height) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
            let column = px(520).min(width - px(32));
            let x = left + (width - column) / 2;
            let mut y = top + height / 2 - px(140);
            SetBkMode(dc, TRANSPARENT as i32);
            let face = wide("Segoe UI");
            let mut line = |text: &str, size: i32, weight: i32, color: COLORREF, tall: i32| {
                if text.is_empty() {
                    // DrawTextW reads an empty string's pointer anyway: nothing to draw.
                    y += px(tall);
                    return;
                }
                let font = CreateFontW(
                    -px(size),
                    0,
                    0,
                    0,
                    weight,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    face.as_ptr(),
                );
                let old = SelectObject(dc, font as HGDIOBJ);
                SetTextColor(dc, color);
                let mut text = wide(text);
                let mut rect = RECT {
                    left: x,
                    top: y,
                    right: x + column,
                    bottom: y + px(tall),
                };
                DrawTextW(
                    dc,
                    text.as_mut_ptr(),
                    -1,
                    &raw mut rect,
                    DT_CENTER | DT_WORDBREAK | DT_NOPREFIX,
                );
                SelectObject(dc, old);
                DeleteObject(font as HGDIOBJ);
                y += px(tall);
            };
            let ink = rgb(0xF2, 0xEE, 0xE6);
            let graphite = rgb(0xA8, 0xA2, 0x96);
            line(&words.title, 24, 400, ink, 48);
            line(&words.lead, 14, 400, graphite, 72);
            let dots: String = "●".repeat(count.min(64));
            line(if dots.is_empty() { "—" } else { &dots }, 20, 400, ink, 48);
            line(&words.keys, 13, 400, graphite, 48);
            EndPaint(window, &raw const paint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(units: &[u16]) -> (String, Step) {
        let mut typing = Typing::default();
        let mut last = Step::Go;
        for &unit in units {
            last = typing.unit(unit);
            if last != Step::Go {
                break;
            }
        }
        (typing.buffer.as_str().to_owned(), last)
    }

    #[test]
    fn each_key_goes_into_the_secret_buffer() {
        let units: Vec<u16> = "pässwörd 🔑".encode_utf16().chain([0x0D]).collect();
        assert_eq!(typed(&units), ("pässwörd 🔑".to_owned(), Step::Done));
        // Backspace takes the last character; a lone half of a pair and control keys are
        // left out; Escape cancels.
        assert_eq!(
            typed(&[0x61, 0x62, 0x08, 0xDC00, 0x09, 0x63, 0x1B]).1,
            Step::Cancel
        );
        assert_eq!(typed(&[0x61, 0x62, 0x08, 0xDC00, 0x09, 0x63]).0, "ac");
        assert_eq!(typed(&[0xD83D, 0x08, 0x61]).0, "a");
    }

    /// The window on a desktop of its own, never shown (no switch): what is sent to it as
    /// keys comes back typed, and Escape or the time limit bring nothing.
    #[cfg(windows)]
    #[test]
    fn the_prompt_window_takes_keys_on_a_desktop_of_its_own() {
        let words = PromptWords {
            title: "Master password".into(),
            lead: "What this is".into(),
            keys: "Enter, Esc".into(),
        };
        let keys: Vec<u16> = "correct horse".encode_utf16().chain([0x0D]).collect();
        let ask = |keys: Option<Vec<u16>>, limit| {
            let words = words.clone();
            std::thread::spawn(move || windows_impl::prompt(words, false, limit, keys))
                .join()
                .unwrap()
        };
        match ask(Some(keys), Duration::from_secs(10)) {
            Ok(Prompted::Typed(buffer)) => assert_eq!(buffer.as_str(), "correct horse"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            ask(Some(vec![0x61, 0x1B]), Duration::from_secs(10)),
            Ok(Prompted::Cancelled)
        ));
        assert!(matches!(
            ask(None, Duration::from_millis(200)),
            Ok(Prompted::Cancelled)
        ));
    }
}
