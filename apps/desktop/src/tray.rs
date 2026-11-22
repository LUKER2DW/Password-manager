//! The icon in the notification area (tray mode).
//!
//! With "Keep running in the notification area" on (the default), closing the window hides it
//! instead of quitting: nothing is drawn, the per-second timers stop, and the browser
//! extension keeps getting answers. The vault still locks itself after the usual idle time.
//!
//! A left click opens the window. A right click opens the icon's menu: a small window of the
//! app's own (`ui/tray.slint`), drawn like its other menus, next to the pointer. It shows
//! whether the vault is open and offers Open, Lock now and Quit; it closes when it loses focus
//! or on Escape.

use std::cell::RefCell;

use slint::{
    ComponentHandle, PhysicalPosition, SharedString,
    winit_030::{EventResult, WinitWindowAccessor, winit},
};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::{
    controller::{Controller, TrayAction},
    ui::{AppWindow, Messages, Theme, TrayMenu},
};

/// The extension's 32 × 32 icon, reused so both look the same.
const ICON_PNG: &[u8] = include_bytes!("../../extension/icons/icon32.png");

thread_local! {
    /// The menu window, made once and shown on each right click.
    static MENU: RefCell<Option<TrayMenu>> = const { RefCell::new(None) };
}

/// Keeps the icon in the notification area; dropping it removes the icon.
#[allow(missing_debug_implementations)]
pub struct Tray {
    _icon: TrayIcon,
}

/// Puts the icon in the notification area. Keep the returned value alive: dropping it
/// removes the icon. `None` when the system refused (the app then quits on close).
pub fn install(app: &AppWindow) -> Option<Tray> {
    let words = app.global::<Messages>();
    let icon = TrayIconBuilder::new()
        .with_menu_on_left_click(false)
        .with_tooltip(words.get_tray_tooltip())
        .with_icon(icon()?)
        .build()
        .ok()?;
    make_menu(app);
    TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| match event {
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        }
        | TrayIconEvent::DoubleClick {
            button: MouseButton::Left,
            ..
        } => {
            let _ = slint::invoke_from_event_loop(|| {
                hide_menu();
                Controller::tray_action(TrayAction::Open);
            });
        }
        TrayIconEvent::Click {
            button: MouseButton::Right,
            button_state: MouseButtonState::Up,
            position,
            ..
        } => {
            let at = PhysicalPosition::new(position.x as i32, position.y as i32);
            let _ = slint::invoke_from_event_loop(move || show_menu(at));
        }
        _ => {}
    }));
    Some(Tray { _icon: icon })
}

fn make_menu(app: &AppWindow) {
    let Ok(menu) = TrayMenu::new() else {
        return;
    };
    menu.global::<Theme>()
        .set_dark(app.global::<Theme>().get_dark());
    let act = |action: TrayAction| {
        move || {
            hide_menu();
            Controller::tray_action(action);
        }
    };
    menu.on_open(act(TrayAction::Open));
    menu.on_lock(act(TrayAction::Lock));
    menu.on_quit(act(TrayAction::Quit));
    menu.on_dismiss(hide_menu);
    // Clicking anywhere else takes the focus away: the menu closes, as a menu does.
    menu.window().on_winit_window_event(|_, event| {
        if matches!(event, winit::event::WindowEvent::Focused(false)) {
            // Not from inside the event handler: hiding there would re-enter the window.
            let _ = slint::invoke_from_event_loop(hide_menu);
        }
        EventResult::Propagate
    });
    MENU.with(|slot| *slot.borrow_mut() = Some(menu));
}

/// Opens the menu with its corner at the pointer, inside the screen the pointer is on.
fn show_menu(at: PhysicalPosition) {
    let Some((locked, name, minutes, dark)) = Controller::tray_status() else {
        return;
    };
    MENU.with(|slot| {
        let slot = slot.borrow();
        let Some(menu) = slot.as_ref() else {
            return;
        };
        menu.set_locked(locked);
        menu.set_vault_name(SharedString::from(name));
        menu.set_minutes_left(minutes);
        menu.global::<Theme>().set_dark(dark);
        let window = menu.window();
        // Placed before it shows (no flash in a corner), and again once its real size is
        // known.
        let position = || {
            let size = window.size();
            let (width, height) = (
                i32::try_from(size.width).unwrap_or(0),
                i32::try_from(size.height).unwrap_or(0),
            );
            let bounds = window
                .with_winit_window(|winit_window| monitor_bounds(winit_window, at))
                .flatten();
            let (x, y) = place(at, (width, height), bounds);
            window.set_position(PhysicalPosition::new(x, y));
        };
        position();
        if menu.show().is_err() {
            return;
        }
        position();
        #[cfg(windows)]
        window.with_winit_window(|winit_window| {
            use winit::platform::windows::WindowExtWindows;
            winit_window.set_skip_taskbar(true);
            winit_window.focus_window();
        });
    });
}

/// The edges (left, top, right, bottom) of the screen under `at`.
fn monitor_bounds(
    window: &winit::window::Window,
    at: PhysicalPosition,
) -> Option<(i32, i32, i32, i32)> {
    window.available_monitors().find_map(|monitor| {
        let (p, s) = (monitor.position(), monitor.size());
        let right = p.x + i32::try_from(s.width).unwrap_or(0);
        let bottom = p.y + i32::try_from(s.height).unwrap_or(0);
        (at.x >= p.x && at.y >= p.y && at.x < right && at.y < bottom)
            .then_some((p.x, p.y, right, bottom))
    })
}

/// Where the menu's top-left corner goes for a click at `at`: up and to the left of it, moved
/// inside `bounds` (left, top, right, bottom) when it would stick out.
fn place(
    at: PhysicalPosition,
    (width, height): (i32, i32),
    bounds: Option<(i32, i32, i32, i32)>,
) -> (i32, i32) {
    let mut x = at.x - width;
    let mut y = at.y - height;
    if let Some((left, top, right, bottom)) = bounds {
        if x < left {
            x = at.x.min(right - width);
        }
        if y < top {
            y = at.y.min(bottom - height);
        }
    }
    (x, y)
}

fn hide_menu() {
    MENU.with(|slot| {
        if let Some(menu) = slot.borrow().as_ref() {
            let _ = menu.hide();
        }
    });
}

fn icon() -> Option<Icon> {
    let image = image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png)
        .ok()?
        .into_rgba8();
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_menu_opens_beside_the_pointer_and_stays_on_screen() {
        let screen = Some((0, 0, 1920, 1080));
        // A taskbar at the bottom right: above and to the left.
        assert_eq!(
            place(PhysicalPosition::new(1800, 1060), (240, 200), screen),
            (1560, 860)
        );
        // A taskbar at the top: below the pointer.
        assert_eq!(
            place(PhysicalPosition::new(1800, 10), (240, 200), screen),
            (1560, 10)
        );
        // Near the left edge: to the right of the pointer.
        assert_eq!(
            place(PhysicalPosition::new(100, 1060), (240, 200), screen),
            (100, 860)
        );
    }
}
