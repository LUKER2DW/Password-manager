//! The icon in the notification area (tray mode).
//!
//! With "Keep running in the notification area" on (the default), closing the window hides it
//! instead of quitting: nothing is drawn, the per-second timers stop, and the browser
//! extension keeps getting answers. The vault still locks itself after the usual idle time.
//! The icon's menu opens the window again, locks the vault or quits.

use slint::ComponentHandle;
use tray_icon::{
    Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

use crate::{
    controller::{Controller, TrayAction},
    ui::{AppWindow, Messages},
};

/// The extension's 32 × 32 icon, reused so both look the same.
const ICON_PNG: &[u8] = include_bytes!("../../../extension/icons/icon32.png");

/// Puts the icon in the notification area. Keep the returned value alive: dropping it
/// removes the icon. `None` when the system refused (the app then quits on close).
pub fn install(app: &AppWindow) -> Option<TrayIcon> {
    let words = app.global::<Messages>();
    let open = MenuItem::with_id("open", words.get_tray_open(), true, None);
    let lock = MenuItem::with_id("lock", words.get_tray_lock(), true, None);
    let quit = MenuItem::with_id("quit", words.get_tray_quit(), true, None);
    let menu = Menu::new();
    menu.append_items(&[&open, &lock, &PredefinedMenuItem::separator(), &quit])
        .ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip(words.get_tray_tooltip())
        .with_icon(icon()?)
        .build()
        .ok()?;
    MenuEvent::set_event_handler(Some(|event: MenuEvent| {
        let action = match event.id.0.as_str() {
            "open" => TrayAction::Open,
            "lock" => TrayAction::Lock,
            "quit" => TrayAction::Quit,
            _ => return,
        };
        let _ = slint::invoke_from_event_loop(move || Controller::tray_action(action));
    }));
    TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| {
        let open = matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } | TrayIconEvent::DoubleClick { .. }
        );
        if open {
            let _ = slint::invoke_from_event_loop(|| Controller::tray_action(TrayAction::Open));
        }
    }));
    Some(tray)
}

fn icon() -> Option<Icon> {
    let image = image::load_from_memory_with_format(ICON_PNG, image::ImageFormat::Png)
        .ok()?
        .into_rgba8();
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height).ok()
}
