//! Back and forward through the places visited, like a browser: the arrows in the index, the
//! mouse's back and forward buttons, Alt+Left / Alt+Right, and a few keyboard shortcuts.

use std::{cell::Cell, rc::Rc, time::Duration};

use slint::ComponentHandle;
use vault_core::ItemId;

use super::{Controller, Panel, Screen};

/// Places remembered in each direction.
const MAX_PLACES: usize = 100;

/// Where the user was: a page, and on the item page the category and item.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Place {
    panel: Panel,
    category: i32,
    item: Option<ItemId>,
}

#[derive(Debug, Default)]
pub(super) struct History {
    back: Vec<Place>,
    forward: Vec<Place>,
    here: Option<Place>,
}

/// What a key or mouse button asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Back,
    Forward,
    Lock,
    NewItem,
}

impl Controller {
    fn current_place(&self) -> Option<Place> {
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return None;
        }
        let panel = app.get_panel();
        // The editor is a detour, not a place: leaving it is Save or Cancel.
        if panel == Panel::Editor {
            return None;
        }
        Some(Place {
            panel,
            category: app.get_category(),
            item: if panel == Panel::Detail {
                self.state.borrow().selected
            } else {
                None
            },
        })
    }

    /// Records the current place when it differs from the last one (called after every UI
    /// callback). Moving somewhere new clears the way forward, as in a browser.
    pub(super) fn note_place(&self) {
        let Some(now) = self.current_place() else {
            return;
        };
        {
            let mut state = self.state.borrow_mut();
            let history = &mut state.history;
            if history.here.as_ref() == Some(&now) {
                return;
            }
            if let Some(old) = history.here.replace(now) {
                history.back.push(old);
                if history.back.len() > MAX_PLACES {
                    history.back.remove(0);
                }
                history.forward.clear();
            }
        }
        self.show_navigation();
    }

    /// Forgets every place (on lock, and when a vault opens).
    pub(super) fn reset_history(&self) {
        self.state.borrow_mut().history = History::default();
        self.note_place();
        self.show_navigation();
    }

    fn show_navigation(&self) {
        let app = self.app();
        let state = self.state.borrow();
        app.set_can_go_back(!state.history.back.is_empty());
        app.set_can_go_forward(!state.history.forward.is_empty());
    }

    pub(super) fn go(&self, forward: bool) {
        let app = self.app();
        if app.get_screen() != Screen::Vault
            || app.get_panel() == Panel::Editor
            || app.get_folder_dialog() >= 0
        {
            return;
        }
        let target = {
            let mut state = self.state.borrow_mut();
            let history = &mut state.history;
            let (from, to) = if forward {
                (&mut history.forward, &mut history.back)
            } else {
                (&mut history.back, &mut history.forward)
            };
            let Some(target) = from.pop() else {
                return;
            };
            if let Some(here) = history.here.take() {
                to.push(here);
            }
            history.here = Some(target.clone());
            target
        };
        self.show_place(&target);
        // The place may have changed meanwhile (a deleted item, a removed folder).
        let now = self.current_place();
        self.state.borrow_mut().history.here = now;
        self.show_navigation();
    }

    fn show_place(&self, place: &Place) {
        match place.panel {
            Panel::Detail => {
                let app = self.app();
                let exists = |id: &ItemId| {
                    self.state
                        .borrow()
                        .session
                        .as_ref()
                        .is_some_and(|s| s.vault.get_item(id).is_ok())
                };
                let item = place.item.filter(exists);
                {
                    let mut state = self.state.borrow_mut();
                    state.selected = item;
                    state.editing = None;
                }
                app.set_category(place.category);
                app.set_editing_item(false);
                app.set_panel(Panel::Detail);
                self.refresh_list();
                self.show_detail();
            }
            Panel::Generator => self.open_generator(),
            Panel::Settings => self.open_settings(),
            Panel::Kit => self.open_kit(),
            Panel::Transfer => self.open_transfer(),
            Panel::Authenticator => self.open_authenticator(),
            Panel::Health => self.open_health(),
            Panel::Editor => {}
        }
    }

    fn run_command(&self, command: Command) {
        let app = self.app();
        if app.get_screen() != Screen::Vault {
            return;
        }
        match command {
            Command::Back => self.go(false),
            Command::Forward => self.go(true),
            Command::Lock => self.lock(),
            Command::NewItem => {
                if app.get_folder_dialog() < 0 && app.get_panel() != Panel::Editor {
                    self.open_editor(None);
                    self.note_place();
                }
            }
        }
        self.touch_activity();
    }

    /// The title bar (the window has no frame of the system's, `no-frame`): the system's own
    /// move, so the window snaps to the screen's edges as usual.
    pub(super) fn window_drag(&self) {
        use slint::winit_030::WinitWindowAccessor;
        self.app().window().with_winit_window(|window| {
            let _ = window.drag_window();
        });
    }

    /// An edge or corner of the window (`direction` as in app.slint's `ResizeEdge`): the
    /// system's own resize.
    pub(super) fn window_resize(&self, direction: i32) {
        use slint::winit_030::{WinitWindowAccessor, winit::window::ResizeDirection};
        let direction = match direction {
            0 => ResizeDirection::East,
            1 => ResizeDirection::North,
            2 => ResizeDirection::NorthEast,
            3 => ResizeDirection::NorthWest,
            4 => ResizeDirection::South,
            5 => ResizeDirection::SouthEast,
            6 => ResizeDirection::SouthWest,
            _ => ResizeDirection::West,
        };
        self.app().window().with_winit_window(|window| {
            let _ = window.drag_resize_window(direction);
        });
    }

    pub(super) fn window_minimize(&self) {
        self.app().window().set_minimized(true);
    }

    pub(super) fn window_toggle_maximized(&self) {
        let app = self.app();
        let maximized = !app.window().is_maximized();
        app.window().set_maximized(maximized);
        app.set_window_maximized(maximized);
    }

    /// The title bar's close button: what the system's would do (to the notification area
    /// when that is on, else quit), once the click is done.
    pub(super) fn window_close(&self) {
        let weak = self.app().as_weak();
        slint::Timer::single_shot(Duration::ZERO, move || {
            if let Some(app) = weak.upgrade() {
                let _ = app
                    .window()
                    .dispatch_event_with_result(slint::platform::WindowEvent::CloseRequested);
            }
        });
    }

    /// Mouse buttons 4 and 5, Alt+Left / Alt+Right, the keyboard's own Back and Forward keys,
    /// Ctrl+L (lock) and Ctrl+N (new item). Read from the window's raw events, so they work
    /// wherever the pointer or the focus is. A no-op on backends without a native window
    /// (the tests).
    pub(super) fn install_shortcuts(self: &Rc<Self>, app: &crate::ui::AppWindow) {
        use slint::winit_030::{
            EventResult, WinitWindowAccessor,
            winit::{
                event::{ElementState, MouseButton, WindowEvent},
                keyboard::{Key, NamedKey},
            },
        };
        let weak = Rc::downgrade(self);
        let alt = Cell::new(false);
        let control = Cell::new(false);
        app.window().on_winit_window_event(move |_, event| {
            // Maximized or restored another way (Win+Up, a snap): the title bar's button
            // follows.
            if matches!(event, WindowEvent::Resized(_)) {
                let weak = weak.clone();
                slint::Timer::single_shot(Duration::ZERO, move || {
                    if let Some(controller) = weak.upgrade() {
                        let app = controller.app();
                        app.set_window_maximized(app.window().is_maximized());
                    }
                });
            }
            let command = match event {
                WindowEvent::ModifiersChanged(modifiers) => {
                    alt.set(modifiers.state().alt_key());
                    control.set(modifiers.state().control_key());
                    None
                }
                WindowEvent::MouseInput { state, button, .. } => {
                    let command = match button {
                        MouseButton::Back => Some(Command::Back),
                        MouseButton::Forward => Some(Command::Forward),
                        _ => None,
                    };
                    match command {
                        // Act on the press; swallow the release too.
                        Some(command) if *state == ElementState::Pressed => Some(command),
                        Some(_) => return EventResult::PreventDefault,
                        None => None,
                    }
                }
                WindowEvent::KeyboardInput { event, .. }
                    if event.state == ElementState::Pressed && !event.repeat =>
                {
                    match &event.logical_key {
                        Key::Named(NamedKey::BrowserBack) => Some(Command::Back),
                        Key::Named(NamedKey::BrowserForward) => Some(Command::Forward),
                        Key::Named(NamedKey::ArrowLeft) if alt.get() && !control.get() => {
                            Some(Command::Back)
                        }
                        Key::Named(NamedKey::ArrowRight) if alt.get() && !control.get() => {
                            Some(Command::Forward)
                        }
                        Key::Character(c) if control.get() && !alt.get() => match c.as_str() {
                            "l" | "L" => Some(Command::Lock),
                            "n" | "N" => Some(Command::NewItem),
                            _ => None,
                        },
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(command) = command else {
                return EventResult::Propagate;
            };
            // Run after the window has finished with this event.
            let weak = weak.clone();
            slint::Timer::single_shot(Duration::ZERO, move || {
                if let Some(controller) = weak.upgrade() {
                    controller.run_command(command);
                }
            });
            EventResult::PreventDefault
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_compare_by_page_category_and_item() {
        let a = Place {
            panel: Panel::Detail,
            category: 0,
            item: None,
        };
        let mut b = a.clone();
        assert_eq!(a, b);
        b.category = 2;
        assert_ne!(a, b);
    }
}
