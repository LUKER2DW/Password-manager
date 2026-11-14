//! The browser extension's link: a local pipe on which the extension (through its native
//! host) asks for the logins of the page in front of the person, and for the one they pick.
//!
//! Off unless turned on in Settings. What may be answered is decided in `vault_browser`
//! (exact origin, HTTPS only, nothing while locked, nothing behind the item lock); this file
//! only connects that to the open vault and to the pipe.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use vault_browser::{host::NOT_RUNNING, service};
use vault_platform::browser_link;
use zeroize::Zeroizing;

use super::{CURRENT, Controller, Runner, error, notice};

/// A running link: the flag that stops its thread, and the pipe to wake it on.
#[derive(Debug)]
pub(super) struct BrowserLink {
    stop: Arc<AtomicBool>,
    pipe: String,
}

impl Controller {
    /// Turns the link on or off: tells Chrome and Edge where the native host is (or removes
    /// that), and starts or stops listening.
    pub(super) fn apply_browser_link(&self, on: bool) {
        if self.state.borrow().runner == Runner::Inline {
            return; // headless tests never touch the registry or open pipes
        }
        if let Some(link) = self.state.borrow_mut().browser_link.take() {
            link.stop.store(true, Ordering::Relaxed);
            browser_link::wake(&link.pipe);
        }
        if !on {
            browser_link::unregister_host();
            return;
        }
        let host: Option<PathBuf> = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join(browser_link::HOST_EXE)));
        let Some(host) = host.filter(|host| host.exists()) else {
            self.set_error(error::BROWSER_HOST, browser_link::HOST_EXE);
            return;
        };
        let pipe = match browser_link::register_host(&host).and_then(|()| browser_link::pipe_name())
        {
            Ok(pipe) => pipe,
            Err(err) => {
                self.set_error(error::OTHER, &err.to_string());
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        self.state.borrow_mut().browser_link = Some(BrowserLink {
            stop: stop.clone(),
            pipe: pipe.clone(),
        });
        std::thread::spawn(move || {
            // Taken already: another window of the app is answering the extension.
            let Ok(mut server) = browser_link::Server::bind(&pipe, &host) else {
                return;
            };
            while !stop.load(Ordering::Relaxed) {
                let served = server.serve_one(|message| {
                    // The vault lives on the UI thread: ask there, wait for the answer here.
                    let (reply_to, reply) = mpsc::channel();
                    let message = message.to_vec();
                    let _ = slint::invoke_from_event_loop(move || {
                        let answer = CURRENT
                            .with(|c| c.borrow().upgrade())
                            .map(|controller| controller.browser_request(&message));
                        let _ = reply_to.send(answer);
                    });
                    match reply.recv_timeout(Duration::from_secs(5)) {
                        Ok(Some(answer)) => answer.to_vec(),
                        _ => NOT_RUNNING.to_vec(),
                    }
                });
                if served.is_err() {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        });
    }

    /// Answers one message from the extension. A login handed out is announced in the app,
    /// so a fill the person didn't ask for doesn't go unnoticed.
    pub fn browser_request(&self, message: &[u8]) -> Zeroizing<Vec<u8>> {
        let answer = {
            let state = self.state.borrow();
            let vault = state.session.as_ref().map(|session| &session.vault);
            let secrets_open = state.secrets_open;
            service::answer(message, vault, &|item| {
                !secrets_open && vault.is_some_and(|vault| vault.guards(item))
            })
        };
        if let Some(title) = &answer.filled {
            self.notify(notice::BROWSER_FILLED, title);
        }
        answer.bytes
    }
}
