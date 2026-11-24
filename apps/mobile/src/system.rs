//! What only the phone's own system can do, asked for by the controller: biometrics, keeping
//! the app out of screenshots, Android's autofill settings, installing an update. The Android
//! activity answers it (`apps/mobile-android`); elsewhere (a computer's window, the web
//! preview, the tests) [`NoSystem`] says none of it is there, or a test stands in.
//!
//! Answers that need the person (a fingerprint, a confirmation) come back later, to the
//! controller's `biometric_*` methods.

/// The words the system's own prompts show, translated by the screens (`@tr`).
#[derive(Debug, Clone, Default)]
pub struct PromptWords {
    pub title: String,
    pub detail: String,
    pub cancel: String,
}

pub trait System {
    /// Strong biometrics (Android's Class 3: a fingerprint, or a face where it is as strong)
    /// are set up, so a key can be kept that only they release.
    fn biometrics(&self) -> bool {
        false
    }

    /// Seals `secret` under a key kept by the phone's secure hardware that only a fingerprint
    /// (or face) releases, after asking for one. The sealed bytes come back to
    /// `Controller::biometric_sealed`.
    fn seal_with_biometrics(
        &self,
        _vault_id: &str,
        _secret: &[u8],
        _words: &PromptWords,
    ) -> Result<(), String> {
        Err("no biometrics here".into())
    }

    /// Asks for a fingerprint (or face) and opens what [`System::seal_with_biometrics`]
    /// sealed. The secret comes back to `Controller::biometric_opened`.
    fn open_with_biometrics(
        &self,
        _vault_id: &str,
        _sealed: &[u8],
        _words: &PromptWords,
    ) -> Result<(), String> {
        Err("no biometrics here".into())
    }

    /// Deletes the hardware key of a vault's biometric unlock.
    fn forget_biometrics(&self, _vault_id: &str) {}

    /// Keeps the app's screens out of screenshots, recordings and the recent apps view.
    fn keep_off_screenshots(&self, _on: bool) {}

    /// `None` where there is no autofill; else whether this app is the one Android uses.
    fn autofill(&self) -> Option<bool> {
        None
    }

    /// Opens Android's screen for choosing the autofill service.
    fn open_autofill_settings(&self) {}

    /// Whether this system installs updates of the app (Android does).
    fn installs_updates(&self) -> bool {
        false
    }

    /// Hands an update of the app (an APK) to the system's installer, which asks the person
    /// and checks that it is signed like the installed app. The installer's answer comes back
    /// to `Controller::update_installing`.
    fn install_update(&self, _package: &[u8]) -> Result<(), String> {
        Err("updates are installed only on a phone".into())
    }

    /// The installed app's version ("0.1.0"), when the system knows it better than the
    /// library does.
    fn app_version(&self) -> Option<String> {
        None
    }

    /// The phone's language ("pt-BR"), for "the phone's" in Settings → Appearance.
    fn language(&self) -> Option<String> {
        None
    }

    /// How far the phone's clock is from UTC now, in minutes (-180 in Brasília), so times
    /// show as the phone shows them.
    fn utc_offset_minutes(&self) -> i32 {
        0
    }

    /// Opens a web address (http or https only) in the phone's browser.
    fn open_link(&self, _url: &str) {}

    /// Whether the system can draw a PDF's pages (Android's own renderer).
    fn renders_pdf(&self) -> bool {
        false
    }

    /// A PDF's pages as RGBA pixels (width, height, pixels), drawn inside this app.
    fn render_pdf(&self, _pdf: &[u8]) -> Result<Vec<(u32, u32, Vec<u8>)>, String> {
        Err("PDFs are shown on a phone".into())
    }

    /// Whether the phone can read a QR code (the invite a computer shows): Google's code
    /// scanner on Android.
    fn scans_codes(&self) -> bool {
        false
    }

    /// Opens the code scanner; the code's text comes back to the controller's `code_scanned`
    /// with `purpose` (see `scan::*` in the controller), or to `scan_failed`.
    fn scan_code(&self, _purpose: i32) -> Result<(), String> {
        Err("no camera here".into())
    }
}

/// No system services: a computer's window, the web preview, most tests.
#[derive(Debug, Default)]
pub struct NoSystem;

impl System for NoSystem {}
