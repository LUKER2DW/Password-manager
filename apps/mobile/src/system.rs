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

/// A page of a PDF, drawn: RGBA, four bytes a pixel, row after row.
#[derive(Clone)]
pub struct PdfPage {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl std::fmt::Debug for PdfPage {
    /// Without the pixels: they are the person's document.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdfPage")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// A PDF's first pages, as many as [`PageBudget`] let be drawn.
#[derive(Debug, Clone, Default)]
pub struct PdfPages {
    /// How many pages the PDF has.
    pub total: u32,
    pub pages: Vec<PdfPage>,
}

/// What a PDF's preview may take of the phone's memory, decided page by page before any pixel
/// is asked for. The size of the file says nothing of it: a page a few bytes long may be
/// metres tall, and forty ordinary ones together are a quarter of a gigabyte.
///
/// `PdfPreview.java` refuses the same again before it makes a bitmap (a test here reads its
/// numbers), and the controller checks what it was handed ([`PdfPages::within_budget`]).
#[derive(Debug, Clone)]
pub struct PageBudget {
    width: u64,
    pages: u32,
    bytes: u64,
}

impl PageBudget {
    /// The most pages drawn.
    pub const MAX_PAGES: u32 = 40;
    /// The widest a page is drawn, in pixels (a phone's screen).
    pub const MAX_WIDTH: u32 = 1080;
    /// The tallest a page is drawn: a longer one is drawn narrower.
    pub const MAX_HEIGHT: u32 = 4096;
    /// All the pages of one preview together.
    pub const MAX_BYTES: u64 = 96 * 1024 * 1024;
    /// Below this width text can't be read: fewer pages are shown instead.
    const MIN_WIDTH: u64 = 640;

    /// The budget for a PDF of `pages` pages. Many pages are drawn smaller, so that more of
    /// them fit (forty A4 pages do).
    pub fn new(pages: u32) -> Self {
        let pages = pages.min(Self::MAX_PAGES);
        let each = Self::MAX_BYTES / u64::from(pages.max(1));
        // An A4 page `w` pixels wide is 1.4143 `w` tall, four bytes a pixel.
        let width = (each * 10_000 / (4 * 14_143)).isqrt();
        Self {
            width: width.clamp(Self::MIN_WIDTH, u64::from(Self::MAX_WIDTH)),
            pages,
            bytes: Self::MAX_BYTES,
        }
    }

    /// How many more pages may be drawn at most.
    pub fn pages(&self) -> u32 {
        self.pages
    }

    /// The size, in pixels, to draw the next page at, for a page of `width` × `height` (in
    /// whatever unit the document has). `None`: it has no size, or it no longer fits, so
    /// the preview ends before it.
    pub fn next_page(&mut self, width: i32, height: i32) -> Option<(u32, u32)> {
        let width = u64::try_from(width).ok().filter(|w| *w > 0)?;
        let height = u64::try_from(height).ok().filter(|h| *h > 0)?;
        let max_height = u64::from(Self::MAX_HEIGHT);
        // Both factors fit in 32 bits, so their product in 64.
        let (mut w, mut h) = (self.width, self.width * height / width);
        if h > max_height {
            (w, h) = (max_height * width / height, max_height);
        }
        let (w, h) = (u32::try_from(w.max(1)).ok()?, u32::try_from(h.max(1)).ok()?);
        self.take(w, h).then_some((w, h))
    }

    /// Counts a page of exactly this many pixels, when it still fits.
    fn take(&mut self, width: u32, height: u32) -> bool {
        let bytes = u64::from(width) * u64::from(height) * 4;
        let fits = self.pages > 0
            && (1..=Self::MAX_WIDTH).contains(&width)
            && (1..=Self::MAX_HEIGHT).contains(&height)
            && bytes <= self.bytes;
        if fits {
            self.pages -= 1;
            self.bytes -= bytes;
        }
        fits
    }
}

impl PdfPages {
    /// The pages that are what they say and fit the budget, in order, up to the first that
    /// isn't or doesn't: whatever drew them, nothing more is kept.
    pub fn within_budget(self) -> Self {
        let mut budget = PageBudget::new(self.total);
        let pages = self
            .pages
            .into_iter()
            .take_while(|page| {
                let bytes = u64::from(page.width) * u64::from(page.height) * 4;
                page.pixels.len() as u64 == bytes && budget.take(page.width, page.height)
            })
            .collect();
        Self {
            total: self.total,
            pages,
        }
    }
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

    /// How far the phone's clock is from UTC now, in minutes (-180 for UTC-3), so times
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

    /// A PDF's first pages, drawn inside this app: as many as a [`PageBudget`] for its pages
    /// allows, each at the size it gives, stopping at the first that doesn't fit.
    fn render_pdf(&self, _pdf: &[u8]) -> Result<PdfPages, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes a PDF whose pages are all `width` × `height` points is drawn at.
    fn drawn(pages: u32, width: i32, height: i32) -> Vec<(u32, u32)> {
        let mut budget = PageBudget::new(pages);
        (0..budget.pages())
            .map_while(|_| budget.next_page(width, height))
            .collect()
    }

    fn bytes(pages: &[(u32, u32)]) -> u64 {
        pages
            .iter()
            .map(|(w, h)| u64::from(*w) * u64::from(*h) * 4)
            .sum()
    }

    fn page(width: u32, height: u32) -> PdfPage {
        PdfPage {
            width,
            height,
            pixels: vec![0xFF; width as usize * height as usize * 4],
        }
    }

    #[test]
    fn ordinary_pages_fit_however_many() {
        // A4, in points: a short document at the phone's full width.
        assert_eq!(drawn(1, 595, 842), [(1080, 1528)]);
        assert_eq!(drawn(14, 595, 842).len(), 14);
        // Forty pages would be 252 MiB at that width: they are drawn smaller instead.
        for (width, height) in [(595, 842), (612, 792), (842, 595)] {
            let forty = drawn(40, width, height);
            assert_eq!(forty.len(), 40, "{width} x {height}");
            assert!(forty.iter().all(|(w, _)| (640..1080).contains(w)));
            assert!(bytes(&forty) <= PageBudget::MAX_BYTES);
        }
        // Past forty, the preview ends.
        assert_eq!(drawn(4000, 595, 842).len(), 40);
        assert!(drawn(0, 595, 842).is_empty());
    }

    #[test]
    fn a_tall_page_is_drawn_narrower() {
        // A long receipt, and the tallest page a number can say.
        assert_eq!(drawn(1, 200, 2000), [(409, 4096)]);
        assert_eq!(drawn(1, 1, i32::MAX), [(1, 4096)]);
        assert_eq!(drawn(1, i32::MAX, 1), [(1080, 1)]);
        assert_eq!(drawn(1, i32::MAX, i32::MAX), [(1080, 1080)]);
        // A page with no size ends the preview.
        for (width, height) in [(0, 10), (10, 0), (-1, 10), (10, i32::MIN)] {
            assert!(drawn(1, width, height).is_empty(), "{width} x {height}");
        }
    }

    #[test]
    fn pages_that_fit_one_by_one_stop_where_together_they_do_not() {
        // Each is under every limit of a page: about 6.5 MB, forty of them 260 MB.
        let tall = drawn(40, 1000, 4000);
        assert!(!tall.is_empty() && tall.len() < 40, "{}", tall.len());
        assert!(tall.iter().all(|(_, h)| *h <= PageBudget::MAX_HEIGHT));
        let used = bytes(&tall);
        assert!(used <= PageBudget::MAX_BYTES);
        assert!(
            used + bytes(&tall[..1]) > PageBudget::MAX_BYTES,
            "the next one is what doesn't fit"
        );
    }

    #[test]
    fn what_comes_back_is_held_to_the_budget_too() {
        // Drawn as asked: all of it.
        let pages = PdfPages {
            total: 3,
            pages: vec![page(4, 3), page(1080, 2), page(1, 4096)],
        };
        assert_eq!(pages.within_budget().pages.len(), 3);
        // A page that isn't as big as it says, too wide, too tall or empty ends it.
        let mut short = page(4, 3);
        short.pixels.pop();
        for bad in [short, page(1081, 1), page(1, 4097), page(0, 0)] {
            let pages = PdfPages {
                total: 3,
                pages: vec![page(4, 3), bad, page(4, 3)],
            };
            assert_eq!(pages.within_budget().pages.len(), 1);
        }
        // More pages than may be drawn.
        let pages = PdfPages {
            total: 60,
            pages: vec![page(1, 1); 60],
        };
        let kept = pages.within_budget();
        assert_eq!((kept.total, kept.pages.len()), (60, 40));
        // Together over the total, each within a page's limits (17 MiB).
        let pages = PdfPages {
            total: 7,
            pages: vec![page(1080, 4096); 7],
        };
        assert_eq!(pages.within_budget().pages.len(), 5);
    }

    #[test]
    fn the_java_side_has_the_same_numbers() {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../mobile-android/java/org/passwordvault/phone/PdfPreview.java"),
        )
        .unwrap();
        for line in [
            format!("int MAX_PAGES = {};", PageBudget::MAX_PAGES),
            format!("int MAX_WIDTH = {};", PageBudget::MAX_WIDTH),
            format!("int MAX_HEIGHT = {};", PageBudget::MAX_HEIGHT),
            format!(
                "long MAX_BYTES = {}L * 1024 * 1024;",
                PageBudget::MAX_BYTES / (1024 * 1024)
            ),
        ] {
            assert!(source.contains(&line), "{line}");
        }
    }
}
