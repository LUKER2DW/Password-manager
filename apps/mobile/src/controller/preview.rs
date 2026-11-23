//! A file attached to an item, shown in the app: a picture (PNG, JPEG, GIF, WebP, BMP), text,
//! or a PDF's pages (drawn by the system: Android's own PDF renderer, inside this app). The
//! decrypted file never goes to another app; what is on screen is cleared when the preview
//! closes, and when the item does.

use slint::{Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel};

use super::{Controller, error};

/// What View shows for a file (FileRow.preview): 0 nothing, 1 a picture, 2 text, 3 a PDF.
pub(super) mod kind {
    pub const NONE: i32 = 0;
    pub const PICTURE: i32 = 1;
    pub const TEXT: i32 = 2;
    pub const PDF: i32 = 3;
}

/// The longest text shown (a bigger file is only saved).
const MAX_TEXT: usize = 256 * 1024;
/// The largest side of a picture shown; a bigger one is scaled down first.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
const MAX_SIDE: u32 = 2048;

const TEXT_EXTENSIONS: [&str; 14] = [
    "txt", "md", "csv", "json", "log", "xml", "ini", "conf", "cfg", "yaml", "yml", "toml", "pub",
    "pem",
];

fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

/// What can be shown of a file, by its first bytes and its name.
pub(super) fn kind_of(name: &str, data: &[u8], pdf: bool) -> i32 {
    let ext = extension(name);
    let picture = data.starts_with(b"\x89PNG")
        || data.starts_with(&[0xFF, 0xD8, 0xFF])
        || data.starts_with(b"GIF8")
        || (data.len() > 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP")
        || data.starts_with(b"BM");
    if picture && cfg!(not(target_arch = "wasm32")) {
        return kind::PICTURE;
    }
    if data.starts_with(b"%PDF") || ext == "pdf" {
        return if pdf { kind::PDF } else { kind::NONE };
    }
    if TEXT_EXTENSIONS.contains(&ext.as_str())
        && data.len() <= MAX_TEXT
        && std::str::from_utf8(data).is_ok()
    {
        return kind::TEXT;
    }
    kind::NONE
}

#[cfg(not(target_arch = "wasm32"))]
fn picture(data: &[u8]) -> Option<Image> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let mut decoded = reader.decode().ok()?;
    if decoded.width() > MAX_SIDE || decoded.height() > MAX_SIDE {
        decoded = decoded.resize(MAX_SIDE, MAX_SIDE, image::imageops::FilterType::Triangle);
    }
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();
    Some(Image::from_rgba8(
        SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(rgba.as_raw(), width, height),
    ))
}

#[cfg(target_arch = "wasm32")]
fn picture(_data: &[u8]) -> Option<Image> {
    None
}

impl Controller {
    /// View on one of the open item's files.
    pub(super) fn preview_file(&self, index: i32) {
        let Some(item) = self.selected_item() else {
            return;
        };
        let Some(file) = usize::try_from(index)
            .ok()
            .and_then(|index| item.attachments.get(index))
        else {
            return;
        };
        let app = self.app();
        let pdf = self.system().renders_pdf();
        match kind_of(&file.name, &file.data, pdf) {
            kind::PICTURE => {
                let Some(image) = picture(&file.data) else {
                    return self.set_error(error::UNREADABLE, "the picture can't be read");
                };
                app.set_preview_image(image);
            }
            kind::TEXT => {
                let text = String::from_utf8_lossy(&file.data);
                app.set_preview_text(text.as_ref().into());
            }
            kind::PDF => match self.system().render_pdf(&file.data) {
                Ok(pages) if !pages.is_empty() => {
                    let images: Vec<Image> = pages
                        .into_iter()
                        .filter(|(width, height, pixels)| {
                            pixels.len() == (*width as usize) * (*height as usize) * 4
                        })
                        .map(|(width, height, pixels)| {
                            Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(
                                &pixels, width, height,
                            ))
                        })
                        .collect();
                    app.set_preview_pages(ModelRc::new(VecModel::from(images)));
                }
                Ok(_) => return self.set_error(error::UNREADABLE, "the PDF has no pages"),
                Err(detail) => return self.set_error(error::UNREADABLE, &detail),
            },
            _ => return,
        }
        app.set_preview_name(file.name.as_str().into());
        app.set_preview_kind(kind_of(&file.name, &file.data, pdf));
    }

    /// Closes the preview and takes what it showed off the screen.
    pub(super) fn close_preview(&self) {
        let app = self.app();
        app.set_preview_kind(kind::NONE);
        app.set_preview_name(SharedString::new());
        app.set_preview_text(SharedString::new());
        app.set_preview_image(Image::default());
        app.set_preview_pages(ModelRc::default());
    }
}
