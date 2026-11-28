//! QR codes read from a picture file (Authenticator → From a QR picture…): a screenshot of a
//! site's two-step sign-in code, or another authenticator app's transfer code.
//!
//! The picture is decoded by the `image` crate within limits (a picture that claims to be
//! huge is refused before its pixels are read) and its codes found by `rqrr`.

use zeroize::Zeroizing;

/// The largest picture file read, and the most pixels on a side.
const MAX_FILE_BYTES: usize = 20 * 1024 * 1024;
const MAX_SIDE: u32 = 8000;

/// Why a picture gave no key.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    /// Not a picture this reads, or past the limits (the text says which).
    Unreadable(String),
    /// A picture, with no QR code holding a key.
    NoCode,
}

/// The `otpauth://` or `otpauth-migration://` text of the first QR code in the picture that
/// holds one.
pub fn key_in_picture(bytes: &[u8]) -> Result<Zeroizing<String>, Problem> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Problem::Unreadable("the file is larger than 20 MB".into()));
    }
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|err| Problem::Unreadable(err.to_string()))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    let picture = reader
        .decode()
        .map_err(|err| Problem::Unreadable(err.to_string()))?;
    let grey = picture.to_luma8();
    let (width, height) = grey.dimensions();
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
            grey.get_pixel(x as u32, y as u32).0[0]
        });
    for grid in prepared.detect_grids() {
        let mut text = Zeroizing::new(Vec::new());
        if grid.decode_to(&mut *text).is_err() {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&text) else {
            continue;
        };
        let text = text.trim();
        if text.get(..8).is_some_and(|p| {
            p.eq_ignore_ascii_case("otpauth:") || p.eq_ignore_ascii_case("otpauth-")
        }) {
            return Ok(Zeroizing::new(text.to_owned()));
        }
    }
    Err(Problem::NoCode)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A QR code of `text` drawn as a PNG (black modules, 8 pixels each, a white border), the
    /// way a screenshot holds one.
    pub(crate) fn picture_of(text: &str) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let side = code.width();
        let scale = 8;
        let border = 4 * scale;
        let size = (side * scale + 2 * border) as u32;
        let colors = code.to_colors();
        let picture = image::GrayImage::from_fn(size, size, |x, y| {
            let (x, y) = (x as usize, y as usize);
            let inside = |v: usize| v >= border && v < border + side * scale;
            let dark = inside(x)
                && inside(y)
                && colors[(y - border) / scale * side + (x - border) / scale]
                    == qrcode::Color::Dark;
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut png = Vec::new();
        picture
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        png
    }

    #[test]
    fn a_key_is_read_from_a_picture_of_its_code() {
        let link = "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        assert_eq!(key_in_picture(&picture_of(link)).unwrap().as_str(), link);
        let transfer = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU%3D";
        assert_eq!(
            key_in_picture(&picture_of(transfer)).unwrap().as_str(),
            transfer
        );
    }

    #[test]
    fn a_code_without_a_key_or_no_picture_says_so() {
        assert_eq!(
            key_in_picture(&picture_of("https://example.com")),
            Err(Problem::NoCode)
        );
        assert!(matches!(
            key_in_picture(b"not a picture"),
            Err(Problem::Unreadable(_))
        ));
        // A picture that claims to be larger than the limit is refused before it is read.
        let mut huge = Vec::new();
        image::GrayImage::new(1, 1)
            .write_to(
                &mut std::io::Cursor::new(&mut huge),
                image::ImageFormat::Png,
            )
            .unwrap();
        // Width and height in the IHDR chunk (bytes 16..24), then its CRC left wrong: the
        // decoder refuses it either way, never allocating 4 billion pixels.
        huge[16..20].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(matches!(key_in_picture(&huge), Err(Problem::Unreadable(_))));
    }
}
