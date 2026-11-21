//! A recovery part kept inside a picture: a photo of the person's choice (or a landscape made
//! here), saved as a PNG that any viewer opens as usual, with the part's 16 bytes in the lowest
//! bit of some of its pixels.
//!
//! The picture only hides that the file holds a part. It protects nothing by itself: a part
//! alone opens nothing (CRYPTO.md §2.4), and anyone who knows this scheme can read it back.
//! A photo's own grain (or the grain added to the landscape) makes those bits look like the
//! rest. Reading it back needs the exact pixels, which is why the result is always a PNG (a
//! JPEG changes pixels when it is saved): a copy that was resized, cropped or converted (as
//! chat apps do) no longer holds it. The saved picture keeps none of the original's metadata
//! (no camera, date or place).

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use vault_core::{PartLabel, RecoveryPart};
use zeroize::Zeroizing;

const WIDTH: u32 = 640;
const HEIGHT: u32 = 427;
/// The part's bytes, then a tag that says the bits are a part (and which).
const TAG_LEN: usize = 4;
const PAYLOAD_BITS: usize = (RecoveryPart::LEN + TAG_LEN) * 8;
/// Largest picture read back or taken as the cover (a phone photo is far smaller).
const MAX_FILE: usize = 64 * 1024 * 1024;
/// Most pixels a cover may have (a 50-megapixel camera's photo).
const MAX_PIXELS: u64 = 50_000_000;

/// The pixel that holds bit `i` of `pixels`: spread over the picture in a fixed order.
fn position(i: usize, pixels: usize) -> usize {
    // 7919 is prime and doesn't divide the pixel count of any picture this reads back (a
    // count that is a multiple of it is refused), so the positions never repeat.
    (i * 7919 + 1013) % pixels
}

fn tag(label: PartLabel, part: &[u8]) -> [u8; TAG_LEN] {
    let digest = Sha256::new()
        .chain_update(b"vault-v0/part-picture")
        .chain_update([label.letter() as u8])
        .chain_update(part)
        .finalize();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&digest[..TAG_LEN]);
    out
}

/// A small generator for the scene and its grain (not for keys: the part comes from the vault).
struct Grain(u64);

impl Grain {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in [0, 1).
    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32
    }
}

/// A slow wave along a ridge: frequency, phase, height.
type Wave = (f32, f32, f32);

fn mix(a: [f32; 3], b: [f32; 3], t: f32) -> [f32; 3] {
    let t = t.clamp(0.0, 1.0);
    [
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    ]
}

/// Hills in front of a sky at dusk, morning or under clouds: what a phone's gallery is full of.
fn scene(grain: &mut Grain) -> Zeroizing<Vec<u8>> {
    const SKIES: [([f32; 3], [f32; 3], [f32; 3]); 4] = [
        ([38.0, 52.0, 96.0], [236.0, 150.0, 98.0], [44.0, 36.0, 58.0]),
        (
            [120.0, 170.0, 214.0],
            [246.0, 214.0, 180.0],
            [52.0, 78.0, 70.0],
        ),
        (
            [128.0, 138.0, 150.0],
            [206.0, 208.0, 204.0],
            [60.0, 70.0, 66.0],
        ),
        ([62.0, 40.0, 88.0], [250.0, 120.0, 92.0], [30.0, 24.0, 40.0]),
    ];
    let (top, horizon, ground) = SKIES[(grain.next() % SKIES.len() as u64) as usize];
    let (w, h) = (WIDTH as usize, HEIGHT as usize);
    let sun = (
        0.2 + 0.6 * grain.unit(),
        0.35 + 0.2 * grain.unit(),
        0.04 + 0.05 * grain.unit(),
    );
    // Three ridges, far to near, each a sum of slow waves.
    let ridges: Vec<(f32, [Wave; 3])> = (0..3)
        .map(|layer| {
            let base = 0.55 + 0.12 * layer as f32 + 0.05 * grain.unit();
            let waves = [0, 1, 2].map(|k| {
                let k = k as f32;
                (
                    (1.0 + 2.5 * k + 2.0 * grain.unit()) * std::f32::consts::TAU,
                    std::f32::consts::TAU * grain.unit(),
                    (0.05 / (1.0 + 1.6 * k)) * (0.6 + 0.8 * grain.unit()),
                )
            });
            (base, waves)
        })
        .collect();

    let mut pixels = Zeroizing::new(vec![0u8; w * h * 3]);
    for y in 0..h {
        let v = y as f32 / h as f32;
        let sky = mix(top, horizon, (v / 0.62).powf(1.4));
        for x in 0..w {
            let u = x as f32 / w as f32;
            let mut color = sky;
            let (dx, dy) = (u - sun.0, (v - sun.1) * h as f32 / w as f32);
            let d = (dx * dx + dy * dy).sqrt();
            let glow =
                (1.0 - d / (sun.2 * 6.0)).max(0.0).powi(2) * 0.55 + f32::from(d < sun.2) * 0.45;
            color = mix(color, [255.0, 240.0, 214.0], glow);
            for (layer, (base, waves)) in ridges.iter().enumerate() {
                let line = base
                    + waves
                        .iter()
                        .map(|(freq, phase, amp)| amp * (u * freq + phase).sin())
                        .sum::<f32>();
                if v > line {
                    // Far ridges fade into the sky.
                    let haze = 0.65 - 0.3 * layer as f32;
                    let shade = mix(ground, horizon, haze);
                    color = mix(shade, ground, (v - line) * 2.0);
                }
            }
            let at = (y * w + x) * 3;
            for (channel, value) in color.iter().enumerate() {
                let noise = (grain.next() % 7) as f32 - 3.0;
                pixels[at + channel] = (value + noise).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    pixels
}

/// Pixels to hide a part in: 8-bit RGB or RGBA, row after row.
struct Pixels {
    width: u32,
    height: u32,
    channels: usize,
    data: Zeroizing<Vec<u8>>,
}

/// The person's own picture (any format the app reads; a GIF gives its first frame), as RGB,
/// or RGBA when it has transparency.
fn cover_pixels(file: &[u8]) -> Result<Pixels> {
    if file.len() > MAX_FILE {
        bail!("this picture is too large (more than 64 MB)");
    }
    let image = image::load_from_memory(file)
        .context("this file is not a picture the app can read (PNG, JPEG, WebP, BMP or GIF)")?;
    let (width, mut height) = (image.width(), image.height());
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        bail!("this picture is too large (more than 50 megapixels)");
    }
    let (channels, mut data) = if image.color().has_alpha() {
        (4, Zeroizing::new(image.to_rgba8().into_raw()))
    } else {
        (3, Zeroizing::new(image.to_rgb8().into_raw()))
    };
    // A pixel count that is a multiple of 7919 would make the positions repeat: drop the
    // last row, which nobody will miss.
    if (width as usize * height as usize) % 7919 == 0 && height > 1 {
        height -= 1;
        data.truncate(width as usize * height as usize * channels);
    }
    if (width as usize * height as usize) < 64 * 64 {
        bail!("this picture is too small: choose one of at least 64 × 64 pixels");
    }
    Ok(Pixels {
        width,
        height,
        channels,
        data,
    })
}

/// The picture for `part`, as PNG bytes (wiped on drop: they hold the part). `cover` is a
/// picture of the person's own; `None` makes a landscape here.
pub fn make(part: &RecoveryPart, cover: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let mut pixels = match cover {
        Some(file) => cover_pixels(file)?,
        None => {
            let mut seed = [0u8; 8];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
            let mut grain = Grain(u64::from_le_bytes(seed) | 1);
            Pixels {
                width: WIDTH,
                height: HEIGHT,
                channels: 3,
                data: scene(&mut grain),
            }
        }
    };

    let bytes = part.to_bytes();
    let mut payload = Zeroizing::new([0u8; RecoveryPart::LEN + TAG_LEN]);
    payload[..RecoveryPart::LEN].copy_from_slice(bytes.as_ref());
    payload[RecoveryPart::LEN..].copy_from_slice(&tag(part.label(), bytes.as_ref()));
    let count = pixels.width as usize * pixels.height as usize;
    for i in 0..PAYLOAD_BITS {
        let bit = (payload[i / 8] >> (7 - i % 8)) & 1;
        let blue = position(i, count) * pixels.channels + 2;
        pixels.data[blue] = (pixels.data[blue] & !1) | bit;
    }

    let mut out = Zeroizing::new(Vec::with_capacity(pixels.data.len() / 2));
    {
        let mut encoder = png::Encoder::new(&mut *out, pixels.width, pixels.height);
        encoder.set_color(if pixels.channels == 4 {
            png::ColorType::Rgba
        } else {
            png::ColorType::Rgb
        });
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().context("writing the picture")?;
        writer
            .write_image_data(&pixels.data)
            .context("writing the picture")?;
        writer.finish().context("writing the picture")?;
    }
    Ok(out)
}

/// The part a picture made by [`make`] holds.
pub fn read(file: &[u8]) -> Result<RecoveryPart> {
    if file.len() > MAX_FILE {
        bail!("this file is too large to be the picture");
    }
    let mut decoder = png::Decoder::new(std::io::Cursor::new(file));
    decoder.set_transformations(png::Transformations::EXPAND);
    let mut reader = decoder.read_info().context(
        "this file is not a PNG picture: the part is kept only in the PNG the app saved",
    )?;
    let size = reader
        .output_buffer_size()
        .context("this picture is too large")?;
    let mut pixels = Zeroizing::new(vec![0u8; size]);
    let info = reader
        .next_frame(&mut pixels)
        .context("this picture could not be read")?;
    let channels = match (info.color_type, info.bit_depth) {
        (png::ColorType::Rgb, png::BitDepth::Eight) => 3,
        (png::ColorType::Rgba, png::BitDepth::Eight) => 4,
        _ => bail!("this picture doesn't hold a recovery part"),
    };
    let count = info.width as usize * info.height as usize;
    if count < PAYLOAD_BITS || count % 7919 == 0 || info.line_size != info.width as usize * channels
    {
        bail!("this picture doesn't hold a recovery part");
    }
    let mut payload = Zeroizing::new([0u8; RecoveryPart::LEN + TAG_LEN]);
    for i in 0..PAYLOAD_BITS {
        let blue = position(i, count) * channels + 2;
        payload[i / 8] |= (pixels[blue] & 1) << (7 - i % 8);
    }
    let (part, found) = payload.split_at(RecoveryPart::LEN);
    for label in [PartLabel::C, PartLabel::A, PartLabel::B] {
        if bool::from(subtle::ConstantTimeEq::ct_eq(&tag(label, part)[..], found)) {
            return Ok(RecoveryPart::from_bytes(label, part)?);
        }
    }
    bail!("this picture doesn't hold a recovery part (or it was resized or converted since)")
}

/// The name to suggest for the saved picture: the cover's own name as a PNG, or, for a
/// landscape made here, a name like a camera's from the time it is made (Unix seconds).
pub fn suggested_name(cover_name: Option<&str>, unix: u64) -> String {
    match cover_name
        .and_then(|name| std::path::Path::new(name).file_stem()?.to_str())
        .filter(|stem| !stem.trim().is_empty())
    {
        Some(stem) => format!("{stem}.png"),
        None => file_name(unix),
    }
}

/// A name like a camera's for the saved picture, from the time it is made (Unix seconds).
pub fn file_name(unix: u64) -> String {
    let (year, month, day) = crate::kit_pdf::civil_from_days((unix / 86_400) as i64);
    let seconds = unix % 86_400;
    format!(
        "IMG_{year:04}{month:02}{day:02}_{:02}{:02}{:02}.png",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::RecoveryParts;

    #[test]
    fn the_part_comes_back_from_its_picture() {
        let parts = RecoveryParts::generate().unwrap();
        for label in [PartLabel::C, PartLabel::A] {
            let part = parts.part(label);
            let picture = make(part, None).unwrap();
            assert!(picture.starts_with(b"\x89PNG\r\n\x1a\n"));
            // A real picture, not a key in a file: well over a few kilobytes of pixels.
            assert!(picture.len() > 50_000, "{} bytes", picture.len());
            let back = read(&picture).unwrap();
            assert_eq!(&back, part);
            assert_eq!(back.label(), label);
        }
    }

    #[test]
    fn two_pictures_of_the_same_part_look_different() {
        let parts = RecoveryParts::generate().unwrap();
        let part = parts.part(PartLabel::C);
        assert_ne!(*make(part, None).unwrap(), *make(part, None).unwrap());
    }

    /// A cover picture of the person's own, as a file in `format`.
    fn cover(width: u32, height: u32, alpha: bool, format: image::ImageFormat) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        let image: image::DynamicImage = if alpha {
            image::RgbaImage::from_fn(width, height, |x, y| {
                image::Rgba([(x % 256) as u8, (y % 256) as u8, 120, 200])
            })
            .into()
        } else {
            image::RgbImage::from_fn(width, height, |x, y| {
                image::Rgb([
                    (x * 3 % 256) as u8,
                    (y * 5 % 256) as u8,
                    ((x + y) % 256) as u8,
                ])
            })
            .into()
        };
        image.write_to(&mut out, format).unwrap();
        out.into_inner()
    }

    #[test]
    fn a_picture_of_ones_own_carries_the_part() {
        let parts = RecoveryParts::generate().unwrap();
        let part = parts.part(PartLabel::C);
        for (file, alpha) in [
            (cover(300, 200, false, image::ImageFormat::Jpeg), false),
            (cover(257, 131, true, image::ImageFormat::Png), true),
        ] {
            let picture = make(part, Some(&file)).unwrap();
            assert_eq!(&read(&picture).unwrap(), part);
            // The same picture, same size, still a PNG anyone opens.
            let opened = image::load_from_memory(&picture).unwrap();
            assert_eq!(opened.color().has_alpha(), alpha);
            let original = image::load_from_memory(&file).unwrap();
            assert_eq!(
                (opened.width(), opened.height()),
                (original.width(), original.height())
            );
        }
        // A picture too small to hide anything in, or not a picture at all.
        assert!(make(part, Some(&cover(20, 20, false, image::ImageFormat::Png))).is_err());
        assert!(make(part, Some(b"hello")).is_err());
        // The cover itself holds no part.
        assert!(read(&cover(300, 200, false, image::ImageFormat::Png)).is_err());
    }

    #[test]
    fn other_files_and_changed_pictures_are_refused() {
        assert!(read(b"not a picture").is_err());
        let parts = RecoveryParts::generate().unwrap();
        let picture = make(parts.part(PartLabel::C), None).unwrap();
        // Re-encode the same pixels with one hidden bit flipped: the tag no longer matches.
        let mut decoder = png::Decoder::new(std::io::Cursor::new(&picture[..]));
        decoder.set_transformations(png::Transformations::EXPAND);
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0u8; reader.output_buffer_size().unwrap()];
        reader.next_frame(&mut pixels).unwrap();
        pixels[position(3, (WIDTH * HEIGHT) as usize) * 3 + 2] ^= 1;
        let mut changed = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut changed, WIDTH, HEIGHT);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder.write_header().unwrap();
            writer.write_image_data(&pixels).unwrap();
        }
        assert!(read(&changed).is_err());
    }

    #[test]
    fn names_look_like_a_camera_s() {
        // 12 November 2026, 14:05:09 UTC
        assert_eq!(
            file_name(1_794_441_600 + 14 * 3600 + 5 * 60 + 9),
            "IMG_20261112_140509.png"
        );
        assert_eq!(suggested_name(Some("C:\\fotos\\praia.jpg"), 0), "praia.png");
        assert_eq!(suggested_name(None, 0), "IMG_19700101_000000.png");
    }
}
