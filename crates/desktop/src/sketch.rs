//! Hand-drawn strokes, in the spirit of rough.js: every line is drawn twice as a slightly bowed,
//! slightly offset Bézier curve. Output is SVG path data for Slint `Path { commands: ... }`.
//!
//! Generation is deterministic (fixed seeds) so the app looks the same on every launch, and
//! variants (`seed`) keep repeated shapes from looking stamped.

use std::fmt::Write as _;

/// Tiny deterministic PRNG (SplitMix64). Not for cryptography.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(
            seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xD1B5_4A32_D192_ED03),
        )
    }

    fn next_f64(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[-amount, amount]`.
    fn jitter(&mut self, amount: f64) -> f64 {
        (self.next_f64() * 2.0 - 1.0) * amount
    }
}

/// Builder for one path in a fixed view box.
pub struct Pen {
    rng: Rng,
    roughness: f64,
    out: String,
}

impl Pen {
    pub fn new(seed: u64, roughness: f64) -> Self {
        Self {
            rng: Rng::new(seed),
            roughness,
            out: String::with_capacity(512),
        }
    }

    /// One rough line, drawn twice (the second pass with half the offset), like rough.js.
    pub fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64) -> &mut Self {
        let length = ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt();
        let max_offset = 2.0 * self.roughness;
        let offset = if max_offset * max_offset * 100.0 > length * length {
            length / 10.0
        } else {
            max_offset
        };
        for pass_offset in [offset, offset / 2.0] {
            self.bowed_curve(x1, y1, x2, y2, pass_offset, max_offset);
        }
        self
    }

    fn bowed_curve(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, offset: f64, max_offset: f64) {
        let diverge = 0.2 + self.rng.next_f64() * 0.2;
        let bow_x = max_offset * (y2 - y1) / 200.0 + self.rng.jitter(offset * 0.5);
        let bow_y = max_offset * (x1 - x2) / 200.0 + self.rng.jitter(offset * 0.5);
        let r = self.roughness;
        let start = (
            x1 + self.rng.jitter(offset) * r,
            y1 + self.rng.jitter(offset) * r,
        );
        let c1 = (
            bow_x + x1 + (x2 - x1) * diverge + self.rng.jitter(offset) * r,
            bow_y + y1 + (y2 - y1) * diverge + self.rng.jitter(offset) * r,
        );
        let c2 = (
            bow_x + x1 + 2.0 * (x2 - x1) * diverge + self.rng.jitter(offset) * r,
            bow_y + y1 + 2.0 * (y2 - y1) * diverge + self.rng.jitter(offset) * r,
        );
        let end = (
            x2 + self.rng.jitter(offset) * r,
            y2 + self.rng.jitter(offset) * r,
        );
        let _ = write!(
            self.out,
            "M {:.1} {:.1} C {:.1} {:.1} {:.1} {:.1} {:.1} {:.1} ",
            start.0, start.1, c1.0, c1.1, c2.0, c2.1, end.0, end.1
        );
    }

    pub fn rect(&mut self, x: f64, y: f64, w: f64, h: f64) -> &mut Self {
        self.line(x, y, x + w, y)
            .line(x + w, y, x + w, y + h)
            .line(x + w, y + h, x, y + h)
            .line(x, y + h, x, y)
    }

    /// Rough ellipse: jittered points joined by Catmull-Rom curves, drawn twice and slightly
    /// overshooting the start, as a hand closing a circle would.
    pub fn ellipse(&mut self, cx: f64, cy: f64, w: f64, h: f64) -> &mut Self {
        self.arc(cx, cy, w, h, 0.0, std::f64::consts::TAU * 1.06)
    }

    /// Open arc from `start` to `end` radians (0 = right, clockwise in screen space).
    pub fn arc(&mut self, cx: f64, cy: f64, w: f64, h: f64, start: f64, end: f64) -> &mut Self {
        let (rx, ry) = (w / 2.0, h / 2.0);
        let steps = 12;
        for pass in 0..2 {
            let wobble =
                (rx.min(ry) * 0.06).max(0.4) * self.roughness * if pass == 0 { 1.0 } else { 0.6 };
            let points: Vec<(f64, f64)> = (0..=steps)
                .map(|i| {
                    let t = start + (end - start) * f64::from(i) / f64::from(steps);
                    (
                        cx + rx * t.cos() + self.rng.jitter(wobble),
                        cy + ry * t.sin() + self.rng.jitter(wobble),
                    )
                })
                .collect();
            let _ = write!(self.out, "M {:.1} {:.1} ", points[0].0, points[0].1);
            for i in 0..points.len() - 1 {
                let p0 = points[i.saturating_sub(1)];
                let (p1, p2) = (points[i], points[i + 1]);
                let p3 = points[(i + 2).min(points.len() - 1)];
                let c1 = (p1.0 + (p2.0 - p0.0) / 6.0, p1.1 + (p2.1 - p0.1) / 6.0);
                let c2 = (p2.0 - (p3.0 - p1.0) / 6.0, p2.1 - (p3.1 - p1.1) / 6.0);
                let _ = write!(
                    self.out,
                    "C {:.1} {:.1} {:.1} {:.1} {:.1} {:.1} ",
                    c1.0, c1.1, c2.0, c2.1, p2.0, p2.1
                );
            }
        }
        self
    }

    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.out).trim_end().to_owned()
    }
}

/// All hand-drawn shapes the UI uses, generated once at startup.
/// View boxes are documented next to each field; Slint stretches them to the element size.
#[derive(Debug, Clone)]
pub struct Sketches {
    /// 200 × 48 box outlines (three variants).
    pub boxes: [String; 3],
    /// 200 × 24 marker swashes: one thick stroke, used with a wide stroke width (three variants).
    pub markers: [String; 3],
    /// 200 × 8 underlines (two variants).
    pub underlines: [String; 2],
    /// 64 × 72 padlock.
    pub padlock: String,
    /// 24 × 24 check mark.
    pub check: String,
    /// 24 × 24 star outline.
    pub star: String,
    /// 24 × 24 plus sign.
    pub plus: String,
}

impl Sketches {
    pub fn generate() -> Self {
        let boxes = [1, 2, 3].map(|seed| Pen::new(seed, 1.0).rect(2.0, 2.0, 196.0, 44.0).finish());
        let markers = [11, 12, 13].map(|seed| {
            let mut pen = Pen::new(seed, 1.4);
            // A marker stroke drifts a little upwards and back, never perfectly level.
            pen.line(4.0, 14.0, 196.0, 10.0);
            pen.finish()
        });
        let underlines =
            [21, 22].map(|seed| Pen::new(seed, 0.8).line(1.0, 4.0, 199.0, 4.5).finish());

        let mut padlock = Pen::new(31, 1.1);
        padlock
            .arc(
                32.0,
                26.0,
                34.0,
                36.0,
                std::f64::consts::PI,
                std::f64::consts::TAU,
            )
            .line(15.0, 26.0, 15.0, 34.0)
            .line(49.0, 26.0, 49.0, 34.0)
            .rect(6.0, 34.0, 52.0, 34.0)
            .ellipse(32.0, 48.0, 8.0, 8.0)
            .line(32.0, 52.0, 32.0, 59.0);

        let check = Pen::new(41, 0.8)
            .line(4.0, 13.0, 10.0, 19.0)
            .line(10.0, 19.0, 21.0, 5.0)
            .finish();

        let mut star = Pen::new(51, 0.7);
        let points: Vec<(f64, f64)> = (0..10)
            .map(|i| {
                let angle =
                    -std::f64::consts::FRAC_PI_2 + f64::from(i) * std::f64::consts::PI / 5.0;
                let radius = if i % 2 == 0 { 10.5 } else { 4.6 };
                (12.0 + radius * angle.cos(), 12.5 + radius * angle.sin())
            })
            .collect();
        for i in 0..points.len() {
            let (a, b) = (points[i], points[(i + 1) % points.len()]);
            star.line(a.0, a.1, b.0, b.1);
        }

        let plus = Pen::new(61, 0.8)
            .line(12.0, 3.0, 12.0, 21.0)
            .line(3.0, 12.0, 21.0, 12.0)
            .finish();

        Self {
            boxes,
            markers,
            underlines,
            padlock: padlock.finish(),
            check,
            star: star.finish(),
            plus,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_well_formed() {
        let a = Sketches::generate();
        let b = Sketches::generate();
        assert_eq!(a.padlock, b.padlock, "same seeds, same drawing");
        assert_ne!(a.boxes[0], a.boxes[1], "variants differ");
        for path in a
            .boxes
            .iter()
            .chain(&a.markers)
            .chain(&a.underlines)
            .chain([&a.padlock, &a.check, &a.star, &a.plus])
        {
            assert!(path.starts_with("M "), "{path}");
            assert!(!path.contains("NaN") && !path.contains("inf"));
        }
    }

    #[test]
    fn lines_stay_near_their_endpoints() {
        let path = Pen::new(7, 1.0).line(0.0, 0.0, 100.0, 0.0).finish();
        let numbers: Vec<f64> = path
            .split_whitespace()
            .filter_map(|token| token.parse().ok())
            .collect();
        // Every coordinate pair stays within a few units of the ideal segment.
        for pair in numbers.chunks(2) {
            assert!(
                (-6.0..=106.0).contains(&pair[0]) && pair[1].abs() <= 6.0,
                "{pair:?}"
            );
        }
    }
}
