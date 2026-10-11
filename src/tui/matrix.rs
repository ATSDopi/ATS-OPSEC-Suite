//! Pluie de glyphes façon « matrix » — fond animé de la séquence de boot.
//! Cosmétique uniquement : `rand::rng()` (thread rng) est volontaire ici,
//! aucun secret n'est impliqué.

use rand::Rng;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

use super::theme::Theme;

const GLYPHS: &[char] = &[
    'ｱ', 'ｲ', 'ｳ', 'ｴ', 'ｵ', 'ｶ', 'ｷ', 'ｸ', 'ｹ', 'ｺ', 'ｻ', 'ｼ', 'ｽ', 'ｾ', 'ｿ', 'ﾀ', 'ﾁ', 'ﾂ', 'ﾃ',
    'ﾄ', 'ﾅ', 'ﾆ', 'ﾇ', 'ﾈ', 'ﾉ', '0', '1', '7', '9', 'Z', ':', '・', '<', '>', '*', '+', '=',
];

struct Column {
    x: u16,
    head: f32,
    speed: f32,
    trail: u16,
}

pub struct Rain {
    cols: Vec<Column>,
    w: u16,
    h: u16,
}

impl Rain {
    pub fn new(w: u16, h: u16) -> Self {
        let mut r = Self {
            cols: Vec::new(),
            w,
            h,
        };
        r.reseed();
        r
    }

    pub fn resize(&mut self, w: u16, h: u16) {
        if w != self.w || h != self.h {
            self.w = w;
            self.h = h;
            self.reseed();
        }
    }

    fn reseed(&mut self) {
        let mut rng = rand::rng();
        let target = (self.w as usize / 3).max(4);
        self.cols = (0..target)
            .map(|_| Column {
                x: rng.random_range(0..self.w.max(1)),
                head: rng.random_range(0.0..self.h.max(1) as f32),
                speed: rng.random_range(0.25..0.9),
                trail: rng.random_range(6..18),
            })
            .collect();
    }

    pub fn step(&mut self) {
        let mut rng = rand::rng();
        for c in &mut self.cols {
            c.head += c.speed;
            if c.head - c.trail as f32 > self.h as f32 {
                c.x = rng.random_range(0..self.w.max(1));
                c.head = 0.0;
                c.speed = rng.random_range(0.25..0.9);
                c.trail = rng.random_range(6..18);
            }
        }
    }

    /// Dessine la pluie dans `area`. `dim_factor` (0.0-1.0) estompe l'effet.
    pub fn draw(&self, buf: &mut Buffer, area: Rect, theme: &Theme, tick: u64, dim_factor: f32) {
        if area.width < 4 || area.height < 4 {
            return;
        }
        let fade = |c: Color, f: f32| -> Color {
            if let Color::Rgb(r, g, b) = c {
                Color::Rgb(
                    (r as f32 * f) as u8,
                    (g as f32 * f) as u8,
                    (b as f32 * f) as u8,
                )
            } else {
                c
            }
        };
        for col in &self.cols {
            let x = area.x + (col.x % area.width);
            for k in 0..col.trail {
                let y = col.head - k as f32;
                if y < 0.0 || y >= area.height as f32 {
                    continue;
                }
                let yy = area.y + y as u16;
                let g = glyph_at(col.x, k, tick);
                let f = 1.0 - (k as f32 / col.trail as f32);
                let style = if k == 0 {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(fade(theme.accent, f * dim_factor * 0.85))
                };
                buf.set_string(x, yy, g.to_string(), style);
            }
        }
    }
}

fn glyph_at(x: u16, k: u16, tick: u64) -> char {
    let h = (x as u64)
        .wrapping_mul(31)
        .wrapping_add((k as u64).wrapping_mul(131))
        .wrapping_add((tick / 3).wrapping_mul(7));
    GLYPHS[(h as usize) % GLYPHS.len()]
}
