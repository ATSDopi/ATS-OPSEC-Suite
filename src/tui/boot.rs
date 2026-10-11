//! Séquence de boot cinématique : pluie matrix → décodage du logo →
//! checklist d'initialisation (données RÉELLES du probe) → transition.

use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Widget};

use super::logo::{LOGO_BIG, LOGO_MINI, SCRAMBLE, TAGLINE, logo_width};
use super::theme::Theme;
use crate::sys::SystemProfile;

const LOGO_START: u64 = 600;
const LOGO_SPAN: u64 = 2100;
const TAGLINE_AT: u64 = 2750;
const CHECK_START: u64 = 3150;
const CHECK_STEP: u64 = 340;
const COMPLETE_AT: u64 = 6000;
const AUTO_ENTER_AT: u64 = 6900;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ItemStatus {
    Ok,
    Warn,
    Fail,
}

pub struct BootItem {
    pub label: &'static str,
    pub result: String,
    pub status: ItemStatus,
}

pub struct Boot {
    pub start: Instant,
    pub items: Vec<BootItem>,
    skipped: bool,
}

impl Boot {
    pub fn new(p: &SystemProfile) -> Self {
        let cpu = {
            let mut v = Vec::new();
            if p.cpu.aes_ni {
                v.push("AES-NI");
            }
            if p.cpu.avx2 {
                v.push("AVX2");
            }
            if p.cpu.sse42 {
                v.push("SSE4.2");
            }
            if v.is_empty() {
                "BASELINE".to_string()
            } else {
                v.join(" ")
            }
        };
        let env = if p.tracer_detected == Some(true) {
            ("TRACER DETECTED".to_string(), ItemStatus::Warn)
        } else if p.cpu.hypervisor == Some(true) {
            ("HYPERVISOR PRESENT".to_string(), ItemStatus::Warn)
        } else {
            ("CLEAN".to_string(), ItemStatus::Ok)
        };

        let items = vec![
            item(
                "csprng entropy pool",
                if p.rng_ok { "SEEDED 256b" } else { "FAILURE" },
                p.rng_ok,
            ),
            item(
                "host capability probe",
                &format!("{} · {}", p.os, p.arch),
                true,
            ),
            item("cpu feature matrix", &cpu, true),
            item("secure memory lock", p.memlock.label(), p.memlock.ok()),
            item(
                "filesystem scan",
                p.fs_type.as_deref().unwrap_or("unknown"),
                p.fs_type.is_some(),
            ),
            BootItem {
                label: "environment integrity",
                result: env.0,
                status: env.1,
            },
            item("crypto engine mount", "3 SUITES STAGED", true),
            item("module registry", "8 MODULES", true),
        ];
        Self {
            start: Instant::now(),
            items,
            skipped: false,
        }
    }

    pub fn elapsed(&self) -> u64 {
        if self.skipped {
            return u64::MAX / 2;
        }
        self.start.elapsed().as_millis() as u64
    }

    pub fn skip(&mut self) {
        self.skipped = true;
    }

    /// Tous les items sont affichés + la fenêtre finale est passée →
    /// on peut entrer dans le main automatiquement.
    pub fn should_auto_enter(&self) -> bool {
        self.elapsed() >= AUTO_ENTER_AT
    }

    pub fn all_done(&self) -> bool {
        self.elapsed() >= COMPLETE_AT
    }
}

fn item(label: &'static str, result: &str, ok: bool) -> BootItem {
    BootItem {
        label,
        result: result.to_string(),
        status: if ok { ItemStatus::Ok } else { ItemStatus::Fail },
    }
}

// ---------------------------------------------------------------- draw

/// Rendu complet du boot (pluie + logo + checklist + progress).
pub fn draw(f: &mut Frame, boot: &Boot, rain: &super::matrix::Rain, theme: &Theme, tick: u64) {
    let area = f.area();
    let buf = f.buffer_mut();
    let t = boot.elapsed().min(30_000);

    // Fond noir + pluie.
    clear(buf, area);
    rain.draw(buf, area, theme, tick, 0.55);

    if area.width < 50 || area.height < 16 {
        Paragraph::new("ATS-OPSEC-SUITE — enlarge terminal")
            .alignment(Alignment::Center)
            .style(Style::default().fg(theme.accent))
            .render(area, buf);
        return;
    }

    // Bandeau haut : bootloader typing.
    draw_bootloader_line(buf, area, theme, t);

    // Logo centré verticalement (zone haute).
    let big = area.width >= 96;
    let logo: &[&str] = if big { LOGO_BIG } else { LOGO_MINI };
    let lw = if big {
        logo_width()
    } else {
        logo.iter().map(|l| l.chars().count()).max().unwrap_or(0) as u16
    };
    let lx = area.x + area.width.saturating_sub(lw) / 2;
    let ly = area.y + 2;
    draw_logo(buf, lx, ly, logo, theme, t);

    // Tagline typewriter.
    if t >= TAGLINE_AT {
        let tag_w = TAGLINE.chars().count() as u16;
        let typed = ((t - TAGLINE_AT) / 14) as usize;
        let s: String = TAGLINE.chars().take(typed).collect();
        let tx = area.x + area.width.saturating_sub(tag_w) / 2;
        buf.set_string(
            tx,
            ly + logo.len() as u16 + 1,
            s,
            Style::default()
                .fg(theme.dim)
                .add_modifier(Modifier::ITALIC),
        );
    }

    // Checklist — sous le logo.
    let cy = ly + logo.len() as u16 + 3;
    draw_checklist(buf, area, cy, boot, theme, t);

    // Barre de progression bas.
    let prog_area = Rect::new(
        area.x + 8,
        area.y + area.height.saturating_sub(3),
        area.width.saturating_sub(16),
        1,
    );
    draw_progress(buf, prog_area, theme, t);

    // Ligne finale : clignote en attente de touche, fixe quand on entre.
    if t >= COMPLETE_AT {
        let entering = boot.skipped || t >= AUTO_ENTER_AT - 600;
        let msg = if entering {
            "ALL SYSTEMS NOMINAL — ENTERING"
        } else {
            "ALL SYSTEMS NOMINAL — PRESS ANY KEY"
        };
        if entering || (t / 400).is_multiple_of(2) {
            let w = msg.chars().count() as u16;
            let x = area.x + area.width.saturating_sub(w) / 2;
            buf.set_string(
                x,
                area.y + area.height.saturating_sub(2),
                msg,
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            );
        }
    }

    // Meta bas-gauche.
    let meta = format!("ats-opsec v{} · boot seq", env!("CARGO_PKG_VERSION"));
    buf.set_string(
        area.x + 1,
        area.y + area.height.saturating_sub(1),
        meta,
        Style::default().fg(theme.dim),
    );
}

fn clear(buf: &mut Buffer, area: Rect) {
    let blank = Style::default().bg(Color::Black);
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            if let Some(c) = buf.cell_mut((x, y)) {
                c.set_style(blank);
                c.set_symbol(" ");
            }
        }
    }
}

fn draw_bootloader_line(buf: &mut Buffer, area: Rect, theme: &Theme, t: u64) {
    const LINE: &str = "ATS SECURE BOOTLOADER v0.1 — integrity check in progress";
    let typed = (t / 18) as usize;
    if typed == 0 {
        return;
    }
    let s: String = LINE.chars().take(typed).collect();
    buf.set_string(area.x + 1, area.y, s, Style::default().fg(theme.dim));
}

/// Chaque glyphe du logo « se décode » à un instant déterministe ; avant,
/// un caractère pseudo-aléatoire tourne. Balayage lumineux horizontal.
fn draw_logo(buf: &mut Buffer, lx: u16, ly: u16, logo: &[&str], theme: &Theme, t: u64) {
    if t < LOGO_START {
        return;
    }
    let rel = t - LOGO_START;
    // Balayage : une colonne brillante traverse le logo deux fois.
    let sweep_x = if rel < 1600 {
        Some(((rel as f32 / 1600.0) * (logo_width() as f32 + 20.0)) as i32 - 10)
    } else {
        None
    };

    for (r, line) in logo.iter().enumerate() {
        for (c, ch) in line.chars().enumerate() {
            if ch == ' ' {
                continue;
            }
            // Instant de « stabilisation » du glyphe : dépend de (r,c).
            let order = ((r as u64 * 73 + c as u64 * 31) % 97) * (LOGO_SPAN / 120);
            let settle = order;
            let x = lx + c as u16;
            let y = ly + r as u16;

            let (glyph, mut style) = if rel < settle {
                let g = SCRAMBLE[((r * 31 + c * 17) as u64 + rel / 40) as usize % SCRAMBLE.len()];
                (g, Style::default().fg(theme.dim))
            } else {
                let since = rel - settle;
                let mut st = Style::default().fg(theme.accent);
                if since < 150 {
                    st = st.fg(Color::White).add_modifier(Modifier::BOLD);
                }
                (ch, st)
            };
            if let Some(sx) = sweep_x
                && (x as i32 - (lx as i32 + sx)).abs() <= 1
                && rel >= settle
            {
                style = Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD);
            }
            buf.set_string(x, y, glyph.to_string(), style);
        }
    }
}

fn draw_checklist(buf: &mut Buffer, area: Rect, cy: u16, boot: &Boot, theme: &Theme, t: u64) {
    let width = 62u16.min(area.width.saturating_sub(8));
    let x = area.x + area.width.saturating_sub(width) / 2;

    if t >= CHECK_START {
        let title: String = "── MODULE INIT "
            .chars()
            .chain(std::iter::repeat('─'))
            .take(width as usize)
            .collect();
        buf.set_string(x, cy, title, Style::default().fg(theme.dim));
    }

    for (i, it) in boot.items.iter().enumerate() {
        let y = cy + 2 + i as u16;
        if y >= area.y + area.height.saturating_sub(4) {
            break;
        }
        let start = CHECK_START + i as u64 * CHECK_STEP;
        if t < start {
            continue;
        }
        let rel = t - start;

        // Label typewriter (~110 ms).
        let typed = (rel / 9) as usize;
        let label: String = it.label.chars().take(typed).collect();
        buf.set_string(
            x + 1,
            y,
            format!("{:<38}", label),
            Style::default().fg(theme.fg),
        );

        if typed < it.label.chars().count() {
            continue;
        }

        // Spinner ~170 ms puis résultat.
        if rel < 110 + 170 {
            const SPIN: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
            let s = SPIN[(rel / 30) as usize % SPIN.len()];
            buf.set_string(x + 40, y, s.to_string(), Style::default().fg(theme.accent2));
            continue;
        }

        let (badge, color) = match it.status {
            ItemStatus::Ok => ("[ OK ]", theme.ok),
            ItemStatus::Warn => ("[WARN]", theme.warn),
            ItemStatus::Fail => ("[FAIL]", theme.err),
        };
        buf.set_string(
            x + 40,
            y,
            badge,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        );
        buf.set_string(x + 47, y, &it.result, Style::default().fg(theme.fg));
    }
}

fn draw_progress(buf: &mut Buffer, area: Rect, theme: &Theme, t: u64) {
    if area.width < 10 || t < CHECK_START {
        return;
    }
    let ratio = ((t.saturating_sub(CHECK_START)) as f64 / (COMPLETE_AT - CHECK_START) as f64)
        .clamp(0.0, 1.0);
    Gauge::default()
        .block(Block::default().borders(Borders::NONE))
        .gauge_style(Style::default().fg(theme.accent).bg(Color::Black))
        .ratio(ratio)
        .label("")
        .render(area, buf);
}

/// Bruit de transition (glitch) — superposé à l'écran suivant ~300 ms.
pub fn draw_glitch(buf: &mut Buffer, area: Rect, theme: &Theme, frac_left: f32, tick: u64) {
    let density = (frac_left * 0.16).clamp(0.0, 0.16);
    let cells = area.width as u64 * area.height as u64;
    let n = (cells as f32 * density) as u64;
    for i in 0..n {
        let h = i
            .wrapping_mul(2654435761)
            .wrapping_add(tick.wrapping_mul(97));
        let x = area.x + (h % area.width.max(1) as u64) as u16;
        let y = area.y + ((h >> 13) % area.height.max(1) as u64) as u16;
        let g = SCRAMBLE[(h >> 7) as usize % SCRAMBLE.len()];
        buf.set_string(x, y, g.to_string(), Style::default().fg(theme.dim));
    }
}

#[allow(dead_code)]
pub const BOOT_BUDGET: Duration = Duration::from_millis(AUTO_ENTER_AT);
