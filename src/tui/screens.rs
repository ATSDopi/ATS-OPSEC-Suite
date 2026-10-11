//! Écrans des onglets — dashboard, vault (picker), stego, shred, xfer
//! (QR live), keys, settings, logs.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Widget,
};

use super::app::{App, FilePicker, Tab};
use super::theme::Theme;
use crate::config::Mode;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    match app.tab {
        Tab::Dashboard => dashboard(f, area, app, theme),
        Tab::Vault => vault(f, area, app, theme),
        Tab::Stego => stego(f, area, app, theme),
        Tab::Shred => shred(f, area, app, theme),
        Tab::Transfer => transfer(f, area, app, theme),
        Tab::Keys => keys(f, area, app, theme),
        Tab::Settings => settings(f, area, app, theme),
        Tab::Logs => logs(f, area, app, theme),
    }
}

fn panel<'a>(title: &'a str, theme: &Theme) -> Block<'a> {
    Block::default()
        .title(format!(" {} ", title))
        .title_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.dim))
}

// ---------------------------------------------------------------- dashboard

fn dashboard(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let vrows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(38),
            Constraint::Percentage(30),
            Constraint::Percentage(32),
        ])
        .split(vrows[0]);

    // Col 1 — profil système (données réelles du probe).
    let p = &app.profile;
    let feats = {
        let mut v = Vec::new();
        if p.cpu.aes_ni {
            v.push("aes-ni");
        }
        if p.cpu.avx2 {
            v.push("avx2");
        }
        if p.cpu.sse42 {
            v.push("sse4.2");
        }
        if v.is_empty() {
            "baseline".to_string()
        } else {
            v.join(" ")
        }
    };
    let kv = |k: &str, v: String, c: Color| {
        Line::from(vec![
            Span::styled(format!("{k:<12}"), Style::default().fg(theme.dim)),
            Span::styled(v, Style::default().fg(c)),
        ])
    };
    let hyper = match p.cpu.hypervisor {
        Some(true) => ("DETECTED", theme.warn),
        Some(false) => ("none", theme.ok),
        None => ("n/a", theme.dim),
    };
    let tracer = match p.tracer_detected {
        Some(true) => ("DETECTED", theme.err),
        Some(false) => ("none", theme.ok),
        None => ("n/a", theme.dim),
    };
    let sys_lines = vec![
        kv("host", format!("{} / {}", p.os, p.arch), theme.fg),
        kv("cpu", feats, theme.fg),
        kv("hypervisor", hyper.0.into(), hyper.1),
        kv(
            "ram",
            p.total_ram_mb
                .map(|m| format!("{m} MiB"))
                .unwrap_or_else(|| "n/a".into()),
            theme.fg,
        ),
        kv(
            "memlock",
            p.memlock.label().into(),
            if p.memlock.ok() { theme.ok } else { theme.warn },
        ),
        kv(
            "fs (cwd)",
            p.fs_type.clone().unwrap_or_else(|| "n/a".into()),
            theme.fg,
        ),
        kv(
            "csprng",
            if p.rng_ok {
                "seeded".into()
            } else {
                "FAIL".into()
            },
            if p.rng_ok { theme.ok } else { theme.err },
        ),
        kv("tracer", tracer.0.into(), tracer.1),
        kv(
            "swap",
            match p.swap_present {
                Some(true) => "present".into(),
                Some(false) => "none".into(),
                None => "n/a".into(),
            },
            match p.swap_present {
                Some(true) => theme.warn,
                Some(false) => theme.ok,
                None => theme.dim,
            },
        ),
    ];
    Paragraph::new(sys_lines)
        .block(panel("HOST PROFILE", theme))
        .render(cols[0], f.buffer_mut());

    // Col 2 — score OPSEC.
    let score = app.opsec_score();
    let score_color = if score >= 70 {
        theme.ok
    } else if score >= 40 {
        theme.warn
    } else {
        theme.err
    };
    let score_area = cols[1];
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(score_area);
    Gauge::default()
        .block(panel("OPSEC POSTURE", theme))
        .gauge_style(Style::default().fg(score_color))
        .ratio(score as f64 / 100.0)
        .label(format!("{score}/100"))
        .render(v[0], f.buffer_mut());
    let notes = vec![
        Line::from(Span::styled(
            "scoring heuristic v0.1",
            Style::default().fg(theme.dim),
        )),
        Line::from(Span::styled(
            format!(
                "mode: {}",
                if app.mode == Mode::Expert {
                    "expert"
                } else {
                    "standard"
                }
            ),
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            if p.cpu.hypervisor == Some(true) || p.tracer_detected == Some(true) {
                "⚠ hostile-env indicators"
            } else {
                "environment nominal"
            },
            Style::default().fg(
                if p.cpu.hypervisor == Some(true) || p.tracer_detected == Some(true) {
                    theme.warn
                } else {
                    theme.ok
                },
            ),
        )),
    ];
    Paragraph::new(notes)
        .block(panel("ASSESSMENT", theme))
        .render(v[1], f.buffer_mut());

    // Col 3 — modules.
    let modules = [
        ("crypto engine", "staged", "v0.2", theme.warn),
        ("cascade cipher", "staged", "v0.2", theme.warn),
        ("pq hybrid kem", "planned", "v0.2", theme.dim),
        ("stego carrier", "planned", "v0.2", theme.dim),
        ("secure wipe", "staged", "v0.2", theme.warn),
        ("qr fountain", "static qr", "v0.1", theme.ok),
        ("keyring", "planned", "v0.2", theme.dim),
        ("hidden volumes", "planned", "v0.3", theme.dim),
        ("duress/decoy", "planned", "v0.3", theme.dim),
        ("honeyfiles", "planned", "v0.3", theme.dim),
    ];
    let rows_t: Vec<Row> = modules
        .iter()
        .map(|(n, s, v, c)| {
            Row::new(vec![
                Cell::from(*n),
                Cell::from(Span::styled(*s, Style::default().fg(*c))),
                Cell::from(Span::styled(*v, Style::default().fg(theme.dim))),
            ])
        })
        .collect();
    Table::new(
        rows_t,
        [
            Constraint::Percentage(52),
            Constraint::Percentage(28),
            Constraint::Percentage(20),
        ],
    )
    .block(panel("MODULES", theme))
    .render(cols[2], f.buffer_mut());

    // Bandeau bas — derniers logs.
    let recent: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(4)
        .map(|(t, l, m)| {
            let c = match l {
                super::app::Level::Info => theme.dim,
                super::app::Level::Ok => theme.ok,
                super::app::Level::Warn => theme.warn,
                super::app::Level::Err => theme.err,
            };
            Line::from(vec![
                Span::styled(format!("{t} "), Style::default().fg(theme.dim)),
                Span::styled(m.clone(), Style::default().fg(c)),
            ])
        })
        .collect();
    Paragraph::new(recent)
        .block(panel("SESSION FEED", theme))
        .render(vrows[1], f.buffer_mut());
}

// ---------------------------------------------------------------- vault

fn vault(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);

    draw_picker(f, cols[0], &app.picker_vault, app.tab == Tab::Vault, theme);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(9)])
        .split(cols[1]);

    // Target info.
    let mut lines = Vec::new();
    let target = app
        .picker_vault
        .target
        .as_ref()
        .map(|t| (t.name.clone(), t.size, t.path.clone()));
    match target {
        Some((name, size, path)) => {
            lines.push(Line::from(vec![
                Span::styled("target   ", Style::default().fg(theme.dim)),
                Span::styled(name, Style::default().fg(theme.accent)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("size     ", Style::default().fg(theme.dim)),
                Span::styled(human_size(size), Style::default().fg(theme.fg)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("path     ", Style::default().fg(theme.dim)),
                Span::styled(path.display().to_string(), Style::default().fg(theme.fg)),
            ]));
            let hash = app.picker_vault.target_hash();
            lines.push(Line::from(vec![
                Span::styled("blake3   ", Style::default().fg(theme.dim)),
                Span::styled(
                    hash.map(|h| h.chars().take(32).collect::<String>())
                        .map(|h| format!("{h}…"))
                        .unwrap_or_else(|| "n/a".into()),
                    Style::default().fg(theme.accent2),
                ),
            ]));
        }
        None => {
            lines.push(Line::from(Span::styled(
                "no target — select a file with [enter]",
                Style::default().fg(theme.dim),
            )));
        }
    }
    Paragraph::new(lines)
        .block(panel("TARGET", theme))
        .render(right[0], f.buffer_mut());

    // Actions.
    let actions = vec![
        Line::from(vec![
            Span::styled("[e] ", Style::default().fg(theme.accent)),
            Span::raw("encrypt → .aos container   "),
            Span::styled("staged v0.2", Style::default().fg(theme.warn)),
        ]),
        Line::from(vec![
            Span::styled("[d] ", Style::default().fg(theme.accent)),
            Span::raw("decrypt .aos → plaintext  "),
            Span::styled("staged v0.2", Style::default().fg(theme.warn)),
        ]),
        Line::from(vec![
            Span::styled("[i] ", Style::default().fg(theme.accent)),
            Span::raw("container header audit   "),
            Span::styled("staged v0.2", Style::default().fg(theme.warn)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "pipeline: argon2id → stream aead → ",
                Style::default().fg(theme.dim),
            ),
            Span::styled(
                "xchacha20 | aes-256-gcm | cascade",
                Style::default().fg(theme.accent2),
            ),
        ]),
    ];
    Paragraph::new(actions)
        .block(panel("OPERATIONS", theme))
        .render(right[1], f.buffer_mut());
}

fn draw_picker(f: &mut Frame, area: Rect, picker: &FilePicker, focused: bool, theme: &Theme) {
    let title = format!(" {} ", picker.dir.display());
    let mut block = panel("FILES", theme).title(title);
    if focused {
        block = block.border_style(Style::default().fg(theme.accent));
    }
    let inner_h = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = picker
        .entries
        .iter()
        .skip(picker.sel.saturating_sub(inner_h.saturating_sub(1)))
        .take(inner_h.max(1))
        .map(|e| {
            let (icon, c) = if e.is_dir {
                ("▸", theme.accent2)
            } else {
                (" ", theme.fg)
            };
            let name = if e.is_dir {
                format!("{}/", e.name)
            } else {
                format!("{:<38} {}", e.name, human_size(e.size))
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{icon} "), Style::default().fg(c)),
                Span::styled(name, Style::default().fg(c)),
            ]))
        })
        .collect();
    let list = List::new(items).block(block).highlight_style(
        Style::default()
            .bg(Color::Rgb(30, 50, 45))
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(picker.sel.min(inner_h.saturating_sub(1))));
    f.render_stateful_widget(list, area, &mut state);
}

fn human_size(n: u64) -> String {
    const U: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

// ---------------------------------------------------------------- stego

fn stego(f: &mut Frame, area: Rect, _app: &App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let diagram = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  plaintext ─▶ compress ─▶ .aos encrypt ─▶ PRNG-dispersed",
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            "                                            │",
            Style::default().fg(theme.dim),
        )),
        Line::from(Span::styled(
            "                                            ▼",
            Style::default().fg(theme.dim),
        )),
        Line::from(Span::styled(
            "                                    ┌───────────────┐",
            Style::default().fg(theme.accent2),
        )),
        Line::from(Span::styled(
            "                                    │  cover media  │  PNG · WAV",
            Style::default().fg(theme.accent2),
        )),
        Line::from(Span::styled(
            "                                    └───────────────┘",
            Style::default().fg(theme.accent2),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  ciphertext ≈ white noise → statistically invisible",
            Style::default().fg(theme.dim),
        )),
    ];
    Paragraph::new(diagram)
        .block(panel("PIPELINE", theme))
        .render(cols[0], f.buffer_mut());

    let feats = [
        ("png lsb dispersé (keyed prng)", "v0.2", theme.fg),
        ("wav pcm lsb", "v0.2", theme.fg),
        ("capacity analyzer + heatmap", "v0.2", theme.fg),
        ("auto-steganalysis chi²/rs", "v0.3", theme.dim),
        ("jpeg dct (f5-style)", "stretch", theme.dim),
        ("multi-carrier split", "stretch", theme.dim),
        ("exif/metadata scrub", "v0.2", theme.fg),
    ];
    let items: Vec<ListItem> = feats
        .iter()
        .map(|(n, v, c)| {
            ListItem::new(Line::from(vec![
                Span::styled("· ", Style::default().fg(theme.dim)),
                Span::styled(*n, Style::default().fg(*c)),
                Span::styled(format!("  [{v}]"), Style::default().fg(theme.dim)),
            ]))
        })
        .collect();
    List::new(items)
        .block(panel("CAPABILITIES — PLANNED", theme))
        .render(cols[1], f.buffer_mut());
}

// ---------------------------------------------------------------- shred

fn shred(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);
    draw_picker(f, cols[0], &app.picker_shred, app.tab == Tab::Shred, theme);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(6)])
        .split(cols[1]);

    let target = app
        .picker_shred
        .target
        .as_ref()
        .map(|t| t.name.clone())
        .unwrap_or_else(|| "none — select a file".into());
    let info = vec![
        Line::from(vec![
            Span::styled("target  ", Style::default().fg(theme.dim)),
            Span::styled(target, Style::default().fg(theme.warn)),
        ]),
        Line::from(vec![
            Span::styled("passes  ", Style::default().fg(theme.dim)),
            Span::styled(
                format!("◀ {} ▶  (0x00 / 0xFF / random)", app.shred_passes),
                Style::default().fg(theme.accent),
            ),
        ]),
        Line::from(Span::styled(
            "rename→truncate→unlink after overwrite",
            Style::default().fg(theme.dim),
        )),
    ];
    Paragraph::new(info)
        .block(panel("SHREDDER", theme))
        .render(right[0], f.buffer_mut());

    let fs = app.profile.fs_type.as_deref().unwrap_or("unknown");
    let warn = vec![
        Line::from(Span::styled(
            "⚠ HONEST FORENSICS",
            Style::default().fg(theme.warn).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("fs: {fs} — overwrite is NOT guaranteed on"),
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            "SSD (TRIM/wear-leveling), journaled or CoW",
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            "filesystems. Prefer full-disk encryption.",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("[s] ", Style::default().fg(theme.err)),
            Span::styled(
                "shred target — staged v0.2",
                Style::default().fg(theme.warn),
            ),
        ]),
    ];
    Paragraph::new(warn)
        .block(panel("WARNING", theme).border_style(Style::default().fg(theme.warn)))
        .render(right[1], f.buffer_mut());
}

// ---------------------------------------------------------------- transfer

fn transfer(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    // Ligne d'input.
    let cursor = if app.qr_edit && (app.tick / 15).is_multiple_of(2) {
        "█"
    } else {
        " "
    };
    let input = Paragraph::new(format!("{}{}", app.qr_input, cursor))
        .block(panel("QR PAYLOAD — type to edit", theme));
    input.render(rows[0], f.buffer_mut());

    // QR rendu réel.
    if app.qr_input.is_empty() {
        Paragraph::new("type a payload to render a live QR")
            .alignment(Alignment::Center)
            .style(Style::default().fg(theme.dim))
            .block(panel("QR CODE", theme))
            .render(rows[1], f.buffer_mut());
    } else {
        match qrcode::QrCode::new(app.qr_input.as_bytes()) {
            Ok(code) => {
                let s = code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .dark_color(qrcode::render::unicode::Dense1x2::Dark)
                    .light_color(qrcode::render::unicode::Dense1x2::Light)
                    .build();
                Paragraph::new(s)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Black).bg(Color::White))
                    .block(panel("QR CODE — STATIC", theme))
                    .render(rows[1], f.buffer_mut());
            }
            Err(_) => {
                Paragraph::new(
                    "payload too large for a single QR — animated RaptorQ fountain lands in v0.2",
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme.warn))
                .block(panel("QR CODE", theme))
                .render(rows[1], f.buffer_mut());
            }
        }
    }

    let footer = Line::from(vec![
        Span::styled("mode: ", Style::default().fg(theme.dim)),
        Span::styled("static single-qr", Style::default().fg(theme.ok)),
        Span::styled("   planned: ", Style::default().fg(theme.dim)),
        Span::styled(
            "animated tx (raptorq) · webcam rx · audio fsk",
            Style::default().fg(theme.accent2),
        ),
    ]);
    Paragraph::new(footer)
        .alignment(Alignment::Center)
        .render(rows[2], f.buffer_mut());
}

// ---------------------------------------------------------------- keys

fn keys(f: &mut Frame, area: Rect, _app: &App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let empty = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  keyring empty",
            Style::default().fg(theme.dim),
        )),
        Line::from(Span::styled(
            "  sealed by master passphrase (argon2id → aead) — v0.2",
            Style::default().fg(theme.dim),
        )),
    ];
    Paragraph::new(empty)
        .block(panel("KEYRING", theme))
        .render(cols[0], f.buffer_mut());

    let feats = [
        ("keygen: x25519 · ed25519", "v0.2"),
        ("keygen: ml-kem-768 · ml-dsa-65 (pq)", "v0.2"),
        ("hybrid x-wing recipients", "v0.2"),
        ("keyfiles (blake3 facteur)", "v0.2"),
        ("ssh-style randomart fingerprint", "v0.2"),
        ("shamir k-of-n + paper backup", "v0.3"),
        ("duress key → decoy vault", "v0.3"),
    ];
    let items: Vec<ListItem> = feats
        .iter()
        .map(|(n, v)| {
            ListItem::new(Line::from(vec![
                Span::styled("· ", Style::default().fg(theme.dim)),
                Span::styled(*n, Style::default().fg(theme.fg)),
                Span::styled(format!("  [{v}]"), Style::default().fg(theme.dim)),
            ]))
        })
        .collect();
    List::new(items)
        .block(panel("PLANNED", theme))
        .render(cols[1], f.buffer_mut());
}

// ---------------------------------------------------------------- settings

fn settings(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let expert = app.mode == Mode::Expert;
    let rows = [
        (
            "mode",
            if expert { "expert" } else { "standard" }.to_string(),
            true,
        ),
        ("theme", app.theme().name.to_string(), true),
        (
            "boot animation",
            if app.boot_anim { "on" } else { "off" }.to_string(),
            true,
        ),
        ("argon2 memory (KiB)", app.argon2.m_kib.to_string(), expert),
        ("argon2 iterations", app.argon2.t.to_string(), expert),
        ("argon2 lanes", app.argon2.p.to_string(), expert),
        ("save config", "write to config.toml".to_string(), true),
    ];
    let sel = app.settings_sel.min(rows.len() - 1);

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (k, v, enabled))| {
            let c = if *enabled { theme.fg } else { theme.dim };
            let vc = if *enabled { theme.accent } else { theme.dim };
            let suffix = if !enabled { "   (expert mode)" } else { "" };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{k:<24}"), Style::default().fg(c)),
                Span::styled(format!("◀ {v} ▶"), Style::default().fg(vc)),
                Span::styled(suffix, Style::default().fg(theme.dim)),
            ]))
            .style(if i == sel {
                Style::default().bg(Color::Rgb(30, 50, 45))
            } else {
                Style::default()
            })
        })
        .collect();

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(9), Constraint::Length(4)])
        .split(area);
    List::new(items)
        .block(panel("CONFIGURATION", theme))
        .render(split[0], f.buffer_mut());

    let cfg_path = crate::config::Config::path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "n/a".into());
    Paragraph::new(vec![
        Line::from(Span::styled(
            "↑↓ navigate · ←→ adjust · enter apply/save",
            Style::default().fg(theme.dim),
        )),
        Line::from(Span::styled(
            format!("file: {cfg_path}"),
            Style::default().fg(theme.dim),
        )),
    ])
    .block(panel("HELP", theme))
    .render(split[1], f.buffer_mut());
}

// ---------------------------------------------------------------- logs

fn logs(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let start = total.saturating_sub(inner_h + app.log_scroll as usize);
    let items: Vec<Line> = app
        .log
        .iter()
        .skip(start)
        .map(|(t, l, m)| {
            let c = match l {
                super::app::Level::Info => theme.fg,
                super::app::Level::Ok => theme.ok,
                super::app::Level::Warn => theme.warn,
                super::app::Level::Err => theme.err,
            };
            Line::from(vec![
                Span::styled(format!("{t} "), Style::default().fg(theme.dim)),
                Span::styled(
                    format!(
                        "{:<5}",
                        match l {
                            super::app::Level::Info => "info",
                            super::app::Level::Ok => "ok",
                            super::app::Level::Warn => "warn",
                            super::app::Level::Err => "err",
                        }
                    ),
                    Style::default().fg(c),
                ),
                Span::styled(m.clone(), Style::default().fg(theme.fg)),
            ])
        })
        .collect();
    Paragraph::new(items)
        .block(panel(
            &format!("SESSION LOG — {total} events  (↑↓ scroll)"),
            theme,
        ))
        .render(area, f.buffer_mut());
}
