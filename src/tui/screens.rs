//! Écrans des onglets — dashboard, vault (picker), stego, shred, xfer
//! (QR live), keys, settings, logs.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Widget,
};

use super::app::{App, CryptMode, FilePicker, Tab};
use super::theme::Theme;
use crate::config::Mode;

pub fn draw(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    match app.tab {
        Tab::Dashboard => dashboard(f, area, app, theme),
        Tab::Crypt => crypt(f, area, app, theme),
        Tab::Stego => stego(f, area, app, theme),
        Tab::Shred => shred(f, area, app, theme),
        Tab::Keys => keys(f, area, app, theme),
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
                "mode: {} · [x] toggle",
                if app.mode == Mode::Expert {
                    "expert"
                } else {
                    "standard"
                }
            ),
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            format!("ops done: {} · keys: {}", app.ops_done, app.keyring.len()),
            Style::default().fg(theme.fg),
        )),
        Line::from(Span::styled(
            format!("argon2: {}MiB [a] · [w] save cfg", app.argon2.m_kib / 1024),
            Style::default().fg(theme.dim),
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
        ("crypto engine .aos", "live", "v0.2", theme.ok),
        ("cascade cipher", "live", "v0.2", theme.ok),
        ("pq hybrid kem (xwing)", "live", "v0.2", theme.ok),
        ("keyring", "live", "v0.2", theme.ok),
        ("secure wipe", "live", "v0.2", theme.ok),
        ("zstd + pad-size", "live", "v0.2", theme.ok),
        ("stego carrier", "planned", "v0.3", theme.dim),
        ("qr fountain", "static qr", "v0.3", theme.warn),
        ("hidden volumes", "planned", "v0.3", theme.dim),
        ("duress/decoy", "planned", "v0.3", theme.dim),
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

fn crypt(f: &mut Frame, area: Rect, app: &mut App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(area);

    draw_picker(f, cols[0], &app.picker_vault, app.tab == Tab::Crypt, theme);

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

    // Actions + options live, catégorisées par niveau.
    let on = |b: bool| {
        if b {
            ("on ", theme.ok)
        } else {
            ("off", theme.dim)
        }
    };
    let (zc, zo) = (on(app.vault_compress), on(app.vault_shred_orig));
    let gc = on(app.vault_pad);
    let (mode_s, mode_c) = match app.crypt_mode {
        CryptMode::Password => ("passphrase (argon2id)", theme.fg),
        CryptMode::Recipients => ("recipient keys — POST-QUANTUM", theme.accent2),
    };
    let tier = match app.vault_suite {
        crate::crypto::CipherSuite::Cascade => ("MAX", theme.accent2),
        crate::crypto::CipherSuite::XChaCha20 => ("STRONG", theme.ok),
        crate::crypto::CipherSuite::Aes256Gcm => ("STRONG·AES-NI", theme.ok),
    };
    let actions = vec![
        Line::from(vec![
            Span::styled("[e] ", Style::default().fg(theme.accent)),
            Span::raw("encrypt  "),
            Span::styled("[d] ", Style::default().fg(theme.accent)),
            Span::raw("decrypt  "),
            Span::styled("[i] ", Style::default().fg(theme.accent)),
            Span::raw("audit  "),
            Span::styled("[drop]", Style::default().fg(theme.dim)),
            Span::raw(" = select file"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("[m] ", Style::default().fg(theme.accent)),
            Span::raw("auth mode   "),
            Span::styled(mode_s, Style::default().fg(mode_c)),
        ]),
        Line::from(vec![
            Span::styled("[c] ", Style::default().fg(theme.accent)),
            Span::raw("cipher      "),
            Span::styled(
                format!("{:<22}", app.vault_suite.label()),
                Style::default().fg(theme.fg),
            ),
            Span::styled(tier.0, Style::default().fg(tier.1)),
        ]),
        Line::from(vec![
            Span::styled("[z] ", Style::default().fg(theme.accent)),
            Span::raw("compress    "),
            Span::styled(zc.0, Style::default().fg(zc.1)),
            Span::raw("   [g] pad-size    "),
            Span::styled(gc.0, Style::default().fg(gc.1)),
        ]),
        Line::from(vec![
            Span::styled("[o] ", Style::default().fg(theme.accent)),
            Span::raw("shred orig  "),
            Span::styled(zo.0, Style::default().fg(zo.1)),
            Span::styled(
                "   [j] jump  [h] home  [⬅] up",
                Style::default().fg(theme.dim),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            format!(
                "kdf argon2id m={}KiB t={} p={}  ([a] on DASH)",
                app.argon2.m_kib, app.argon2.t, app.argon2.p
            ),
            Style::default().fg(theme.dim),
        )),
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

// ---------------------------------------------------------------- keys

fn keys(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    if app.keyring.is_empty() {
        let empty = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  keyring empty — [g] generate an X-Wing keypair",
                Style::default().fg(theme.dim),
            )),
            Line::from(Span::styled(
                "  hybrid x25519 + ml-kem-768 (post-quantum safe)",
                Style::default().fg(theme.dim),
            )),
        ];
        Paragraph::new(empty)
            .block(panel("KEYRING", theme))
            .render(cols[0], f.buffer_mut());
    } else {
        let rows: Vec<Row> = app
            .keyring
            .iter()
            .enumerate()
            .map(|(i, (n, fp, has_sec))| {
                let sel = i == app.keys_sel;
                Row::new(vec![
                    Cell::from(if sel { "▶" } else { " " }),
                    Cell::from(n.clone()),
                    Cell::from(Span::styled(fp.clone(), Style::default().fg(theme.accent2))),
                    Cell::from(Span::styled(
                        if *has_sec { "pub+sec" } else { "pub only" },
                        Style::default().fg(if *has_sec { theme.ok } else { theme.dim }),
                    )),
                ])
            })
            .collect();
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Percentage(38),
                Constraint::Percentage(36),
                Constraint::Percentage(26),
            ],
        )
        .block(panel("KEYRING — xwing (x25519+ml-kem-768)", theme))
        .render(cols[0], f.buffer_mut());
    }

    let rows_r = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(cols[1]);

    // Explainer : comment le chiffrement à clé publique fonctionne ici.
    let explain = vec![
        Line::from(vec![Span::styled(
            "pub key = open padlock you hand out",
            Style::default().fg(theme.fg),
        )]),
        Line::from(Span::styled(
            "  anyone can LOCK a file for you, nobody can open it",
            Style::default().fg(theme.dim),
        )),
        Line::from(vec![Span::styled(
            "sec key = your private key — never shared",
            Style::default().fg(theme.fg),
        )]),
        Line::from(Span::styled(
            "  the ONLY thing that can unlock those files",
            Style::default().fg(theme.dim),
        )),
        Line::from(vec![Span::styled(
            "xwing = x25519 + ml-kem-768 hybrid",
            Style::default().fg(theme.accent2),
        )]),
        Line::from(Span::styled(
            "  safe even against future quantum computers",
            Style::default().fg(theme.dim),
        )),
    ];
    Paragraph::new(explain)
        .block(panel("HOW IT WORKS", theme))
        .render(rows_r[0], f.buffer_mut());

    let ops = [
        ("[g]", "generate xwing keypair"),
        ("[x]", "export public key (hex)"),
        ("[d]", "delete selected pair"),
        ("[r]", "refresh keyring"),
    ];
    let mut items: Vec<ListItem> = ops
        .iter()
        .map(|(k, n)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{k} "), Style::default().fg(theme.accent)),
                Span::styled(*n, Style::default().fg(theme.fg)),
            ]))
        })
        .collect();
    items.push(ListItem::new(""));
    items.push(ListItem::new(Line::from(Span::styled(
        "⚠ .sec files are UNENCRYPTED on disk (seal: v0.3)",
        Style::default().fg(theme.warn),
    ))));
    items.push(ListItem::new(Line::from(Span::styled(
        "  use: CRYPT [m] recipients mode or `encrypt f --to @name`",
        Style::default().fg(theme.dim),
    ))));
    List::new(items)
        .block(panel("OPERATIONS", theme))
        .render(rows_r[1], f.buffer_mut());
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
