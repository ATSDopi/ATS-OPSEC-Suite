//! Rendu principal : chrome (tab bar + status bar), dispatch des écrans,
//! modales, écran leurre (panic), overlay de transition glitch.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Tabs, Widget};

use super::app::{App, Modal, Screen, Tab};
use super::boot;
use super::screens;
use super::theme::Theme;

pub fn draw(f: &mut Frame, app: &mut App) {
    let theme = *app.theme();
    if app.panic {
        draw_panic(f, app);
        return;
    }
    match app.screen {
        Screen::Boot => {
            boot::draw(f, &app.boot, &app.rain, &theme, app.tick);
        }
        Screen::Main => {
            draw_main(f, app, &theme);
        }
    }
}

fn draw_main(f: &mut Frame, app: &mut App, theme: &Theme) {
    let area = f.area();
    if area.width < 60 || area.height < 18 {
        Paragraph::new("TERMINAL TOO SMALL — need ≥ 60×18")
            .alignment(Alignment::Center)
            .style(Style::default().fg(theme.err))
            .render(area, f.buffer_mut());
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], app, theme);
    screens::draw(f, chunks[1], app, theme);
    draw_statusbar(f, chunks[2], app, theme);

    // Modales par-dessus.
    if app.help_open {
        draw_help(f, area, theme);
    }
    if let Some(m) = &app.modal {
        draw_modal(f, area, m, theme);
    }

    // Overlay glitch de transition.
    if let Some(end) = app.transition_end {
        let now = Instant::now();
        if now < end {
            let frac = (end - now).as_millis() as f32 / 300.0;
            boot::draw_glitch(f.buffer_mut(), area, theme, frac, app.tick);
        } else {
            app.transition_end = None;
        }
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(13),
            Constraint::Min(20),
            Constraint::Length(10),
        ])
        .split(area);

    let logo = Paragraph::new(Line::from(vec![
        Span::styled(
            "▛ ",
            Style::default()
                .fg(theme.accent2)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "ATS·OPSEC",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center);
    logo.render(parts[0], f.buffer_mut());

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
        .collect();
    Tabs::new(titles)
        .select(app.tab.idx())
        .divider("│")
        .padding(" ", " ")
        .style(Style::default().fg(theme.dim))
        .highlight_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .render(parts[1], f.buffer_mut());

    let ver = Paragraph::new(format!("v{}", env!("CARGO_PKG_VERSION")))
        .alignment(Alignment::Right)
        .style(Style::default().fg(theme.dim));
    ver.render(parts[2], f.buffer_mut());

    // Ligne séparatrice animée — un segment brillant qui oscille.
    let y = parts[0].y + 2;
    let buf = f.buffer_mut();
    for x in area.x..area.x + area.width {
        buf.set_string(x, y, "─", Style::default().fg(theme.dim));
    }
    let w = area.width.max(1) as usize;
    let pos =
        ((app.tick as usize / 2) % (w * 2)).min(w * 2 - 1 - (app.tick as usize / 2) % (w * 2));
    let seg = 8.min(w);
    for i in 0..seg {
        let x = area.x + ((pos + i) % w) as u16;
        buf.set_string(x, y, "─", Style::default().fg(theme.accent));
    }
}

fn draw_statusbar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let mode = match app.mode {
        crate::config::Mode::Standard => "STD",
        crate::config::Mode::Expert => "EXPRT",
    };
    let memlock = app.profile.memlock.label();
    let host = format!("{}/{}", app.profile.os, app.profile.arch);

    let mut spans = vec![
        Span::styled(" ", Style::default()),
        Span::styled(format!("◈ {mode}"), Style::default().fg(theme.accent2)),
        Span::styled("  ", Style::default()),
        Span::styled(app.theme().name, Style::default().fg(theme.dim)),
        Span::styled("  ", Style::default()),
        Span::styled(host, Style::default().fg(theme.dim)),
        Span::styled("  ", Style::default()),
        Span::styled(format!("mem:{memlock}"), Style::default().fg(theme.dim)),
        Span::styled("  ", Style::default()),
        Span::styled(app.uptime(), Style::default().fg(theme.dim)),
    ];

    // Toast ou hints à droite.
    let toast = app
        .status_msg
        .as_ref()
        .and_then(|(m, t)| (t.elapsed().as_secs() < 3).then(|| m.clone()));
    let right = toast.unwrap_or_else(|| "?:help · t:theme · p:panic · q:quit".into());
    let left_w: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let pad = (area.width as usize).saturating_sub(left_w + right.chars().count() + 1);
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(right, Style::default().fg(theme.dim)));

    Paragraph::new(Line::from(spans)).render(area, f.buffer_mut());
}

/// Rectangle centré pour modales.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(4));
    let h = h.min(area.height.saturating_sub(4));
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

fn draw_modal(f: &mut Frame, area: Rect, m: &Modal, theme: &Theme) {
    let (title, lines, confirm) = match m {
        Modal::Info { title, lines } => (title.clone(), lines.clone(), false),
        Modal::Confirm { title, lines, .. } => (title.clone(), lines.clone(), true),
    };
    let h = (lines.len() as u16 + 5).min(24);
    let r = centered(area, 68, h);
    Clear.render(r, f.buffer_mut());

    let border_color = if confirm { theme.warn } else { theme.accent };
    let block = Block::default()
        .title(format!(" {} ", title))
        .title_style(
            Style::default()
                .fg(border_color)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(border_color));
    block.render(r, f.buffer_mut());

    let inner = Rect::new(
        r.x + 2,
        r.y + 2,
        r.width.saturating_sub(4),
        r.height.saturating_sub(3),
    );
    let text: Vec<Line> = lines.iter().map(|l| Line::from(l.clone())).collect();
    Paragraph::new(text)
        .style(Style::default().fg(theme.fg))
        .render(inner, f.buffer_mut());

    let hint = if confirm {
        "[y] confirm    [n/esc] abort"
    } else {
        "[enter/esc] close"
    };
    let hw = hint.len() as u16;
    f.buffer_mut().set_string(
        r.x + r.width.saturating_sub(hw + 2),
        r.y + r.height.saturating_sub(1),
        hint,
        Style::default().fg(theme.dim),
    );
}

fn draw_help(f: &mut Frame, area: Rect, theme: &Theme) {
    let lines = [
        ("global", ""),
        ("  ← → / tab", "switch module"),
        ("  1-8", "jump to module"),
        ("  ?", "this help"),
        ("  t", "cycle theme"),
        ("  p", "panic screen"),
        ("  q / ctrl+c", "quit"),
        ("vault / shred", ""),
        ("  ↑ ↓", "navigate files"),
        ("  enter", "open dir / select file"),
        ("  e d i", "encrypt · decrypt · info (staged v0.2)"),
        ("  s", "shred (staged v0.2)"),
        ("xfer", ""),
        ("  type", "edit QR payload"),
        ("settings", ""),
        ("  ↑ ↓ ← → enter", "navigate / adjust / apply"),
    ];
    let h = (lines.len() as u16 + 4).min(area.height - 2);
    let r = centered(area, 52, h);
    Clear.render(r, f.buffer_mut());
    let block = Block::default()
        .title(" KEYS ")
        .title_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.accent));
    block.render(r, f.buffer_mut());
    let inner = Rect::new(r.x + 2, r.y + 1, r.width - 4, r.height - 2);
    let text: Vec<Line> = lines
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                Line::from(Span::styled(
                    format!("── {k} "),
                    Style::default()
                        .fg(theme.accent2)
                        .add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(vec![
                    Span::styled(format!("{k:<18}"), Style::default().fg(theme.fg)),
                    Span::styled(*v, Style::default().fg(theme.dim)),
                ])
            }
        })
        .collect();
    Paragraph::new(text).render(inner, f.buffer_mut());
}

/// Écran leurre — un faux prompt PowerShell inoffensif. v0.2 : purge des
/// clés en RAM en plus du swap d'écran.
fn draw_panic(f: &mut Frame, app: &App) {
    let area = f.area();
    let buf = f.buffer_mut();
    let fg = Style::default()
        .fg(Color::Rgb(210, 210, 210))
        .bg(Color::Rgb(1, 36, 86));
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            if let Some(c) = buf.cell_mut((x, y)) {
                c.set_style(fg);
                c.set_symbol(" ");
            }
        }
    }
    let fake = [
        "Windows PowerShell",
        "Copyright (C) Microsoft Corporation. All rights reserved.",
        "",
        "PS C:\\Users\\operator> dir",
        "",
        "    Directory: C:\\Users\\operator",
        "",
        "Mode                 LastWriteTime         Length Name",
        "----                 -------------         ------ ----",
        "d-----         10/2/2026   9:41 AM                Documents",
        "d-----         10/4/2026   6:12 PM                Downloads",
        "d-----          9/28/2026  11:03 AM                Pictures",
        "-a----         10/8/2026   8:55 PM             2411 notes.txt",
        "-a----         10/9/2026  10:14 AM            38412 report.pdf",
        "",
        "PS C:\\Users\\operator> ",
    ];
    for (i, l) in fake.iter().enumerate() {
        if (i as u16) < area.height {
            buf.set_string(area.x, area.y + i as u16, *l, fg);
        }
    }
    // Curseur clignotant au prompt.
    if (app.tick / 15).is_multiple_of(2) {
        let last = fake.len() as u16 - 1;
        if last < area.height {
            buf.set_string(
                area.x + fake[fake.len() - 1].len() as u16,
                area.y + last,
                "█",
                fg,
            );
        }
    }
}
