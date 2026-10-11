//! Point d'entrée TUI — setup/restore du terminal + boucle événementielle.

mod app;
mod boot;
mod logo;
mod matrix;
mod screens;
mod theme;
mod ui;

use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::config::{Config, Mode};
use crate::error::Result;
use app::{App, Level, Modal, PendingAction, Screen, Tab};

/// Lance le TUI. Sans TTY (pipe/CI) : message et retour propre.
pub fn run(config: &mut Config, no_anim: bool) -> Result<()> {
    if !io::stdout().is_terminal() {
        eprintln!("tui requires a terminal — non-interactive commands: `ats-opsec probe [--json]`");
        return Ok(());
    }

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(config, no_anim);
    seed_logs(&mut app);

    let res = event_loop(&mut term, &mut app);

    // Restore systématique, même en cas d'erreur.
    let _ = disable_raw_mode();
    let _ = execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show);
    res
}

fn seed_logs(app: &mut App) {
    let (host, memlock, hypervisor, tracer, swap) = {
        let p = &app.profile;
        (
            format!(
                "{}/{} · fs {}",
                p.os,
                p.arch,
                p.fs_type.as_deref().unwrap_or("?")
            ),
            p.memlock.label(),
            p.cpu.hypervisor,
            p.tracer_detected,
            p.swap_present,
        )
    };
    app.push_log(Level::Info, format!("probe: {host}"));
    app.push_log(Level::Info, format!("memlock: {memlock}"));
    if hypervisor == Some(true) {
        app.push_log(
            Level::Warn,
            "hypervisor detected — consider a bare-metal env for sensitive ops",
        );
    }
    if tracer == Some(true) {
        app.push_log(Level::Err, "tracer/debugger attached to this process");
    }
    if swap == Some(true) {
        app.push_log(
            Level::Warn,
            "swap present — secrets may reach disk despite mlock",
        );
    }
    app.push_log(Level::Ok, "boot sequence complete");
}

fn event_loop(term: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        term.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(33))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => on_key(app, k),
                Event::Resize(w, h) => app.rain.resize(w, h),
                _ => {}
            }
        }
        on_tick(app);
        if app.should_quit {
            return Ok(());
        }
    }
}

fn on_tick(app: &mut App) {
    app.tick = app.tick.wrapping_add(1);
    if app.screen == Screen::Boot {
        app.rain.step();
        if app.boot.should_auto_enter() {
            enter_main(app);
        }
    }
}

fn enter_main(app: &mut App) {
    app.screen = Screen::Main;
    app.transition_end = Some(Instant::now() + Duration::from_millis(300));
}

fn on_key(app: &mut App, k: KeyEvent) {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);

    // Panic : toute touche restaure (v0.2 : + purge des secrets).
    if app.panic {
        app.panic = false;
        app.transition_end = Some(Instant::now() + Duration::from_millis(300));
        app.push_log(
            Level::Warn,
            "panic screen disengaged (ram purge lands v0.2)",
        );
        return;
    }
    if ctrl && k.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }
    if app.help_open {
        app.help_open = false;
        return;
    }
    if let Some(m) = app.modal.take() {
        if let Modal::Confirm { action, .. } = m {
            if k.code == KeyCode::Char('y') {
                do_action(app, action);
            } else {
                app.push_log(Level::Info, "action aborted");
            }
        }
        return;
    }
    if app.screen == Screen::Boot {
        if !app.boot.all_done() {
            app.boot.skip();
        } else {
            enter_main(app);
        }
        return;
    }

    // Champ de saisie QR : capture du texte en priorité.
    if app.tab == Tab::Transfer && app.qr_edit {
        match k.code {
            KeyCode::Esc | KeyCode::Enter => app.qr_edit = false,
            KeyCode::Backspace => {
                app.qr_input.pop();
            }
            KeyCode::Char(c) if !ctrl => app.qr_input.push(c),
            _ => {}
        }
        return;
    }

    match k.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('?') => app.help_open = true,
        KeyCode::Char('p') => {
            app.panic = true;
            app.push_log(Level::Warn, "panic screen engaged");
        }
        KeyCode::Char('t') => {
            app.theme_idx = (app.theme_idx + 1) % theme::THEMES.len();
            app.toast(format!("theme: {}", app.theme().name));
        }
        KeyCode::Tab | KeyCode::Right => app.tab = Tab::from_idx(app.tab.idx() + 1),
        KeyCode::BackTab | KeyCode::Left => {
            app.tab = Tab::from_idx(app.tab.idx() + Tab::ALL.len() - 1)
        }
        KeyCode::Char(c @ '1'..='8') => app.tab = Tab::from_idx((c as usize) - ('1' as usize)),
        _ => on_tab_key(app, k),
    }
}

fn on_tab_key(app: &mut App, k: KeyEvent) {
    match app.tab {
        Tab::Vault => match k.code {
            KeyCode::Up => app.picker_vault.move_sel(-1),
            KeyCode::Down => app.picker_vault.move_sel(1),
            KeyCode::Enter => app.picker_vault.activate(),
            KeyCode::Char('e') | KeyCode::Char('d') | KeyCode::Char('i') => {
                if app.picker_vault.target.is_some() {
                    let op = if k.code == KeyCode::Char('e') {
                        "encrypt"
                    } else if k.code == KeyCode::Char('d') {
                        "decrypt"
                    } else {
                        "header audit"
                    };
                    app.modal = Some(staged_modal(op));
                } else {
                    app.toast("select a target file first");
                }
            }
            _ => {}
        },
        Tab::Shred => match k.code {
            KeyCode::Up => app.picker_shred.move_sel(-1),
            KeyCode::Down => app.picker_shred.move_sel(1),
            KeyCode::Enter => app.picker_shred.activate(),
            KeyCode::Home => app.shred_passes = 1,
            KeyCode::Char('[') => app.shred_passes = (app.shred_passes - 1).max(1),
            KeyCode::Char(']') => app.shred_passes = (app.shred_passes + 1).min(35),
            KeyCode::Char('s') => {
                if let Some(t) = &app.picker_shred.target {
                    let name = t.name.clone();
                    app.modal = Some(Modal::Confirm {
                        title: "CONFIRM SHRED".into(),
                        lines: vec![
                            format!("irreversibly destroy: {name}"),
                            format!("passes: {}", app.shred_passes),
                            "fs caveat: SSD/journal may retain blocks".into(),
                        ],
                        action: PendingAction::Shred(t.path.clone()),
                    });
                } else {
                    app.toast("select a target file first");
                }
            }
            _ => {}
        },
        Tab::Transfer => {
            if matches!(k.code, KeyCode::Enter | KeyCode::Char('e')) {
                app.qr_edit = true;
            }
        }
        Tab::Settings => match k.code {
            KeyCode::Up => {
                app.settings_sel = app.settings_sel.saturating_sub(1);
            }
            KeyCode::Down => app.settings_sel = (app.settings_sel + 1).min(6),
            KeyCode::Left => settings_adjust(app, -1),
            KeyCode::Right => settings_adjust(app, 1),
            KeyCode::Enter => settings_apply(app),
            _ => {}
        },
        Tab::Logs => match k.code {
            KeyCode::Up => app.log_scroll = app.log_scroll.saturating_add(1),
            KeyCode::Down => app.log_scroll = app.log_scroll.saturating_sub(1),
            KeyCode::PageUp => app.log_scroll = app.log_scroll.saturating_add(10),
            KeyCode::PageDown => app.log_scroll = app.log_scroll.saturating_sub(10),
            _ => {}
        },
        _ => {}
    }
}

fn settings_adjust(app: &mut App, dir: i64) {
    let expert = app.mode == Mode::Expert;
    match app.settings_sel {
        0 => {
            app.mode = match app.mode {
                Mode::Standard => Mode::Expert,
                Mode::Expert => Mode::Standard,
            };
        }
        1 => {
            let n = theme::THEMES.len() as i64;
            app.theme_idx = ((app.theme_idx as i64 + dir).rem_euclid(n)) as usize;
        }
        2 => app.boot_anim = !app.boot_anim,
        3 if expert => {
            app.argon2.m_kib =
                (app.argon2.m_kib as i64 + dir * 32 * 1024).clamp(8 * 1024, 2 * 1024 * 1024) as u32;
        }
        4 if expert => {
            app.argon2.t = (app.argon2.t as i64 + dir).clamp(1, 10) as u32;
        }
        5 if expert => {
            app.argon2.p = (app.argon2.p as i64 + dir).clamp(1, 8) as u32;
        }
        3..=5 => app.toast("expert mode required to tune kdf params"),
        _ => {}
    }
}

fn settings_apply(app: &mut App) {
    if app.settings_sel == 6 {
        let cfg = Config {
            mode: app.mode,
            theme: app.theme().name.into(),
            boot_anim: app.boot_anim,
            argon2: app.argon2,
        };
        match cfg.save() {
            Ok(p) => {
                app.toast("config saved");
                app.push_log(Level::Ok, format!("config written → {}", p.display()));
            }
            Err(e) => {
                app.toast("save failed");
                app.push_log(Level::Err, format!("config save failed: {e}"));
            }
        }
    } else {
        settings_adjust(app, 1);
    }
}

fn do_action(app: &mut App, action: PendingAction) {
    match action {
        PendingAction::Shred(path) => {
            app.push_log(
                Level::Warn,
                format!("shred requested → {} (engine staged v0.2)", path.display()),
            );
            app.modal = Some(staged_modal("shred"));
        }
    }
}

fn staged_modal(op: &str) -> Modal {
    Modal::Info {
        title: "MODULE STAGED".into(),
        lines: vec![
            format!("`{op}` is wired but the engine lands in v0.2."),
            String::new(),
            "pipeline ready: kdf(argon2id) → stream aead → verify-then-write".into(),
            "see docs/SPEC.md §7 roadmap".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use app::Level;
    use ratatui::backend::TestBackend;

    fn term() -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(140, 42)).unwrap()
    }

    fn buf_text(t: &Terminal<TestBackend>) -> String {
        let b = t.backend().buffer();
        let mut s = String::new();
        for y in 0..b.area.height {
            for x in 0..b.area.width {
                if let Some(c) = b.cell((x, y)) {
                    s.push_str(c.symbol());
                }
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn boot_frames_never_panic_and_complete() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, false);
        let mut t = term();
        // Boot complet simulé via skip — toutes phases affichées.
        app.boot.skip();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let text = buf_text(&t);
        assert!(text.contains("csprng entropy pool"), "checklist absente");
        assert!(text.contains("MODULE INIT"), "titre checklist absent");
        assert!(text.contains("SYSTEMS NOMINAL"), "ligne finale absente");
    }

    #[test]
    fn every_tab_renders_without_panic() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true); // no_anim → main direct
        let mut t = term();
        for i in 0..Tab::ALL.len() {
            app.tab = Tab::from_idx(i);
            t.draw(|f| ui::draw(f, &mut app)).unwrap();
        }
        let text = buf_text(&t);
        assert!(text.contains("SESSION LOG"));
    }

    #[test]
    fn dashboard_shows_real_probe() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true);
        let mut t = term();
        app.tab = Tab::Dashboard;
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
        let text = buf_text(&t);
        assert!(text.contains("HOST PROFILE"));
        assert!(text.contains("OPSEC POSTURE"));
        assert!(text.contains("MODULES"));
    }

    #[test]
    fn keys_q_quits_p_toggles_panic() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true);
        on_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
        );
        assert!(app.panic);
        on_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        );
        assert!(!app.panic);
        on_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        );
        assert!(app.should_quit);
    }

    #[test]
    fn qr_input_capture_and_render() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true);
        app.tab = Tab::Transfer;
        on_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('A'), KeyModifiers::NONE),
        );
        on_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('B'), KeyModifiers::NONE),
        );
        assert_eq!(app.qr_input, "AB");
        let mut t = term();
        t.draw(|f| ui::draw(f, &mut app)).unwrap();
    }

    #[test]
    fn transfer_tab_tab_cycles() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true);
        on_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.tab, Tab::Vault);
    }

    #[test]
    fn config_toml_roundtrip() {
        let cfg = Config {
            mode: Mode::Expert,
            theme: "ice".into(),
            boot_anim: false,
            argon2: crate::crypto::Argon2Params::PARANOID,
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.mode, Mode::Expert);
        assert_eq!(back.argon2.m_kib, 512 * 1024);
    }

    #[test]
    fn file_picker_lists_and_navigates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), b"x").unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let mut p = app::FilePicker::new();
        p.dir = tmp.path().to_path_buf();
        p.refresh();
        assert!(p.entries.iter().any(|e| e.name == "a.txt"));
        assert!(p.entries.iter().any(|e| e.name == "sub" && e.is_dir));
        let _ = Level::Info; // silence unused import pattern
    }
}
