//! Point d'entrée TUI — setup/restore du terminal + boucle événementielle.

mod app;
mod boot;
mod logo;
mod matrix;
mod screens;
mod theme;
mod ui;

use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::config::{Config, Mode};
use crate::error::Result;
use app::{
    App, CryptFocus, CryptMode, Field, HitAction, Level, Modal, OptRow, PendingAction, Screen, Tab,
};

/// Lance le TUI. Sans TTY (pipe/CI) : message et retour propre.
pub fn run(config: &mut Config, no_anim: bool) -> Result<()> {
    if !io::stdout().is_terminal() {
        eprintln!("tui requires a terminal — non-interactive commands: `ats-opsec probe [--json]`");
        return Ok(());
    }

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(
        stdout,
        EnterAlternateScreen,
        cursor::Hide,
        event::EnableBracketedPaste,
        event::EnableMouseCapture
    )?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(config, no_anim);
    seed_logs(&mut app);

    let res = event_loop(&mut term, &mut app);

    // Restore systématique, même en cas d'erreur.
    let _ = disable_raw_mode();
    let _ = execute!(
        term.backend_mut(),
        event::DisableBracketedPaste,
        event::DisableMouseCapture,
        LeaveAlternateScreen,
        cursor::Show
    );
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
                // Drag & drop : le terminal colle le chemin du fichier
                // (bracketed paste) → on le sélectionne comme cible.
                Event::Paste(text) => on_paste(app, &text),
                Event::Mouse(m) => on_mouse(app, m),
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
    drain_worker(app);
}

/// Consomme les messages du worker : progression → modale, Done/Err → log.
fn drain_worker(app: &mut App) {
    let mut msgs = Vec::new();
    let mut finished = false;
    if let Some(w) = &app.worker {
        while let Ok(m) = w.rx.try_recv() {
            if matches!(m, app::WorkerMsg::Done(_) | app::WorkerMsg::Err(_)) {
                finished = true;
            }
            msgs.push(m);
        }
    }
    for m in msgs {
        match m {
            app::WorkerMsg::Progress(d) => {
                if let Some(Modal::Progress { done, .. }) = &mut app.modal {
                    *done = d;
                }
            }
            app::WorkerMsg::Done(msg) => {
                app.push_log(Level::Ok, msg.clone());
                app.toast(msg);
                app.ops_done += 1;
                app.modal = None;
            }
            app::WorkerMsg::Err(msg) => {
                app.push_log(Level::Err, msg.clone());
                app.modal = Some(Modal::Info {
                    title: "OPERATION FAILED".into(),
                    lines: vec![msg],
                });
            }
        }
    }
    if finished {
        app.worker = None;
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
        handle_modal_key(app, m, k, ctrl);
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
        KeyCode::Char(c @ '1'..='6') => app.tab = Tab::from_idx((c as usize) - ('1' as usize)),
        _ => on_tab_key(app, k),
    }
}

/// Drag & drop / paste d'un chemin de fichier :
/// CRYPT → ajout à la file de cibles · SHRED → cible du picker ·
/// KEYS (un .aos) → modale de déchiffrement par clé.
fn on_paste(app: &mut App, text: &str) {
    // Si une modale de saisie est ouverte → le texte collé va dans le champ.
    if let Some(Modal::Input {
        title,
        mut fields,
        sel,
        strength_meter,
        action,
    }) = app.modal.take()
    {
        for c in text.chars() {
            if !c.is_control() {
                fields[sel].value.push(c);
            }
        }
        app.modal = Some(Modal::Input {
            title,
            fields,
            sel,
            strength_meter,
            action,
        });
        return;
    }
    let cleaned = app::clean_dropped_path(text);
    if cleaned.is_empty() {
        return;
    }
    let p = PathBuf::from(&cleaned);
    match app.tab {
        Tab::Crypt => {
            if app.add_target(p.clone()) {
                let n = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                app.push_log(Level::Ok, format!("dropped → {n}"));
                app.toast(format!("target queued: {n} ({} total)", app.targets.len()));
            } else {
                app.toast(if p.exists() {
                    "already queued"
                } else {
                    "dropped path not found"
                });
            }
        }
        Tab::Shred => {
            if app.picker_shred.jump(&cleaned) {
                let name = app
                    .picker_shred
                    .target
                    .as_ref()
                    .map(|t| t.name.clone())
                    .unwrap_or_else(|| cleaned.clone());
                app.push_log(Level::Ok, format!("dropped → {name}"));
                app.toast(format!("target: {name}"));
            } else {
                app.toast("dropped path not found");
                app.push_log(Level::Warn, format!("drop ignored: {cleaned}"));
            }
        }
        Tab::Keys => {
            if p.extension().and_then(|e| e.to_str()) == Some("aos") {
                let default_key = app
                    .keyring
                    .get(app.keys_sel)
                    .map(|(n, _, _)| n.clone())
                    .unwrap_or_default();
                app.modal = Some(Modal::Input {
                    title: format!("DECRYPT WITH KEY — {}", cleaned),
                    fields: vec![Field::plain("key name").hint(format!(
                        "selected: {default_key} · empty = try whole keyring"
                    ))],
                    sel: 0,
                    strength_meter: false,
                    action: PendingAction::DecryptKey(p),
                });
            } else {
                app.toast("drop an .aos container here to decrypt it");
            }
        }
        _ => app.toast("drop files onto CRYPT, SHRED or KEYS tabs"),
    }
}

/// Clic souris / scroll — hit-testing sur les zones enregistrées au draw.
fn on_mouse(app: &mut App, m: MouseEvent) {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let Some(hit) = app.hit_at(m.column, m.row) else {
                return;
            };
            match hit {
                HitAction::Tab(i) => app.tab = Tab::from_idx(i),
                HitAction::OptRow(row) => {
                    let rows = app.opt_rows();
                    if let Some(pos) = rows.iter().position(|r| *r == row) {
                        app.opts_sel = pos;
                    }
                    app.crypt_focus = CryptFocus::Options;
                    app.toggle_opt_row(row);
                }
                HitAction::Target(i) => {
                    app.targets_sel = i;
                    app.crypt_focus = CryptFocus::Targets;
                }
                HitAction::TargetRemove(i) => {
                    if i < app.targets.len() {
                        let rm = app.targets.remove(i);
                        app.targets_sel = app.targets_sel.min(app.targets.len().saturating_sub(1));
                        app.push_log(Level::Info, format!("removed {}", rm.display()));
                    }
                }
                HitAction::OpEncrypt => open_encrypt_modal(app),
                HitAction::OpDecrypt => {
                    if let Some(p) = app.targets.first().cloned() {
                        open_decrypt_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
                HitAction::OpAudit => {
                    if let Some(p) = app.targets.first().cloned() {
                        open_audit_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
            }
        }
        MouseEventKind::Down(MouseButton::Right) => {
            if let Some(HitAction::Target(i)) = app.hit_at(m.column, m.row)
                && i < app.targets.len()
            {
                let rm = app.targets.remove(i);
                app.targets_sel = app.targets_sel.min(app.targets.len().saturating_sub(1));
                app.push_log(Level::Info, format!("removed {}", rm.display()));
            }
        }
        MouseEventKind::ScrollUp => match app.tab {
            Tab::Crypt => {
                if app.crypt_focus == CryptFocus::Targets {
                    app.targets_sel = app.targets_sel.saturating_sub(1);
                } else {
                    app.opts_sel = app.opts_sel.saturating_sub(1);
                }
            }
            Tab::Logs => app.log_scroll = app.log_scroll.saturating_add(1),
            Tab::Shred => app.picker_shred.move_sel(-1),
            Tab::Keys => app.keys_sel = app.keys_sel.saturating_sub(1),
            _ => {}
        },
        MouseEventKind::ScrollDown => match app.tab {
            Tab::Crypt => {
                if app.crypt_focus == CryptFocus::Targets {
                    if !app.targets.is_empty() {
                        app.targets_sel = (app.targets_sel + 1).min(app.targets.len() - 1);
                    }
                } else {
                    let n = app.opt_rows().len();
                    app.opts_sel = (app.opts_sel + 1).min(n.saturating_sub(1));
                }
            }
            Tab::Logs => app.log_scroll = app.log_scroll.saturating_sub(1),
            Tab::Shred => app.picker_shred.move_sel(1),
            Tab::Keys if !app.keyring.is_empty() => {
                app.keys_sel = (app.keys_sel + 1).min(app.keyring.len() - 1)
            }
            _ => {}
        },
        _ => {}
    }
}

/// Touches du picker SHRED — navigation (j)saut, (h)ome, backspace parent.
/// Retourne vrai si la touche est consommée.
fn picker_nav(app: &mut App, k: &KeyEvent) -> bool {
    let picker = &mut app.picker_shred;
    match k.code {
        KeyCode::Up => picker.move_sel(-1),
        KeyCode::Down => picker.move_sel(1),
        KeyCode::Enter => picker.activate(),
        KeyCode::Backspace => {
            if let Some(par) = picker.dir.parent().map(|p| p.to_path_buf()) {
                picker.dir = par;
                picker.sel = 0;
                picker.refresh();
            }
        }
        KeyCode::Char('h') | KeyCode::Home => picker.home(),
        KeyCode::Char('j') => {
            app.modal = Some(Modal::Input {
                title: "JUMP TO PATH".into(),
                fields: vec![
                    Field::plain("path").hint("absolute or relative path · folder or file"),
                ],
                sel: 0,
                strength_meter: false,
                action: PendingAction::JumpPath(true),
            });
        }
        _ => return false,
    }
    true
}

// ------------------------------------------------- helpers crypt modals

/// Modale de chiffrement — selon le mode auth choisi dans OPTIONS.
fn open_encrypt_modal(app: &mut App) {
    if app.targets.is_empty() {
        app.toast("drop files here or press [j] to queue targets");
        return;
    }
    if app.crypt_ciphers.is_empty() {
        app.toast("no cipher selected — check at least one");
        return;
    }
    let first = &app.targets[0];
    let label = if app.targets.len() == 1 {
        first
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        format!("{} items", app.targets.len())
    };
    match app.crypt_mode {
        CryptMode::Password => {
            app.modal = Some(Modal::Input {
                title: format!("ENCRYPT — {label}"),
                fields: vec![
                    Field::masked("passphrase").hint("[tab] next · empty = abort"),
                    Field::masked("confirm"),
                ],
                sel: 0,
                strength_meter: true,
                action: PendingAction::Encrypt(app.targets.clone()),
            });
        }
        CryptMode::Recipients => {
            let names: String = app
                .keyring
                .iter()
                .map(|(n, _, _)| n.clone())
                .collect::<Vec<_>>()
                .join(", ");
            app.modal = Some(Modal::Input {
                title: format!("ENCRYPT TO RECIPIENTS — {label}"),
                fields: vec![
                    Field::plain("recipients")
                        .hint(format!("keyring: {names} · comma-separated names")),
                ],
                sel: 0,
                strength_meter: false,
                action: PendingAction::EncryptTo(app.targets.clone()),
            });
        }
    }
}

/// Modale de déchiffrement pour un `.aos` (password ou recipient key).
fn open_decrypt_modal(app: &mut App, path: &std::path::Path) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match crate::crypto::inspect(path) {
        Ok(h) if h.is_password_mode() => {
            app.modal = Some(Modal::Input {
                title: format!("DECRYPT — {name}"),
                fields: vec![Field::masked("passphrase")],
                sel: 0,
                strength_meter: false,
                action: PendingAction::Decrypt(path.to_path_buf()),
            });
        }
        Ok(h) => {
            let fps: Vec<String> = h.recipients.iter().map(|r| r.fingerprint.clone()).collect();
            app.modal = Some(Modal::Input {
                title: format!("DECRYPT — {name}"),
                fields: vec![Field::plain("key name").hint(format!(
                    "slots: {} · empty = try whole keyring",
                    fps.join(", ")
                ))],
                sel: 0,
                strength_meter: false,
                action: PendingAction::DecryptKey(path.to_path_buf()),
            });
        }
        Err(_) => app.toast("not an .aos container"),
    }
}

/// Modale audit : dump du header d'un container.
fn open_audit_modal(app: &mut App, path: &std::path::Path) {
    match crate::crypto::inspect(path) {
        Ok(h) => app.modal = Some(header_modal(&h)),
        Err(e) => {
            app.modal = Some(Modal::Info {
                title: "NOT A CONTAINER".into(),
                lines: vec![e.to_string()],
            })
        }
    }
}

fn on_tab_key(app: &mut App, k: KeyEvent) {
    match app.tab {
        Tab::Dashboard => match k.code {
            KeyCode::Char('x') => {
                app.mode = match app.mode {
                    Mode::Standard => Mode::Expert,
                    Mode::Expert => Mode::Standard,
                };
                app.toast(format!("mode: {:?}", app.mode).to_lowercase());
            }
            KeyCode::Char('a') => {
                // Presets Argon2 : Standard 64Mio ↔ Paranoid 512Mio.
                app.argon2 = if app.argon2.m_kib >= 512 * 1024 {
                    crate::crypto::Argon2Params::default()
                } else {
                    crate::crypto::Argon2Params::PARANOID
                };
                app.toast(format!("argon2: {} MiB", app.argon2.m_kib / 1024));
            }
            KeyCode::Char('w') => save_config(app),
            _ => {}
        },
        Tab::Crypt => match app.crypt_focus {
            CryptFocus::Targets => match k.code {
                KeyCode::Up => app.targets_sel = app.targets_sel.saturating_sub(1),
                KeyCode::Down if !app.targets.is_empty() => {
                    app.targets_sel = (app.targets_sel + 1).min(app.targets.len() - 1)
                }
                KeyCode::Char('o') => app.crypt_focus = CryptFocus::Options,
                KeyCode::Char('j') => {
                    app.modal = Some(Modal::Input {
                        title: "ADD TARGET PATH".into(),
                        fields: vec![
                            Field::plain("path").hint("absolute or relative path · file or folder"),
                        ],
                        sel: 0,
                        strength_meter: false,
                        action: PendingAction::JumpPath(false),
                    });
                }
                KeyCode::Char('x') | KeyCode::Delete if !app.targets.is_empty() => {
                    let i = app.targets_sel.min(app.targets.len() - 1);
                    let rm = app.targets.remove(i);
                    app.targets_sel = app.targets_sel.min(app.targets.len().saturating_sub(1));
                    app.push_log(Level::Info, format!("removed {}", rm.display()));
                }
                KeyCode::Char('c') => {
                    app.targets.clear();
                    app.targets_sel = 0;
                    app.push_log(Level::Info, "targets cleared");
                }
                KeyCode::Char('m') => crypt_toggle_mode(app),
                KeyCode::Char('e') => open_encrypt_modal(app),
                KeyCode::Char('d') => {
                    if let Some(p) = app.targets.get(app.targets_sel).cloned() {
                        open_decrypt_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
                KeyCode::Char('i') => {
                    if let Some(p) = app.targets.get(app.targets_sel).cloned() {
                        open_audit_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
                _ => {}
            },
            CryptFocus::Options => match k.code {
                KeyCode::Up => app.opts_sel = app.opts_sel.saturating_sub(1),
                KeyCode::Down => {
                    let n = app.opt_rows().len();
                    app.opts_sel = (app.opts_sel + 1).min(n.saturating_sub(1))
                }
                KeyCode::Char('o') | KeyCode::Esc => app.crypt_focus = CryptFocus::Targets,
                KeyCode::Char(' ') | KeyCode::Enter => {
                    let row = app.opt_rows().get(app.opts_sel).copied();
                    if let Some(r) = row {
                        app.toggle_opt_row(r);
                    }
                }
                KeyCode::Left => {
                    if let Some(OptRow::Cipher(i)) = app.opt_rows().get(app.opts_sel).copied()
                        && let Some(kind) = crate::crypto::CipherKind::ALL.get(i)
                    {
                        app.move_cipher(*kind, -1);
                    }
                }
                KeyCode::Right => {
                    if let Some(OptRow::Cipher(i)) = app.opt_rows().get(app.opts_sel).copied()
                        && let Some(kind) = crate::crypto::CipherKind::ALL.get(i)
                    {
                        app.move_cipher(*kind, 1);
                    }
                }
                KeyCode::Char(c @ '1'..='8') => {
                    let i = (c as usize) - ('1' as usize);
                    app.toggle_opt_row(OptRow::Cipher(i));
                }
                KeyCode::Char('m') => crypt_toggle_mode(app),
                KeyCode::Char('e') => open_encrypt_modal(app),
                KeyCode::Char('d') => {
                    if let Some(p) = app.targets.get(app.targets_sel).cloned() {
                        open_decrypt_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
                KeyCode::Char('i') => {
                    if let Some(p) = app.targets.get(app.targets_sel).cloned() {
                        open_audit_modal(app, &p);
                    } else {
                        app.toast("queue a target first");
                    }
                }
                _ => {}
            },
        },
        Tab::Shred => {
            if picker_nav(app, &k) {
                return;
            }
            match k.code {
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
                                "fs caveat: SSD/journal/CoW may retain blocks".into(),
                            ],
                            action: PendingAction::Shred(t.path.clone()),
                        });
                    } else {
                        app.toast("select a target file first");
                    }
                }
                _ => {}
            }
        }
        Tab::Keys => match k.code {
            KeyCode::Up => app.keys_sel = app.keys_sel.saturating_sub(1),
            KeyCode::Down if !app.keyring.is_empty() => {
                app.keys_sel = (app.keys_sel + 1).min(app.keyring.len() - 1)
            }
            KeyCode::Char('g') => {
                app.modal = Some(Modal::Input {
                    title: "GENERATE X-WING KEYPAIR".into(),
                    fields: vec![
                        Field::plain("name").hint("x25519 + ml-kem-768 · empty = random name"),
                    ],
                    sel: 0,
                    strength_meter: false,
                    action: PendingAction::Keygen,
                });
            }
            KeyCode::Char('d') => {
                if let Some((name, _, _)) = app.keyring.get(app.keys_sel).cloned() {
                    app.modal = Some(Modal::Confirm {
                        title: "DELETE KEYPAIR".into(),
                        lines: vec![
                            format!("delete '{name}' (.pub + .sec) ?"),
                            "files encrypted to it become unrecoverable".into(),
                        ],
                        action: PendingAction::DeleteKey(name),
                    });
                }
            }
            KeyCode::Char('r') => {
                app.keyring = crate::crypto::keys::list().unwrap_or_default();
                app.keys_sel = app.keys_sel.min(app.keyring.len().saturating_sub(1));
            }
            KeyCode::Char('x') => {
                if let Some((name, fp, _)) = app.keyring.get(app.keys_sel).cloned()
                    && let Ok(p) = crate::crypto::keys::load_public(&name)
                {
                    app.modal = Some(Modal::Info {
                        title: format!("PUBLIC KEY — {name}"),
                        lines: vec![
                            format!("fingerprint : {fp}"),
                            format!("xwing bytes : {} B", p.to_bytes().len()),
                            String::new(),
                            format!("hex (share this):"),
                            hex::encode(p.to_bytes()),
                        ],
                    });
                }
            }
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

/// Bascule le mode d'authentification (raccourci `m`).
fn crypt_toggle_mode(app: &mut App) {
    app.crypt_mode = match app.crypt_mode {
        CryptMode::Password => CryptMode::Recipients,
        CryptMode::Recipients => CryptMode::Password,
    };
    app.toast(match app.crypt_mode {
        CryptMode::Password => "auth: passphrase".to_string(),
        CryptMode::Recipients => "auth: recipient public keys (post-quantum)".to_string(),
    });
}

fn save_config(app: &mut App) {
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
}

/// Clavier quand une modale est ouverte — la modale a été `.take()`n,
/// la remettre via `app.modal = Some(m)` pour la garder ouverte.
fn handle_modal_key(app: &mut App, m: Modal, k: KeyEvent, ctrl: bool) {
    match m {
        Modal::Info { .. } => {}
        Modal::Progress { title, done } => {
            // Esc = cacher la fenêtre, le worker continue → résultat en log.
            if k.code != KeyCode::Esc {
                app.modal = Some(Modal::Progress { title, done });
            }
        }
        Modal::Confirm { action, .. } => {
            if k.code == KeyCode::Char('y') {
                do_action(app, action, &[]);
            } else {
                app.push_log(Level::Info, "action aborted");
            }
        }
        Modal::Input {
            title,
            mut fields,
            mut sel,
            strength_meter,
            action,
        } => match k.code {
            KeyCode::Esc => app.push_log(Level::Info, "input cancelled"),
            KeyCode::Tab | KeyCode::Down => {
                sel = (sel + 1) % fields.len().max(1);
                app.modal = Some(Modal::Input {
                    title,
                    fields,
                    sel,
                    strength_meter,
                    action,
                });
            }
            KeyCode::Up | KeyCode::BackTab => {
                sel = (sel + fields.len().saturating_sub(1)) % fields.len().max(1);
                app.modal = Some(Modal::Input {
                    title,
                    fields,
                    sel,
                    strength_meter,
                    action,
                });
            }
            KeyCode::Backspace => {
                fields[sel].value.pop();
                app.modal = Some(Modal::Input {
                    title,
                    fields,
                    sel,
                    strength_meter,
                    action,
                });
            }
            KeyCode::Enter => {
                if sel + 1 < fields.len() {
                    sel += 1;
                    app.modal = Some(Modal::Input {
                        title,
                        fields,
                        sel,
                        strength_meter,
                        action,
                    });
                } else {
                    do_action(app, action, &fields);
                }
            }
            KeyCode::Char(c) if !ctrl => {
                fields[sel].value.push(c);
                app.modal = Some(Modal::Input {
                    title,
                    fields,
                    sel,
                    strength_meter,
                    action,
                });
            }
            _ => {
                app.modal = Some(Modal::Input {
                    title,
                    fields,
                    sel,
                    strength_meter,
                    action,
                });
            }
        },
    }
}

/// Lance une tâche en arrière-plan + modale de progression.
fn spawn_worker<F>(app: &mut App, label: String, f: F)
where
    F: FnOnce(std::sync::mpsc::Sender<app::WorkerMsg>) -> crate::error::Result<String>
        + Send
        + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = f(tx.clone());
        let _ = tx.send(match res {
            Ok(m) => app::WorkerMsg::Done(m),
            Err(e) => app::WorkerMsg::Err(e.to_string()),
        });
    });
    app.worker = Some(app::Worker { rx });
    app.modal = Some(Modal::Progress {
        title: label,
        done: 0,
    });
}

fn do_action(app: &mut App, action: PendingAction, fields: &[app::Field]) {
    use crate::crypto::engine::{self, Credential, EncryptOptions, KeySource};
    let val = |i: usize| {
        fields
            .get(i)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    };

    match action {
        PendingAction::Shred(path) => {
            let passes = app.shred_passes as u32;
            spawn_worker(app, format!("SHRED {}", path.display()), move |tx| {
                crate::wipe::shred(&path, passes, &mut |d| {
                    let _ = tx.send(app::WorkerMsg::Progress(d));
                })
                .map(|r| format!("shredded {} B ×{} passes", r.bytes, r.passes))
            });
        }
        PendingAction::Encrypt(paths) => {
            let (p1, p2) = (val(0), val(1));
            if p1.is_empty() {
                app.toast("empty passphrase — aborted");
                return;
            }
            if p1 != p2 {
                app.toast("passphrases do not match");
                app.push_log(Level::Err, "encrypt aborted: passphrase mismatch");
                return;
            }
            let (score, _) = crate::crypto::passphrase::strength(&p1);
            if score < 2 {
                app.push_log(Level::Warn, "weak passphrase used (zxcvbn <2/4)");
            }
            let out = default_aos_out(&paths);
            let opts = EncryptOptions {
                ciphers: app.crypt_ciphers.clone(),
                argon2: app.argon2,
                compress: app.crypt_compress,
                pad: app.crypt_pad,
                ..Default::default()
            };
            let shred_orig = app.crypt_shred_orig;
            let srcs = paths.clone();
            spawn_worker(app, format!("ENCRYPT {} items", paths.len()), move |tx| {
                let key = KeySource::Password {
                    pass: zeroize::Zeroizing::new(p1.into_bytes()),
                    keyfile: None,
                };
                engine::encrypt_paths(&srcs, &out, &key, &opts, &mut |d| {
                    let _ = tx.send(app::WorkerMsg::Progress(d));
                })?;
                let mut msg = format!("encrypted → {}", out.display());
                if shred_orig {
                    for s in &srcs {
                        if s.is_file() {
                            crate::wipe::shred(s, 3, &mut |_| {})?;
                        }
                    }
                    msg.push_str(" · originals shredded");
                }
                Ok(msg)
            });
        }
        PendingAction::EncryptTo(paths) => {
            let raw = val(0);
            let names: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().trim_start_matches('@').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                app.toast("no recipient given — aborted");
                return;
            }
            let mut pubs = Vec::new();
            for n in &names {
                match crate::crypto::keys::load_public(n) {
                    Ok(p) => pubs.push(p),
                    Err(e) => {
                        app.push_log(Level::Err, format!("recipient '{n}': {e}"));
                        app.toast(format!("unknown key '{n}' — aborted"));
                        return;
                    }
                }
            }
            let out = default_aos_out(&paths);
            let opts = EncryptOptions {
                ciphers: app.crypt_ciphers.clone(),
                argon2: app.argon2,
                compress: app.crypt_compress,
                pad: app.crypt_pad,
                ..Default::default()
            };
            let shred_orig = app.crypt_shred_orig;
            let srcs = paths.clone();
            spawn_worker(app, format!("ENCRYPT →{}", paths.len()), move |tx| {
                engine::encrypt_paths(
                    &srcs,
                    &out,
                    &KeySource::Recipients(pubs),
                    &opts,
                    &mut |d| {
                        let _ = tx.send(app::WorkerMsg::Progress(d));
                    },
                )?;
                let mut msg = format!("encrypted → {}", out.display());
                if shred_orig {
                    for s in &srcs {
                        if s.is_file() {
                            crate::wipe::shred(s, 3, &mut |_| {})?;
                        }
                    }
                    msg.push_str(" · originals shredded");
                }
                Ok(msg)
            });
        }
        PendingAction::Decrypt(path) => {
            let pass = val(0);
            if pass.is_empty() {
                app.toast("empty passphrase — aborted");
                return;
            }
            let out = decrypt_out(&path);
            spawn_worker(app, format!("DECRYPT {}", path.display()), move |tx| {
                engine::decrypt_file(
                    &path,
                    &out,
                    &Credential::Password {
                        pass: zeroize::Zeroizing::new(pass.into_bytes()),
                        keyfile: None,
                    },
                    &mut |d| {
                        let _ = tx.send(app::WorkerMsg::Progress(d));
                    },
                )?;
                Ok(format!("decrypted → {}", out.display()))
            });
        }
        PendingAction::DecryptKey(path) => {
            let name = val(0);
            let out = decrypt_out(&path);
            spawn_worker(app, format!("DECRYPT {}", path.display()), move |tx| {
                let sec = if name.is_empty() {
                    // essayer chaque clé secrète du keyring par fingerprint
                    let mut hit = None;
                    for (n, fp, has_sec) in crate::crypto::keys::list().unwrap_or_default() {
                        if has_sec
                            && engine::inspect(&path)
                                .map(|h| h.recipients.iter().any(|r| r.fingerprint == fp))
                                .unwrap_or(false)
                        {
                            hit = crate::crypto::keys::load_secret(&n).ok();
                            if hit.is_some() {
                                break;
                            }
                        }
                    }
                    hit.ok_or(crate::error::OpsecError::InvalidParam(
                        "aucune clé du keyring ne correspond".into(),
                    ))?
                } else {
                    crate::crypto::keys::load_secret(&name)?
                };
                engine::decrypt_file(&path, &out, &Credential::SecretKey(sec), &mut |d| {
                    let _ = tx.send(app::WorkerMsg::Progress(d));
                })?;
                Ok(format!("decrypted → {}", out.display()))
            });
        }
        PendingAction::Keygen => {
            let name = val(0);
            match crate::crypto::keys::keygen(&name) {
                Ok((_pubp, _secp, fp)) => {
                    app.push_log(Level::Ok, format!("xwing keypair '{name}' fp={fp}"));
                    app.toast(format!("key '{name}' generated — {fp}"));
                }
                Err(e) => {
                    app.toast("keygen failed");
                    app.push_log(Level::Err, format!("keygen: {e}"));
                }
            }
            app.keyring = crate::crypto::keys::list().unwrap_or_default();
        }
        PendingAction::DeleteKey(name) => {
            match crate::crypto::keys::delete(&name) {
                Ok(()) => app.push_log(Level::Warn, format!("keypair '{name}' deleted")),
                Err(e) => app.push_log(Level::Err, format!("delete key: {e}")),
            }
            app.keyring = crate::crypto::keys::list().unwrap_or_default();
            app.keys_sel = app.keys_sel.min(app.keyring.len().saturating_sub(1));
        }
        PendingAction::JumpPath(shred) => {
            let p = val(0);
            if shred {
                let ok = app.picker_shred.jump(&p);
                if ok {
                    app.toast(format!("→ {}", app.picker_shred.dir.display()));
                } else {
                    app.toast("path not found");
                }
            } else {
                let pb = PathBuf::from(app::clean_dropped_path(&p));
                if app.add_target(pb.clone()) {
                    app.toast(format!("target queued: {}", pb.display()));
                } else if pb.exists() {
                    app.toast("already queued");
                } else {
                    app.toast("path not found");
                }
            }
        }
    }
}

/// `.aos` de sortie : `<premier-stem>.aos` à côté de la première cible.
fn default_aos_out(paths: &[std::path::PathBuf]) -> std::path::PathBuf {
    let first = &paths[0];
    let name = first
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    first.with_file_name(format!("{name}.aos"))
}

fn decrypt_out(path: &std::path::Path) -> std::path::PathBuf {
    if path.extension().and_then(|e| e.to_str()) == Some("aos") {
        path.with_extension("")
    } else {
        path.with_extension("dec")
    }
}

fn header_modal(h: &crate::crypto::AosHeader) -> Modal {
    let ciphers = h
        .cipher_kinds()
        .map(|ks| ks.iter().map(|k| k.id()).collect::<Vec<_>>().join(" → "))
        .unwrap_or_else(|_| h.suite.label().into());
    let mut lines = vec![
        format!("format        : .aos v{}", h.v),
        format!("ciphers       : {ciphers}"),
        format!("packed (tar)  : {}", h.packed),
        format!("chunk size    : {} KiB", h.chunk_size / 1024),
        format!(
            "nonce prefix  : {}…",
            &h.nonce_prefix_hex[..24.min(h.nonce_prefix_hex.len())]
        ),
        format!("compressed    : {}", h.compressed),
        format!("padded        : {}", h.padded),
    ];
    match &h.kdf {
        Some(k) => lines.push(format!(
            "auth          : password · argon2id m={}KiB t={} p={}",
            k.m_kib, k.t, k.p
        )),
        None => {
            lines.push(format!(
                "auth          : {} recipient slot(s)",
                h.recipients.len()
            ));
            for s in &h.recipients {
                lines.push(format!("  slot xwing  → {}", s.fingerprint));
            }
        }
    }
    Modal::Info {
        title: "CONTAINER HEADER".into(),
        lines,
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
    fn tab_cycles_from_dash() {
        let cfg = Config::default();
        let mut app = App::new(&cfg, true);
        on_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.tab, Tab::Crypt);
    }

    #[test]
    fn picker_jump_selects_target() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("secret.txt");
        std::fs::write(&f, b"data").unwrap();
        let mut p = app::FilePicker::new();
        assert!(p.jump(f.to_str().unwrap()));
        assert_eq!(p.target.as_ref().unwrap().name, "secret.txt");
        // dossier → navigation dedans
        assert!(p.jump(tmp.path().to_str().unwrap()));
        assert_eq!(p.dir, tmp.path());
    }

    #[test]
    fn clean_dropped_path_handles_quotes() {
        assert_eq!(
            app::clean_dropped_path("  \"C:\\foo\\bar baz.txt\"  "),
            "C:\\foo\\bar baz.txt"
        );
        assert_eq!(app::clean_dropped_path("& 'C:\\x y.txt'"), "C:\\x y.txt");
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
