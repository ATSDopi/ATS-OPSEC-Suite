//! État de l'application TUI — machine à états Boot → Main, onglets,
//! modales, picker fichiers, log de session, panic screen.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Instant;

use super::matrix::Rain;
use super::theme::{self, Theme};
use crate::config::{Config, Mode};
use crate::sys::SystemProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Boot,
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Crypt,
    Stego,
    Shred,
    Keys,
    Logs,
}

impl Tab {
    pub const ALL: &'static [Tab] = &[
        Tab::Dashboard,
        Tab::Crypt,
        Tab::Stego,
        Tab::Shred,
        Tab::Keys,
        Tab::Logs,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "DASH",
            Tab::Crypt => "CRYPT",
            Tab::Stego => "STEGO",
            Tab::Shred => "SHRED",
            Tab::Keys => "KEYS",
            Tab::Logs => "LOGS",
        }
    }

    pub fn idx(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_idx(i: usize) -> Tab {
        Self::ALL[i % Self::ALL.len()]
    }
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Debug)]
pub struct FilePicker {
    pub dir: PathBuf,
    pub entries: Vec<FileEntry>,
    pub sel: usize,
    /// Fichier actuellement « target » par les actions.
    pub target: Option<FileEntry>,
    pub hash_cache: Option<(PathBuf, String)>,
}

impl FilePicker {
    pub fn new() -> Self {
        let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut p = Self {
            dir,
            entries: Vec::new(),
            sel: 0,
            target: None,
            hash_cache: None,
        };
        p.refresh();
        p
    }

    pub fn refresh(&mut self) {
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let md = e.metadata().ok();
                let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = md.map(|m| m.len()).unwrap_or(0);
                let entry = FileEntry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    path: e.path(),
                    is_dir,
                    size,
                };
                if is_dir {
                    dirs.push(entry);
                } else {
                    files.push(entry);
                }
            }
        }
        dirs.sort_by_key(|a| a.name.to_lowercase());
        files.sort_by_key(|a| a.name.to_lowercase());
        let parent = self.dir.parent().map(|p| FileEntry {
            name: "..".into(),
            path: p.to_path_buf(),
            is_dir: true,
            size: 0,
        });
        // À la racine (pas de parent) : proposer les lettres de lecteurs.
        let drives: Vec<FileEntry> = if parent.is_none() {
            drive_entries()
        } else {
            Vec::new()
        };
        self.entries = parent
            .into_iter()
            .chain(drives)
            .chain(dirs)
            .chain(files)
            .collect();
        self.sel = self.sel.min(self.entries.len().saturating_sub(1));
    }

    /// Saut direct vers un chemin (collé / tapé) : dossier → navigation,
    /// fichier → sélection comme cible + focus sur le dossier parent.
    pub fn jump(&mut self, raw: &str) -> bool {
        let cleaned = clean_dropped_path(raw);
        let p = PathBuf::from(&cleaned);
        if !p.exists() {
            return false;
        }
        if p.is_dir() {
            self.dir = p;
            self.sel = 0;
            self.target = None;
            self.refresh();
            return true;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.dir = p.parent().map(|d| d.to_path_buf()).unwrap_or(p.clone());
        self.refresh();
        self.sel = self
            .entries
            .iter()
            .position(|e| e.name == name)
            .unwrap_or(0);
        self.target = Some(FileEntry {
            name,
            path: p,
            is_dir: false,
            size: std::fs::metadata(
                self.entries
                    .get(self.sel)
                    .map(|e| e.path.clone())
                    .unwrap_or_default(),
            )
            .map(|m| m.len())
            .unwrap_or(0),
        });
        self.hash_cache = None;
        true
    }

    /// Home de l'utilisateur.
    pub fn home(&mut self) {
        if let Some(h) = dirs::home_dir() {
            self.dir = h;
            self.sel = 0;
            self.target = None;
            self.refresh();
        }
    }

    pub fn selected(&self) -> Option<&FileEntry> {
        self.entries.get(self.sel)
    }

    pub fn move_sel(&mut self, delta: i64) {
        if self.entries.is_empty() {
            return;
        }
        let n = self.entries.len() as i64;
        self.sel = ((self.sel as i64 + delta).rem_euclid(n)) as usize;
    }

    /// Enter : descend dans un dossier, ou sélectionne un fichier comme target.
    pub fn activate(&mut self) {
        let Some(e) = self.selected() else { return };
        if e.is_dir {
            self.dir = e.path.clone();
            self.sel = 0;
            self.refresh();
        } else {
            self.target = Some(FileEntry {
                name: e.name.clone(),
                path: e.path.clone(),
                is_dir: false,
                size: e.size,
            });
            self.hash_cache = None;
        }
    }

    /// Hash blake3 du target (calcul paresseux, mis en cache).
    pub fn target_hash(&mut self) -> Option<String> {
        let path = self.target.as_ref()?.path.clone();
        if let Some((p, h)) = &self.hash_cache
            && *p == path
        {
            return Some(h.clone());
        }
        let bytes = std::fs::read(&path).ok()?;
        let h = blake3::hash(&bytes).to_hex().to_string();
        self.hash_cache = Some((path, h.clone()));
        Some(h)
    }
}

/// Nettoie un chemin venant d'un drag & drop / paste terminal :
/// guillemets, `& ` PowerShell, préfixe `file://`.
pub fn clean_dropped_path(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix('&') {
        s = rest.trim().to_string();
    }
    if let Some(rest) = s.strip_prefix("file://") {
        s = rest.to_string();
    }
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s = s[1..s.len() - 1].to_string();
    }
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        s = s[1..s.len() - 1].to_string();
    }
    s
}

/// Entrées `C:\`, `D:\`… pour la racine (Windows uniquement).
#[cfg(windows)]
fn drive_entries() -> Vec<FileEntry> {
    (b'A'..=b'Z')
        .filter_map(|c| {
            let p = PathBuf::from(format!("{}:\\", c as char));
            p.exists().then(|| FileEntry {
                name: format!("{}:\\", c as char),
                path: p,
                is_dir: true,
                size: 0,
            })
        })
        .collect()
}

#[cfg(not(windows))]
fn drive_entries() -> Vec<FileEntry> {
    Vec::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Err,
}

#[derive(Debug)]
pub enum Modal {
    /// Popup d'information (fermer : Esc/Enter).
    Info { title: String, lines: Vec<String> },
    /// Confirmation O/N avant action destructive.
    Confirm {
        title: String,
        lines: Vec<String>,
        action: PendingAction,
    },
    /// Saisie multi-champs (Enter = champ suivant / valider, Tab navigue).
    Input {
        title: String,
        fields: Vec<Field>,
        sel: usize,
        /// Affiche le meter zxcvbn sous le premier champ.
        strength_meter: bool,
        action: PendingAction,
    },
    /// Travail en cours (alimenté par app.worker).
    Progress { title: String, done: u64 },
}

#[derive(Debug)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub masked: bool,
    pub hint: Option<String>,
}

impl Field {
    pub fn masked(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            masked: true,
            hint: None,
        }
    }
    pub fn plain(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            masked: false,
            hint: None,
        }
    }
    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
}

#[derive(Debug, Clone)]
pub enum PendingAction {
    Shred(PathBuf),
    /// fields: [password, confirm]
    Encrypt(PathBuf),
    /// fields: [recipients, comma-sep names]
    EncryptTo(PathBuf),
    /// fields: [password]
    Decrypt(PathBuf),
    /// fields: [key name or .sec path]
    DecryptKey(PathBuf),
    /// fields: [name]
    Keygen,
    DeleteKey(String),
    /// fields: [path] — true = picker shred, false = picker crypt.
    JumpPath(bool),
}

/// Mode de chiffrement dans l'onglet CRYPT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptMode {
    /// Mot de passe → Argon2id → clé symétrique.
    Password,
    /// Clés publiques X-Wing de destinataires → partage sans mot de passe.
    Recipients,
}

/// Message d'un thread worker vers la UI.
#[derive(Debug)]
pub enum WorkerMsg {
    Progress(u64),
    Done(String),
    Err(String),
}

pub struct Worker {
    pub rx: std::sync::mpsc::Receiver<WorkerMsg>,
}

pub struct App {
    pub should_quit: bool,
    pub screen: Screen,
    pub boot: super::boot::Boot,
    pub rain: Rain,
    pub tab: Tab,
    pub theme_idx: usize,
    pub profile: SystemProfile,
    pub mode: Mode,
    pub boot_anim: bool,
    pub argon2: crate::crypto::Argon2Params,
    pub start: Instant,
    pub tick: u64,
    pub log: VecDeque<(String, Level, String)>,
    pub modal: Option<Modal>,
    pub help_open: bool,
    pub panic: bool,
    pub picker_vault: FilePicker,
    pub picker_shred: FilePicker,
    pub shred_passes: usize,
    pub log_scroll: u16,
    /// Fenêtre de transition glitch après boot/panic.
    pub transition_end: Option<Instant>,
    pub status_msg: Option<(String, Instant)>,
    /// Worker crypto/shred en arrière-plan (progression → modale).
    pub worker: Option<Worker>,
    /// Options du vault (toggles).
    pub vault_suite: crate::crypto::CipherSuite,
    pub vault_compress: bool,
    pub vault_pad: bool,
    pub vault_shred_orig: bool,
    /// Mode d'authentification de l'onglet CRYPT.
    pub crypt_mode: CryptMode,
    /// Opérations réussies cette session (compteur dashboard).
    pub ops_done: u32,
    /// Keyring (nom, fingerprint, a_secret).
    pub keyring: Vec<(String, String, bool)>,
    pub keys_sel: usize,
}

impl App {
    pub fn new(cfg: &Config, no_anim: bool) -> Self {
        let profile = crate::sys::probe();
        let anim = cfg.boot_anim && !no_anim;
        Self {
            should_quit: false,
            screen: if anim { Screen::Boot } else { Screen::Main },
            boot: super::boot::Boot::new(&profile),
            rain: Rain::new(120, 40),
            tab: Tab::Dashboard,
            theme_idx: theme::by_name(&cfg.theme),
            profile,
            mode: cfg.mode,
            boot_anim: cfg.boot_anim,
            argon2: cfg.argon2,
            start: Instant::now(),
            tick: 0,
            log: VecDeque::with_capacity(256),
            modal: None,
            help_open: false,
            panic: false,
            picker_vault: FilePicker::new(),
            picker_shred: FilePicker::new(),
            shred_passes: 3,
            log_scroll: 0,
            transition_end: None,
            status_msg: None,
            worker: None,
            vault_suite: crate::crypto::CipherSuite::XChaCha20,
            vault_compress: false,
            vault_pad: false,
            vault_shred_orig: false,
            crypt_mode: CryptMode::Password,
            ops_done: 0,
            keyring: crate::crypto::keys::list().unwrap_or_default(),
            keys_sel: 0,
        }
    }

    pub fn theme(&self) -> &'static Theme {
        &theme::THEMES[self.theme_idx % theme::THEMES.len()]
    }

    pub fn uptime(&self) -> String {
        let s = self.start.elapsed().as_secs();
        format!("T+{:02}:{:02}", s / 60, s % 60)
    }

    pub fn push_log(&mut self, level: Level, msg: impl Into<String>) {
        let t = self.uptime();
        if self.log.len() >= 512 {
            self.log.pop_front();
        }
        self.log.push_back((t, level, msg.into()));
    }

    pub fn toast(&mut self, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), Instant::now()));
    }

    /// Score OPSEC 0-100 affiché au dashboard — heuristique v0.1.
    pub fn opsec_score(&self) -> u16 {
        let p = &self.profile;
        let mut s = 0u16;
        if p.rng_ok {
            s += 30;
        }
        if p.memlock.ok() {
            s += 25;
        }
        if p.cpu.hypervisor == Some(false) {
            s += 20;
        }
        if p.tracer_detected == Some(false) {
            s += 15;
        }
        if self.mode == Mode::Expert {
            s += 10;
        } else {
            s += 5;
        }
        s.min(100)
    }
}
