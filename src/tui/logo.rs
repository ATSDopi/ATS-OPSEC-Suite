//! ASCII art du logo — deux tailles (full ≥ 96 cols, mini sinon).

pub const LOGO_BIG: &[&str] = &[
    r" █████╗ ████████╗███████╗       ██████╗ ██████╗ ███████╗███████╗ ██████╗",
    r"██╔══██╗╚══██╔══╝██╔════╝      ██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝",
    r"███████║   ██║   ███████╗      ██║   ██║██████╔╝███████╗█████╗  ██║     ",
    r"██╔══██║   ██║   ╚════██║      ██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║     ",
    r"██║  ██║   ██║   ███████║      ╚██████╔╝██║     ███████║███████╗╚██████╗",
    r"╚═╝  ╚═╝   ╚═╝   ╚══════╝       ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝",
];

pub const LOGO_MINI: &[&str] = &[
    r"╔═╗╔╦╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╔═╗",
    r"╠═╣ ║ ╚═╗  ║ ║╠═╝╚═╗║╣ ║  ",
    r"╩ ╩ ╩ ╚═╝  ╚═╝╩  ╚═╝╚═╝╚═╝",
];

pub const TAGLINE: &str =
    "F I L E - C E N T R I C   O P E R A T I O N A L   S E C U R I T Y   T O O L K I T";

/// Glyphes pseudo-aléatoires affichés pendant le « decode » du logo.
pub const SCRAMBLE: &[char] = &[
    '<', '>', '/', '\\', '[', ']', '{', '}', '=', '+', '*', '^', '?', '#', '|', ':', ';', '░', '▒',
    '▓', '█', '▄', '▀', '0', '1', '7', 'Z', 'X', '$', '%', '&',
];

/// Largeur réelle du grand logo (toutes lignes égales, padding ok).
pub fn logo_width() -> u16 {
    LOGO_BIG
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0) as u16
}
