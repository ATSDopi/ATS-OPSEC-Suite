//! Palette cyberpunk — presets cyclables (touche `t` ou Settings).

use ratatui::style::Color;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub name: &'static str,
    pub accent: Color,
    pub accent2: Color,
    pub fg: Color,
    pub dim: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
}

pub const CYBER: Theme = Theme {
    name: "cyber",
    accent: Color::Rgb(0, 255, 156),
    accent2: Color::Rgb(0, 170, 255),
    fg: Color::Rgb(200, 230, 215),
    dim: Color::Rgb(60, 100, 85),
    ok: Color::Rgb(0, 255, 156),
    warn: Color::Rgb(255, 176, 0),
    err: Color::Rgb(255, 60, 80),
};

pub const AMBER: Theme = Theme {
    name: "amber",
    accent: Color::Rgb(255, 176, 0),
    accent2: Color::Rgb(255, 120, 40),
    fg: Color::Rgb(235, 215, 175),
    dim: Color::Rgb(110, 85, 40),
    ok: Color::Rgb(255, 176, 0),
    warn: Color::Rgb(255, 220, 80),
    err: Color::Rgb(255, 60, 80),
};

pub const ICE: Theme = Theme {
    name: "ice",
    accent: Color::Rgb(0, 213, 255),
    accent2: Color::Rgb(120, 120, 255),
    fg: Color::Rgb(190, 225, 240),
    dim: Color::Rgb(50, 80, 100),
    ok: Color::Rgb(0, 213, 255),
    warn: Color::Rgb(255, 176, 0),
    err: Color::Rgb(255, 60, 80),
};

pub const CRIMSON: Theme = Theme {
    name: "crimson",
    accent: Color::Rgb(255, 51, 85),
    accent2: Color::Rgb(255, 150, 60),
    fg: Color::Rgb(240, 200, 205),
    dim: Color::Rgb(100, 50, 60),
    ok: Color::Rgb(255, 51, 85),
    warn: Color::Rgb(255, 176, 0),
    err: Color::Rgb(255, 60, 80),
};

pub const THEMES: &[Theme] = &[CYBER, AMBER, ICE, CRIMSON];

pub fn by_name(name: &str) -> usize {
    THEMES.iter().position(|t| t.name == name).unwrap_or(0)
}
