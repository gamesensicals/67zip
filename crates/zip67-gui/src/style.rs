//! Look and feel: our own light and dark palettes, accent colours and
//! widget styles. Everything is drawn by 67zip itself, so it looks the same
//! on every distribution and desktop.

use iced::widget::{button, container, scrollable, text_input};
use iced::{border, Background, Border, Color, Shadow, Theme, Vector};

pub const ACCENTS: [(&str, Color); 8] = [
    ("Blue", rgb(0x3b, 0x82, 0xf6)),
    ("Violet", rgb(0x8b, 0x5c, 0xf6)),
    ("Teal", rgb(0x14, 0xb8, 0xa6)),
    ("Green", rgb(0x22, 0xa0, 0x55)),
    ("Orange", rgb(0xf9, 0x73, 0x16)),
    ("Pink", rgb(0xec, 0x48, 0x99)),
    ("Red", rgb(0xe5, 0x48, 0x4d)),
    ("Graphite", rgb(0x6b, 0x72, 0x80)),
];

pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color { r: r as f32 / 255.0, g: g as f32 / 255.0, b: b as f32 / 255.0, a: 1.0 }
}

pub fn with_alpha(c: Color, a: f32) -> Color {
    Color { a, ..c }
}

pub fn mix(a: Color, b: Color, t: f32) -> Color {
    Color { r: a.r + (b.r - a.r) * t, g: a.g + (b.g - a.g) * t, b: a.b + (b.b - a.b) * t, a: a.a + (b.a - a.a) * t }
}

/// Builds the 67zip theme.
pub fn make_theme(dark: bool, accent: Color) -> Theme {
    let palette = if dark {
        iced::theme::Palette {
            background: rgb(0x1b, 0x1e, 0x24),
            text: rgb(0xe8, 0xea, 0xee),
            primary: accent,
            success: rgb(0x3f, 0xb9, 0x50),
            warning: rgb(0xe3, 0xb3, 0x41),
            danger: rgb(0xf0, 0x5d, 0x5e),
        }
    } else {
        iced::theme::Palette {
            background: rgb(0xf6, 0xf7, 0xf9),
            text: rgb(0x1c, 0x20, 0x26),
            primary: accent,
            success: rgb(0x1f, 0x88, 0x3d),
            warning: rgb(0xb0, 0x80, 0x00),
            danger: rgb(0xd1, 0x24, 0x2f),
        }
    };
    Theme::custom(if dark { "67zip Dark" } else { "67zip Light" }, palette)
}

pub fn is_dark(theme: &Theme) -> bool {
    theme.extended_palette().is_dark
}

/// Surface colour of panels (toolbar, sidebar, dialogs).
pub fn surface(theme: &Theme) -> Color {
    let p = theme.extended_palette();
    if p.is_dark { rgb(0x23, 0x27, 0x2e) } else { Color::WHITE }
}

pub fn border_color(theme: &Theme) -> Color {
    if is_dark(theme) { rgb(0x34, 0x39, 0x42) } else { rgb(0xe1, 0xe4, 0xe8) }
}

pub fn muted_text(theme: &Theme) -> Color {
    if is_dark(theme) { rgb(0x9a, 0xa1, 0xac) } else { rgb(0x66, 0x6d, 0x78) }
}

pub fn panel(theme: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(surface(theme))), ..Default::default() }
}

pub fn toolbar(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(surface(theme))),
        border: Border { color: border_color(theme), width: 0.0, radius: 0.0.into() },
        shadow: Shadow { color: with_alpha(Color::BLACK, if is_dark(theme) { 0.35 } else { 0.06 }), offset: Vector::new(0.0, 1.0), blur_radius: 3.0 },
        ..Default::default()
    }
}

pub fn sidebar(theme: &Theme) -> container::Style {
    let bg = if is_dark(theme) { rgb(0x1f, 0x22, 0x29) } else { rgb(0xef, 0xf1, 0xf4) };
    container::Style { background: Some(Background::Color(bg)), ..Default::default() }
}

pub fn status_bar(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(surface(theme))),
        text_color: Some(muted_text(theme)),
        border: Border { color: border_color(theme), width: 1.0, radius: 0.0.into() },
        ..Default::default()
    }
}

pub fn list_header(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(surface(theme))),
        text_color: Some(muted_text(theme)),
        border: Border { color: border_color(theme), width: 1.0, radius: 0.0.into() },
        ..Default::default()
    }
}

pub fn list_area(theme: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(theme.palette().background)), ..Default::default() }
}

pub fn row(theme: &Theme, selected: bool, odd: bool) -> container::Style {
    let p = theme.extended_palette();
    let bg = if selected {
        Some(Background::Color(with_alpha(p.primary.base.color, if p.is_dark { 0.38 } else { 0.18 })))
    } else if odd {
        Some(Background::Color(if p.is_dark { rgb(0x1f, 0x22, 0x29) } else { rgb(0xfb, 0xfb, 0xfc) }))
    } else {
        None
    };
    container::Style { background: bg, border: Border { radius: 6.0.into(), ..Default::default() }, ..Default::default() }
}

pub fn card(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(surface(theme))),
        border: Border { color: border_color(theme), width: 1.0, radius: 14.0.into() },
        shadow: Shadow { color: with_alpha(Color::BLACK, 0.35), offset: Vector::new(0.0, 8.0), blur_radius: 32.0 },
        ..Default::default()
    }
}

pub fn menu(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(surface(theme))),
        border: Border { color: border_color(theme), width: 1.0, radius: 10.0.into() },
        shadow: Shadow { color: with_alpha(Color::BLACK, 0.30), offset: Vector::new(0.0, 4.0), blur_radius: 18.0 },
        ..Default::default()
    }
}

pub fn backdrop(_theme: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(with_alpha(Color::BLACK, 0.45))), ..Default::default() }
}

pub fn badge(theme: &Theme, color: Color) -> container::Style {
    let _ = theme;
    container::Style {
        background: Some(Background::Color(with_alpha(color, 0.16))),
        text_color: Some(color),
        border: Border { radius: 999.0.into(), ..Default::default() },
        ..Default::default()
    }
}

pub fn warning_box(theme: &Theme) -> container::Style {
    let c = theme.palette().warning;
    container::Style {
        background: Some(Background::Color(with_alpha(c, 0.12))),
        border: Border { color: with_alpha(c, 0.4), width: 1.0, radius: 8.0.into() },
        ..Default::default()
    }
}

pub fn address(theme: &Theme) -> container::Style {
    let bg = if is_dark(theme) { rgb(0x1b, 0x1e, 0x24) } else { rgb(0xf2, 0xf4, 0xf7) };
    container::Style {
        background: Some(Background::Color(bg)),
        border: Border { color: border_color(theme), width: 1.0, radius: 8.0.into() },
        ..Default::default()
    }
}

/// Flat toolbar / icon button: transparent until hovered.
pub fn tool_button(theme: &Theme, status: button::Status) -> button::Style {
    let text = theme.palette().text;
    let hover = if is_dark(theme) { with_alpha(Color::WHITE, 0.07) } else { with_alpha(Color::BLACK, 0.05) };
    let pressed = if is_dark(theme) { with_alpha(Color::WHITE, 0.12) } else { with_alpha(Color::BLACK, 0.09) };
    let background = match status {
        button::Status::Hovered => Some(Background::Color(hover)),
        button::Status::Pressed => Some(Background::Color(pressed)),
        _ => None,
    };
    button::Style {
        background,
        text_color: if status == button::Status::Disabled { with_alpha(text, 0.35) } else { text },
        border: border::rounded(8),
        ..Default::default()
    }
}

/// Sidebar place entry; `active` marks the current location.
pub fn place_button(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let mut s = tool_button(theme, status);
        if active {
            s.background = Some(Background::Color(with_alpha(theme.palette().primary, 0.16)));
        }
        s
    }
}

pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut s = button::primary(theme, status);
    s.border = border::rounded(8);
    s
}

pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
    let base = if is_dark(theme) { rgb(0x30, 0x35, 0x3e) } else { rgb(0xec, 0xee, 0xf1) };
    let bg = match status {
        button::Status::Hovered => mix(base, theme.palette().text, 0.06),
        button::Status::Pressed => mix(base, theme.palette().text, 0.12),
        _ => base,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: if status == button::Status::Disabled { with_alpha(theme.palette().text, 0.4) } else { theme.palette().text },
        border: Border { radius: 8.0.into(), ..Default::default() },
        ..Default::default()
    }
}

pub fn danger_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut s = button::danger(theme, status);
    s.border = border::rounded(8);
    s
}

pub fn menu_item(theme: &Theme, status: button::Status) -> button::Style {
    let mut s = tool_button(theme, status);
    s.border = border::rounded(6);
    if status == button::Status::Hovered {
        s.background = Some(Background::Color(with_alpha(theme.palette().primary, 0.85)));
        s.text_color = Color::WHITE;
    }
    s
}

pub fn header_button(theme: &Theme, status: button::Status) -> button::Style {
    let mut s = tool_button(theme, status);
    s.text_color = muted_text(theme);
    s.border = border::rounded(4);
    s
}

pub fn input(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let mut s = text_input::default(theme, status);
    s.border.radius = 8.0.into();
    if !matches!(status, text_input::Status::Focused { .. }) {
        s.border.color = border_color(theme);
    }
    s.background = Background::Color(if is_dark(theme) { rgb(0x1b, 0x1e, 0x24) } else { Color::WHITE });
    s
}

pub fn address_input(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let mut s = input(theme, status);
    s.border.width = 0.0;
    s.background = Background::Color(Color::TRANSPARENT);
    s
}

pub fn scroll(theme: &Theme, status: scrollable::Status) -> scrollable::Style {
    let mut s = scrollable::default(theme, status);
    let c = with_alpha(muted_text(theme), 0.45);
    s.vertical_rail.scroller.background = Background::Color(c);
    s.vertical_rail.scroller.border = border::rounded(4);
    s.vertical_rail.background = None;
    s.vertical_rail.border = Border::default();
    s
}
