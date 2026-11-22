//! 67zip's own icon set (inline SVG, drawn for this project).

use std::collections::HashMap;
use std::sync::LazyLock;

use iced::widget::svg;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Icon {
    Add,
    Extract,
    Test,
    Copy,
    Move,
    Delete,
    Info,
    Up,
    Refresh,
    Settings,
    Sidebar,
    Home,
    Desktop,
    Documents,
    Downloads,
    Pictures,
    Music,
    Drive,
    Hash,
    Bench,
    Lock,
    Shield,
    ShieldOff,
    NewFolder,
    Rename,
    Close,
    Eye,
    Star,
    Folder,
    File,
    Archive,
    Image,
    Audio,
    Video,
    Text,
    Code,
    Pdf,
    Exec,
    Link,
    Warning,
    Logo,
}

const G: &str = "#8A94A6"; // neutral glyph grey, readable on light and dark

fn doc(color: &str, inner: &str) -> String {
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M6 2.5h8l5 5V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20V4a1.5 1.5 0 0 1 1-1.5z" fill="{color}"/><path d="M14 2.5v4a1 1 0 0 0 1 1h4z" fill="#ffffff" fill-opacity=".45"/>{inner}</svg>"##
    )
}

fn source(icon: Icon) -> String {
    let s = |body: &str| format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">{body}</svg>"#);
    let box_ = r##"<rect x="2.5" y="8.5" width="15" height="12" rx="2" fill="#F59E0B"/><rect x="1.5" y="5.5" width="17" height="4.2" rx="1.4" fill="#D97706"/><rect x="8" y="9.7" width="4" height="3.2" rx=".8" fill="#FEF3C7"/>"##;
    match icon {
        Icon::Add => s(&format!(r##"{box_}<circle cx="17.5" cy="17" r="5.2" fill="#22A055"/><path d="M17.5 14.2v5.6M14.7 17h5.6" stroke="#fff" stroke-width="2" stroke-linecap="round"/>"##)),
        Icon::Extract => s(&format!(r##"{box_}<circle cx="17.5" cy="7.5" r="5.2" fill="#3B82F6"/><path d="M17.5 10.4V5M15.2 7.2l2.3-2.3 2.3 2.3" stroke="#fff" stroke-width="1.9" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##)),
        Icon::Test => s(r##"<circle cx="12" cy="12" r="9.5" fill="#22A055"/><path d="M7.5 12.3l3 3 6-6.3" stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::Copy => s(r##"<rect x="7.5" y="7.5" width="13" height="14" rx="2" fill="#3B82F6"/><rect x="3.5" y="2.5" width="13" height="14" rx="2" fill="#93C5FD" stroke="#3B82F6" stroke-width="1.2"/>"##),
        Icon::Move => s(r##"<rect x="2.5" y="3.5" width="11" height="15" rx="2" fill="#C4B5FD"/><path d="M10 13h10M16.5 9.5L20 13l-3.5 3.5" stroke="#8B5CF6" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::Delete => s(r##"<path d="M5 7h14l-1.2 13a1.8 1.8 0 0 1-1.8 1.5H8a1.8 1.8 0 0 1-1.8-1.5z" fill="#EF4444"/><rect x="3" y="4" width="18" height="3" rx="1.2" fill="#B91C1C"/><rect x="9" y="2" width="6" height="2.5" rx="1" fill="#B91C1C"/><path d="M10 10.5v7M14 10.5v7" stroke="#FECACA" stroke-width="1.6" stroke-linecap="round"/>"##),
        Icon::Info => s(r##"<circle cx="12" cy="12" r="9.5" fill="#3B82F6"/><circle cx="12" cy="7.6" r="1.4" fill="#fff"/><path d="M12 11v6.5" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>"##),
        Icon::Up => s(&format!(r##"<path d="M12 19V5M6 11l6-6 6 6" stroke="{G}" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##)),
        Icon::Refresh => s(&format!(r##"<path d="M19 12a7 7 0 1 1-2.05-4.95" stroke="{G}" stroke-width="2.2" fill="none" stroke-linecap="round"/><path d="M19.5 3.5v4.5H15" stroke="{G}" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##)),
        Icon::Settings => s(&format!(r##"<path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z" fill="none" stroke="{G}" stroke-width="2"/><path d="M12 2.5l1.6 2.6 3-.6.6 3 2.6 1.6-1.5 2.9 1.5 2.9-2.6 1.6-.6 3-3-.6L12 21.5l-1.6-2.6-3 .6-.6-3-2.6-1.6 1.5-2.9-1.5-2.9 2.6-1.6.6-3 3 .6z" fill="none" stroke="{G}" stroke-width="1.8" stroke-linejoin="round"/>"##)),
        Icon::Sidebar => s(&format!(r##"<rect x="3" y="4" width="18" height="16" rx="2.5" fill="none" stroke="{G}" stroke-width="2"/><path d="M9 4v16" stroke="{G}" stroke-width="2"/>"##)),
        Icon::Home => s(r##"<path d="M3.5 11L12 3.5 20.5 11V20a1 1 0 0 1-1 1h-4.5v-6h-6v6H4.5a1 1 0 0 1-1-1z" fill="#3B82F6"/>"##),
        Icon::Desktop => s(r##"<rect x="2.5" y="3.5" width="19" height="13" rx="2" fill="#6366F1"/><rect x="4.5" y="5.5" width="15" height="9" rx="1" fill="#C7D2FE"/><path d="M8 20.5h8M12 16.5v4" stroke="#6366F1" stroke-width="2" stroke-linecap="round"/>"##),
        Icon::Documents => doc("#3B82F6", r##"<path d="M8 12h8M8 15h8M8 18h5" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>"##),
        Icon::Downloads => s(r##"<circle cx="12" cy="12" r="9.5" fill="#22A055"/><path d="M12 6.5v8.5M8.5 11.5L12 15l3.5-3.5M7.5 18h9" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::Pictures => s(r##"<rect x="2.5" y="4" width="19" height="16" rx="2.5" fill="#14B8A6"/><circle cx="8.5" cy="9.5" r="2" fill="#fff"/><path d="M3.5 18l5.5-5.5 3.5 3.5 3-3 5 5" fill="#fff" fill-opacity=".85"/>"##),
        Icon::Music => s(r##"<circle cx="12" cy="12" r="9.5" fill="#EC4899"/><path d="M10 16.5V8l6-1.5v8" stroke="#fff" stroke-width="1.8" fill="none"/><circle cx="8.8" cy="16.5" r="1.8" fill="#fff"/><circle cx="14.8" cy="14.5" r="1.8" fill="#fff"/>"##),
        Icon::Drive => s(r##"<rect x="2.5" y="6" width="19" height="12" rx="2.5" fill="#64748B"/><circle cx="17" cy="12" r="1.5" fill="#A7F3D0"/><path d="M6 12h6" stroke="#CBD5E1" stroke-width="2" stroke-linecap="round"/>"##),
        Icon::Hash => s(r##"<rect x="2.5" y="2.5" width="19" height="19" rx="4" fill="#0EA5E9"/><path d="M10 6.5L8.5 17.5M15.5 6.5L14 17.5M6.5 10h11M6 14h11" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>"##),
        Icon::Bench => s(r##"<path d="M3 16a9 9 0 0 1 18 0" fill="none" stroke="#F59E0B" stroke-width="3" stroke-linecap="round"/><path d="M12 16l4.5-6" stroke="#EF4444" stroke-width="2.4" stroke-linecap="round"/><circle cx="12" cy="16" r="2" fill="#EF4444"/>"##),
        Icon::Lock => s(r##"<rect x="4.5" y="10" width="15" height="11" rx="2.5" fill="#F59E0B"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10" stroke="#F59E0B" stroke-width="2.4" fill="none"/><circle cx="12" cy="15.5" r="1.6" fill="#fff"/>"##),
        Icon::Shield => s(r##"<path d="M12 2.5l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6z" fill="#22A055"/><path d="M8.3 12l2.6 2.6 4.8-5" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::ShieldOff => s(r##"<path d="M12 2.5l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10v-6z" fill="#E3B341"/><path d="M12 7.5v6" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="16.6" r="1.3" fill="#fff"/>"##),
        Icon::NewFolder => s(r##"<path d="M2.5 6.5A1.5 1.5 0 0 1 4 5h5l2 2h9a1.5 1.5 0 0 1 1.5 1.5V18A1.5 1.5 0 0 1 20 19.5H4A1.5 1.5 0 0 1 2.5 18z" fill="#F4B740"/><path d="M12 10v6M9 13h6" stroke="#fff" stroke-width="2" stroke-linecap="round"/>"##),
        Icon::Rename => s(r##"<path d="M4 20l1-4.5L15.5 5a2.1 2.1 0 0 1 3 3L8 18.5z" fill="#8B5CF6"/><path d="M13.5 7l3 3" stroke="#EDE9FE" stroke-width="1.5"/>"##),
        Icon::Close => s(&format!(r##"<path d="M6 6l12 12M18 6L6 18" stroke="{G}" stroke-width="2.2" stroke-linecap="round"/>"##)),
        Icon::Eye => s(&format!(r##"<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" fill="none" stroke="{G}" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="{G}"/>"##)),
        Icon::Star => s(r##"<path d="M12 2.8l2.8 5.8 6.3.9-4.6 4.4 1.1 6.3L12 17.2l-5.6 3 1.1-6.3L2.9 9.5l6.3-.9z" fill="#F59E0B"/>"##),
        Icon::Folder => s(r##"<path d="M2.5 6A1.5 1.5 0 0 1 4 4.5h5.2l2 2.2H20A1.5 1.5 0 0 1 21.5 8.2V18.5A1.5 1.5 0 0 1 20 20H4a1.5 1.5 0 0 1-1.5-1.5z" fill="#E9A23B"/><path d="M2.5 9.2A1.5 1.5 0 0 1 4 7.7h16A1.5 1.5 0 0 1 21.5 9.2v9.3A1.5 1.5 0 0 1 20 20H4a1.5 1.5 0 0 1-1.5-1.5z" fill="#F7C25C"/>"##),
        Icon::File => doc("#94A3B8", ""),
        Icon::Archive => doc("#8B5CF6", r##"<path d="M11 3v2h2v2h-2v2h2v2h-2v2" stroke="#EDE9FE" stroke-width="1.6" fill="none"/><rect x="9.5" y="14" width="5" height="4.5" rx="1.2" fill="#EDE9FE"/>"##),
        Icon::Image => doc("#14B8A6", r##"<circle cx="10" cy="11.5" r="1.6" fill="#fff"/><path d="M7 18.5l3.5-3.5 2.5 2.5 2-2 2.5 3z" fill="#fff"/>"##),
        Icon::Audio => doc("#EC4899", r##"<path d="M11 17.5v-7l4.5-1v6" stroke="#fff" stroke-width="1.5" fill="none"/><circle cx="10" cy="17.5" r="1.5" fill="#fff"/><circle cx="14.5" cy="15.5" r="1.5" fill="#fff"/>"##),
        Icon::Video => doc("#EF4444", r##"<path d="M10 11v7l5.5-3.5z" fill="#fff"/>"##),
        Icon::Text => doc("#3B82F6", r##"<path d="M8 11h8M8 14h8M8 17h5" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>"##),
        Icon::Code => doc("#0D9488", r##"<path d="M10 11.5l-2.5 2.5 2.5 2.5M14 11.5l2.5 2.5-2.5 2.5" stroke="#fff" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::Pdf => doc("#DC2626", r##"<rect x="7" y="12" width="10" height="5" rx="1" fill="#fff"/><path d="M8.5 15.8v-2.6h1a.8.8 0 0 1 0 1.6h-1M11.5 15.8v-2.6h.8a1.3 1.3 0 0 1 0 2.6zM14.5 15.8v-2.6h1.6M14.5 14.5h1.2" stroke="#DC2626" stroke-width=".8" fill="none"/>"##),
        Icon::Exec => doc("#475569", r##"<circle cx="12" cy="14.5" r="3.2" fill="none" stroke="#fff" stroke-width="1.6"/><circle cx="12" cy="14.5" r="1" fill="#fff"/>"##),
        Icon::Link => s(r##"<circle cx="12" cy="12" r="9.5" fill="#0EA5E9"/><path d="M8 15.5c0-4 2.5-6.5 7.5-6.5M12.5 6.5L15.5 9l-3 2.5" stroke="#fff" stroke-width="1.9" fill="none" stroke-linecap="round" stroke-linejoin="round"/>"##),
        Icon::Warning => s(r##"<path d="M12 3l10 17.5H2z" fill="#E3B341" stroke="#E3B341" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 9.5v5" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><circle cx="12" cy="17.5" r="1.3" fill="#fff"/>"##),
        Icon::Logo => LOGO.to_string(),
    }
}

/// The 67zip application icon (also installed as the desktop icon).
pub const LOGO: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7C5CFF"/><stop offset="1" stop-color="#00B8D9"/></linearGradient></defs><rect x="6" y="6" width="116" height="116" rx="28" fill="url(#g)"/><path d="M20 30h88" stroke="#ffffff" stroke-opacity=".35" stroke-width="6" stroke-linecap="round"/><path d="M28 24v12M40 24v12M52 24v12M64 24v12M76 24v12M88 24v12M100 24v12" stroke="#ffffff" stroke-opacity=".55" stroke-width="5" stroke-linecap="round"/><path d="M56 50c-16 2-26 15-26 33 0 13 8 23 21 23s21-9 21-20-8-19-19-19c-10 0-17 5-21 13" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/><path d="M76 52h28L84 104" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

static HANDLES: LazyLock<std::sync::Mutex<HashMap<Icon, svg::Handle>>> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

pub fn handle(icon: Icon) -> svg::Handle {
    if let Ok(mut m) = HANDLES.lock() {
        return m.entry(icon).or_insert_with(|| svg::Handle::from_memory(source(icon).into_bytes())).clone();
    }
    svg::Handle::from_memory(source(icon).into_bytes())
}

/// An icon widget of the given size.
pub fn icon<'a, M: 'a>(icon: Icon, size: f32) -> iced::Element<'a, M> {
    svg(handle(icon)).width(size).height(size).into()
}
