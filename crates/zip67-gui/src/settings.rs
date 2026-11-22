//! Persistent settings in `~/.config/67zip/settings.json`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// None = follow the desktop's accent colour (falls back to blue).
    pub accent: Option<String>,
    pub show_hidden: bool,
    pub sidebar: bool,
    pub confirm_delete: bool,
    pub use_trash: bool,
    pub default_format: String,
    pub default_level: u32,
    pub last_dir: Option<PathBuf>,
    pub favorites: Vec<PathBuf>,
    pub scale: f32,
    /// Tell when a file from an encrypted archive had to be decrypted into
    /// a temporary folder on a disk (no in-memory folder available).
    pub warn_temp_on_disk: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::System,
            accent: None,
            show_hidden: false,
            sidebar: true,
            confirm_delete: true,
            use_trash: true,
            default_format: "7z".into(),
            default_level: 5,
            last_dir: None,
            favorites: Vec::new(),
            scale: 1.0,
            warn_temp_on_disk: true,
        }
    }
}

fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("67zip").join("settings.json"))
}

impl Settings {
    pub fn load() -> Settings {
        path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) {
        let Some(p) = path() else { return };
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(json) = serde_json::to_vec_pretty(self) {
            let tmp = p.with_extension("json.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(tmp, p);
            }
        }
    }
}
