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
    /// Look for a new version once a day.
    pub auto_update: bool,
    /// Unix time of the last automatic check.
    pub last_update_check: i64,
    /// A version the user doesn't want to hear about.
    pub skipped_version: Option<String>,
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
            auto_update: true,
            last_update_check: 0,
            skipped_version: None,
        }
    }
}

fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("67zip").join("settings.json"))
}

impl Settings {
    pub fn load() -> Settings {
        path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::Settings;

    #[test]
    fn older_settings_files_get_the_new_defaults() {
        // A settings file from before the update checker existed.
        let s: Settings = serde_json::from_str(r#"{"theme":"Dark","show_hidden":true}"#).unwrap();
        assert!(s.show_hidden && s.auto_update && s.warn_temp_on_disk);
        assert_eq!((s.last_update_check, s.skipped_version), (0, None));
        // And the new fields survive a save and load.
        let mut s = Settings { auto_update: false, last_update_check: 1_800_000_000, skipped_version: Some("0.1.2".into()), ..Settings::default() };
        s = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert!(!s.auto_update);
        assert_eq!((s.last_update_check, s.skipped_version.as_deref()), (1_800_000_000, Some("0.1.2")));
    }
}
