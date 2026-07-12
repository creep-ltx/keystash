use serde::{Serialize, Deserialize};
use crate::generator::GeneratorOptions;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub idle_timeout_seconds: u64,
    pub clipboard_clear_seconds: u64,
    pub auto_sync: bool,
    pub generator: GeneratorOptions,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            idle_timeout_seconds: 300,
            clipboard_clear_seconds: 10,
            auto_sync: true,
            generator: GeneratorOptions::default(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let mut path = crate::get_db_path();
        path.set_file_name("config.json");
        if path.exists() {
            match std::fs::read_to_string(&path).map(|content| serde_json::from_str::<Self>(&content)) {
                Ok(Ok(mut config)) => {
                    // Clamp here too, not just in the settings-screen save path,
                    // so a hand-edited or otherwise corrupted config.json can't
                    // reintroduce an idle timeout of 0 (instant, permanent
                    // relock loop on every tick).
                    config.idle_timeout_seconds = config.idle_timeout_seconds.max(10);
                    config.clipboard_clear_seconds = config.clipboard_clear_seconds.clamp(1, 3600);
                    return config;
                }
                Ok(Err(e)) => Self::warn_and_quarantine(&path, &e.to_string()),
                Err(e) => Self::warn_and_quarantine(&path, &e.to_string()),
            }
        }
        let default_config = Self::default();
        let _ = default_config.save();
        default_config
    }

    /// A truncated write or hand-edit typo used to fall straight through to
    /// `Self::default()` and immediately overwrite `config.json` with it --
    /// silently resetting idle timeout, clipboard delay, auto-sync, and
    /// generator defaults with no indication anything was wrong. Move the
    /// unreadable file aside instead, so it isn't lost, and say why.
    fn warn_and_quarantine(path: &std::path::Path, reason: &str) {
        let bad_path = path.with_file_name("config.json.bad");
        if std::fs::rename(path, &bad_path).is_ok() {
            eprintln!(
                "Warning: {:?} could not be read ({}) -- moved aside to {:?} and reset to defaults.",
                path, reason, bad_path
            );
        } else {
            eprintln!(
                "Warning: {:?} could not be read ({}) -- resetting to defaults.",
                path, reason
            );
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let mut path = crate::get_db_path();
        path.set_file_name("config.json");
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}
