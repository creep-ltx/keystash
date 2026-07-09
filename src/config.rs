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
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(mut config) = serde_json::from_str::<Self>(&content) {
                    // Clamp here too, not just in the settings-screen save path,
                    // so a hand-edited or otherwise corrupted config.json can't
                    // reintroduce an idle timeout of 0 (instant, permanent
                    // relock loop on every tick).
                    config.idle_timeout_seconds = config.idle_timeout_seconds.max(10);
                    config.clipboard_clear_seconds = config.clipboard_clear_seconds.clamp(1, 3600);
                    return config;
                }
            }
        }
        let default_config = Self::default();
        let _ = default_config.save();
        default_config
    }

    pub fn save(&self) -> Result<(), String> {
        let mut path = crate::get_db_path();
        path.set_file_name("config.json");
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}
