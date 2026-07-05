use rand::seq::SliceRandom;
use rand::Rng;

use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneratorOptions {
    pub length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_numbers: bool,
    pub use_symbols: bool,
}

impl GeneratorOptions {
    pub fn load() -> Self {
        crate::config::AppConfig::load().generator
    }

    pub fn save(&self) -> Result<(), String> {
        let mut config = crate::config::AppConfig::load();
        config.generator = self.clone();
        config.save()
    }
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            use_lowercase: true,
            use_uppercase: true,
            use_numbers: true,
            use_symbols: true,
        }
    }
}

pub fn generate_password(options: &GeneratorOptions) -> Result<String, String> {
    if options.length == 0 {
        return Err("Password length must be greater than 0".to_string());
    }

    let mut char_pool = Vec::new();
    let mut guaranteed_chars = Vec::new();
    let mut rng = rand::thread_rng();

    if options.use_lowercase {
        let chars = b"abcdefghijkmnopqrstuvwxyz";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.gen_range(0..chars.len())]);
    }
    if options.use_uppercase {
        let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.gen_range(0..chars.len())]);
    }
    if options.use_numbers {
        let chars = b"23456789";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.gen_range(0..chars.len())]);
    }
    if options.use_symbols {
        let chars = b"!@#$%^&*()_+-=[]{};:,.<>?";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.gen_range(0..chars.len())]);
    }

    if char_pool.is_empty() {
        return Err("At least one character set must be selected".to_string());
    }

    let mut password = Vec::with_capacity(options.length);
    
    // First, fill with the guaranteed characters to satisfy strength rules
    for char in guaranteed_chars {
        if password.len() < options.length {
            password.push(char);
        }
    }

    // Fill the rest of the length with random characters from the pool
    while password.len() < options.length {
        let idx = rng.gen_range(0..char_pool.len());
        password.push(char_pool[idx]);
    }

    // Shuffle the characters so the guaranteed ones aren't always at the start
    password.shuffle(&mut rng);

    String::from_utf8(password).map_err(|e| e.to_string())
}
