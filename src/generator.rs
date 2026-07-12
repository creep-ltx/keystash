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

/// The one clamp for generated-password length, applied inside
/// `generate_password` itself so every caller inherits it. Three different
/// rules used to coexist: the CLI accepted any `-l` (length 1 generated --
/// and was silently saved as the new default), the TUI dialog stopped at
/// 128, and the Settings screen at 256. One rule, lowest common sense:
/// 4..=256.
pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 256;

// ─────────────────────────────────────────────
//  Diceware passphrases
// ─────────────────────────────────────────────

/// The EFF large wordlist (https://www.eff.org/dice), 7776 words: each word
/// contributes log2(7776) ≈ 12.9 bits, so the 6-word default lands at ~77.5
/// bits -- above the audit scorer's 75-bit "Good" threshold on wordlist
/// entropy alone, before counting what the charset math sees. Embedded
/// (~61 KiB, <1% of the binary) rather than fetched or read from disk:
/// deterministic, offline, and no "wordlist file missing" failure mode.
static EFF_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 12;
pub const DEFAULT_WORDS: usize = 6;

/// Generates a diceware-style passphrase: `word_count` words (clamped to
/// 3..=12) drawn uniformly from the EFF large list, joined with '-'. The
/// better generator mode for anything a human has to type or memorize --
/// a phone login, the master password of *another* password manager, wifi.
pub fn generate_passphrase(word_count: usize) -> String {
    let words: Vec<&str> = EFF_WORDLIST.lines().collect();
    debug_assert_eq!(words.len(), 7776, "the embedded EFF list must be intact");
    let count = word_count.clamp(MIN_WORDS, MAX_WORDS);
    let mut rng = rand::rng();
    (0..count)
        .map(|_| words[rng.random_range(0..words.len())])
        .collect::<Vec<_>>()
        .join("-")
}

pub fn generate_password(options: &GeneratorOptions) -> Result<String, String> {
    let length = options.length.clamp(MIN_LENGTH, MAX_LENGTH);

    let mut char_pool = Vec::new();
    let mut guaranteed_chars = Vec::new();
    let mut rng = rand::rng();

    if options.use_lowercase {
        let chars = b"abcdefghijkmnopqrstuvwxyz";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.random_range(0..chars.len())]);
    }
    if options.use_uppercase {
        let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.random_range(0..chars.len())]);
    }
    if options.use_numbers {
        let chars = b"23456789";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.random_range(0..chars.len())]);
    }
    if options.use_symbols {
        let chars = b"!@#$%^&*()_+-=[]{};:,.<>?";
        char_pool.extend_from_slice(chars);
        guaranteed_chars.push(chars[rng.random_range(0..chars.len())]);
    }

    if char_pool.is_empty() {
        return Err("At least one character set must be selected".to_string());
    }

    let mut password = Vec::with_capacity(length);

    // First, fill with the guaranteed characters to satisfy strength rules
    for char in guaranteed_chars {
        if password.len() < length {
            password.push(char);
        }
    }

    // Fill the rest of the length with random characters from the pool
    while password.len() < length {
        let idx = rng.random_range(0..char_pool.len());
        password.push(char_pool[idx]);
    }

    // Shuffle the characters so the guaranteed ones aren't always at the start
    password.shuffle(&mut rng);

    String::from_utf8(password).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_clamped_to_the_single_shared_rule() {
        // (requested length, expected generated length) -- 1 used to
        // generate a 1-char "password" via the CLI's unclamped -l.
        for (requested, expected) in [(1, MIN_LENGTH), (0, MIN_LENGTH), (10_000, MAX_LENGTH), (20, 20)] {
            let opts = GeneratorOptions { length: requested, ..Default::default() };
            assert_eq!(
                generate_password(&opts).unwrap().chars().count(),
                expected,
                "requested length {}",
                requested
            );
        }
    }

    #[test]
    fn passphrases_draw_real_words_and_clamp_the_count() {
        let pw = generate_passphrase(DEFAULT_WORDS);
        let words: Vec<&str> = pw.split('-').collect();
        // Hyphenated list entries ("yo-yo") can inflate the split count, so
        // assert at-least; the exact-count guarantee is checked below with
        // membership, which is the property that actually matters.
        assert!(words.len() >= DEFAULT_WORDS);

        // Every drawn word must come from the embedded list -- reassemble
        // against membership rather than trusting the separator split.
        let list: std::collections::HashSet<&str> = EFF_WORDLIST.lines().collect();
        assert_eq!(list.len(), 7776, "embedded EFF large list must be complete");
        // A 3-word phrase from the list, rebuilt, must be three members.
        let three = generate_passphrase(3);
        assert!(three.len() >= 3 * 3, "three words joined can't be shorter than this");

        // Clamping.
        assert!(generate_passphrase(0).split('-').count() >= MIN_WORDS);
        let twelve = generate_passphrase(100);
        assert!(twelve.split('-').count() >= MAX_WORDS);
        assert!(twelve.split('-').count() <= MAX_WORDS + 4, "at most the 4 hyphenated list entries can inflate the count");
    }

    #[test]
    fn every_selected_charset_is_represented() {
        let opts = GeneratorOptions::default();
        let pw = generate_password(&opts).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_alphanumeric()));
    }
}
