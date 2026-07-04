use rusqlite::{params, Connection, Result};
use std::path::Path;
use crate::crypto::{self, KEY_LEN, SALT_LEN};

#[derive(Clone)]
pub struct SecretRecord {
    pub id: i64,
    pub title: String,
    pub category: String,
    pub username: String,
    pub url: String,
    pub encrypted_password: Vec<u8>,
    pub encrypted_notes: Option<Vec<u8>>,
    pub updated_at: String,
}

pub fn init_db<P: AsRef<Path>>(path: P) -> Result<Connection> {
    let conn = Connection::open(path)?;
    
    // Create metadata table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )?;

    // Create secrets table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            username TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            encrypted_password BLOB NOT NULL,
            encrypted_notes BLOB,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Migration: Add 'url' column if database existed before this field was added
    let has_url: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'url'",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        )
        .unwrap_or(false);

    if !has_url {
        let _ = conn.execute("ALTER TABLE secrets ADD COLUMN url TEXT NOT NULL DEFAULT ''", []);
    }

    Ok(conn)
}

pub fn is_first_run(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM metadata WHERE key = 'salt'")?;
    let count: i64 = stmt.query_row([], |row| row.get(0))?;
    Ok(count == 0)
}

/// Sets up the vault for the first time by generating a salt and saving the verification token.
pub fn setup_vault(conn: &Connection, master_password: &str) -> Result<[u8; KEY_LEN], String> {
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(master_password, &salt)?;

    // Store salt
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('salt', ?1)",
        params![salt.to_vec()],
    )
    .map_err(|e| e.to_string())?;

    // Create a verification token by encrypting a known phrase
    let verification_phrase = b"keystash-verification-token";
    let encrypted_token = crypto::encrypt(verification_phrase, &key)?;

    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
        params![encrypted_token],
    )
    .map_err(|e| e.to_string())?;

    Ok(key)
}

/// Attempts to unlock the vault. Returns the derived key if successful, or an error message.
pub fn unlock_vault(conn: &Connection, master_password: &str) -> Result<[u8; KEY_LEN], String> {
    // Get salt
    let salt: Vec<u8> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'salt'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "Vault salt not found. Database might be corrupted.".to_string())?;

    if salt.len() != SALT_LEN {
        return Err("Invalid salt length in metadata.".to_string());
    }

    let key = crypto::derive_key(master_password, &salt)?;

    // Get validation token
    let encrypted_token: Vec<u8> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'verification'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "Verification token not found. Database might be corrupted.".to_string())?;

    // Decrypt and check validation token
    let decrypted = crypto::decrypt(&encrypted_token, &key)
        .map_err(|_| "Incorrect master password.".to_string())?;

    if decrypted == b"keystash-verification-token" {
        Ok(key)
    } else {
        Err("Incorrect master password.".to_string())
    }
}

pub fn add_secret(
    conn: &Connection,
    title: &str,
    category: &str,
    username: &str,
    url: &str,
    plaintext_password: &str,
    plaintext_notes: Option<&str>,
    key: &[u8; KEY_LEN],
) -> Result<(), String> {
    let encrypted_password = crypto::encrypt(plaintext_password.as_bytes(), key)?;
    let encrypted_notes = match plaintext_notes {
        Some(notes) if !notes.is_empty() => Some(crypto::encrypt(notes.as_bytes(), key)?),
        _ => None,
    };

    conn.execute(
        "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)",
        params![title, category, username, url, encrypted_password, encrypted_notes],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

pub fn update_secret(
    conn: &Connection,
    id: i64,
    title: &str,
    category: &str,
    username: &str,
    url: &str,
    plaintext_password: &str,
    plaintext_notes: Option<&str>,
    key: &[u8; KEY_LEN],
) -> Result<(), String> {
    let encrypted_password = crypto::encrypt(plaintext_password.as_bytes(), key)?;
    let encrypted_notes = match plaintext_notes {
        Some(notes) if !notes.is_empty() => Some(crypto::encrypt(notes.as_bytes(), key)?),
        _ => None,
    };

    conn.execute(
        "UPDATE secrets 
         SET title = ?1, category = ?2, username = ?3, url = ?4, encrypted_password = ?5, encrypted_notes = ?6, updated_at = CURRENT_TIMESTAMP
         WHERE id = ?7",
        params![title, category, username, url, encrypted_password, encrypted_notes, id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

pub fn get_secrets(conn: &Connection) -> Result<Vec<SecretRecord>, String> {
    let mut stmt = conn
        .prepare("SELECT id, title, category, username, url, encrypted_password, encrypted_notes, updated_at FROM secrets ORDER BY title ASC")
        .map_err(|e| e.to_string())?;
    
    let secret_iter = stmt
        .query_map([], |row| {
            Ok(SecretRecord {
                id: row.get(0)?,
                title: row.get(1)?,
                category: row.get(2)?,
                username: row.get(3)?,
                url: row.get(4)?,
                encrypted_password: row.get(5)?,
                encrypted_notes: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut secrets = Vec::new();
    for secret in secret_iter {
        secrets.push(secret.map_err(|e| e.to_string())?);
    }
    Ok(secrets)
}

pub fn delete_secret(conn: &Connection, id: i64) -> Result<(), String> {
    conn.execute("DELETE FROM secrets WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}
