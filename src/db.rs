use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use crate::crypto::{self, KEY_LEN, SALT_LEN};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
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

// ─────────────────────────────────────────────
//  Vault salt sidecar file
//
//  Once vault.db is a SQLCipher-encrypted file, nothing in it -- including a
//  stored salt -- can be read before the key is already known. So the Argon2id
//  salt used to derive that key has to live outside the encrypted file. A salt
//  isn't secret, it only needs to not move, so this file needs no stronger
//  protection than restrictive permissions (matching vault.db's own 0600).
// ─────────────────────────────────────────────

fn salt_sidecar_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    p.set_file_name("vault.salt");
    p
}

fn read_salt_sidecar(db_path: &Path) -> Result<[u8; SALT_LEN], String> {
    let bytes = std::fs::read(salt_sidecar_path(db_path))
        .map_err(|e| format!("Could not read vault salt file: {}", e))?;
    let salt: [u8; SALT_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Vault salt file has an invalid length.".to_string())?;
    Ok(salt)
}

fn write_salt_sidecar(db_path: &Path, salt: &[u8; SALT_LEN]) -> Result<(), String> {
    let path = salt_sidecar_path(db_path);
    std::fs::write(&path, salt).map_err(|e| format!("Could not write vault salt file: {}", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Describes what, if anything, exists at `db_path` -- used to decide whether to
/// show the Setup screen, prompt for a legacy-vault migration, or do a normal
/// unlock. Deliberately does not open the database file itself: that would need
/// the key this is used to decide whether to even ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No vault.db and no salt sidecar -- brand new install.
    New,
    /// vault.db exists but predates SQLCipher (no salt sidecar) -- needs migration.
    NeedsMigration,
    /// Salt sidecar exists -- normal SQLCipher-encrypted vault, ready to unlock.
    Ready,
}

pub fn detect_vault_state(db_path: &Path) -> VaultState {
    if salt_sidecar_path(db_path).exists() {
        VaultState::Ready
    } else if db_path.exists() {
        VaultState::NeedsMigration
    } else {
        VaultState::New
    }
}

/// True if no vault has been created at `db_path` yet. Kept alongside
/// `detect_vault_state` for callers that only care about the new-vs-existing
/// distinction (e.g. the CLI's `init` command).
pub fn is_first_run(db_path: &Path) -> bool {
    detect_vault_state(db_path) == VaultState::New
}

/// Opens (creating the file if needed) a SQLite connection already keyed for
/// SQLCipher and configured for WAL mode. Does not create the schema. The
/// `SELECT ... FROM sqlite_master` probe is what actually proves the key is
/// correct (or that this is a brand new, still-empty file): SQLCipher only
/// validates the key lazily, on first real page read.
pub(crate) fn open_keyed_connection<P: AsRef<Path>>(
    path: P,
    sqlcipher_key: &[u8; KEY_LEN],
) -> Result<Connection, String> {
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    let pragma_hex = crypto::pragma_key_hex(sqlcipher_key);
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", *pragma_hex))
        .map_err(|e| e.to_string())?;

    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| "Incorrect master password, or the vault file is corrupted.".to_string())?;

    let _ = conn.execute("PRAGMA journal_mode=WAL", []);
    let _ = conn.execute("PRAGMA synchronous=NORMAL", []);

    Ok(conn)
}

/// Creates the schema if it doesn't already exist. Safe to call on every open
/// (not just vault creation) since every statement is idempotent -- this is also
/// how the historical `url` column backfill below gets applied to older vaults.
/// `pub(crate)` so test modules in other files can build a schema-ready
/// in-memory connection without needing a full vault on disk.
pub(crate) fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            username TEXT NOT NULL,
            url TEXT NOT NULL DEFAULT '',
            encrypted_password BLOB NOT NULL,
            encrypted_notes BLOB,
            updated_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS hibp_checks (
            password_hash TEXT PRIMARY KEY,
            hibp_count INTEGER
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS deleted_secrets (
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            username TEXT NOT NULL,
            deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
            PRIMARY KEY (title, category, username)
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_secrets_lookup ON secrets (title, category, username)",
        [],
    )
    .map_err(|e| e.to_string())?;

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

    Ok(())
}

/// Creates a brand new vault at `db_path`: generates a fresh salt (written to the
/// sidecar file only after everything else below succeeds, so a failure never
/// leaves an orphaned salt file with no matching vault), derives the master key
/// and the independent SQLCipher key from `master_password`, creates the
/// SQLCipher-encrypted database and schema, and stores an encrypted verification
/// token. Returns the open connection and the master key.
pub fn create_vault(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    if detect_vault_state(db_path) != VaultState::New {
        return Err("Vault is already initialized.".to_string());
    }

    let salt = crypto::generate_salt();
    let master_key = crypto::derive_key(master_password, &salt)?;
    let sqlcipher_key = crypto::derive_sqlcipher_key(&master_key);

    let conn = open_keyed_connection(db_path, &sqlcipher_key)?;
    ensure_schema(&conn)?;

    let encrypted_token = crypto::encrypt(b"keystash-verification-token", &master_key)?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
        params![encrypted_token],
    )
    .map_err(|e| e.to_string())?;

    write_salt_sidecar(db_path, &salt)?;

    Ok((conn, master_key))
}

/// Opens an existing (already-migrated) vault at `db_path`, deriving the key from
/// `master_password` and the salt sidecar file. `open_keyed_connection`'s
/// `sqlite_master` probe is the primary "is this the right password" check
/// (SQLCipher itself rejects a wrong key); the encrypted verification token is
/// kept as a secondary check purely for a consistent, friendly error message.
pub fn open_vault(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    let salt = read_salt_sidecar(db_path)?;
    let master_key = crypto::derive_key(master_password, &salt)?;
    let sqlcipher_key = crypto::derive_sqlcipher_key(&master_key);

    let conn = open_keyed_connection(db_path, &sqlcipher_key)
        .map_err(|_| "Incorrect master password.".to_string())?;
    ensure_schema(&conn)?;

    let encrypted_token: Vec<u8> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'verification'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "Verification token not found. Database might be corrupted.".to_string())?;

    match crypto::decrypt(&encrypted_token, &master_key) {
        Ok(decrypted) if *decrypted == *b"keystash-verification-token" => Ok((conn, master_key)),
        _ => Err("Incorrect master password.".to_string()),
    }
}

/// One-time migration of a pre-SQLCipher vault (plaintext schema/metadata, only
/// the `encrypted_password`/`encrypted_notes` columns encrypted) into the
/// SQLCipher whole-database format. A fresh salt is generated for the new vault
/// (also giving vaults still on the weaker legacy Argon2id parameters a chance
/// to move to the modern ones), so every field-level ciphertext has to be
/// decrypted with the old key and re-encrypted with the new one -- unlike
/// `change_master_password`'s in-place rekey, this can't reuse the ciphertexts
/// verbatim. The pre-migration file is kept as a backup rather than deleted.
pub fn migrate_legacy_vault(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    if detect_vault_state(db_path) != VaultState::NeedsMigration {
        return Err("No legacy vault found to migrate.".to_string());
    }

    // 1. Open the old (plain SQLite) database and verify the password against its
    //    existing salt/verification-token scheme, trying modern then legacy Argon2
    //    parameters exactly as the old unlock_vault() used to.
    let old_conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    let old_salt: Vec<u8> = old_conn
        .query_row("SELECT value FROM metadata WHERE key = 'salt'", [], |row| row.get(0))
        .map_err(|_| "This does not look like a legacy KeyStash vault (no salt found).".to_string())?;
    if old_salt.len() != SALT_LEN {
        return Err("Invalid salt length in legacy vault metadata.".to_string());
    }
    let old_encrypted_token: Vec<u8> = old_conn
        .query_row("SELECT value FROM metadata WHERE key = 'verification'", [], |row| row.get(0))
        .map_err(|_| "Verification token not found. Legacy database might be corrupted.".to_string())?;

    let modern_old_key = crypto::derive_key(master_password, &old_salt)?;
    let modern_ok = crypto::decrypt(&old_encrypted_token, &modern_old_key)
        .map(|d| *d == *b"keystash-verification-token")
        .unwrap_or(false);
    // The migration also generates a brand new salt (see step 3), so every
    // field-level ciphertext has to be decrypted with whichever old key just
    // proved correct and re-encrypted with the new one -- it can't be copied
    // verbatim the way it could if the master key were staying the same.
    let old_key = if modern_ok {
        modern_old_key
    } else {
        let legacy_old_key = crypto::derive_key_legacy(master_password, &old_salt)?;
        let legacy_ok = crypto::decrypt(&old_encrypted_token, &legacy_old_key)
            .map(|d| *d == *b"keystash-verification-token")
            .unwrap_or(false);
        if !legacy_ok {
            return Err("Incorrect master password.".to_string());
        }
        legacy_old_key
    };

    // 2. Read every row that needs to carry over.
    let secrets = get_secrets(&old_conn)?;
    let tombstones: Vec<(String, String, String, String)> = {
        let mut stmt = old_conn
            .prepare("SELECT title, category, username, deleted_at FROM deleted_secrets")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
    };
    let hibp_checks = get_all_hibp_checks(&old_conn)?;
    old_conn.close().map_err(|(_, e)| e.to_string())?;

    // 3. Create the new SQLCipher-encrypted vault at a temp path alongside the old
    //    file, using a freshly generated salt (the password itself is unchanged
    //    from the user's point of view -- only the salt/derivation is refreshed).
    let new_salt = crypto::generate_salt();
    let new_master_key = crypto::derive_key(master_password, &new_salt)?;
    let new_sqlcipher_key = crypto::derive_sqlcipher_key(&new_master_key);

    let tmp_path = db_path.with_file_name("vault.db.migrating");
    let _ = std::fs::remove_file(&tmp_path);
    let new_conn = open_keyed_connection(&tmp_path, &new_sqlcipher_key)?;
    ensure_schema(&new_conn)?;

    let new_encrypted_token = crypto::encrypt(b"keystash-verification-token", &new_master_key)?;
    new_conn
        .execute(
            "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
            params![new_encrypted_token],
        )
        .map_err(|e| e.to_string())?;

    for r in &secrets {
        let plaintext_pass = crypto::decrypt(&r.encrypted_password, &old_key)?;
        let re_encrypted_pass = crypto::encrypt(&plaintext_pass, &new_master_key)?;
        let re_encrypted_notes = match &r.encrypted_notes {
            Some(notes_blob) => {
                let plaintext_notes = crypto::decrypt(notes_blob, &old_key)?;
                Some(crypto::encrypt(&plaintext_notes, &new_master_key)?)
            }
            None => None,
        };
        new_conn
            .execute(
                "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![r.title, r.category, r.username, r.url, re_encrypted_pass, re_encrypted_notes, r.updated_at],
            )
            .map_err(|e| e.to_string())?;
    }
    for (title, category, username, deleted_at) in &tombstones {
        new_conn
            .execute(
                "INSERT OR REPLACE INTO deleted_secrets (title, category, username, deleted_at) VALUES (?1, ?2, ?3, ?4)",
                params![title, category, username, deleted_at],
            )
            .map_err(|e| e.to_string())?;
    }
    for (hash, count) in &hibp_checks {
        new_conn
            .execute(
                "INSERT OR REPLACE INTO hibp_checks (password_hash, hibp_count) VALUES (?1, ?2)",
                params![hash, count.map(|c| c as i64)],
            )
            .map_err(|e| e.to_string())?;
    }
    new_conn.close().map_err(|(_, e)| e.to_string())?;

    // 4. Back up the old file, then move the new one into place, then persist the
    //    new salt. Order matters: the salt sidecar is only written once the
    //    migrated file is already sitting at db_path.
    let backup_path = db_path.with_file_name("vault.db.pre-sqlcipher-backup");
    std::fs::rename(db_path, &backup_path).map_err(|e| format!("Failed to back up legacy vault: {}", e))?;
    std::fs::rename(&tmp_path, db_path).map_err(|e| format!("Failed to move migrated vault into place: {}", e))?;
    write_salt_sidecar(db_path, &new_salt)?;

    // 5. Re-open the now-migrated vault through the normal path, so callers get a
    //    connection exactly like any other successful unlock.
    open_vault(db_path, master_password)
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
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))",
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
         SET title = ?1, category = ?2, username = ?3, url = ?4, encrypted_password = ?5, encrypted_notes = ?6, updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')
         WHERE id = ?7",
        params![title, category, username, url, encrypted_password, encrypted_notes, id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Current time in the same format used for `updated_at` columns elsewhere.
/// Callers that must supply an explicit timestamp -- notably sync conflict
/// resolution, which needs its result to look unambiguously "newest" so the
/// ordinary last-write-wins merge (`sync::git_sync_vault`) doesn't immediately
/// clobber it again with whichever side's original timestamp was older -- use
/// this instead of copying local's or remote's pre-existing timestamp.
pub fn now_timestamp(conn: &Connection) -> Result<String, String> {
    conn.query_row("SELECT STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')", [], |row| row.get(0))
        .map_err(|e| e.to_string())
}

pub fn update_secret_raw(
    conn: &Connection,
    id: i64,
    url: &str,
    encrypted_password: &[u8],
    encrypted_notes: Option<&[u8]>,
    updated_at: &str,
) -> Result<(), String> {
    conn.execute(
        "UPDATE secrets 
         SET url = ?1, encrypted_password = ?2, encrypted_notes = ?3, updated_at = ?4
         WHERE id = ?5",
        rusqlite::params![url, encrypted_password, encrypted_notes, updated_at, id],
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

pub fn get_secret_by_id(conn: &Connection, id: i64) -> Result<Option<SecretRecord>, String> {
    conn.query_row(
        "SELECT id, title, category, username, url, encrypted_password, encrypted_notes, updated_at FROM secrets WHERE id = ?1",
        params![id],
        |row| Ok(SecretRecord {
            id: row.get(0)?,
            title: row.get(1)?,
            category: row.get(2)?,
            username: row.get(3)?,
            url: row.get(4)?,
            encrypted_password: row.get(5)?,
            encrypted_notes: row.get(6)?,
            updated_at: row.get(7)?,
        }),
    )
    .optional()
    .map_err(|e| e.to_string())
}

pub fn delete_secret(conn: &Connection, id: i64) -> Result<(), String> {
    // 1. Fetch details for tombstone
    let record: Option<(String, String, String)> = conn
        .query_row(
            "SELECT title, category, username FROM secrets WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    if let Some((title, category, username)) = record {
        // 2. Insert into deleted_secrets tombstone table
        conn.execute(
            "INSERT OR REPLACE INTO deleted_secrets (title, category, username, deleted_at)
             VALUES (?1, ?2, ?3, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))",
            params![title, category, username],
        )
        .map_err(|e| e.to_string())?;
    }

    // 3. Delete the actual secret
    conn.execute("DELETE FROM secrets WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Rotates the master password: re-derives a new salt/master key/SQLCipher key,
/// re-keys the SQLCipher layer itself (`PRAGMA rekey`), re-encrypts every
/// field-level secret, and replaces the salt sidecar file. All of the fallible,
/// data-dependent work (decrypting/re-encrypting every secret) happens first and
/// is fully validated in memory before either of the two irreversible steps
/// (`PRAGMA rekey` and writing the new salt sidecar) run, to keep the window
/// where a mid-operation failure could leave the vault inconsistent as small as
/// possible. `PRAGMA rekey` is a SQLCipher-internal operation and can't be
/// wrapped in the same explicit transaction as the subsequent metadata/secret
/// updates.
pub fn change_master_password(
    conn: &Connection,
    db_path: &Path,
    old_key: &[u8; KEY_LEN],
    new_password: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    // 1. Generate new salt and derive new master + SQLCipher keys
    let new_salt = crypto::generate_salt();
    let new_key = crypto::derive_key(new_password, &new_salt)?;
    let new_sqlcipher_key = crypto::derive_sqlcipher_key(&new_key);

    // 2. Fetch all secrets
    let secrets = get_secrets(conn)?;

    // 3. Decrypt and re-encrypt all secrets in memory first to verify success
    let mut re_encrypted_secrets = Vec::with_capacity(secrets.len());
    for r in &secrets {
        let plaintext_pass = crypto::decrypt(&r.encrypted_password, old_key)?;
        let encrypted_pass = crypto::encrypt(&plaintext_pass, &new_key)?;

        let encrypted_notes = match &r.encrypted_notes {
            Some(notes_blob) => {
                let plaintext_notes = crypto::decrypt(notes_blob, old_key)?;
                Some(crypto::encrypt(&plaintext_notes, &new_key)?)
            }
            None => None,
        };

        re_encrypted_secrets.push((r.id, encrypted_pass, encrypted_notes));
    }

    // 4. Encrypt verification token with the new key
    let new_verification = crypto::encrypt(b"keystash-verification-token", &new_key)?;

    // 5. Re-key the SQLCipher layer itself. This commits immediately and can't be
    //    rolled back, so it only runs once every crypto operation above has
    //    already succeeded.
    let pragma_hex = crypto::pragma_key_hex(&new_sqlcipher_key);
    conn.execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", *pragma_hex))
        .map_err(|e| format!("Failed to re-key vault: {}", e))?;

    // 6. Update SQLite records in a transaction
    conn.execute("BEGIN TRANSACTION", [])
        .map_err(|e| format!("Failed to start key rotation transaction: {}", e))?;

    // Update verification token
    if let Err(e) = conn.execute(
        "UPDATE metadata SET value = ?1 WHERE key = 'verification'",
        params![new_verification],
    ) {
        let _ = conn.execute("ROLLBACK", []);
        return Err(e.to_string());
    }

    // Update each secret
    for (id, enc_pass, enc_notes) in re_encrypted_secrets {
        if let Err(e) = conn.execute(
            "UPDATE secrets SET encrypted_password = ?1, encrypted_notes = ?2, updated_at = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW') WHERE id = ?3",
            params![enc_pass, enc_notes, id],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e.to_string());
        }
    }

    conn.execute("COMMIT", [])
        .map_err(|e| format!("Failed to commit key rotation: {}", e))?;

    // 7. Only persist the new salt sidecar once everything above has committed.
    write_salt_sidecar(db_path, &new_salt)?;

    Ok(new_key)
}

pub fn save_hibp_check(conn: &Connection, password_hash: &str, count: Option<u64>) -> Result<(), String> {
    let count_val = count.map(|c| c as i64);
    conn.execute(
        "INSERT OR REPLACE INTO hibp_checks (password_hash, hibp_count) VALUES (?1, ?2)",
        params![password_hash, count_val],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

pub fn get_all_hibp_checks(conn: &Connection) -> Result<std::collections::HashMap<String, Option<u64>>, String> {
    let mut stmt = conn.prepare("SELECT password_hash, hibp_count FROM hibp_checks")
        .map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        let hash: String = row.get(0)?;
        let count_val: Option<i64> = row.get(1)?;
        Ok((hash, count_val.map(|c| c as u64)))
    }).map_err(|e| e.to_string())?;

    let mut map = std::collections::HashMap::new();
    for row in rows {
        if let Ok((hash, count)) = row {
            map.insert(hash, count);
        }
    }
    Ok(map)
}

#[cfg(test)]
mod sqlcipher_tests {
    use super::*;

    // Each test gets its own directory (not just its own filename), since
    // `Path::with_file_name` is used throughout db.rs to find sidecar files
    // (vault.salt, vault.db-wal, the migration backup) alongside vault.db --
    // sharing a directory across tests would let them stomp on each other's
    // sidecar files when run concurrently (the default for `cargo test`).
    fn temp_db_path(name: &str) -> std::path::PathBuf {
        // Deliberately under target/, not the system temp dir: keeps test
        // fixtures inside the project tree instead of wherever `TMPDIR`/`/tmp`
        // happens to point, which is enough of a moving part across sandboxes
        // and CI runners to not be worth relying on here.
        let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("target");
        dir.push("sqlcipher-test-tmp");
        dir.push(format!("{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("failed to create test directory");
        dir.join("vault.db")
    }

    fn cleanup(db_path: &Path) {
        if let Some(dir) = db_path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn create_then_open_round_trip_and_wrong_password_rejected() {
        let db_path = temp_db_path("roundtrip");

        assert_eq!(detect_vault_state(&db_path), VaultState::New);

        let (conn, key) = create_vault(&db_path, "correct horse battery staple").expect("create_vault should succeed");
        add_secret(&conn, "GitHub", "Dev", "tobias", "https://github.com", "S3cretPW!", Some("hello notes"), &key)
            .expect("add_secret should succeed");
        drop(conn);

        assert_eq!(detect_vault_state(&db_path), VaultState::Ready);

        // Correct password opens the vault and decrypts the stored secret correctly.
        let (conn2, key2) = open_vault(&db_path, "correct horse battery staple").expect("open_vault with correct password should succeed");
        let secrets = get_secrets(&conn2).unwrap();
        assert_eq!(secrets.len(), 1);
        let decrypted = crypto::decrypt(&secrets[0].encrypted_password, &key2).unwrap();
        assert_eq!(&*decrypted, b"S3cretPW!");
        let notes = crypto::decrypt(secrets[0].encrypted_notes.as_ref().unwrap(), &key2).unwrap();
        assert_eq!(&*notes, b"hello notes");
        drop(conn2);

        // Wrong password must be rejected, not silently accepted.
        let wrong = open_vault(&db_path, "totally wrong password");
        assert!(wrong.is_err(), "open_vault with the wrong password must fail");

        cleanup(&db_path);
    }

    #[test]
    fn change_master_password_rekeys_and_rotates_field_encryption() {
        let db_path = temp_db_path("rekey");

        let (conn, old_key) = create_vault(&db_path, "old-password-123").unwrap();
        add_secret(&conn, "Site", "Cat", "user", "", "hunter2", None, &old_key).unwrap();

        let new_key = change_master_password(&conn, &db_path, &old_key, "new-password-456").unwrap();
        let secrets = get_secrets(&conn).unwrap();
        let decrypted = crypto::decrypt(&secrets[0].encrypted_password, &new_key).unwrap();
        assert_eq!(&*decrypted, b"hunter2");
        drop(conn);

        // Old password no longer opens the vault; SQLCipher itself was re-keyed.
        assert!(open_vault(&db_path, "old-password-123").is_err());
        // New password does.
        let (_conn3, key3) = open_vault(&db_path, "new-password-456").expect("new password should unlock after rotation");
        assert_eq!(&*key3, &*new_key);

        cleanup(&db_path);
    }

    #[test]
    fn migrate_legacy_vault_preserves_secrets_under_new_password_scheme() {
        let db_path = temp_db_path("migrate");

        // Build a legacy-format vault by hand: plain (unencrypted-schema) SQLite,
        // salt/verification stored in the metadata table, exactly like pre-SQLCipher
        // KeyStash produced.
        let legacy_conn = Connection::open(&db_path).unwrap();
        legacy_conn.execute_batch(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL,
                username TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', encrypted_password BLOB NOT NULL,
                encrypted_notes BLOB, updated_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')));
             CREATE TABLE deleted_secrets (title TEXT NOT NULL, category TEXT NOT NULL, username TEXT NOT NULL,
                deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), PRIMARY KEY (title, category, username));
             CREATE TABLE hibp_checks (password_hash TEXT PRIMARY KEY, hibp_count INTEGER);",
        ).unwrap();
        let legacy_salt = crypto::generate_salt();
        let legacy_key = crypto::derive_key("legacy-master-pw", &legacy_salt).unwrap();
        legacy_conn.execute("INSERT INTO metadata (key, value) VALUES ('salt', ?1)", params![legacy_salt.to_vec()]).unwrap();
        let token = crypto::encrypt(b"keystash-verification-token", &legacy_key).unwrap();
        legacy_conn.execute("INSERT INTO metadata (key, value) VALUES ('verification', ?1)", params![token]).unwrap();
        add_secret(&legacy_conn, "Old Site", "Legacy", "olduser", "", "legacy-pass", None, &legacy_key).unwrap();
        drop(legacy_conn);

        assert_eq!(detect_vault_state(&db_path), VaultState::NeedsMigration);

        let (conn, new_key) = migrate_legacy_vault(&db_path, "legacy-master-pw").expect("migration should succeed with the correct legacy password");
        assert_eq!(detect_vault_state(&db_path), VaultState::Ready);
        assert!(db_path.with_file_name("vault.db.pre-sqlcipher-backup").exists());

        let secrets = get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        let decrypted = crypto::decrypt(&secrets[0].encrypted_password, &new_key).unwrap();
        assert_eq!(&*decrypted, b"legacy-pass");
        drop(conn);

        // The migrated file is now SQLCipher-encrypted: file(1)-style magic-header
        // check should fail, i.e. it must not start with the plain SQLite header.
        let header = std::fs::read(&db_path).unwrap();
        assert_ne!(&header[..15.min(header.len())], b"SQLite format 3".as_slice());

        // And the same password re-opens it through the normal path afterwards.
        assert!(open_vault(&db_path, "legacy-master-pw").is_ok());

        let _ = std::fs::remove_file(db_path.with_file_name("vault.db.pre-sqlcipher-backup"));
        cleanup(&db_path);
    }
}

