use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use crate::crypto::{self, KEY_LEN, SALT_LEN};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────
//  Minimum compatible app version
//
//  Stored in the vault itself (`metadata` table) so an older KeyStash binary
//  can tell it's too old to safely open a given vault, instead of failing
//  with a raw, confusing SQL/schema error partway through. This is a *floor*,
//  not a timestamp of "whatever version last wrote this file" -- most
//  releases don't touch it at all. It only moves when a change genuinely
//  cannot be read safely by older code. Notably, the sync_uuid column (H2)
//  deliberately does *not* bump this: old code's explicit column-list queries
//  just ignore the extra column, so it stays fully readable without a floor
//  bump (that transition has its own narrower, dedicated compatibility check
//  in `sync.rs` instead). The last change that actually broke old readers
//  outright was the move to whole-database SQLCipher encryption -- a
//  pre-0.3.0 binary can't read a 0.3.0+ vault at all, not even its metadata,
//  since the entire file is opaque ciphertext to it from byte one.
//
//  0.3.6 moved the Argon2 salt from the `vault.salt` sidecar file into the
//  SQLCipher header (the first 16 bytes of vault.db) and stopped syncing the
//  sidecar. A pre-0.3.6 binary can only derive the key from the sidecar; when
//  a vault has been converted, that file no longer exists, so old code
//  misdiagnoses the vault as a legacy pre-encryption file and fails to open
//  it -- genuinely unreadable, hence the floor bump.
// ─────────────────────────────────────────────

pub const MIN_COMPATIBLE_APP_VERSION: &str = "0.3.6";

/// Parses a plain `MAJOR.MINOR.PATCH` version string (KeyStash doesn't use
/// pre-release/build suffixes) into a comparable tuple. `None` on anything
/// that doesn't fit that shape.
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// True if `running_version` is new enough to satisfy `required_version`.
/// Treats unparseable input as satisfied rather than blocking access: this
/// check exists to give a friendlier error than a raw SQL failure, not to act
/// as a security boundary, and a corrupt/unexpected value here shouldn't be
/// able to lock someone out of their own vault.
pub fn version_satisfies(running_version: &str, required_version: &str) -> bool {
    match (parse_version(running_version), parse_version(required_version)) {
        (Some(running), Some(required)) => running >= required,
        _ => true,
    }
}

/// Reads the vault's stored minimum-compatible-version, if any. Vaults
/// created before this feature existed simply have no row -- treated as "no
/// floor recorded", not as a compatibility failure.
pub(crate) fn read_min_app_version(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key = 'min_app_version'",
        [],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

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
    /// Stable identity used for sync/merge, independent of (title, category,
    /// username) -- see `new_uuid`.
    pub sync_uuid: String,
}

/// Generates a random v4 UUID used as a record's stable sync/merge identity.
/// Not derived from any secret and not itself sensitive -- it exists purely
/// so `sync.rs`'s merge logic and tombstones have something unique to key on,
/// instead of the (title, category, username) triple, which two distinct
/// records can share (e.g. two blank-username entries for the same site).
/// Uniqueness, not unpredictability, is what matters here, but `rand`'s
/// thread-local CSPRNG is what's already used elsewhere in this codebase
/// (`generator.rs`) so there's no reason to reach for anything weaker.
pub fn new_uuid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

// ─────────────────────────────────────────────
//  Vault salt storage
//
//  Once vault.db is a SQLCipher-encrypted file, nothing in it -- including a
//  stored salt -- can be read before the key is already known. So the Argon2id
//  salt used to derive that key has to live somewhere readable up front. A
//  SQLCipher file conveniently already has such a slot: its first 16 bytes
//  are the (deliberately plaintext) salt SQLCipher itself stores in the file
//  header. Since KeyStash supplies SQLCipher a raw key (`PRAGMA key =
//  "x'...'"`), that header salt is not used for page-key derivation, only
//  HMAC-key derivation -- so it's free to double as the Argon2id salt,
//  stamped in at creation via `PRAGMA cipher_salt`. That makes vault.db fully
//  self-contained: one file to sync, and the first 16 bytes of any copy of it
//  identify which salt (and therefore which master-password generation) that
//  copy was encrypted under -- which is what sync.rs's rotation check reads.
//
//  Vaults created before 0.3.6 kept the salt in a `vault.salt` sidecar file
//  instead (with a random, unrelated SQLCipher header salt). `open_vault`
//  converts those once on unlock; the sidecar paths below survive only for
//  that migration and for restoring not-yet-converted repos.
// ─────────────────────────────────────────────

/// Path of the temp file `migrate_legacy_vault` builds the new SQLCipher-encrypted
/// vault in before atomically moving it into place at `db_path`.
fn migrating_tmp_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    p.set_file_name("vault.db.migrating");
    p
}

/// Path `migrate_legacy_vault` renames the pre-migration legacy vault to, rather
/// than deleting it, before moving the new file into place at `db_path`.
fn pre_sqlcipher_backup_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    p.set_file_name("vault.db.pre-sqlcipher-backup");
    p
}

/// Path `change_master_password` builds the freshly re-keyed vault in before
/// atomically moving it into place at `db_path`.
fn rekeying_tmp_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    p.set_file_name("vault.db.rekeying");
    p
}

/// Path `change_master_password` renames the pre-rotation vault to, before
/// moving the new file into place at `db_path`. Deleted once the new vault is
/// confirmed to open successfully.
fn pre_rekey_backup_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    p.set_file_name("vault.db.pre-rekey-backup");
    p
}

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

/// The 16-byte magic header of a plain (unencrypted) SQLite file. Exactly
/// SALT_LEN bytes, which is what makes the first-16-bytes read below able to
/// distinguish a legacy plaintext vault from an SQLCipher one. `pub(crate)`
/// because sync.rs makes the same distinction on fetched remote copies.
pub(crate) const SQLITE_PLAINTEXT_MAGIC: &[u8; SALT_LEN] = b"SQLite format 3\0";

/// Reads the first 16 bytes of the vault file -- the SQLCipher header salt,
/// which for vaults on the 0.3.6+ format is also the Argon2id salt.
fn read_embedded_salt(db_path: &Path) -> Result<[u8; SALT_LEN], String> {
    use std::io::Read;
    let mut file = std::fs::File::open(db_path)
        .map_err(|e| format!("Could not read vault file: {}", e))?;
    let mut salt = [0u8; SALT_LEN];
    file.read_exact(&mut salt)
        .map_err(|e| format!("Vault file is too short to contain a salt header: {}", e))?;
    if &salt == SQLITE_PLAINTEXT_MAGIC {
        return Err("This vault predates full-database encryption and must be migrated first.".to_string());
    }
    Ok(salt)
}

/// Confirms a freshly built vault file actually carries `expected` as its
/// header salt. `PRAGMA cipher_salt` is how the salt gets stamped in, and an
/// unknown pragma is silently ignored by SQLite rather than erroring -- if
/// the bundled SQLCipher ever lost support for it, every new vault would be
/// created with a random header salt and become unopenable on the next
/// unlock. This check turns that silent failure mode into a loud one before
/// any file is swapped into place.
fn verify_embedded_salt(path: &Path, expected: &[u8; SALT_LEN]) -> Result<(), String> {
    let actual = read_embedded_salt(path)?;
    if &actual != expected {
        return Err(
            "The vault file was not created with the expected salt header (PRAGMA cipher_salt \
             appears to be unsupported by this SQLCipher build)."
                .to_string(),
        );
    }
    Ok(())
}

/// Describes what, if anything, exists at `db_path` -- used to decide whether to
/// show the Setup screen, prompt for a legacy-vault migration, or do a normal
/// unlock. Deliberately does not open the database file itself: that would need
/// the key this is used to decide whether to even ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No vault.db and no leftover migration/rotation files -- brand new install.
    New,
    /// vault.db exists but starts with the plain-SQLite magic header: it
    /// predates full-database encryption and needs migration.
    NeedsMigration,
    /// vault.db exists and is SQLCipher-encrypted -- ready to unlock. (Whether
    /// its Argon2 salt is embedded in the header or still in a `vault.salt`
    /// sidecar is `open_vault`'s concern, not a separate state.)
    Ready,
    /// A previous `migrate_legacy_vault` run was interrupted (crash, power loss,
    /// OOM kill) with the vault left in a not-completed shape: either vault.db
    /// is missing entirely (crash between the two swap renames), or it's still
    /// the plaintext legacy file with a `vault.db.migrating` temp and/or
    /// `vault.db.pre-sqlcipher-backup` alongside. Either way there's real data
    /// recoverable on disk, so this must be surfaced before the
    /// `NeedsMigration`/`New` fallthrough -- otherwise the app would invite the
    /// user to `init` a fresh empty vault right over their recoverable data.
    InterruptedMigration,
    /// A previous `change_master_password` run was interrupted between backing
    /// up the pre-rotation file and swapping the new one in, leaving no
    /// vault.db at all -- detected via the leftover `vault.db.rekeying` temp
    /// file and/or `vault.db.pre-rekey-backup`. Same recovery shape as
    /// `InterruptedMigration`. A crash *after* the swap is not this state
    /// anymore: with the salt embedded in the new file itself, the swapped-in
    /// vault is already complete and simply reports `Ready` (the stale backup
    /// gets overwritten by the next rotation).
    InterruptedRotation,
}

pub fn detect_vault_state(db_path: &Path) -> VaultState {
    if db_path.exists() {
        // The first 16 bytes distinguish the two on-disk formats: a legacy
        // plaintext vault starts with SQLite's magic header, an
        // SQLCipher-encrypted one with its (public, random-looking) salt. An
        // unreadable or too-short file is treated as encrypted so the unlock
        // path surfaces the real I/O or corruption error, rather than
        // misrouting the user into a legacy migration.
        let is_plaintext = {
            use std::io::Read;
            let mut head = [0u8; SALT_LEN];
            std::fs::File::open(db_path)
                .and_then(|mut f| f.read_exact(&mut head))
                .is_ok()
                && &head == SQLITE_PLAINTEXT_MAGIC
        };
        if is_plaintext {
            if migrating_tmp_path(db_path).exists() || pre_sqlcipher_backup_path(db_path).exists() {
                VaultState::InterruptedMigration
            } else {
                VaultState::NeedsMigration
            }
        } else {
            VaultState::Ready
        }
    } else if migrating_tmp_path(db_path).exists() || pre_sqlcipher_backup_path(db_path).exists() {
        VaultState::InterruptedMigration
    } else if rekeying_tmp_path(db_path).exists() || pre_rekey_backup_path(db_path).exists() {
        VaultState::InterruptedRotation
    } else {
        VaultState::New
    }
}

/// Recovery instructions shown by both the CLI and TUI when `detect_vault_state`
/// reports `InterruptedMigration`. Nothing is destroyed in this state -- the
/// pre-migration backup (and/or a partially-built new-format copy) is still on
/// disk -- but the app can't tell that automatically from just "no vault.db",
/// so it surfaces the exact recovery command instead of silently falling
/// through to "no vault found".
pub fn interrupted_migration_message(db_path: &Path) -> String {
    format!(
        "A previous migration to the encrypted database format was interrupted \
(e.g. a crash or power loss) and left the vault in an inconsistent state. \
Nothing was lost -- your data is still on disk and recoverable:\n\n\
1. Restore the pre-migration backup:\n   mv {:?} {:?}\n\
2. Then run keystash again to retry the migration.\n\n\
(If present, {:?} is a partially-built copy from the interrupted attempt and \
can be safely deleted.)",
        pre_sqlcipher_backup_path(db_path),
        db_path,
        migrating_tmp_path(db_path),
    )
}

/// Recovery instructions shown by both the CLI and TUI when `detect_vault_state`
/// reports `InterruptedRotation`. Same reasoning as `interrupted_migration_message`.
pub fn interrupted_rotation_message(db_path: &Path) -> String {
    format!(
        "A previous master password change was interrupted \
(e.g. a crash or power loss) and left the vault in an inconsistent state. \
Nothing was lost -- your data is still on disk and recoverable:\n\n\
1. Restore the pre-rotation backup:\n   mv {:?} {:?}\n\
2. Then run keystash again and retry the password change.\n\n\
(If present, {:?} is a partially-built copy from the interrupted attempt and \
can be safely deleted.)",
        pre_rekey_backup_path(db_path),
        db_path,
        rekeying_tmp_path(db_path),
    )
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
    open_keyed_connection_impl(path, sqlcipher_key, None)
}

/// `open_keyed_connection` for *brand new* vault files: additionally stamps
/// `salt` into the SQLCipher header via `PRAGMA cipher_salt`, making the
/// file's first 16 bytes the Argon2id salt (see the "Vault salt storage"
/// comment above). Only meaningful at creation -- an existing file's header
/// salt is fixed, so every caller pairs this with a fresh temp path. Callers
/// must `verify_embedded_salt` the finished file before trusting it.
fn open_keyed_connection_with_salt<P: AsRef<Path>>(
    path: P,
    sqlcipher_key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<Connection, String> {
    open_keyed_connection_impl(path, sqlcipher_key, Some(salt))
}

fn open_keyed_connection_impl<P: AsRef<Path>>(
    path: P,
    sqlcipher_key: &[u8; KEY_LEN],
    creation_salt: Option<&[u8; SALT_LEN]>,
) -> Result<Connection, String> {
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    let pragma_hex = crypto::pragma_key_hex(sqlcipher_key);
    // pragma_key_hex already returns a Zeroizing<String> for exactly this
    // reason -- build the SQL statement itself as one too instead of
    // letting format! hand back a plain String that drops unwiped.
    let pragma_sql: Zeroizing<String> = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", *pragma_hex));
    conn.execute_batch(&pragma_sql)
        .map_err(|e| e.to_string())?;

    if let Some(salt) = creation_salt {
        // Must run after PRAGMA key (it configures the same codec context)
        // and before the first write materializes the file header.
        let salt_hex: String = salt.iter().map(|b| format!("{:02x}", b)).collect();
        conn.execute_batch(&format!("PRAGMA cipher_salt = \"x'{}'\";", salt_hex))
            .map_err(|e| e.to_string())?;
    }

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
            updated_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
            sync_uuid TEXT
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

    // Deliberately no PRIMARY KEY on the (title, category, username) triple:
    // sync_uuid is the identity merge steps actually match tombstones on (see
    // H2), and several distinct records can legitimately share a triple -- the
    // exact case the dedup screen exists to find. Under the old triple PK,
    // deleting N >= 3 such duplicates collapsed the N-1 tombstones into one
    // PK slot via INSERT OR REPLACE, so the lost deletions never propagated
    // and the deleted records resurrected on other devices. Uniqueness lives
    // in idx_deleted_secrets_sync_uuid below instead; NULL sync_uuids (legacy
    // tombstones) are distinct under a UNIQUE index, so they coexist without
    // colliding and stay inert for uuid-based merge matching as before.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS deleted_secrets (
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            username TEXT NOT NULL,
            deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
            sync_uuid TEXT
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

    // Migration: add 'sync_uuid' -- a stable per-record identity for sync/merge
    // that isn't the user-editable (and not-actually-unique) title/category/
    // username triple every merge step and tombstone used to key on. See H2 in
    // the fix roadmap: two records legitimately sharing that triple (the exact
    // case the dedup screen exists to find) made scalar-subquery merge steps
    // pick an arbitrary row, and could conflate or drop the wrong one entirely.
    let has_sync_uuid: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'sync_uuid'",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        )
        .unwrap_or(false);

    if !has_sync_uuid {
        conn.execute("ALTER TABLE secrets ADD COLUMN sync_uuid TEXT", [])
            .map_err(|e| e.to_string())?;

        let ids: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT id FROM secrets WHERE sync_uuid IS NULL")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, i64>(0))
                .map_err(|e| e.to_string())?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
        };
        for id in ids {
            conn.execute(
                "UPDATE secrets SET sync_uuid = ?1 WHERE id = ?2",
                params![new_uuid(), id],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    // Enforced regardless of whether the column was just added or already
    // existed, same as the ALTER above being safe to re-run every open.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_sync_uuid ON secrets(sync_uuid)",
        [],
    )
    .map_err(|e| e.to_string())?;

    let has_tombstone_uuid: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('deleted_secrets') WHERE name = 'sync_uuid'",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        )
        .unwrap_or(false);
    if !has_tombstone_uuid {
        // Old tombstones predate sync_uuid entirely and there's no way to
        // recover which record they originally referred to -- they're left
        // NULL and simply become inert for merge-matching purposes (a NULL
        // sync_uuid never matches a real record's non-null one), rather than
        // risk mismatching them against an unrelated record that happens to
        // share the old title/category/username triple.
        let _ = conn.execute("ALTER TABLE deleted_secrets ADD COLUMN sync_uuid TEXT", []);
    }

    // Migration: rebuild a deleted_secrets table still carrying the old
    // (title, category, username) composite PRIMARY KEY into the PK-less
    // shape created above -- see the comment on that CREATE TABLE for why
    // the triple PK destroyed tombstones. Runs after the ALTER above so the
    // copy always has a sync_uuid column to read. The rare legacy edge of
    // two rows sharing a non-NULL sync_uuid (a record renamed between
    // delete/restore cycles, so same uuid under two triples) is collapsed
    // to the newest tombstone per uuid, since the UNIQUE index below could
    // not be created over both.
    let tombstones_keyed_on_triple: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('deleted_secrets') WHERE pk > 0",
            [],
            |row| {
                let count: i64 = row.get(0)?;
                Ok(count > 0)
            },
        )
        .unwrap_or(false);
    if tombstones_keyed_on_triple {
        conn.execute_batch(
            "BEGIN;
             CREATE TABLE deleted_secrets_rebuilt (
                 title TEXT NOT NULL,
                 category TEXT NOT NULL,
                 username TEXT NOT NULL,
                 deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
                 sync_uuid TEXT
             );
             INSERT INTO deleted_secrets_rebuilt (title, category, username, deleted_at, sync_uuid)
                 SELECT title, category, username, MAX(deleted_at), sync_uuid
                 FROM deleted_secrets WHERE sync_uuid IS NOT NULL GROUP BY sync_uuid;
             INSERT INTO deleted_secrets_rebuilt (title, category, username, deleted_at, sync_uuid)
                 SELECT title, category, username, deleted_at, NULL
                 FROM deleted_secrets WHERE sync_uuid IS NULL;
             DROP TABLE deleted_secrets;
             ALTER TABLE deleted_secrets_rebuilt RENAME TO deleted_secrets;
             COMMIT;",
        )
        .map_err(|e| e.to_string())?;
    }
    // Enforced regardless of whether the table was just created, just
    // rebuilt, or already in the new shape -- same as the secrets index
    // above being safe to re-run every open. INSERT OR REPLACE at the
    // delete/merge call sites keys on this.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_deleted_secrets_sync_uuid ON deleted_secrets(sync_uuid)",
        [],
    )
    .map_err(|e| e.to_string())?;

    // Stamp the current compatibility floor, raising a lower one if present.
    // Raising is correct (and necessary) because opening a vault with this
    // binary converts it to this binary's format on the spot -- e.g. 0.3.6
    // embeds the salt and stops syncing the sidecar, after which a pre-0.3.6
    // device could no longer derive the key and must be refused with a clear
    // message rather than left to misread the repo. A *higher* recorded
    // floor (written by a newer version) is never lowered; this call only
    // runs after `open_vault`'s own pre-check already confirmed the running
    // binary satisfies whatever floor is currently on file.
    match read_min_app_version(conn) {
        None => {
            let _ = conn.execute(
                "INSERT INTO metadata (key, value) VALUES ('min_app_version', ?1)",
                params![MIN_COMPATIBLE_APP_VERSION],
            );
        }
        Some(stored) if !version_satisfies(&stored, MIN_COMPATIBLE_APP_VERSION) => {
            let _ = conn.execute(
                "UPDATE metadata SET value = ?1 WHERE key = 'min_app_version'",
                params![MIN_COMPATIBLE_APP_VERSION],
            );
        }
        Some(_) => {}
    }

    Ok(())
}

/// Creates a brand new vault at `db_path`: generates a fresh salt (embedded
/// into the SQLCipher file header, so the vault is a single self-contained
/// file), derives the master key and the independent SQLCipher key from
/// `master_password`, creates the SQLCipher-encrypted database and schema,
/// and stores an encrypted verification token. Returns the open connection
/// and the master key.
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

    let conn = open_keyed_connection_with_salt(db_path, &sqlcipher_key, &salt)?;
    ensure_schema(&conn)?;

    let encrypted_token = crypto::encrypt(b"keystash-verification-token", &master_key)?;
    conn.execute(
        "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
        params![encrypted_token],
    )
    .map_err(|e| e.to_string())?;

    // In WAL mode everything written so far -- including the header page
    // carrying the salt -- may still be sitting in vault.db-wal. Checkpoint
    // so the main file is complete, then confirm the salt actually landed
    // (see verify_embedded_salt for why this can't be assumed).
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| e.to_string())?;
    if let Err(e) = verify_embedded_salt(db_path, &salt) {
        // A half-created vault with a wrong header salt must not be left
        // behind: it would detect as Ready and then never unlock.
        drop(conn);
        for p in [
            db_path.to_path_buf(),
            db_path.with_file_name("vault.db-wal"),
            db_path.with_file_name("vault.db-shm"),
        ] {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }

    Ok((conn, master_key))
}

/// Opens an existing (already-migrated) vault at `db_path`, deriving the key
/// from `master_password` and the salt embedded in the file header.
/// `open_keyed_connection`'s `sqlite_master` probe is the primary "is this
/// the right password" check (SQLCipher itself rejects a wrong key); the
/// encrypted verification token is kept as a secondary check purely for a
/// consistent, friendly error message.
///
/// A vault still on the pre-0.3.6 layout (salt in a `vault.salt` sidecar,
/// random header salt) is converted once, here, on its first successful
/// unlock -- see `embed_sidecar_salt`.
pub fn open_vault(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    if salt_sidecar_path(db_path).exists() {
        return embed_sidecar_salt(db_path, master_password);
    }
    open_vault_embedded(db_path, master_password)
}

/// The normal unlock path for vaults whose salt lives in the file header.
/// Kept separate from `open_vault` so `embed_sidecar_salt` can verify its
/// freshly converted file *before* deleting the sidecar -- calling
/// `open_vault` at that point would route straight back into the migration.
fn open_vault_embedded(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    let salt = read_embedded_salt(db_path)?;
    let master_key = crypto::derive_key(master_password, &salt)?;
    let sqlcipher_key = crypto::derive_sqlcipher_key(&master_key);

    let conn = open_keyed_connection(db_path, &sqlcipher_key)
        .map_err(|_| "Incorrect master password.".to_string())?;

    // Checked before ensure_schema runs any migration logic against this
    // vault: if it was last written by a version whose format this binary
    // predates, we shouldn't be altering its schema at all, let alone trying
    // to operate on it further.
    if let Some(required) = read_min_app_version(&conn)
        && !version_satisfies(env!("CARGO_PKG_VERSION"), &required)
    {
        return Err(format!(
            "This vault requires KeyStash v{} or newer to open. You are running v{}. Please update KeyStash and try again.",
            required,
            env!("CARGO_PKG_VERSION"),
        ));
    }

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

/// One-time conversion of a pre-0.3.6 vault (salt in the `vault.salt`
/// sidecar, random SQLCipher header salt) to the self-contained layout: the
/// vault is rebuilt at a temp path with the *same* salt -- so the same master
/// key, meaning every ciphertext copies over verbatim, no re-encryption --
/// but this time stamped into the header via `PRAGMA cipher_salt`, then
/// atomically swapped into place. Only after the new file is verified to
/// open are the sidecar and the backup deleted; a failure at any earlier
/// point leaves the original file and sidecar untouched.
///
/// Reuses `change_master_password`'s temp/backup paths: an interruption
/// mid-swap is detected as `VaultState::InterruptedRotation`, whose recovery
/// (restore the backup, retry) applies here identically -- the sidecar is
/// still on disk in that state, so the restored backup unlocks as before.
fn embed_sidecar_salt(
    db_path: &Path,
    master_password: &str,
) -> Result<(Connection, Zeroizing<[u8; KEY_LEN]>), String> {
    // 1. Unlock exactly like the old sidecar-era open_vault did.
    let salt = read_salt_sidecar(db_path)?;
    let master_key = crypto::derive_key(master_password, &salt)?;
    let sqlcipher_key = crypto::derive_sqlcipher_key(&master_key);

    let conn = open_keyed_connection(db_path, &sqlcipher_key)
        .map_err(|_| "Incorrect master password.".to_string())?;

    if let Some(required) = read_min_app_version(&conn)
        && !version_satisfies(env!("CARGO_PKG_VERSION"), &required)
    {
        return Err(format!(
            "This vault requires KeyStash v{} or newer to open. You are running v{}. Please update KeyStash and try again.",
            required,
            env!("CARGO_PKG_VERSION"),
        ));
    }

    ensure_schema(&conn)?;

    let encrypted_token: Vec<u8> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'verification'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "Verification token not found. Database might be corrupted.".to_string())?;
    match crypto::decrypt(&encrypted_token, &master_key) {
        Ok(decrypted) if *decrypted == *b"keystash-verification-token" => {}
        _ => return Err("Incorrect master password.".to_string()),
    }

    // 2. Read everything that carries over. All of it copies verbatim: the
    //    salt (and therefore the master key) is unchanged, only where the
    //    salt is stored changes.
    let secrets = get_secrets(&conn)?;
    let tombstones: Vec<(String, String, String, Option<String>, String)> = {
        let mut stmt = conn
            .prepare("SELECT title, category, username, sync_uuid, deleted_at FROM deleted_secrets")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
    };
    let hibp_checks = get_all_hibp_checks(&conn)?;

    // 3. Build the replacement at a temp path with the salt in its header.
    let tmp_path = rekeying_tmp_path(db_path);
    let _ = std::fs::remove_file(&tmp_path);
    let new_conn = open_keyed_connection_with_salt(&tmp_path, &sqlcipher_key, &salt)?;
    ensure_schema(&new_conn)?;

    new_conn
        .execute(
            "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
            params![encrypted_token],
        )
        .map_err(|e| e.to_string())?;
    for r in &secrets {
        // updated_at and sync_uuid are preserved exactly -- this rebuild is
        // invisible to the sync merge logic, which must not see every record
        // as freshly edited.
        new_conn
            .execute(
                "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![r.title, r.category, r.username, r.url, r.encrypted_password, r.encrypted_notes, r.updated_at, r.sync_uuid],
            )
            .map_err(|e| e.to_string())?;
    }
    for (title, category, username, sync_uuid, deleted_at) in &tombstones {
        new_conn
            .execute(
                "INSERT OR REPLACE INTO deleted_secrets (title, category, username, sync_uuid, deleted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![title, category, username, sync_uuid, deleted_at],
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
    // Same WAL discipline as change_master_password: force everything into
    // the main file, since only tmp_path itself gets renamed below.
    new_conn
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|e| e.to_string())?;
    new_conn.close().map_err(|(_, e)| e.to_string())?;

    // The header salt must actually be ours before we swap anything -- see
    // verify_embedded_salt. Failing here leaves the live vault untouched.
    if let Err(e) = verify_embedded_salt(&tmp_path, &salt) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // 4. Empty our own WAL sidecars in place before the rename, for the same
    //    stale-WAL-mistaken-for-the-new-file's reason documented in
    //    change_master_password.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| format!("Failed to checkpoint vault before salt conversion: {}", e))?;
    drop(conn);

    // 5. Swap, verify the new file opens on its own (deliberately *not*
    //    open_vault -- the sidecar still exists and must be ignored), and
    //    only then delete the sidecar and the backup.
    let backup_path = pre_rekey_backup_path(db_path);
    std::fs::rename(db_path, &backup_path).map_err(|e| format!("Failed to back up vault before salt conversion: {}", e))?;
    std::fs::rename(&tmp_path, db_path).map_err(|e| format!("Failed to move converted vault into place: {}", e))?;

    match open_vault_embedded(db_path, master_password) {
        Ok(pair) => {
            let _ = std::fs::remove_file(salt_sidecar_path(db_path));
            let _ = std::fs::remove_file(&backup_path);
            Ok(pair)
        }
        Err(e) => Err(format!(
            "Salt conversion produced a vault that failed to reopen ({}). The pre-conversion backup was kept at {:?} and the salt file was left in place.",
            e, backup_path
        )),
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

    // 2. Read every row that needs to carry over. Uses the pre-sync_uuid
    //    8-column layout, not the shared get_secrets(): old_conn is a genuine
    //    legacy vault, deliberately never run through ensure_schema (which
    //    would alter its on-disk format before the password above is even
    //    confirmed against it), so it has no sync_uuid column to select.
    let secrets = get_secrets_legacy(&old_conn)?;
    let tombstones: Vec<(String, String, String, String)> = {
        let mut stmt = old_conn
            .prepare("SELECT title, category, username, deleted_at FROM deleted_secrets")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
    };
    old_conn.close().map_err(|(_, e)| e.to_string())?;

    // 3. Create the new SQLCipher-encrypted vault at a temp path alongside the old
    //    file, using a freshly generated salt (the password itself is unchanged
    //    from the user's point of view -- only the salt/derivation is refreshed).
    let new_salt = crypto::generate_salt();
    let new_master_key = crypto::derive_key(master_password, &new_salt)?;
    let new_sqlcipher_key = crypto::derive_sqlcipher_key(&new_master_key);

    let tmp_path = migrating_tmp_path(db_path);
    let _ = std::fs::remove_file(&tmp_path);
    let new_conn = open_keyed_connection_with_salt(&tmp_path, &new_sqlcipher_key, &new_salt)?;
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
        // Legacy vaults predate sync_uuid entirely, so every migrated row gets
        // a freshly generated one here rather than carrying over anything.
        new_conn
            .execute(
                "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![r.title, r.category, r.username, r.url, re_encrypted_pass, re_encrypted_notes, r.updated_at, new_uuid()],
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
    // The HIBP cache is deliberately *not* carried over here: its lookup key
    // is HMAC'd with a key derived from the master key (see
    // crypto::hibp_cache_fingerprint), so a fresh salt/master key -- exactly
    // what this migration generates -- makes every existing cache entry
    // permanently unmatchable anyway. Leaving hibp_checks empty in the new
    // vault is the correct outcome, not a bug: entries get re-populated the
    // next time each password is checked.
    // Force everything into the main file before it gets renamed -- only
    // tmp_path itself moves, never a -wal sidecar -- and confirm the salt
    // actually landed in the header before touching the live file.
    new_conn
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|e| e.to_string())?;
    new_conn.close().map_err(|(_, e)| e.to_string())?;
    if let Err(e) = verify_embedded_salt(&tmp_path, &new_salt) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // 4. Back up the old file, then move the new one into place. The salt
    //    travels inside the new file's header, so the swap is the whole
    //    hand-over -- there is no separate salt file to persist (a stray
    //    sidecar from some earlier layout would misroute the reopen below,
    //    so make sure none survives).
    let backup_path = pre_sqlcipher_backup_path(db_path);
    std::fs::rename(db_path, &backup_path).map_err(|e| format!("Failed to back up legacy vault: {}", e))?;
    std::fs::rename(&tmp_path, db_path).map_err(|e| format!("Failed to move migrated vault into place: {}", e))?;
    let _ = std::fs::remove_file(salt_sidecar_path(db_path));

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
        "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'), ?7)",
        params![title, category, username, url, encrypted_password, encrypted_notes, new_uuid()],
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

/// Reads `secrets` using the pre-sync_uuid 8-column layout. Only for
/// `migrate_legacy_vault`'s `old_conn` -- see the comment at its call site.
/// `sync_uuid` is left empty; every row read this way gets a freshly
/// generated one when copied into the new vault, so nothing reads this
/// placeholder back.
fn get_secrets_legacy(conn: &Connection) -> Result<Vec<SecretRecord>, String> {
    let mut stmt = conn
        .prepare("SELECT id, title, category, username, url, encrypted_password, encrypted_notes, updated_at FROM secrets")
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
                sync_uuid: String::new(),
            })
        })
        .map_err(|e| e.to_string())?;

    let mut secrets = Vec::new();
    for secret in secret_iter {
        secrets.push(secret.map_err(|e| e.to_string())?);
    }
    Ok(secrets)
}

pub fn get_secrets(conn: &Connection) -> Result<Vec<SecretRecord>, String> {
    let mut stmt = conn
        .prepare("SELECT id, title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid FROM secrets ORDER BY title ASC")
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
                sync_uuid: row.get(8)?,
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
        "SELECT id, title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid FROM secrets WHERE id = ?1",
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
            sync_uuid: row.get(8)?,
        }),
    )
    .optional()
    .map_err(|e| e.to_string())
}

pub fn delete_secret(conn: &Connection, id: i64) -> Result<(), String> {
    // 1. Fetch details for tombstone
    let record: Option<(String, String, String, String)> = conn
        .query_row(
            "SELECT title, category, username, sync_uuid FROM secrets WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    // Tombstone-insert and delete run in one transaction: without it, a crash
    // between the two left the tombstone written but the row still present --
    // harmless on its own (the next delete attempt just re-writes the
    // tombstone), but needlessly leaves the vault in an inconsistent
    // in-between state for however long until that retry happens.
    conn.execute("BEGIN TRANSACTION", [])
        .map_err(|e| e.to_string())?;

    if let Some((title, category, username, sync_uuid)) = record {
        // 2. Insert into deleted_secrets tombstone table. sync_uuid, not the
        // triple, is what sync merge steps actually match a tombstone against
        // -- see H2 -- the triple is kept only for display/debugging.
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO deleted_secrets (title, category, username, sync_uuid, deleted_at)
             VALUES (?1, ?2, ?3, ?4, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))",
            params![title, category, username, sync_uuid],
        ) {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e.to_string());
        }
    }

    // 3. Delete the actual secret
    if let Err(e) = conn.execute("DELETE FROM secrets WHERE id = ?1", params![id]) {
        let _ = conn.execute("ROLLBACK", []);
        return Err(e.to_string());
    }

    conn.execute("COMMIT", []).map_err(|e| e.to_string())?;
    Ok(())
}

/// Rotates the master password by building a brand new SQLCipher-encrypted
/// vault at a temp path (fresh salt, every secret decrypted with `old_key` and
/// re-encrypted with the new one) and atomically swapping it into place --
/// the same build-then-swap discipline `migrate_legacy_vault` already uses,
/// and for the same reason.
///
/// This replaces an earlier version that re-keyed the live file in place via
/// `PRAGMA rekey` and only wrote the new salt sidecar at the very end. That
/// had a real bricking window: `PRAGMA rekey` commits immediately and can't
/// be rolled back, so if the process died anywhere between that and the final
/// `write_salt_sidecar` call, the on-disk file ended up re-keyed with a salt
/// that existed nowhere but that process's now-gone memory -- permanently
/// unrecoverable, with no backup file to point the user at (unlike a botched
/// migration, which at least keeps `vault.db.pre-sqlcipher-backup`). Building
/// the new file at a temp path first means the live file is never touched
/// until a fully-formed, already-validated replacement is ready to swap in;
/// an interruption anywhere before that swap leaves the original file and
/// salt untouched, and an interruption during the swap itself is the exact
/// same recoverable shape as `VaultState::InterruptedMigration` (see
/// `VaultState::InterruptedRotation`).
///
/// The caller's existing `conn` is only read from here, never written to or
/// closed -- but it should be treated as stale after this returns `Ok`: on
/// success the live file at `db_path` is a different file than the one that
/// connection was opened against. Reopen with `open_vault` (as both call
/// sites do) rather than continuing to use the old connection.
pub fn change_master_password(
    conn: &Connection,
    db_path: &Path,
    old_key: &[u8; KEY_LEN],
    new_password: &str,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    // 1. Generate new salt and derive new master + SQLCipher keys.
    let new_salt = crypto::generate_salt();
    let new_key = crypto::derive_key(new_password, &new_salt)?;
    let new_sqlcipher_key = crypto::derive_sqlcipher_key(&new_key);

    // 2. Read everything that needs to carry over from the still-untouched
    //    live vault: secrets (to be re-encrypted below) and tombstones. The
    //    HIBP cache deliberately does NOT carry over -- its lookup key is
    //    HMAC'd with a key derived from the master key (see
    //    crypto::hibp_cache_fingerprint), so rotating to `new_key` above
    //    makes every existing cache entry permanently unmatchable. Starting
    //    the rotated vault with an empty cache is the correct outcome, not
    //    a bug: entries get re-populated the next time each password is
    //    checked.
    let secrets = get_secrets(conn)?;
    let tombstones: Vec<(String, String, String, Option<String>, String)> = {
        let mut stmt = conn
            .prepare("SELECT title, category, username, sync_uuid, deleted_at FROM deleted_secrets")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .map_err(|e| e.to_string())?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
    };

    // 3. Decrypt and re-encrypt every secret in memory, fully validated before
    //    any file is touched. sync_uuid is carried over unchanged -- rotating
    //    the password doesn't change a record's sync identity, only how its
    //    ciphertext is encrypted.
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

        re_encrypted_secrets.push((r, encrypted_pass, encrypted_notes));
    }
    let new_verification = crypto::encrypt(b"keystash-verification-token", &new_key)?;

    // 4. Build the new vault at a temp path. The live file at db_path is not
    //    touched by anything above or below this point until step 5's renames.
    let tmp_path = rekeying_tmp_path(db_path);
    let _ = std::fs::remove_file(&tmp_path);
    let new_conn = open_keyed_connection_with_salt(&tmp_path, &new_sqlcipher_key, &new_salt)?;
    ensure_schema(&new_conn)?;

    new_conn
        .execute(
            "INSERT INTO metadata (key, value) VALUES ('verification', ?1)",
            params![new_verification],
        )
        .map_err(|e| e.to_string())?;

    for (r, enc_pass, enc_notes) in &re_encrypted_secrets {
        new_conn
            .execute(
                "INSERT INTO secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'), ?7)",
                params![r.title, r.category, r.username, r.url, enc_pass, enc_notes, r.sync_uuid],
            )
            .map_err(|e| e.to_string())?;
    }
    for (title, category, username, sync_uuid, deleted_at) in &tombstones {
        new_conn
            .execute(
                "INSERT OR REPLACE INTO deleted_secrets (title, category, username, sync_uuid, deleted_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![title, category, username, sync_uuid, deleted_at],
            )
            .map_err(|e| e.to_string())?;
    }
    // open_keyed_connection leaves this file in WAL mode, meaning the inserts
    // above may still be sitting in vault.db.rekeying-wal rather than the main
    // file. Only tmp_path itself gets renamed below, not its WAL sidecar, so
    // switching off WAL here forces a full checkpoint back into the main file
    // and removes the sidecar entirely -- otherwise the swapped-in file can
    // be nearly empty, containing only what ensure_schema wrote before any of
    // this function's own inserts ran.
    new_conn
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|e| e.to_string())?;
    new_conn.close().map_err(|(_, e)| e.to_string())?;

    // The fresh salt must actually be in the new file's header before the
    // live file is touched -- the next unlock derives the key from those 16
    // bytes, so a silently ignored PRAGMA cipher_salt (see
    // verify_embedded_salt) would brick the rotated vault.
    if let Err(e) = verify_embedded_salt(&tmp_path, &new_salt) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // The caller's own `conn` is still open in WAL mode against db_path, and
    // renaming db_path away (below) only moves the main file -- its
    // `-wal`/`-shm` sidecars stay behind under db_path's original name. Left
    // alone, they'd sit right next to the freshly swapped-in file at that
    // same name and get mistaken for *its* WAL state on next open, which is
    // exactly what caused the new vault to fail reopening (SQLCipher-decoded
    // WAL frames from a different key look like corruption, not merely a
    // stale/mismatched WAL SQLite could safely ignore). Checkpointing and
    // truncating here empties them out first, in place, while `conn` is still
    // valid to call this on.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| format!("Failed to checkpoint vault before key rotation: {}", e))?;

    // 5. Swap: back up the current file (deleted below once the new one is
    //    confirmed working, unlike the permanent migration backup -- password
    //    rotation is routine, not a one-time format change worth keeping
    //    insurance for indefinitely), then move the new file into place. The
    //    fresh salt travels inside the new file's header, so the swap is
    //    atomic and complete in itself -- the old "re-keyed file on disk but
    //    its salt only in this process's memory" bricking window no longer
    //    has a shape it could take.
    let backup_path = pre_rekey_backup_path(db_path);
    std::fs::rename(db_path, &backup_path).map_err(|e| format!("Failed to back up vault before key rotation: {}", e))?;
    std::fs::rename(&tmp_path, db_path).map_err(|e| format!("Failed to move re-keyed vault into place: {}", e))?;

    // 6. Confirm the new vault actually opens before discarding the backup
    //    (via the embedded path directly: rotation only ever runs on an
    //    already-unlocked vault, so no sidecar should exist -- but if a stale
    //    one somehow did, routing through it here would wrongly re-derive
    //    from the pre-rotation salt and report a false failure). A stray
    //    sidecar is deleted only after success: it still holds the old salt,
    //    which a restored backup would need.
    match open_vault_embedded(db_path, new_password) {
        Ok(_) => {
            let _ = std::fs::remove_file(salt_sidecar_path(db_path));
            let _ = std::fs::remove_file(&backup_path);
            Ok(new_key)
        }
        Err(e) => Err(format!(
            "Key rotation produced a vault that failed to reopen ({}). The pre-rotation backup was kept at {:?}.",
            e, backup_path
        )),
    }
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
        let header_before: Vec<u8> = std::fs::read(&db_path).unwrap()[..16].to_vec();

        let new_key = change_master_password(&conn, &db_path, &old_key, "new-password-456").unwrap();
        // change_master_password swaps in a physically different file at
        // db_path; `conn` (left open against whatever now sits at the
        // pre-rotation backup path) must not be reused afterward -- reopen
        // fresh, exactly as both real call sites (main.rs, tui.rs) now do.
        drop(conn);

        let (conn2, key2) = open_vault(&db_path, "new-password-456").expect("new password should unlock after rotation");
        assert_eq!(&*key2, &*new_key);
        let secrets = get_secrets(&conn2).unwrap();
        let decrypted = crypto::decrypt(&secrets[0].encrypted_password, &new_key).unwrap();
        assert_eq!(&*decrypted, b"hunter2");
        drop(conn2);

        // Old password no longer opens the vault; SQLCipher itself was re-keyed.
        assert!(open_vault(&db_path, "old-password-123").is_err());

        // The pre-rotation backup is cleaned up once the new vault is
        // confirmed to open successfully.
        assert!(!db_path.with_file_name("vault.db.pre-rekey-backup").exists());

        // Rotation embeds a *fresh* salt -- that's the point of it -- and
        // leaves no sidecar behind.
        let rotated_header = std::fs::read(&db_path).unwrap();
        assert_ne!(&rotated_header[..16], header_before.as_slice(), "rotation must change the header salt");
        assert_ne!(&rotated_header[..16], SQLITE_PLAINTEXT_MAGIC.as_slice());
        assert!(!db_path.with_file_name("vault.salt").exists());

        cleanup(&db_path);
    }

    #[test]
    fn change_master_password_invalidates_hibp_cache() {
        let db_path = temp_db_path("rekey-hibp");

        let (conn, old_key) = create_vault(&db_path, "old-password-123").unwrap();
        add_secret(&conn, "Site", "Cat", "user", "", "hunter2", None, &old_key).unwrap();
        let old_fingerprint = crypto::hibp_cache_fingerprint(b"hunter2", &old_key);
        save_hibp_check(&conn, &old_fingerprint, Some(3)).unwrap();
        assert_eq!(get_all_hibp_checks(&conn).unwrap().len(), 1);

        let new_key = change_master_password(&conn, &db_path, &old_key, "new-password-456").unwrap();
        drop(conn);

        // The old cache entry must not survive rotation: its lookup key was
        // HMAC'd with the old master key, so keeping it around would be
        // silently unmatchable dead weight at best -- dropping it is correct.
        let (conn2, _) = open_vault(&db_path, "new-password-456").unwrap();
        assert!(get_all_hibp_checks(&conn2).unwrap().is_empty());

        // And the new fingerprint for the same password differs from the old
        // one, confirming the cache key really did change with rotation.
        let new_fingerprint = crypto::hibp_cache_fingerprint(b"hunter2", &new_key);
        assert_ne!(old_fingerprint, new_fingerprint);

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
        // Insert directly against the legacy 8-column schema above rather than
        // through add_secret(), which now also writes sync_uuid -- a column a
        // genuine legacy vault (and this hand-built fixture matching it) never has.
        let legacy_encrypted_pass = crypto::encrypt(b"legacy-pass", &legacy_key).unwrap();
        legacy_conn.execute(
            "INSERT INTO secrets (title, category, username, url, encrypted_password) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["Old Site", "Legacy", "olduser", "", legacy_encrypted_pass],
        ).unwrap();
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

        // The salt is embedded in that header -- no sidecar gets written.
        assert!(
            !db_path.with_file_name("vault.salt").exists(),
            "migration must not create a vault.salt sidecar"
        );

        // And the same password re-opens it through the normal path afterwards.
        assert!(open_vault(&db_path, "legacy-master-pw").is_ok());

        let _ = std::fs::remove_file(db_path.with_file_name("vault.db.pre-sqlcipher-backup"));
        cleanup(&db_path);
    }

    #[test]
    fn new_vaults_are_self_contained_with_the_salt_in_the_header() {
        let db_path = temp_db_path("embedded-salt");
        let (conn, _key) = create_vault(&db_path, "some-password").unwrap();
        drop(conn);

        // No sidecar: the salt lives in the file itself.
        assert!(
            !db_path.with_file_name("vault.salt").exists(),
            "a new vault must not create a vault.salt sidecar"
        );

        // The header is a salt, not the plaintext-SQLite magic, and the vault
        // opens from the file alone -- proving the key really derives from
        // those 16 bytes.
        let header = std::fs::read(&db_path).unwrap();
        assert_ne!(&header[..16], SQLITE_PLAINTEXT_MAGIC.as_slice());
        assert!(open_vault(&db_path, "some-password").is_ok());

        cleanup(&db_path);
    }

    #[test]
    fn sidecar_era_vault_is_converted_on_first_unlock() {
        let db_path = temp_db_path("sidecar-conversion");

        // Build a pre-0.3.6 vault by hand: salt in a sidecar file, vault.db
        // created *without* cipher_salt (random header salt), exactly like
        // the old create_vault produced.
        let salt = crypto::generate_salt();
        let master_key = crypto::derive_key("legacy-layout-pw", &salt).unwrap();
        let sqlcipher_key = crypto::derive_sqlcipher_key(&master_key);
        {
            let conn = open_keyed_connection(&db_path, &sqlcipher_key).unwrap();
            ensure_schema(&conn).unwrap();
            let token = crypto::encrypt(b"keystash-verification-token", &master_key).unwrap();
            conn.execute("INSERT INTO metadata (key, value) VALUES ('verification', ?1)", params![token]).unwrap();
            add_secret(&conn, "Site", "Cat", "user", "https://example.com", "hunter2", Some("note"), &master_key).unwrap();
        }
        let sidecar = db_path.with_file_name("vault.salt");
        std::fs::write(&sidecar, salt).unwrap();

        // Sanity: the sidecar-era file's header salt is NOT the Argon2 salt.
        let header_before = std::fs::read(&db_path).unwrap();
        assert_ne!(&header_before[..16], &salt[..]);

        // Capture the record's identity fields; the conversion must not
        // disturb them (the sync merge must not see a rebuilt vault as
        // freshly edited).
        let (uuid_before, updated_before) = {
            let conn = open_keyed_connection(&db_path, &sqlcipher_key).unwrap();
            let s = get_secrets(&conn).unwrap();
            (s[0].sync_uuid.clone(), s[0].updated_at.clone())
        };

        // First unlock through the normal path converts the vault.
        let (conn2, key2) = open_vault(&db_path, "legacy-layout-pw")
            .expect("a sidecar-era vault must unlock (and convert) through open_vault");
        assert!(!sidecar.exists(), "the sidecar must be deleted after conversion");
        let header_after = std::fs::read(&db_path).unwrap();
        assert_eq!(&header_after[..16], &salt[..], "the Argon2 salt must now be the file header");
        assert!(
            !db_path.with_file_name("vault.db.pre-rekey-backup").exists(),
            "the conversion backup must be cleaned up on success"
        );

        // Data intact, identity fields untouched, ciphertexts still decrypt.
        let secrets = get_secrets(&conn2).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].sync_uuid, uuid_before);
        assert_eq!(secrets[0].updated_at, updated_before);
        assert_eq!(&*crypto::decrypt(&secrets[0].encrypted_password, &key2).unwrap(), b"hunter2");
        drop(conn2);

        // And the second unlock takes the plain embedded path.
        assert!(open_vault(&db_path, "legacy-layout-pw").is_ok());

        cleanup(&db_path);
    }

    #[test]
    fn stored_version_floor_is_raised_on_open() {
        let db_path = temp_db_path("floor-raise");
        let (conn, _key) = create_vault(&db_path, "some-password").unwrap();

        // Simulate a vault last written by an older version.
        conn.execute("UPDATE metadata SET value = '0.3.0' WHERE key = 'min_app_version'", []).unwrap();
        drop(conn);

        // Opening with this binary converts the vault to this binary's
        // format, so the floor must come up with it.
        let (conn2, _) = open_vault(&db_path, "some-password").unwrap();
        let floor: String = conn2
            .query_row("SELECT value FROM metadata WHERE key = 'min_app_version'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(floor, MIN_COMPATIBLE_APP_VERSION);

        cleanup(&db_path);
    }

    #[test]
    fn deleting_duplicates_sharing_a_triple_keeps_every_tombstone() {
        let db_path = temp_db_path("tombstone-collapse");
        let (conn, key) = create_vault(&db_path, "some-password").unwrap();

        // Three records sharing the exact (title, category, username) triple
        // -- the case the dedup screen exists to find. Under the old triple
        // PRIMARY KEY, deleting two of them collapsed both tombstones into
        // one PK slot via INSERT OR REPLACE, and the lost deletion silently
        // resurrected on other devices at the next merge.
        for pw in ["dup-v1", "dup-v2", "dup-v3"] {
            add_secret(&conn, "Dup", "Cat", "user", "", pw, None, &key).unwrap();
        }
        let secrets = get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 3);

        delete_secret(&conn, secrets[0].id).unwrap();
        delete_secret(&conn, secrets[1].id).unwrap();

        let tombstones: Vec<(String, Option<String>)> = {
            let mut stmt = conn
                .prepare("SELECT title, sync_uuid FROM deleted_secrets")
                .unwrap();
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        assert_eq!(
            tombstones.len(),
            2,
            "both deletions must leave their own tombstone, got: {:?}",
            tombstones
        );
        let tombstone_uuids: std::collections::HashSet<Option<String>> =
            tombstones.into_iter().map(|(_, uuid)| uuid).collect();
        assert!(tombstone_uuids.contains(&Some(secrets[0].sync_uuid.clone())));
        assert!(tombstone_uuids.contains(&Some(secrets[1].sync_uuid.clone())));

        cleanup(&db_path);
    }

    #[test]
    fn legacy_triple_keyed_tombstone_table_is_rebuilt_on_open() {
        let db_path = temp_db_path("tombstone-rebuild");
        let (conn, _key) = create_vault(&db_path, "some-password").unwrap();

        // Swap in the old-format table: composite triple PK, holding one
        // uuid-carrying tombstone and one legacy NULL-uuid tombstone.
        conn.execute_batch(
            "DROP TABLE deleted_secrets;
             CREATE TABLE deleted_secrets (
                 title TEXT NOT NULL,
                 category TEXT NOT NULL,
                 username TEXT NOT NULL,
                 deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
                 sync_uuid TEXT,
                 PRIMARY KEY (title, category, username)
             );
             INSERT INTO deleted_secrets (title, category, username, deleted_at, sync_uuid)
                 VALUES ('A', 'Cat', 'user', '2026-01-01 00:00:00.000', 'uuid-a');
             INSERT INTO deleted_secrets (title, category, username, deleted_at, sync_uuid)
                 VALUES ('B', 'Cat', 'user', '2026-01-02 00:00:00.000', NULL);",
        )
        .unwrap();
        drop(conn);

        // Reopening runs ensure_schema, which must rebuild the table.
        let (conn2, _) = open_vault(&db_path, "some-password").unwrap();
        let pk_columns: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('deleted_secrets') WHERE pk > 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pk_columns, 0, "the triple PRIMARY KEY must be gone after the rebuild");

        let rows: Vec<(String, Option<String>)> = {
            let mut stmt = conn2
                .prepare("SELECT title, sync_uuid FROM deleted_secrets ORDER BY title")
                .unwrap();
            let r = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap();
            r.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        assert_eq!(rows.len(), 2, "both tombstones must survive the rebuild, got: {:?}", rows);
        assert_eq!(rows[0], ("A".to_string(), Some("uuid-a".to_string())));
        assert_eq!(rows[1], ("B".to_string(), None));

        // The uuid uniqueness the merge steps rely on must now be enforced.
        let index_exists: i64 = conn2
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_deleted_secrets_sync_uuid'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_exists, 1);

        cleanup(&db_path);
    }

    #[test]
    fn version_satisfies_compares_major_minor_patch_correctly() {
        assert!(version_satisfies("0.4.0", "0.3.0"));
        assert!(version_satisfies("0.3.0", "0.3.0"));
        assert!(!version_satisfies("0.2.9", "0.3.0"));
        assert!(version_satisfies("1.0.0", "0.9.9"));
        assert!(version_satisfies("0.10.0", "0.9.0"), "numeric, not lexicographic, comparison");
        assert!(!version_satisfies("0.9.0", "0.10.0"));
        // Unparseable input is treated as satisfied -- a friendliness feature,
        // not a security boundary, so it shouldn't lock anyone out.
        assert!(version_satisfies("garbage", "0.3.0"));
        assert!(version_satisfies("0.3.0", "garbage"));
    }

    #[test]
    fn open_vault_refuses_a_vault_requiring_a_newer_version() {
        let db_path = temp_db_path("min-version-gate");
        let (conn, _key) = create_vault(&db_path, "some-password").unwrap();

        conn.execute(
            "UPDATE metadata SET value = '99.0.0' WHERE key = 'min_app_version'",
            [],
        )
        .unwrap();
        drop(conn);

        let result = open_vault(&db_path, "some-password");
        assert!(result.is_err(), "opening a vault requiring v99.0.0 should fail");
        let err = result.unwrap_err();
        assert!(err.contains("99.0.0"), "error should name the required version, got: {}", err);
        assert!(err.contains("KeyStash"), "error should be a clear, distinct message, got: {}", err);

        cleanup(&db_path);
    }

    #[test]
    fn open_vault_ignores_a_missing_or_older_min_version_row() {
        let db_path = temp_db_path("min-version-ok");
        let (conn, _key) = create_vault(&db_path, "some-password").unwrap();

        // A vault created by current code always has the row; simulate one
        // predating this feature entirely by deleting it, and confirm that's
        // still treated as compatible, not as a failure.
        conn.execute("DELETE FROM metadata WHERE key = 'min_app_version'", [])
            .unwrap();
        drop(conn);
        assert!(open_vault(&db_path, "some-password").is_ok(), "a vault with no min_app_version row at all should still open");

        // And an explicitly low floor should obviously still be satisfied.
        let (conn2, _) = open_vault(&db_path, "some-password").unwrap();
        conn2.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('min_app_version', '0.0.1')",
            [],
        )
        .unwrap();
        drop(conn2);
        assert!(open_vault(&db_path, "some-password").is_ok());

        cleanup(&db_path);
    }
}

