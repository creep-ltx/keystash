use std::path::Path;
use std::process::{Command, Stdio};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// Combined with the process id, guarantees the temp filenames below are unique
/// even across two sync operations racing on separate threads within the same
/// process (which share a process id) -- relying on process id alone caused a
/// real collision where two concurrently-running syncs read/wrote/deleted the
/// same temp file out from under each other.
static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
fn unique_tmp_suffix() -> u64 {
    TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Deletes the given temp vault-copy paths when dropped, regardless of which
/// return path (success, an early `?`, or a panic) is taken. These files are
/// SQLCipher-encrypted copies -- not a plaintext exposure -- but left uncleaned
/// they accumulate under `~/.config/keystash` and could get swept into a git
/// commit by an unrelated `git add -A` elsewhere.
struct TempCleanup(Vec<std::path::PathBuf>);
impl Drop for TempCleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

/// Check if the database folder is configured as a git repository.
pub fn is_git_configured<P: AsRef<Path>>(db_path: P) -> bool {
    if let Some(parent) = db_path.as_ref().parent() {
        parent.join(".git").exists()
    } else {
        false
    }
}

/// Perform a full git pull, logical SQLite database merge, auto-commit, and git push.
///
/// `key` is the master key (the same one returned by `db::open_vault` et al.) --
/// this derives the independent SQLCipher key from it internally wherever a
/// connection needs to be opened or attached, since the vault is now a
/// whole-database-encrypted file.
pub fn git_sync_vault<P: AsRef<Path>>(db_path: P, key: &[u8; 32]) -> Result<String, String> {
    let db_ref = db_path.as_ref();
    let dir = db_ref.parent().ok_or("Invalid database directory")?;
    let sqlcipher_key = crate::crypto::derive_sqlcipher_key(key);
    let pragma_hex = crate::crypto::pragma_key_hex(&sqlcipher_key);

    if !dir.join(".git").exists() {
        return Err("Sync not configured. Set up git in ~/.config/keystash to enable syncing.".to_string());
    }

    // 1. Run git fetch to see if remote changes exist
    let fetch_status = Command::new("git")
        .arg("-c")
        .arg("connection.timeout=5")
        .arg("-c")
        .arg("http.lowSpeedLimit=1000")
        .arg("-c")
        .arg("http.lowSpeedTime=5")
        .arg("fetch")
        .arg("origin")
        .arg("main")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o ConnectTimeout=5 -o ConnectionAttempts=1")
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("git fetch failed: {}", e))?;

    if !fetch_status.success() {
        return Err("Could not reach git remote 'origin/main'. Check network or SSH configuration.".to_string());
    }

    // Determine if we have remote commits we need to merge
    let remote_db_path = dir.join(format!("vault_remote_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let _cleanup = TempCleanup(vec![remote_db_path.clone()]);

    // Extract remote database to temp file using git show
    let show_output = Command::new("git")
        .arg("show")
        .arg("origin/main:vault.db")
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let mut has_remote = false;
    if let Ok(output) = show_output {
        if output.status.success() && !output.stdout.is_empty() {
            if fs::write(&remote_db_path, output.stdout).is_ok() {
                has_remote = true;
            }
        }
    }

    // 2. Perform SQLite logical merge if remote database was successfully extracted
    let mut unmerged_remote_backup: Option<std::path::PathBuf> = None;
    if has_remote {
        if !db_ref.exists() {
            fs::copy(&remote_db_path, db_ref).map_err(|e| format!("Failed to restore vault.db from remote: {}", e))?;

            // vault.salt is tracked in git alongside vault.db (see the staging
            // step below), so restore it the same way if it's also missing
            // locally -- without it, the restored vault.db can't be unlocked.
            let salt_path = db_ref.with_file_name("vault.salt");
            if !salt_path.exists() {
                if let Ok(salt_output) = Command::new("git")
                    .arg("show")
                    .arg("origin/main:vault.salt")
                    .current_dir(dir)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output()
                {
                    if salt_output.status.success() && !salt_output.stdout.is_empty() {
                        let _ = fs::write(&salt_path, salt_output.stdout);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o600));
                        }
                    }
                }
            }

            return Ok("Sync complete: Local vault restored from remote repository!".to_string());
        }

        // Check the remote extract is actually readable with our current
        // SQLCipher key *before* attempting to merge it. It won't be if it's a
        // legacy pre-SQLCipher copy (e.g. from a device that hasn't been
        // updated yet) or otherwise corrupted -- there's nothing safe to merge
        // in that case. Rather than fail the whole sync on a low-level SQLite
        // error, back up the un-mergeable copy for manual recovery and fall
        // through to pushing our own (already-correct) local vault as the new
        // source of truth, so this never requires manual git surgery.
        let remote_is_compatible = crate::db::open_keyed_connection(&remote_db_path, &sqlcipher_key).is_ok();

        if remote_is_compatible {
            let conn = crate::db::open_keyed_connection(db_ref, &sqlcipher_key)
                .map_err(|e| format!("Local database open error: {}", e))?;

            // Attach the remote database. It's the same vault under the same
            // master password, so it uses the same derived SQLCipher key.
            let remote_path_str = remote_db_path.to_string_lossy();
            let escaped_path = remote_path_str.replace('\'', "''");
            conn.execute(
                &format!("ATTACH DATABASE '{}' AS remote_db KEY \"x'{}'\"", escaped_path, *pragma_hex),
                [],
            )
            .map_err(|e| format!("Failed to attach remote database: {}", e))?;

            // General forward-compatibility gate: if the remote was last
            // pushed by a version whose format this binary predates, don't
            // attempt to merge against it at all (unlike the sync_uuid case
            // right below, there's no narrower fallback possible here by
            // definition -- this only ever fires for a change that couldn't
            // be made safely backward-compatible in the first place). Regular
            // `schema.table` qualification (unlike the pragma-function form
            // below) is standard ATTACH DATABASE usage and already relied on
            // throughout the merge steps further down, so this is safe.
            let remote_min_version: Option<String> = conn
                .query_row(
                    "SELECT value FROM remote_db.metadata WHERE key = 'min_app_version'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .ok();
            if let Some(required) = &remote_min_version
                && !crate::db::version_satisfies(env!("CARGO_PKG_VERSION"), required)
            {
                let _ = conn.execute("DETACH DATABASE remote_db", []);
                return Err(format!(
                    "The remote vault requires KeyStash v{} or newer to sync. You are running v{}. Please update KeyStash and try again.",
                    required,
                    env!("CARGO_PKG_VERSION"),
                ));
            }

            // The remote copy is a valid SQLCipher vault under our key (that's
            // what `remote_is_compatible` already confirmed) but may still
            // predate the sync_uuid merge identity below if it was last pushed
            // by a KeyStash version older than this one.
            //
            // Deliberately the `PRAGMA schema.table_info(table)` statement
            // form here, not the `schema.pragma_table_info('table')`
            // table-valued-function form used elsewhere in this file: the
            // schema-qualified prefix on the function form silently reads the
            // connection's own main schema instead of the attached one on the
            // SQLite version this build vendors, rather than erroring -- so it
            // always reported the *local* vault's schema (which, post
            // ensure_schema, always has sync_uuid), never the remote's. That
            // made the "remote predates sync_uuid" branch below dead code,
            // silently replaced by a raw "no such column" SQL error instead of
            // either the intended fallback or even the old refusal message.
            let remote_has_sync_uuid: bool = {
                let mut stmt = conn
                    .prepare("PRAGMA remote_db.table_info(secrets)")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                let mut found = false;
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    let name: String = row.get(1).map_err(|e| e.to_string())?;
                    if name == "sync_uuid" {
                        found = true;
                        break;
                    }
                }
                found
            };

            conn.execute("BEGIN TRANSACTION", [])
                .map_err(|e| format!("Failed to start merge transaction: {}", e))?;

            let merge_steps: Vec<&str> = if remote_has_sync_uuid {
                vec![
                    // Delete local records if remote deleted them and the deletion is newer than the local update
                    "DELETE FROM main.secrets
                     WHERE EXISTS (
                         SELECT 1 FROM remote_db.deleted_secrets rd
                         WHERE rd.sync_uuid = main.secrets.sync_uuid
                           AND rd.sync_uuid IS NOT NULL
                           AND rd.deleted_at > main.secrets.updated_at
                     )",

                    // Copy new secrets from remote to local
                    "INSERT INTO main.secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid)
                     SELECT title, category, username, url, encrypted_password, encrypted_notes, updated_at, sync_uuid
                     FROM remote_db.secrets r
                     WHERE r.sync_uuid IS NOT NULL
                       AND NOT EXISTS (
                         SELECT 1 FROM main.secrets l WHERE l.sync_uuid = r.sync_uuid
                     ) AND NOT EXISTS (
                         SELECT 1 FROM main.deleted_secrets ld
                         WHERE ld.sync_uuid = r.sync_uuid AND ld.deleted_at >= r.updated_at
                     )",

                    // Update local secrets if remote is newer. sync_uuid has a
                    // UNIQUE index, so unlike the old title/category/username
                    // triple, these scalar subqueries can never match more than
                    // one remote row.
                    "UPDATE main.secrets
                     SET url = (SELECT url FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         encrypted_password = (SELECT encrypted_password FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         encrypted_notes = (SELECT encrypted_notes FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         updated_at = (SELECT updated_at FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid)
                     WHERE EXISTS (
                         SELECT 1 FROM remote_db.secrets r
                         WHERE r.sync_uuid = main.secrets.sync_uuid
                           AND r.updated_at > main.secrets.updated_at
                     )",

                    // Sync deleted_secrets tombstones from remote to local.
                    // OR REPLACE keys on the UNIQUE sync_uuid index, so a
                    // re-deleted record refreshes its tombstone rather than
                    // duplicating it. NULL-uuid legacy tombstones never
                    // conflict under that index (NULLs are distinct), so they
                    // need the explicit triple-match guard below or every
                    // sync would re-insert all of them.
                    "INSERT OR REPLACE INTO main.deleted_secrets (title, category, username, sync_uuid, deleted_at)
                     SELECT rd.title, rd.category, rd.username, rd.sync_uuid, rd.deleted_at
                     FROM remote_db.deleted_secrets rd
                     WHERE rd.sync_uuid IS NOT NULL
                        OR NOT EXISTS (
                            SELECT 1 FROM main.deleted_secrets ld
                            WHERE ld.sync_uuid IS NULL
                              AND ld.title = rd.title AND ld.category = rd.category AND ld.username = rd.username
                        )"
                ]
            } else {
                // Remote predates sync_uuid entirely (last pushed by an older
                // KeyStash version). Refusing to merge here would mean no
                // upgraded device could ever be the first to introduce the new
                // schema to the shared repo -- git has no way for one device
                // to know the other has updated, so every device would keep
                // refusing forever and the remote backup would never move
                // forward. Instead, fall back to the exact triple-based merge
                // pre-H2 KeyStash used, just for this one sync, then let the
                // push below carry the result (now with sync_uuid populated,
                // backfilled below) into the shared repo -- the remote adopts
                // the new schema the first time *any* updated device syncs,
                // with no coordination required.
                vec![
                    "DELETE FROM main.secrets
                     WHERE EXISTS (
                         SELECT 1 FROM remote_db.deleted_secrets rd
                         WHERE main.secrets.title = rd.title
                           AND main.secrets.category = rd.category
                           AND main.secrets.username = rd.username
                           AND rd.deleted_at > main.secrets.updated_at
                     )",

                    "INSERT INTO main.secrets (title, category, username, url, encrypted_password, encrypted_notes, updated_at)
                     SELECT title, category, username, url, encrypted_password, encrypted_notes, updated_at
                     FROM remote_db.secrets r
                     WHERE NOT EXISTS (
                         SELECT 1 FROM main.secrets l
                         WHERE l.title = r.title AND l.category = r.category AND l.username = r.username
                     ) AND NOT EXISTS (
                         SELECT 1 FROM main.deleted_secrets ld
                         WHERE ld.title = r.title AND ld.category = r.category AND ld.username = r.username
                           AND ld.deleted_at >= r.updated_at
                     )",

                    "UPDATE main.secrets
                     SET url = (SELECT url FROM remote_db.secrets r WHERE main.secrets.title = r.title AND main.secrets.category = r.category AND main.secrets.username = r.username),
                         encrypted_password = (SELECT encrypted_password FROM remote_db.secrets r WHERE main.secrets.title = r.title AND main.secrets.category = r.category AND main.secrets.username = r.username),
                         encrypted_notes = (SELECT encrypted_notes FROM remote_db.secrets r WHERE main.secrets.title = r.title AND main.secrets.category = r.category AND main.secrets.username = r.username),
                         updated_at = (SELECT updated_at FROM remote_db.secrets r WHERE main.secrets.title = r.title AND main.secrets.category = r.category AND main.secrets.username = r.username)
                     WHERE EXISTS (
                         SELECT 1 FROM remote_db.secrets r
                         WHERE main.secrets.title = r.title
                           AND main.secrets.category = r.category
                           AND main.secrets.username = r.username
                           AND r.updated_at > main.secrets.updated_at
                     )",

                    // A pre-sync_uuid remote's tombstones all arrive with a
                    // NULL sync_uuid, which never conflicts under the UNIQUE
                    // index (NULLs are distinct) -- guard on the triple so
                    // repeated syncs against the same legacy remote don't
                    // re-insert them every time.
                    "INSERT INTO main.deleted_secrets (title, category, username, deleted_at)
                     SELECT rd.title, rd.category, rd.username, rd.deleted_at
                     FROM remote_db.deleted_secrets rd
                     WHERE NOT EXISTS (
                         SELECT 1 FROM main.deleted_secrets ld
                         WHERE ld.sync_uuid IS NULL
                           AND ld.title = rd.title AND ld.category = rd.category AND ld.username = rd.username
                     )"
                ]
            };

            for step in merge_steps {
                if let Err(e) = conn.execute(step, []) {
                    let _ = conn.execute("ROLLBACK", []);
                    return Err(format!("Database merge transaction failed: {}", e));
                }
            }

            conn.execute("COMMIT", []).map_err(|e| format!("Failed to commit merge: {}", e))?;

            if !remote_has_sync_uuid {
                // The legacy fallback above can only have pulled in rows with
                // no sync_uuid at all (the remote had none to copy). Backfill
                // them the same way ensure_schema does for a freshly-migrated
                // vault, so every row has a real, unique one going forward --
                // otherwise these rows would have no stable sync identity
                // until some *other* future sync happened to fix them up.
                let ids_needing_uuid: Vec<i64> = {
                    let mut stmt = conn
                        .prepare("SELECT id FROM main.secrets WHERE sync_uuid IS NULL")
                        .map_err(|e| e.to_string())?;
                    let rows = stmt
                        .query_map([], |row| row.get::<_, i64>(0))
                        .map_err(|e| e.to_string())?;
                    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())?
                };
                for id in ids_needing_uuid {
                    conn.execute(
                        "UPDATE main.secrets SET sync_uuid = ?1 WHERE id = ?2",
                        rusqlite::params![crate::db::new_uuid(), id],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }

            // Detach database
            let _ = conn.execute("DETACH DATABASE remote_db", []);
        } else {
            let backup_path = dir.join(format!(
                "vault.db.unmerged-remote-{}",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            if fs::copy(&remote_db_path, &backup_path).is_ok() {
                unmerged_remote_backup = Some(backup_path);
            }
        }

        // Align local branch history with the remote before committing (preserves
        // the merged -- or, in the incompatible-remote case, purely local -- vault.db)
        Command::new("git")
            .arg("reset")
            .arg("origin/main")
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git reset failed: {}", e))?;
    }

    // 3. Stage changes, commit, and push local updates to remote repository
    let status_output = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git status failed: {}", e))?;

    let is_dirty = !status_output.stdout.is_empty();

    if is_dirty {
        // Stage vault.db
        Command::new("git")
            .arg("add")
            .arg("vault.db")
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git add failed: {}", e))?;

        // Also stage vault.salt (force-added, since the documented setup's
        // `.gitignore` only allow-lists `vault.db`). Without this, a second
        // device that clones/pulls this repo would get vault.db but never the
        // salt needed to derive its SQLCipher key -- it would be misdiagnosed
        // as a legacy (pre-SQLCipher) vault and fail to open at all. The salt
        // isn't secret, only the derived key is, so tracking it is safe.
        Command::new("git")
            .arg("add")
            .arg("-f")
            .arg("vault.salt")
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git add failed: {}", e))?;

        // Create commit
        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("sync: auto-merge vault updates")
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git commit failed: {}", e))?;
    }

    // Run push to update remote repository state
    let push_status = Command::new("git")
        .arg("-c")
        .arg("connection.timeout=5")
        .arg("-c")
        .arg("http.lowSpeedLimit=1000")
        .arg("-c")
        .arg("http.lowSpeedTime=5")
        .arg("push")
        .arg("origin")
        .arg("main")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o ConnectTimeout=5 -o ConnectionAttempts=1")
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("git push failed: {}", e))?;

    if !push_status.success() {
        return Err("Git push failed. You might have conflicts or remote changes that couldn't rebase automatically.".to_string());
    }

    if let Some(backup_path) = unmerged_remote_backup {
        Ok(format!(
            "Sync complete: remote vault was in an incompatible format (likely an outdated pre-encryption copy) and could not be merged. Your local vault was pushed as the new source of truth; the old remote copy was saved to {:?} in case you need anything from it.",
            backup_path
        ))
    } else if is_dirty {
        Ok("Sync complete: Local and remote vaults merged and updated!".to_string())
    } else {
        Ok("Sync complete: Vault is already up-to-date with remote.".to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ConflictGroup {
    pub title: String,
    pub category: String,
    pub username: String,
    pub local_secret: crate::db::SecretRecord,
    pub remote_secret: crate::db::SecretRecord,
    pub base_secret: Option<crate::db::SecretRecord>,
}

pub fn detect_sync_conflicts(
    db_path: &Path,
    key: &[u8; 32],
) -> Result<Vec<ConflictGroup>, String> {
    let dir = db_path.parent().ok_or("Invalid database directory")?;
    
    let remote_db_path = dir.join(format!("vault_remote_detect_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let base_db_path = dir.join(format!("vault_base_detect_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let _cleanup = TempCleanup(vec![remote_db_path.clone(), base_db_path.clone()]);

    let show_remote = Command::new("git")
        .arg("show")
        .arg("origin/main:vault.db")
        .current_dir(dir)
        .output();
        
    let mut has_remote = false;
    if let Ok(output) = show_remote {
        if output.status.success() && !output.stdout.is_empty() {
            if fs::write(&remote_db_path, output.stdout).is_ok() {
                has_remote = true;
            }
        }
    }

    if !has_remote {
        return Ok(Vec::new());
    }

    let merge_base_output = Command::new("git")
        .arg("merge-base")
        .arg("HEAD")
        .arg("origin/main")
        .current_dir(dir)
        .output();

    let mut has_base = false;
    if let Ok(output) = merge_base_output {
        if output.status.success() {
            let ancestor_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let show_base = Command::new("git")
                .arg("show")
                .arg(format!("{}:vault.db", ancestor_hash))
                .current_dir(dir)
                .output();

            if let Ok(base_out) = show_base {
                if base_out.status.success() && !base_out.stdout.is_empty() {
                    if fs::write(&base_db_path, base_out.stdout).is_ok() {
                        has_base = true;
                    }
                }
            }
        }
    }

    let sqlcipher_key = crate::crypto::derive_sqlcipher_key(key);
    let local_conn = crate::db::open_keyed_connection(db_path, &sqlcipher_key).map_err(|e| e.to_string())?;

    // If the remote copy can't be opened with our current key -- e.g. it's a
    // legacy pre-SQLCipher copy from a device that hasn't been updated yet, or
    // otherwise incompatible/corrupted -- there's nothing meaningful to compare
    // for conflicts. Defer to `git_sync_vault`'s own handling of that case
    // rather than failing here.
    let remote_conn = match crate::db::open_keyed_connection(&remote_db_path, &sqlcipher_key) {
        Ok(conn) => conn,
        Err(_) => return Ok(Vec::new()),
    };

    // Same forward-compatibility gate as git_sync_vault: defer to its own
    // refusal rather than attempting a 3-way diff against a remote this
    // binary is too old to understand.
    let remote_min_version: Option<String> = remote_conn
        .query_row(
            "SELECT value FROM metadata WHERE key = 'min_app_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok();
    if let Some(required) = &remote_min_version
        && !crate::db::version_satisfies(env!("CARGO_PKG_VERSION"), required)
    {
        return Ok(Vec::new());
    }

    // A remote that predates sync_uuid has nothing meaningful to key a 3-way
    // diff on. Defer to git_sync_vault's own legacy-merge fallback for this
    // case instead -- it applies the pre-sync_uuid last-write-wins merge
    // directly, without a conflict-resolution UI step, which is an acceptable
    // trade-off for this one transitional sync (the same trade-off already
    // made for a genuinely incompatible/unreadable remote, below).
    let remote_has_sync_uuid: bool = remote_conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'sync_uuid'",
            [],
            |row| { let c: i64 = row.get(0)?; Ok(c > 0) },
        )
        .unwrap_or(false);
    if !remote_has_sync_uuid {
        return Ok(Vec::new());
    }

    let local_secrets = crate::db::get_secrets(&local_conn).map_err(|e| e.to_string())?;
    let remote_secrets = crate::db::get_secrets(&remote_conn).map_err(|e| e.to_string())?;

    let base_secrets = if has_base {
        if let Ok(base_conn) = crate::db::open_keyed_connection(&base_db_path, &sqlcipher_key) {
            crate::db::get_secrets(&base_conn).unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    use std::collections::HashMap;
    let mut local_map: HashMap<String, crate::db::SecretRecord> = HashMap::new();
    for s in local_secrets {
        local_map.insert(s.sync_uuid.clone(), s);
    }

    let mut remote_map: HashMap<String, crate::db::SecretRecord> = HashMap::new();
    for s in remote_secrets {
        remote_map.insert(s.sync_uuid.clone(), s);
    }

    let mut base_map: HashMap<String, crate::db::SecretRecord> = HashMap::new();
    for s in base_secrets {
        base_map.insert(s.sync_uuid.clone(), s);
    }

    let mut conflicts = Vec::new();

    for (k, local_sec) in &local_map {
        if let Some(remote_sec) = remote_map.get(k) {
            let local_pw: Zeroizing<String> = crate::crypto::decrypt(&local_sec.encrypted_password, key)
                .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                .unwrap_or_default();
            let remote_pw: Zeroizing<String> = crate::crypto::decrypt(&remote_sec.encrypted_password, key)
                .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                .unwrap_or_default();

            let local_notes: Zeroizing<String> = if let Some(notes) = &local_sec.encrypted_notes {
                crate::crypto::decrypt(notes, key)
                    .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                    .unwrap_or_default()
            } else {
                Zeroizing::new(String::new())
            };

            let remote_notes: Zeroizing<String> = if let Some(notes) = &remote_sec.encrypted_notes {
                crate::crypto::decrypt(notes, key)
                    .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                    .unwrap_or_default()
            } else {
                Zeroizing::new(String::new())
            };

            let differs = local_pw != remote_pw || local_notes != remote_notes || local_sec.url != remote_sec.url;
            if differs {
                if let Some(base_sec) = base_map.get(k) {
                    let base_pw: Zeroizing<String> = crate::crypto::decrypt(&base_sec.encrypted_password, key)
                        .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                        .unwrap_or_default();
                    let base_notes: Zeroizing<String> = if let Some(notes) = &base_sec.encrypted_notes {
                        crate::crypto::decrypt(notes, key)
                            .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                            .unwrap_or_default()
                    } else {
                        Zeroizing::new(String::new())
                    };

                    let local_changed = local_pw != base_pw || local_notes != base_notes || local_sec.url != base_sec.url;
                    let remote_changed = remote_pw != base_pw || remote_notes != base_notes || remote_sec.url != base_sec.url;

                    if local_changed && remote_changed {
                        conflicts.push(ConflictGroup {
                            title: local_sec.title.clone(),
                            category: local_sec.category.clone(),
                            username: local_sec.username.clone(),
                            local_secret: local_sec.clone(),
                            remote_secret: remote_sec.clone(),
                            base_secret: Some(base_sec.clone()),
                        });
                    }
                } else {
                    conflicts.push(ConflictGroup {
                        title: local_sec.title.clone(),
                        category: local_sec.category.clone(),
                        username: local_sec.username.clone(),
                        local_secret: local_sec.clone(),
                        remote_secret: remote_sec.clone(),
                        base_secret: None,
                    });
                }
            }
        }
    }

    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    /// A scratch "device" directory: its own git repo, its own vault.db, all
    /// pointed at a shared bare "origin" repo -- mirrors the real
    /// `~/.config/keystash` setup on two separate machines syncing the same vault.
    struct Device {
        dir: PathBuf,
        vault_path: PathBuf,
    }

    fn scratch_root(name: &str) -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("target");
        dir.push("sync-test-tmp");
        dir.push(format!("{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("failed to create test root");
        dir
    }

    fn init_bare_origin(root: &PathBuf) -> PathBuf {
        let origin = root.join("origin.git");
        let status = Command::new("git").arg("init").arg("--bare").arg(&origin).status().unwrap();
        assert!(status.success());
        origin
    }

    fn init_device(root: &PathBuf, name: &str, origin: &PathBuf) -> Device {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for args in [
            vec!["init"],
            vec!["config", "user.name", "Test"],
            vec!["config", "user.email", "test@example.com"],
            vec!["remote", "add", "origin", origin.to_str().unwrap()],
            vec!["branch", "-M", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }
        Device { vault_path: dir.join("vault.db"), dir }
    }

    /// `git pull origin main` -- used the same way the README tells a second
    /// device to bring down an existing vault.
    fn pull(device: &Device) {
        let status = Command::new("git")
            .arg("pull")
            .arg("origin")
            .arg("main")
            .current_dir(&device.dir)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn find_secret<'a>(secrets: &'a [crate::db::SecretRecord], title: &str) -> &'a crate::db::SecretRecord {
        secrets.iter().find(|s| s.title == title).unwrap_or_else(|| panic!("secret {:?} not found", title))
    }

    /// End-to-end regression test for two related sync bugs:
    /// 1. A second device couldn't derive the right key at all without
    ///    `vault.salt` also being synced (it lives outside vault.db and the
    ///    documented `.gitignore` only allow-lists vault.db).
    /// 2. Resolving a sync conflict used to skip the real merge entirely,
    ///    silently dropping any *other* concurrent, non-conflicting change.
    #[test]
    fn conflict_resolution_preserves_unrelated_remote_changes() {
        let root = scratch_root("conflict_merge");
        let origin = init_bare_origin(&root);

        // --- Device A: create the vault, push the initial state ---
        // git_sync_vault always fetches origin/main first, so (matching the
        // README's actual Device A instructions) it's not used for this very
        // first push to a brand new, still-empty remote -- only for ongoing
        // sync afterwards.
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        crate::db::add_secret(&conn_a, "Common", "Cat", "user", "", "common-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db", "vault.salt"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clone it (this is the exact README "Device B" flow) ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        assert!(device_b.vault_path.exists(), "vault.db did not come down with git pull");
        assert!(
            device_b.vault_path.with_file_name("vault.salt").exists(),
            "vault.salt did not come down with git pull -- a second device could never derive the right key"
        );

        // Device B must be able to open the vault A created, with A's password,
        // using only what `git pull` brought down.
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password")
            .expect("Device B could not open the vault it just cloned");
        let secrets_b = crate::db::get_secrets(&conn_b).unwrap();
        assert_eq!(secrets_b.len(), 2);

        // Device B: one brand new, non-conflicting secret, and one edit to the
        // *same* record ("Common") that Device A is about to also edit below.
        crate::db::add_secret(&conn_b, "Bravo", "Cat", "user", "", "bravo-v1", None, &key_b).unwrap();
        let common_b = find_secret(&secrets_b, "Common");
        crate::db::update_secret(&conn_b, common_b.id, "Common", "Cat", "user", "", "common-v2-from-B", None, &key_b).unwrap();
        drop(conn_b);

        std::thread::sleep(Duration::from_millis(20));

        let push_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(push_b.is_ok(), "Device B's push failed: {:?}", push_b);

        std::thread::sleep(Duration::from_millis(20));

        // --- Back on Device A: edit "Common" too, *before* fetching B's push,
        // so both sides have genuinely diverged from the shared base. Each step
        // opens and drops its own connection rather than holding one open across
        // `detect_sync_conflicts` (which opens its own separate connection to
        // the same file) -- these are meant to be, and are exercised as,
        // independent connections exactly like the real CLI/TUI processes use.
        let a_sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_a);
        {
            let conn_a = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
            let secrets_a = crate::db::get_secrets(&conn_a).unwrap();
            let common_a = find_secret(&secrets_a, "Common");
            crate::db::update_secret(&conn_a, common_a.id, "Common", "Cat", "user", "", "common-v2-from-A", None, &key_a).unwrap();
        }

        // Device A fetches and should now see a genuine conflict on "Common"
        // (both sides changed it since the shared base), but no conflict on
        // "Alpha" (untouched) or "Bravo" (new on B's side only, not conflicting).
        let fetch_status = Command::new("git").arg("fetch").arg("origin").arg("main").current_dir(&device_a.dir).status().unwrap();
        assert!(fetch_status.success());
        let conflicts = super::detect_sync_conflicts(&device_a.vault_path, &key_a).unwrap();
        assert_eq!(conflicts.len(), 1, "expected exactly one conflict (Common), got: {:?}", conflicts.iter().map(|c| &c.title).collect::<Vec<_>>());
        assert_eq!(conflicts[0].title, "Common");

        std::thread::sleep(Duration::from_millis(20));

        // Resolve it exactly the way the TUI's 'r' ("keep remote") handler
        // does: re-stamp with a fresh "now" timestamp, not the old one.
        let resolved = &conflicts[0];
        {
            let conn_a = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
            let now = crate::db::now_timestamp(&conn_a).unwrap();
            crate::db::update_secret_raw(
                &conn_a,
                resolved.local_secret.id,
                &resolved.remote_secret.url,
                &resolved.remote_secret.encrypted_password,
                resolved.remote_secret.encrypted_notes.as_deref(),
                &now,
            ).unwrap();
        }

        // This is the exact call `trigger_postconflict_sync` now makes -- the
        // real merge, not a bare git add/commit/push.
        let final_sync = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(final_sync.is_ok(), "post-conflict sync failed: {:?}", final_sync);

        // Verify Device A ends up with all three: Alpha untouched, Common
        // resolved to B's version (what we chose), and -- the actual point of
        // this test -- Bravo, which was never part of the conflict and would
        // have been silently lost by the old bare commit/push logic.
        let conn_a_final = crate::db::open_keyed_connection(&device_a.vault_path, &crate::crypto::derive_sqlcipher_key(&key_a)).unwrap();
        let final_secrets = crate::db::get_secrets(&conn_a_final).unwrap();
        assert_eq!(final_secrets.len(), 3, "expected Alpha, Common, and Bravo; got: {:?}", final_secrets.iter().map(|s| &s.title).collect::<Vec<_>>());

        let alpha = find_secret(&final_secrets, "Alpha");
        assert_eq!(&*crate::crypto::decrypt(&alpha.encrypted_password, &key_a).unwrap(), b"alpha-v1");

        let common = find_secret(&final_secrets, "Common");
        assert_eq!(&*crate::crypto::decrypt(&common.encrypted_password, &key_a).unwrap(), b"common-v2-from-B");

        let bravo = find_secret(&final_secrets, "Bravo");
        assert_eq!(&*crate::crypto::decrypt(&bravo.encrypted_password, &key_a).unwrap(), b"bravo-v1");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for H2: two records that legitimately share the same
    /// (title, category, username) triple -- exactly the case the dedup
    /// screen exists to find -- must both survive a merge intact, keyed by
    /// sync_uuid rather than the ambiguous triple. Under the old triple-keyed
    /// merge, the "insert new secrets from remote" step's `NOT EXISTS` check
    /// matched purely on the triple: Device A already having *a* "Dup" row
    /// made it wrongly conclude Device B's distinct "Dup" row was already
    /// present, silently dropping it instead of merging it in.
    #[test]
    fn duplicate_triple_records_both_survive_a_merge() {
        let root = scratch_root("dup_triple");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Dup", "Cat", "user", "", "dup-v1-from-A", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db", "vault.salt"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // Device B clones A's vault (one "Dup" row) and independently adds its
        // *own* "Dup" row sharing the exact same triple -- the ambiguous case.
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();
        let secrets_b = crate::db::get_secrets(&conn_b).unwrap();
        assert_eq!(secrets_b.len(), 1);
        crate::db::add_secret(&conn_b, "Dup", "Cat", "user", "", "dup-v2-from-B", None, &key_b).unwrap();
        drop(conn_b);

        let push_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(push_b.is_ok(), "Device B's push failed: {:?}", push_b);

        // Device A merges B's push. If sync_uuid identity works, A ends up
        // with both "Dup" rows: its own original one, plus B's distinct one.
        let final_sync = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(final_sync.is_ok(), "Device A's merge failed: {:?}", final_sync);

        let conn_a_final = crate::db::open_keyed_connection(&device_a.vault_path, &crate::crypto::derive_sqlcipher_key(&key_a)).unwrap();
        let final_secrets = crate::db::get_secrets(&conn_a_final).unwrap();
        let dup_rows: Vec<&crate::db::SecretRecord> = final_secrets.iter().filter(|s| s.title == "Dup").collect();
        assert_eq!(
            dup_rows.len(),
            2,
            "expected both ambiguous-triple 'Dup' rows to survive the merge, got {} row(s)",
            dup_rows.len()
        );

        let decrypted_passwords: std::collections::HashSet<Vec<u8>> = dup_rows
            .iter()
            .map(|s| crate::crypto::decrypt(&s.encrypted_password, &key_a).unwrap().to_vec())
            .collect();
        assert!(decrypted_passwords.contains(&b"dup-v1-from-A".to_vec()));
        assert!(decrypted_passwords.contains(&b"dup-v2-from-B".to_vec()));

        // And their sync_uuids are genuinely distinct -- the whole point.
        assert_ne!(dup_rows[0].sync_uuid, dup_rows[1].sync_uuid);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for the tombstone PK collapse: deduping N >= 3 records
    /// sharing a (title, category, username) triple used to collapse the N-1
    /// tombstones into one slot (the old composite PRIMARY KEY plus INSERT OR
    /// REPLACE), so one deletion never propagated and the deleted duplicate
    /// resurrected on the other device at the next merge.
    #[test]
    fn dedup_deletions_of_shared_triple_records_propagate_to_other_devices() {
        let root = scratch_root("dedup_tombstones");
        let origin = init_bare_origin(&root);

        // --- Device A: three records sharing the same triple, pushed. ---
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        for pw in ["dup-v1", "dup-v2", "dup-keep"] {
            crate::db::add_secret(&conn_a, "Dup", "Cat", "user", "", pw, None, &key_a).unwrap();
        }
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db", "vault.salt"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clones all three. ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();
        assert_eq!(crate::db::get_secrets(&conn_b).unwrap().len(), 3);
        drop(conn_b);

        std::thread::sleep(Duration::from_millis(20));

        // --- Device A dedups: keep "dup-keep", delete the other two, then
        // re-stamp the kept record -- exactly what the TUI's dedup screen
        // does (delete_secret per loser, restamp_record on the winner). ---
        let a_sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_a);
        let keep_uuid;
        {
            let conn_a = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
            let secrets = crate::db::get_secrets(&conn_a).unwrap();
            let keep = secrets
                .iter()
                .find(|s| crate::crypto::decrypt(&s.encrypted_password, &key_a).unwrap().as_slice() == b"dup-keep")
                .unwrap();
            keep_uuid = keep.sync_uuid.clone();
            let losers: Vec<i64> = secrets.iter().filter(|s| s.id != keep.id).map(|s| s.id).collect();
            for id in &losers {
                crate::db::delete_secret(&conn_a, *id).unwrap();
            }
            let now = crate::db::now_timestamp(&conn_a).unwrap();
            crate::db::update_secret_raw(
                &conn_a,
                keep.id,
                &keep.url,
                &keep.encrypted_password,
                keep.encrypted_notes.as_deref(),
                &now,
            )
            .unwrap();
        }

        let push_a = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(push_a.is_ok(), "Device A's post-dedup sync failed: {:?}", push_a);

        // --- Device B merges. Both deletions must land; the kept record
        // must survive. ---
        let sync_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(sync_b.is_ok(), "Device B's merge failed: {:?}", sync_b);

        let count_tombstones = |vault_path: &PathBuf, key: &[u8; 32]| -> Vec<Option<String>> {
            let conn = crate::db::open_keyed_connection(vault_path, &crate::crypto::derive_sqlcipher_key(key)).unwrap();
            let mut stmt = conn.prepare("SELECT sync_uuid FROM deleted_secrets").unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap();
            rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };

        let conn_b_final = crate::db::open_keyed_connection(&device_b.vault_path, &crate::crypto::derive_sqlcipher_key(&key_b)).unwrap();
        let final_secrets = crate::db::get_secrets(&conn_b_final).unwrap();
        assert_eq!(
            final_secrets.len(),
            1,
            "the two deduped duplicates must not resurrect on Device B, got: {:?}",
            final_secrets.iter().map(|s| (&s.title, &s.sync_uuid)).collect::<Vec<_>>()
        );
        assert_eq!(final_secrets[0].sync_uuid, keep_uuid);
        assert_eq!(
            &*crate::crypto::decrypt(&final_secrets[0].encrypted_password, &key_b).unwrap(),
            b"dup-keep"
        );
        drop(conn_b_final);

        // All N-1 tombstones exist on both sides, each with its own uuid.
        for (label, vault_path, key) in [
            ("Device A", &device_a.vault_path, &key_a),
            ("Device B", &device_b.vault_path, &key_b),
        ] {
            let uuids = count_tombstones(vault_path, key);
            assert_eq!(uuids.len(), 2, "{}: expected both tombstones, got {:?}", label, uuids);
            assert!(uuids.iter().all(|u| u.is_some()), "{}: tombstones must carry sync_uuids", label);
            assert_ne!(uuids[0], uuids[1], "{}: tombstones must be distinct", label);
            assert!(!uuids.contains(&Some(keep_uuid.clone())), "{}: the kept record must not have a tombstone", label);
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for the sync_uuid rollout deadlock: if the first sync
    /// attempt from an upgraded device against a pre-sync_uuid remote just
    /// refused outright, no device could ever be the first to introduce the
    /// new schema to a shared repo -- git has no way for one device to know
    /// the other has updated, so every device would refuse forever. This
    /// builds a vault by hand matching the exact pre-H2 schema (no sync_uuid
    /// column anywhere), pushes it as "device A, not yet updated", then has
    /// an already-updated "device B" pull it, add its own secret, and sync --
    /// the push must succeed and must carry the new schema into the shared
    /// repo, not just fail with "update the other device".
    #[test]
    fn first_upgraded_device_can_still_push_to_a_pre_sync_uuid_remote() {
        let root = scratch_root("legacy_remote");
        let origin = init_bare_origin(&root);

        // --- Device A: a vault written by pre-H2 KeyStash (SQLCipher-encrypted,
        // but its secrets/deleted_secrets tables have no sync_uuid column) ---
        let device_a = init_device(&root, "device_a", &origin);
        let salt = crate::crypto::generate_salt();
        let master_key = crate::crypto::derive_key("shared-master-password", &salt).unwrap();
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&master_key);
        {
            let conn = crate::db::open_keyed_connection(&device_a.vault_path, &sqlcipher_key).unwrap();
            conn.execute_batch(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                 CREATE TABLE secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL,
                    username TEXT NOT NULL, url TEXT NOT NULL DEFAULT '', encrypted_password BLOB NOT NULL,
                    encrypted_notes BLOB, updated_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')));
                 CREATE TABLE deleted_secrets (title TEXT NOT NULL, category TEXT NOT NULL, username TEXT NOT NULL,
                    deleted_at DATETIME DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')), PRIMARY KEY (title, category, username));
                 CREATE TABLE hibp_checks (password_hash TEXT PRIMARY KEY, hibp_count INTEGER);",
            ).unwrap();
            let token = crate::crypto::encrypt(b"keystash-verification-token", &master_key).unwrap();
            conn.execute("INSERT INTO metadata (key, value) VALUES ('verification', ?1)", rusqlite::params![token]).unwrap();
            let enc_pass = crate::crypto::encrypt(b"old-format-secret-v1", &master_key).unwrap();
            conn.execute(
                "INSERT INTO secrets (title, category, username, url, encrypted_password) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params!["OldFormat", "Cat", "user", "", enc_pass],
            ).unwrap();
        }
        let salt_path = device_a.vault_path.with_file_name("vault.salt");
        std::fs::write(&salt_path, salt).unwrap();

        for args in [
            vec!["add", "-f", "vault.db", "vault.salt"],
            vec!["commit", "-m", "Initial vault backup (pre-sync_uuid)"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: already on the updated KeyStash version. Pulls A's
        // pre-sync_uuid vault; open_vault's ensure_schema call silently
        // upgrades B's *local* copy (adds + backfills sync_uuid) regardless
        // of what's on the remote. ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password")
            .expect("Device B should be able to open A's pre-sync_uuid vault");
        let secrets_before = crate::db::get_secrets(&conn_b).unwrap();
        assert_eq!(secrets_before.len(), 1);
        crate::db::add_secret(&conn_b, "NewFromB", "Cat", "user", "", "new-v1-from-B", None, &key_b).unwrap();
        drop(conn_b);

        // The critical assertion: this must succeed (and actually push),
        // not refuse with "update the other device first".
        let push_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(push_b.is_ok(), "Device B's sync against a pre-sync_uuid remote should merge and push, not refuse: {:?}", push_b);

        let conn_b_final = crate::db::open_keyed_connection(&device_b.vault_path, &crate::crypto::derive_sqlcipher_key(&key_b)).unwrap();
        let final_secrets = crate::db::get_secrets(&conn_b_final).unwrap();
        assert_eq!(final_secrets.len(), 2, "expected OldFormat and NewFromB, got: {:?}", final_secrets.iter().map(|s| &s.title).collect::<Vec<_>>());
        for s in &final_secrets {
            assert!(!s.sync_uuid.is_empty(), "every row should have a real sync_uuid after the legacy-merge backfill, got empty for {:?}", s.title);
        }

        // --- Confirm the push actually carried the new schema into the
        // shared repo, not just into Device B's own local file: a brand new
        // Device C cloning from origin now should see the sync_uuid column. ---
        let device_c = init_device(&root, "device_c", &origin);
        pull(&device_c);
        let conn_c = crate::db::open_keyed_connection(&device_c.vault_path, &sqlcipher_key).unwrap();
        let remote_has_sync_uuid: bool = conn_c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('secrets') WHERE name = 'sync_uuid'",
                [],
                |row| { let c: i64 = row.get(0)?; Ok(c > 0) },
            )
            .unwrap();
        assert!(remote_has_sync_uuid, "origin/main should now have the sync_uuid column after Device B's push");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for the general forward-compatibility gate: syncing
    /// against a remote whose stored `min_app_version` is newer than this
    /// binary must refuse to merge with a clear message, not attempt the
    /// merge and fail with a confusing raw SQL/schema error. Device B's own
    /// local vault is deliberately left at the normal floor throughout, so
    /// this isolates the sync-time gate (checking the fetched remote copy)
    /// from the separate open-time gate (checking the local file), which is
    /// already covered by `open_vault_refuses_a_vault_requiring_a_newer_version`
    /// in db.rs.
    #[test]
    fn sync_refuses_a_remote_requiring_a_newer_version() {
        let root = scratch_root("min_version_remote");
        let origin = init_bare_origin(&root);

        // --- Device A: push a normal vault first (floor 0.3.0, as usual). ---
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db", "vault.salt"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clones it while the floor is still normal, and opens
        // successfully -- its own local vault never changes for the rest of
        // this test. ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password")
            .expect("Device B should open the normal-floor vault it just cloned");

        // --- Back on Device A: simulate a future device having made a
        // genuinely breaking change and pushed it (manipulated directly,
        // since no such change exists yet to exercise honestly). ---
        let sqlcipher_key_a = crate::crypto::derive_sqlcipher_key(&key_a);
        {
            let conn_a2 = crate::db::open_keyed_connection(&device_a.vault_path, &sqlcipher_key_a).unwrap();
            conn_a2.execute(
                "UPDATE metadata SET value = '99.0.0' WHERE key = 'min_app_version'",
                [],
            ).unwrap();
        }
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Bump floor (from the future)"],
            vec!["push", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // Device B's own local vault is still at the normal floor and would
        // otherwise be able to derive the right key and merge -- only the
        // remote copy it's about to fetch carries the bumped floor.
        let sync_result = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(sync_result.is_err(), "syncing against a remote requiring a newer version should refuse, not merge");
        let err = sync_result.unwrap_err();
        assert!(err.contains("99.0.0"), "error should name the required version, got: {}", err);

        let _ = std::fs::remove_dir_all(&root);
    }
}
