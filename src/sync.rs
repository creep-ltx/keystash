use std::path::Path;
use std::process::{Command, Stdio};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

/// Combined with the process id, guarantees the temp filenames below are unique
/// even across two sync operations racing on separate threads within the same
/// process (which share a process id) -- relying on process id alone caused a
/// real collision where two concurrently-running syncs read/wrote/deleted the
/// same temp file out from under each other.
static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
fn unique_tmp_suffix() -> u64 {
    TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
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
    
    // Cleanup any stale temporary files
    if remote_db_path.exists() {
        let _ = fs::remove_file(&remote_db_path);
    }

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
            let _ = fs::remove_file(&remote_db_path);

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

            // Start Transaction
            conn.execute("BEGIN TRANSACTION", [])
                .map_err(|e| format!("Failed to start merge transaction: {}", e))?;

            let merge_steps = vec![
                // Delete local records if remote deleted them and the deletion is newer than the local update
                "DELETE FROM main.secrets
                 WHERE EXISTS (
                     SELECT 1 FROM remote_db.deleted_secrets rd
                     WHERE main.secrets.title = rd.title
                       AND main.secrets.category = rd.category
                       AND main.secrets.username = rd.username
                       AND rd.deleted_at > main.secrets.updated_at
                 )",

                // Copy new secrets from remote to local
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

                // Update local secrets if remote is newer
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

                // Sync deleted_secrets tombstones from remote to local
                "INSERT OR REPLACE INTO main.deleted_secrets (title, category, username, deleted_at)
                 SELECT title, category, username, deleted_at FROM remote_db.deleted_secrets"
            ];

            for step in merge_steps {
                if let Err(e) = conn.execute(step, []) {
                    let _ = conn.execute("ROLLBACK", []);
                    let _ = fs::remove_file(&remote_db_path);
                    return Err(format!("Database merge transaction failed: {}", e));
                }
            }

            conn.execute("COMMIT", []).map_err(|e| format!("Failed to commit merge: {}", e))?;

            // Detach database
            let _ = conn.execute("DETACH DATABASE remote_db", []);
            let _ = fs::remove_file(&remote_db_path);
        } else {
            let backup_path = dir.join(format!(
                "vault.db.unmerged-remote-{}",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            if fs::copy(&remote_db_path, &backup_path).is_ok() {
                unmerged_remote_backup = Some(backup_path);
            }
            let _ = fs::remove_file(&remote_db_path);
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
    
    let _ = fs::remove_file(&remote_db_path);
    let _ = fs::remove_file(&base_db_path);

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
        Err(_) => {
            let _ = fs::remove_file(&remote_db_path);
            let _ = fs::remove_file(&base_db_path);
            return Ok(Vec::new());
        }
    };

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

    let _ = fs::remove_file(&remote_db_path);
    let _ = fs::remove_file(&base_db_path);

    use std::collections::HashMap;
    let mut local_map: HashMap<(String, String, String), crate::db::SecretRecord> = HashMap::new();
    for s in local_secrets {
        local_map.insert((s.title.clone(), s.category.clone(), s.username.clone()), s);
    }

    let mut remote_map: HashMap<(String, String, String), crate::db::SecretRecord> = HashMap::new();
    for s in remote_secrets {
        remote_map.insert((s.title.clone(), s.category.clone(), s.username.clone()), s);
    }

    let mut base_map: HashMap<(String, String, String), crate::db::SecretRecord> = HashMap::new();
    for s in base_secrets {
        base_map.insert((s.title.clone(), s.category.clone(), s.username.clone()), s);
    }

    let mut conflicts = Vec::new();

    for (k, local_sec) in &local_map {
        if let Some(remote_sec) = remote_map.get(k) {
            let local_pw = crate::crypto::decrypt(&local_sec.encrypted_password, key)
                .map(|d| String::from_utf8_lossy(&d).into_owned())
                .unwrap_or_default();
            let remote_pw = crate::crypto::decrypt(&remote_sec.encrypted_password, key)
                .map(|d| String::from_utf8_lossy(&d).into_owned())
                .unwrap_or_default();

            let local_notes = if let Some(notes) = &local_sec.encrypted_notes {
                crate::crypto::decrypt(notes, key)
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let remote_notes = if let Some(notes) = &remote_sec.encrypted_notes {
                crate::crypto::decrypt(notes, key)
                    .map(|d| String::from_utf8_lossy(&d).into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let differs = local_pw != remote_pw || local_notes != remote_notes || local_sec.url != remote_sec.url;
            if differs {
                if let Some(base_sec) = base_map.get(k) {
                    let base_pw = crate::crypto::decrypt(&base_sec.encrypted_password, key)
                        .map(|d| String::from_utf8_lossy(&d).into_owned())
                        .unwrap_or_default();
                    let base_notes = if let Some(notes) = &base_sec.encrypted_notes {
                        crate::crypto::decrypt(notes, key)
                            .map(|d| String::from_utf8_lossy(&d).into_owned())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    let local_changed = local_pw != base_pw || local_notes != base_notes || local_sec.url != base_sec.url;
                    let remote_changed = remote_pw != base_pw || remote_notes != base_notes || remote_sec.url != base_sec.url;

                    if local_changed && remote_changed {
                        conflicts.push(ConflictGroup {
                            title: k.0.clone(),
                            category: k.1.clone(),
                            username: k.2.clone(),
                            local_secret: local_sec.clone(),
                            remote_secret: remote_sec.clone(),
                            base_secret: Some(base_sec.clone()),
                        });
                    }
                } else {
                    conflicts.push(ConflictGroup {
                        title: k.0.clone(),
                        category: k.1.clone(),
                        username: k.2.clone(),
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
}
