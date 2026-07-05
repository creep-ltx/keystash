use std::path::Path;
use std::process::{Command, Stdio};
use std::fs;
use rusqlite::Connection;

/// Check if the database folder is configured as a git repository.
pub fn is_git_configured<P: AsRef<Path>>(db_path: P) -> bool {
    if let Some(parent) = db_path.as_ref().parent() {
        parent.join(".git").exists()
    } else {
        false
    }
}

/// Perform a full git pull, logical SQLite database merge, auto-commit, and git push.
pub fn git_sync_vault<P: AsRef<Path>>(db_path: P) -> Result<String, String> {
    let db_ref = db_path.as_ref();
    let dir = db_ref.parent().ok_or("Invalid database directory")?;

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
    let remote_db_path = dir.join("vault_remote.db");
    
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
    if has_remote {
        if !db_ref.exists() {
            fs::copy(&remote_db_path, db_ref).map_err(|e| format!("Failed to restore vault.db from remote: {}", e))?;
            let _ = fs::remove_file(&remote_db_path);
            return Ok("Sync complete: Local vault restored from remote repository!".to_string());
        }

        let conn = Connection::open(db_ref).map_err(|e| format!("Local database open error: {}", e))?;
        
        // Attach the remote database
        let remote_path_str = remote_db_path.to_string_lossy();
        let escaped_path = remote_path_str.replace('\'', "''");
        conn.execute(&format!("ATTACH DATABASE '{}' AS remote_db", escaped_path), [])
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

        // Align local branch history with the remote before committing (preserves merged vault.db)
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

    if is_dirty {
        Ok("Sync complete: Local and remote vaults merged and updated!".to_string())
    } else {
        Ok("Sync complete: Vault is already up-to-date with remote.".to_string())
    }
}
