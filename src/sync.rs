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

/// First 16 bytes of a file: the SQLCipher header salt for an encrypted
/// vault (which on the 0.3.6+ format is also the Argon2 salt), or SQLite's
/// plaintext magic for a legacy pre-encryption one. `None` if unreadable or
/// shorter than 16 bytes.
fn read_file_head(path: &Path) -> Option<[u8; crate::crypto::SALT_LEN]> {
    use std::io::Read;
    let mut head = [0u8; crate::crypto::SALT_LEN];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .ok()
        .map(|_| head)
}

/// Builds a `git` `Command` pre-loaded with the flags every invocation in
/// this file needs: a low-speed abort so a stalled connection doesn't hang
/// forever (`http.lowSpeedLimit`/`http.lowSpeedTime` -- the actual timeout
/// knobs; `connection.timeout` isn't a real git config key and silently did
/// nothing), no credential prompting (`GIT_TERMINAL_PROMPT=0` -- without it,
/// a credential-prompting HTTPS remote tries to write a prompt wherever git
/// thinks the controlling terminal is, which for a background sync thread
/// means hanging forever or garbling a raw-mode TUI screen), a bounded SSH
/// connect timeout, and a null stdin so nothing can block waiting for input
/// that will never come. Safe to use for purely local commands (`reset`,
/// `add`, `commit`, ...) too -- they just ignore the network-only flags.
///
/// Every invocation below assumes a single remote named `origin` with a
/// `main` branch, matching the setup the README walks through; there's no
/// support (yet) for a differently-named remote or default branch.
pub(crate) fn git_command(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-c").arg("http.lowSpeedLimit=1000")
        .arg("-c").arg("http.lowSpeedTime=5")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o ConnectTimeout=5 -o ConnectionAttempts=1")
        .current_dir(dir)
        .stdin(Stdio::null());
    cmd
}

/// Check if the database folder is configured as a git repository.
pub fn is_git_configured<P: AsRef<Path>>(db_path: P) -> bool {
    if let Some(parent) = db_path.as_ref().parent() {
        parent.join(".git").exists()
    } else {
        false
    }
}

/// The testable core behind `keystash sync setup` (main.rs owns the
/// interactive prompting and mode auto-detection). Turns the config
/// directory into a ready-to-sync git repository: init, the two-line
/// `.gitignore`, `origin` remote, `main` branch, a repo-local git identity
/// if none resolves (sync's auto-commits need one; a missing identity was a
/// documented commit-failure cause), a connectivity probe -- then either
/// pushes the existing local vault as the initial backup (`first_device`)
/// or pulls the existing vault down from the remote. Replaces the
/// eight-command README incantation and its two traps (the hand-typed
/// .gitignore, and running `init` on a second device).
///
/// Works with any git remote -- a GitHub/GitLab private repo, any
/// SSH-reachable machine (`user@server:vault.git`), or a plain filesystem
/// path like a NAS mount or USB stick (`/mnt/nas/vault.git`).
pub fn setup_sync_repo(db_path: &Path, remote_url: &str, first_device: bool) -> Result<String, String> {
    let dir = db_path.parent().ok_or("Invalid database directory")?;

    if dir.join(".git").exists() {
        return Err(
            "This directory is already a git repository. To point it at a different remote, run \
             `git remote set-url origin <url>` in it manually -- setup won't touch an existing repo."
                .to_string(),
        );
    }
    if first_device && !db_path.exists() {
        return Err(
            "No local vault found to push. Run `keystash init` (or the TUI first-run setup) to \
             create one first, then re-run `keystash sync setup`."
                .to_string(),
        );
    }
    if !first_device && db_path.exists() {
        return Err(
            "A local vault already exists here, but additional-device setup expects to pull the \
             vault from the remote. If this device's vault is the one to keep, choose first-device \
             setup; otherwise move ~/.config/keystash/vault.db aside and re-run."
                .to_string(),
        );
    }

    let run = |args: &[&str], failure: &str| -> Result<(), String> {
        let status = git_command(dir)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("{}: {}", failure, e))?;
        if !status.success() {
            return Err(failure.to_string());
        }
        Ok(())
    };

    run(&["init"], "git init failed")?;
    fs::write(dir.join(".gitignore"), "*\n!vault.db\n")
        .map_err(|e| format!("Could not write .gitignore: {}", e))?;
    run(&["remote", "add", "origin", remote_url], "git remote add failed")?;
    run(&["branch", "-M", "main"], "git branch -M main failed")?;

    // Sync's auto-commits need a resolvable identity; without one, `git
    // commit` fails. If the user has a global identity it wins; otherwise
    // set a repo-local placeholder -- these commits are machine-generated
    // sync snapshots, not authorship anyone reads.
    let identity_resolves = git_command(dir)
        .args(["config", "user.email"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !identity_resolves {
        run(&["config", "user.name", "KeyStash"], "git config user.name failed")?;
        run(&["config", "user.email", "keystash@localhost"], "git config user.email failed")?;
    }

    // Reachability probe before doing anything with data: a typo'd URL
    // should fail here, with the remote named, not three steps later.
    let probe = git_command(dir)
        .args(["ls-remote", "origin"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("Could not run git ls-remote: {}", e))?;
    if !probe.success() {
        return Err(format!(
            "The remote '{}' is not reachable (check the URL, your SSH keys/credentials, and that \
             the repository exists). Nothing was pushed or pulled; fix the URL with \
             `git remote set-url origin <url>` and re-run `keystash sync`.",
            remote_url
        ));
    }

    if first_device {
        // .gitignore whitelists vault.db, so no -f needed.
        run(&["add", "vault.db"], "git add vault.db failed")?;
        run(&["commit", "-m", "Initial vault backup"], "git commit failed")?;
        run(&["push", "-u", "origin", "main"],
            "git push failed -- if the remote already contains a vault, this device isn't the \
             first one: move the local vault aside and re-run setup as an additional device")?;
        Ok("Sync configured: the local vault was pushed as the initial backup. Other devices can \
            now run `keystash sync setup` as additional devices."
            .to_string())
    } else {
        run(&["pull", "origin", "main"],
            "git pull failed -- the remote may be empty (set up the first device before adding \
             more) or unreachable")?;
        if !db_path.exists() {
            return Err(
                "The remote was pulled but contains no vault.db -- set up the first device (the \
                 one that already has a vault) before adding this one."
                    .to_string(),
            );
        }
        Ok("Sync configured: the vault was pulled from the remote. Run `keystash` and unlock with \
            the vault's master password."
            .to_string())
    }
}

/// The commit hash a ref points at, or `None` if it can't be resolved (fresh
/// repo with no commits, remote branch that doesn't exist yet, ...).
fn rev_parse(dir: &Path, reference: &str) -> Option<String> {
    git_command(dir)
        .arg("rev-parse")
        .arg(reference)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Prunes expired tombstones and checkpoints the WAL into the main vault
/// file. Best-effort on both counts (see the call sites for why each
/// matters); called before anything decides what to stage or whether the
/// on-disk file differs from the committed one -- a fresh edit through the
/// TUI's still-open connection lives in vault.db-wal, invisible to git,
/// until this runs.
fn prune_and_checkpoint(db_ref: &Path, sqlcipher_key: &[u8; 32]) {
    if let Ok(conn) = crate::db::open_keyed_connection(db_ref, sqlcipher_key) {
        let _ = crate::db::prune_old_tombstones(&conn);
        // History rows whose record was deleted by a merged-in tombstone
        // (the merge deletes the secret but doesn't know about history).
        let _ = crate::db::prune_orphaned_history(&conn);
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
}

/// Whether the files sync manages (vault.db, and a legacy vault.salt) differ
/// from the committed state -- scoped so stray untracked files in the config
/// dir can never make a sync look dirty.
fn vault_paths_dirty(dir: &Path) -> Result<bool, String> {
    let status_output = git_command(dir)
        .arg("status")
        .arg("--porcelain")
        .arg("--")
        .arg("vault.db")
        .arg("vault.salt")
        .output()
        .map_err(|e| format!("git status failed: {}", e))?;
    Ok(!status_output.stdout.is_empty())
}

/// `git_sync_vault` without history retention -- what tests and callers
/// that don't carry a config use. Production call sites (TUI triggers, CLI
/// commands) go through `git_sync_vault_with_retention` with the configured
/// value instead.
pub fn git_sync_vault<P: AsRef<Path>>(db_path: P, key: &[u8; 32]) -> Result<String, String> {
    git_sync_vault_with_retention(db_path, key, 0)
}

/// Squashes history older than the newest `keep` snapshots into a single
/// root commit and force-pushes the rewritten (still linear) history.
/// Returns a note to append to the sync message: what happened, or a plain
/// warning on failure -- retention must never turn a *successful* sync into
/// an error, since the push itself already landed.
///
/// Safe by construction for the other devices: every sync fetches and then
/// `git reset origin/main`s before committing on top, so rewritten history
/// is transparent to the data flow. A device that last synced *before* the
/// squash horizon merely loses its 3-way merge base (`has_base = false`,
/// already handled -- more conservative conflict prompts, never data loss).
/// The rebuild uses commit-tree plumbing rather than rebase: every commit
/// here is a whole-file snapshot of vault.db, so the new chain just re-parents
/// the kept snapshots' trees verbatim -- no patch application, no working-
/// tree involvement, byte-identical content guaranteed.
fn maybe_squash_history(dir: &Path, keep: u64) -> Option<String> {
    if keep == 0 {
        return None;
    }

    let git_out = |args: &[&str]| -> Option<String> {
        git_command(dir)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };

    let count: u64 = git_out(&["rev-list", "--count", "HEAD"])?.parse().ok()?;
    if count <= keep {
        return None;
    }

    let old_head = git_out(&["rev-parse", "HEAD"])?;
    // The oldest snapshot to keep; everything before it collapses into the
    // new root, which carries this commit's own tree -- so the kept window
    // still starts from a complete vault state, not a diff.
    let horizon = git_out(&["rev-parse", &format!("HEAD~{}", keep - 1)])?;

    let mut parent = git_out(&[
        "commit-tree",
        &format!("{}^{{tree}}", horizon),
        "-m",
        &format!("keystash: history squashed by retention policy (keeping last {} snapshots)", keep),
    ])?;
    let newer = git_out(&["rev-list", "--reverse", &format!("{}..HEAD", horizon)])?;
    for commit in newer.lines() {
        let msg = git_out(&["log", "-1", "--format=%s", commit]).unwrap_or_else(|| "sync: auto-merge vault updates".to_string());
        parent = git_out(&["commit-tree", &format!("{}^{{tree}}", commit), "-p", &parent, "-m", &msg])?;
    }

    // The final rebuilt commit has the exact tree of the old HEAD, so a
    // soft reset moves the branch without disturbing index or working tree.
    let reset_ok = git_command(dir)
        .args(["reset", "--soft", &parent])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !reset_ok {
        return Some(" (History retention: local branch reset failed; history left unchanged.)".to_string());
    }

    // --force-with-lease, never plain force: if another device pushed
    // between our push moments ago and now, its commit wins and this squash
    // simply doesn't happen this time.
    let push_ok = git_command(dir)
        .args(["push", "--force-with-lease", "origin", "main"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !push_ok {
        // Undo the local rewrite so local and remote histories stay in step.
        let _ = git_command(dir)
            .args(["reset", "--soft", &old_head])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        return Some(
            " (History retention: the remote refused the rewritten history -- a protected branch \
             blocks force-pushes, or another device pushed concurrently. Vault sync itself \
             succeeded; retention will retry next sync.)"
                .to_string(),
        );
    }

    // Local housekeeping only; the remote reclaims space on its own
    // schedule (or via a server-side `git gc` for self-hosted bare repos).
    let _ = git_command(dir)
        .args(["gc", "--auto", "--quiet"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    Some(format!(" History squashed to the most recent {} snapshots.", keep))
}

/// Perform a full git pull, logical SQLite database merge, auto-commit, and git push.
///
/// `key` is the master key (the same one returned by `db::open_vault` et al.) --
/// this derives the independent SQLCipher key from it internally wherever a
/// connection needs to be opened or attached, since the vault is now a
/// whole-database-encrypted file. `history_retention` (0 = unlimited) is
/// the configured snapshot-retention setting, applied after a successful
/// push -- see `maybe_squash_history`.
pub fn git_sync_vault_with_retention<P: AsRef<Path>>(db_path: P, key: &[u8; 32], history_retention: u64) -> Result<String, String> {
    let db_ref = db_path.as_ref();
    let dir = db_ref.parent().ok_or("Invalid database directory")?;
    let sqlcipher_key = crate::crypto::derive_sqlcipher_key(key);
    let pragma_hex = crate::crypto::pragma_key_hex(&sqlcipher_key);

    if !dir.join(".git").exists() {
        // Name the vault's actual directory -- under --profile or
        // KEYSTASH_CONFIG_DIR it isn't ~/.config/keystash, and telling the
        // user to set up git in the wrong place would send them to create a
        // repo the app will never look at.
        return Err(format!(
            "Sync not configured. Run `keystash sync setup` (or set up git in {}) to enable syncing.",
            dir.display()
        ));
    }

    // The README's setup steps write a two-line .gitignore (ignore
    // everything, track only vault.db), but nothing ever created or
    // verified it -- and without it, the untracked -wal/-shm sidecars and
    // any backup/export files in the config dir made `git status` dirty on
    // every sync. Write it if absent so sync is self-sufficient; never
    // touch an existing one (a user's customized version wins).
    let gitignore_path = dir.join(".gitignore");
    if !gitignore_path.exists() {
        let _ = fs::write(&gitignore_path, "*\n!vault.db\n");
    }

    // 1. Run git fetch to see if remote changes exist
    let fetch_status = git_command(dir)
        .arg("fetch")
        .arg("origin")
        .arg("main")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("git fetch failed: {}", e))?;

    if !fetch_status.success() {
        // A fetch of origin/main also fails on a remote that is perfectly
        // reachable but simply has no branch yet -- a brand-new empty repo
        // awaiting its very first push. Tell the two apart with ls-remote:
        // reachable + no main ref means "first push", and the normal
        // stage/commit/push below creates the branch (vault.db is untracked
        // in a fresh repo, so the dirtiness check sees it). Everything else
        // stays a hard connectivity error.
        let empty_remote = git_command(dir)
            .args(["ls-remote", "origin", "main"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| o.stdout.is_empty())
            .unwrap_or(false);
        if !empty_remote {
            return Err("Could not reach git remote 'origin/main'. Check network or SSH configuration.".to_string());
        }
    }

    // Short-circuit: the fetch above already answered "did the remote
    // move?" -- the commit hash is the vault's version number. If
    // origin/main is exactly our HEAD, the remote holds nothing we haven't
    // already merged, so the whole extract/attach/merge/reset ceremony
    // below (and, when nothing changed locally either, the no-op push) is
    // pure waste -- previously every no-change sync paid for all of it,
    // twice per session (post-unlock and exit).
    //
    // Guarded on the local vault file existing: a missing vault.db must
    // keep flowing into the restore-from-remote path below, never into a
    // dirtiness check that would stage (and push!) the file's deletion.
    //
    // Prune+checkpoint runs *before* the dirtiness check, not just for the
    // staging correctness documented on the helper: an edit made through
    // the TUI's open connection seconds ago is WAL-resident, and git would
    // otherwise report the main file unchanged -- wrongly concluding
    // "up-to-date" and leaving the edit unpushed until some later sync.
    let heads_equal = match (rev_parse(dir, "HEAD"), rev_parse(dir, "origin/main")) {
        (Some(local), Some(remote)) => local == remote,
        _ => false, // fresh repo or no remote branch yet: take the full path
    };
    let skip_merge = db_ref.exists() && heads_equal;
    if skip_merge {
        prune_and_checkpoint(db_ref, &sqlcipher_key);
        if !vault_paths_dirty(dir)? {
            // Retention still runs on the up-to-date path -- otherwise a
            // vault that stopped changing would never get its history
            // squashed after the user enables the setting.
            let mut msg = "Sync complete: Vault is already up-to-date with remote.".to_string();
            if let Some(note) = maybe_squash_history(dir, history_retention) {
                msg.push_str(&note);
            }
            return Ok(msg);
        }
        // Local-only changes on top of a remote we're already level with:
        // nothing to merge, fall through directly to stage/commit/push.
    }

    // Determine if we have remote commits we need to merge
    let remote_db_path = dir.join(format!("vault_remote_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let _cleanup = TempCleanup(vec![remote_db_path.clone()]);

    // (backup path, remote was a legacy plaintext copy) -- set when the
    // remote couldn't be merged and local gets pushed as source of truth.
    let mut unmerged_remote_backup: Option<(std::path::PathBuf, bool)> = None;

    // Extract remote database to temp file using git show. Skipped entirely
    // on the short-circuit fast path: heads equal means the remote copy is
    // byte-identical to our own last-merged state.
    let mut has_remote = false;
    if !skip_merge
        && let Ok(output) = git_command(dir)
            .arg("show")
            .arg("origin/main:vault.db")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        && output.status.success() && !output.stdout.is_empty()
            && fs::write(&remote_db_path, output.stdout).is_ok() {
                has_remote = true;
            }

    // 2. Perform SQLite logical merge if remote database was successfully extracted
    if has_remote {
        if !db_ref.exists() {
            fs::copy(&remote_db_path, db_ref).map_err(|e| format!("Failed to restore vault.db from remote: {}", e))?;

            // Transitional: repos last pushed by a pre-0.3.6 device still
            // track a vault.salt sidecar, and their vault.db's header salt is
            // random rather than the Argon2 salt -- restoring such a repo
            // without the sidecar would leave the vault permanently locked.
            // Restore it if present; the first unlock then converts the vault
            // to the embedded-salt layout and deletes the sidecar again. For
            // repos already on the current format this fetch finds nothing
            // and is a no-op.
            let salt_path = db_ref.with_file_name("vault.salt");
            if !salt_path.exists()
                && let Ok(salt_output) = git_command(dir)
                    .arg("show")
                    .arg("origin/main:vault.salt")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output()
                    && salt_output.status.success() && !salt_output.stdout.is_empty() {
                        let _ = fs::write(&salt_path, salt_output.stdout);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o600));
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
            // pragma_hex is already Zeroizing<String> -- build the SQL
            // statement itself as one too instead of a plain format! temporary.
            let attach_sql: Zeroizing<String> = Zeroizing::new(
                format!("ATTACH DATABASE '{}' AS remote_db KEY \"x'{}'\"", escaped_path, *pragma_hex)
            );
            conn.execute(&attach_sql, [])
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
                    // one remote row. Every mutable column must be carried,
                    // title/category/username included: sync_uuid becoming the
                    // merge identity turned the triple into ordinary editable
                    // payload, and leaving it out of this SET list silently
                    // dropped renames -- while still copying updated_at, so
                    // both sides ended up with equal timestamps and the
                    // divergence never healed on any later sync.
                    "UPDATE main.secrets
                     SET title = (SELECT title FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         category = (SELECT category FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         username = (SELECT username FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
                         url = (SELECT url FROM remote_db.secrets r WHERE r.sync_uuid = main.secrets.sync_uuid),
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

            // Password-history union merge, gated on the remote actually
            // having the table (a vault last pushed by a pre-history
            // version doesn't -- same transitional pattern as the
            // sync_uuid check above, same statement-form PRAGMA footgun
            // avoided). Rows are identified by (sync_uuid, replaced_at);
            // only records that exist locally after the steps above get
            // history (deleted records' rows are pruned separately). Cap
            // re-enforced afterward: two devices can each contribute
            // near-cap histories for the same record.
            let remote_has_history: bool = {
                let mut stmt = conn
                    .prepare("PRAGMA remote_db.table_info(password_history)")
                    .map_err(|e| e.to_string())?;
                let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
                rows.next().map_err(|e| e.to_string())?.is_some()
            };
            if remote_has_history {
                let union = conn.execute(
                    "INSERT INTO main.password_history (sync_uuid, encrypted_password, replaced_at)
                     SELECT rh.sync_uuid, rh.encrypted_password, rh.replaced_at
                     FROM remote_db.password_history rh
                     WHERE EXISTS (SELECT 1 FROM main.secrets s WHERE s.sync_uuid = rh.sync_uuid)
                       AND NOT EXISTS (
                           SELECT 1 FROM main.password_history lh
                           WHERE lh.sync_uuid = rh.sync_uuid AND lh.replaced_at = rh.replaced_at
                       )",
                    [],
                );
                // Keep only the newest CAP entries per record: a row is
                // dropped when CAP-or-more newer siblings exist. rowid
                // tiebreaks equal timestamps, same as the local cap in
                // update_secret -- two devices contributing entries with
                // colliding millisecond timestamps would otherwise each
                // count zero "strictly newer" siblings and all survive,
                // quietly overshooting the cap.
                let cap = union.and_then(|_| {
                    conn.execute(
                        "DELETE FROM main.password_history
                         WHERE (
                             SELECT COUNT(*) FROM main.password_history newer
                             WHERE newer.sync_uuid = main.password_history.sync_uuid
                               AND (newer.replaced_at > main.password_history.replaced_at
                                    OR (newer.replaced_at = main.password_history.replaced_at
                                        AND newer.rowid > main.password_history.rowid))
                         ) >= ?1",
                        rusqlite::params![crate::db::PASSWORD_HISTORY_CAP as i64],
                    )
                });
                if let Err(e) = cap {
                    let _ = conn.execute("ROLLBACK", []);
                    return Err(format!("Password-history merge failed: {}", e));
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
            // The fetched remote can't be opened with our key. Three distinct
            // causes, told apart by the first 16 bytes of each file (an
            // SQLCipher vault's header starts with its salt -- on the current
            // format, the Argon2 salt -- a legacy plaintext vault with
            // SQLite's magic):
            let remote_head = read_file_head(&remote_db_path);
            let local_head = read_file_head(db_ref);
            let remote_is_plaintext = remote_head
                .map(|h| &h == crate::db::SQLITE_PLAINTEXT_MAGIC)
                .unwrap_or(false);

            if !remote_is_plaintext
                && let (Some(remote_salt), Some(local_salt)) = (remote_head, local_head)
                && remote_salt != local_salt
            {
                // Different salts: one side rotated the master password (or
                // re-initialized the vault). Which side is the *newer* one is
                // exactly what git ancestry answers: if origin/main is an
                // ancestor of our HEAD, everything on the remote is history
                // we've already synced, so the salt change is this device's
                // own rotation propagating outward -- pushing is precisely
                // correct. If the remote has commits we haven't seen, the
                // rotation happened elsewhere, and pushing our copy as source
                // of truth would silently undo a completed security operation
                // while reporting success. Refuse and say how to adopt the
                // rotated vault instead.
                let remote_is_ancestor = git_command(dir)
                    .arg("merge-base")
                    .arg("--is-ancestor")
                    .arg("origin/main")
                    .arg("HEAD")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);

                if !remote_is_ancestor {
                    // Refusing is settled -- but *whose* rotation this is
                    // decides the recovery instructions, and getting that
                    // wrong is worse than it sounds: the message used to
                    // assume the rotation always happened elsewhere, so a
                    // device that had just rotated *itself* (and lost the
                    // race with an ordinary edit pushed from another device)
                    // was told to delete its own freshly-rotated vault and
                    // unlock the remote "with the NEW master password" --
                    // when the remote actually holds the OLD one. Following
                    // that quietly un-rotates the vault while the user
                    // believes the password was changed.
                    //
                    // The salt in HEAD:vault.db is the state this device
                    // last synced, so it arbitrates: whichever side no
                    // longer matches it is the side that rotated.
                    let head_salt: Option<[u8; crate::crypto::SALT_LEN]> = git_command(dir)
                        .arg("show")
                        .arg("HEAD:vault.db")
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .output()
                        .ok()
                        .filter(|o| o.status.success() && o.stdout.len() >= crate::crypto::SALT_LEN)
                        .map(|o| {
                            let mut s = [0u8; crate::crypto::SALT_LEN];
                            s.copy_from_slice(&o.stdout[..crate::crypto::SALT_LEN]);
                            s
                        });
                    let local_rotated = head_salt.map(|h| h != local_salt).unwrap_or(false);
                    let remote_rotated = head_salt.map(|h| h != remote_salt).unwrap_or(true);

                    let message = if local_rotated && !remote_rotated {
                        // This device rotated; the remote gained ordinary
                        // edits (old salt) in the meantime. The local vault
                        // must NOT be deleted-and-forgotten -- it holds the
                        // rotation -- and the remote unlocks with the OLD
                        // password, not a new one.
                        "Sync refused: this device recently changed its master password, but the remote \
                         has since received other changes still encrypted under the OLD master password \
                         -- pushing now would erase them.\n\n\
                         To combine both safely:\n\
                         1. Back up this device's vault:   keystash export ~/keystash-backup.csv\n\
                         2. Delete the local vault file:   ~/.config/keystash/vault.db\n\
                         3. Run `keystash sync` to restore the remote vault, and unlock it with the \
                         OLD master password.\n\
                         4. Re-import the backup, then run `keystash change-password` to redo the \
                         rotation -- it will push to all devices this time.\n\
                         5. Delete the backup file securely.\n\n\
                         Nothing was pushed."
                    } else if local_rotated && remote_rotated {
                        // Both sides rotated independently -- rare, but the
                        // instructions must not pretend otherwise.
                        "Sync refused: the master password was changed on this device AND on another \
                         device independently -- the two vaults are now encrypted under different new \
                         passwords, and pushing either would erase the other's rotation.\n\n\
                         Pick which rotation wins (the remote's is what other devices will pull), then \
                         on this device:\n\
                         1. Back up this device's vault:   keystash export ~/keystash-backup.csv\n\
                         2. Delete the local vault file:   ~/.config/keystash/vault.db\n\
                         3. Run `keystash sync` to restore the remote vault, and unlock it with the \
                         master password set on the OTHER device.\n\
                         4. Re-import the backup if needed, and rotate again if this device's new \
                         password is the one you wanted.\n\
                         5. Delete the backup file securely.\n\n\
                         Nothing was pushed."
                    } else {
                        // The rotation happened elsewhere (or HEAD:vault.db
                        // was unreadable and this stays the safe default
                        // assumption): adopt the rotated remote.
                        "Sync refused: the remote vault is encrypted under a different master password \
                         -- it was rotated (or re-initialized) on another device, and pushing this \
                         device's vault would undo that change.\n\n\
                         To adopt the rotated vault on this device:\n\
                         1. Back up any local changes:   keystash export ~/keystash-backup.csv\n\
                         2. Delete the local vault file: ~/.config/keystash/vault.db (and vault.salt, if present)\n\
                         3. Run `keystash sync` to restore the vault from the remote.\n\
                         4. Unlock with the NEW master password, re-import the backup if needed, then \
                         delete it securely.\n\n\
                         Nothing was pushed."
                    };
                    return Err(message.to_string());
                }
                // Own rotation: fall through to the push below. No unmerged
                // backup either -- the remote copy is this device's own
                // pre-rotation history, already superseded by the re-encrypted
                // local vault (and by the rotation's own safety backups).
            } else {
                // Same salt (or an unreadable/legacy copy): a pre-encryption
                // file from a not-yet-updated device, or genuine corruption.
                // Nothing mergeable either way -- back up the remote copy for
                // manual recovery and fall through to pushing our own
                // (already-correct) local vault as the new source of truth.
                let backup_path = dir.join(format!(
                    "vault.db.unmerged-remote-{}",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ));
                if fs::copy(&remote_db_path, &backup_path).is_ok() {
                    unmerged_remote_backup = Some((backup_path, remote_is_plaintext));
                }
            }
        }

        // Align local branch history with the remote before committing (preserves
        // the merged -- or, in the incompatible-remote case, purely local -- vault.db)
        let reset_status = git_command(dir)
            .arg("reset")
            .arg("origin/main")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git reset failed: {}", e))?;
        if !reset_status.success() {
            return Err("git reset failed to align local history with the remote before committing. Nothing was pushed; the repository may need manual inspection.".to_string());
        }
    }

    // Prune old tombstones here, before the commit/push below, so the
    // pruned state is what actually gets pushed -- pruning after the push
    // instead would just get the removed rows silently re-added on this
    // device's *next* sync, since the (unpruned) remote copy would still
    // have them and the merge logic copies missing remote tombstones in.
    // Best-effort: a pruning failure shouldn't block the sync itself. The
    // checkpoint bundled with it matters for what `git add vault.db` below
    // actually stages -- see prune_and_checkpoint. Both already ran on the
    // short-circuit fast path, before its dirtiness check.
    if !skip_merge {
        prune_and_checkpoint(db_ref, &sqlcipher_key);
    }

    // 3. Stage changes, commit, and push local updates to remote repository.
    // The dirtiness check is scoped to the files sync actually manages
    // (see vault_paths_dirty): without the scope, stray untracked files in
    // the config dir (the -wal/-shm sidecars whenever a connection is open,
    // unmerged-remote backups, exports) made every sync look dirty --
    // which, combined with the commit exit-status check, turned a plain
    // no-op sync into a misleading "git commit failed" error whenever no
    // .gitignore existed. vault.salt is included so dropping a legacy
    // sidecar (the tracked-file deletion staged by the `git rm --cached`
    // below) still counts as a change worth committing.
    let is_dirty = vault_paths_dirty(dir)?;
    let mut committed = false;

    if is_dirty {
        // Stage vault.db
        let add_status = git_command(dir)
            .arg("add")
            .arg("vault.db")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("git add failed: {}", e))?;
        if !add_status.success() {
            return Err("git add failed to stage the merged vault. Nothing was committed or pushed.".to_string());
        }

        // Drop the retired vault.salt sidecar from the repo if a pre-0.3.6
        // push left it tracked. The salt now travels embedded in vault.db's
        // own header, and a stale tracked sidecar is actively dangerous: a
        // device restoring this repo later would find it and derive its key
        // from an outdated salt instead of the header. --ignore-unmatch
        // makes this a no-op for repos that never tracked it.
        let _ = git_command(dir)
            .arg("rm")
            .arg("--cached")
            .arg("--ignore-unmatch")
            .arg("-f")
            .arg("vault.salt")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // The working tree looked dirty, but after staging, the index can
        // still be empty (e.g. a touched-but-byte-identical file). `git
        // commit` on an empty index exits nonzero with "nothing to commit",
        // which the exit-status check below would misreport as a failed
        // merge -- an empty index is the up-to-date case, not an error.
        let index_empty = git_command(dir)
            .arg("diff")
            .arg("--cached")
            .arg("--quiet")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !index_empty {
            // Create commit. Checking success here matters: previously an
            // unnoticed failure (e.g. missing git identity config) left nothing
            // committed while the code fell straight through to push and
            // reported "Sync complete: ... merged and updated!" -- a merge that
            // never actually landed, with no error shown.
            let commit_status = git_command(dir)
                .arg("commit")
                .arg("-m")
                .arg("sync: auto-merge vault updates")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| format!("git commit failed: {}", e))?;
            if !commit_status.success() {
                return Err("git commit failed while finalizing the merge -- local changes are staged but not committed, and nothing was pushed. Check `git commit` manually in the vault directory (a missing user.name/user.email is a common cause) and re-run sync.".to_string());
            }
            committed = true;
        }
    }

    // Run push to update remote repository state
    let push_status = git_command(dir)
        .arg("push")
        .arg("origin")
        .arg("main")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("git push failed: {}", e))?;

    if !push_status.success() {
        return Err("Git push failed. You might have conflicts or remote changes that couldn't rebase automatically.".to_string());
    }

    let mut msg = if let Some((backup_path, remote_was_plaintext)) = unmerged_remote_backup {
        let reason = if remote_was_plaintext {
            "an outdated pre-encryption copy"
        } else {
            "unreadable under the current key despite carrying the same salt -- most likely corrupted"
        };
        format!(
            "Sync complete: the remote vault was {} and could not be merged. Your local vault was pushed as the new source of truth; the old remote copy was saved to {:?} in case you need anything from it.",
            reason, backup_path
        )
    } else if committed {
        "Sync complete: Local and remote vaults merged and updated!".to_string()
    } else {
        "Sync complete: Vault is already up-to-date with remote.".to_string()
    };
    if let Some(note) = maybe_squash_history(dir, history_retention) {
        msg.push_str(&note);
    }
    Ok(msg)
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

    // Fetch first: detection used to compare against whatever ref the
    // prelock fetch happened to leave behind, while the sync that followed
    // fetched fresh -- so a conflict landing on the remote between those two
    // moments bypassed the resolver entirely and got last-write-wins-merged.
    // Best-effort: if the fetch fails (offline), fall through against the
    // existing ref; git_sync_vault's own fetch surfaces the real error.
    let _ = git_command(dir)
        .arg("fetch")
        .arg("origin")
        .arg("main")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // Same short-circuit as git_sync_vault: origin/main == HEAD means the
    // remote is this device's own already-merged history -- no divergence,
    // so no conflicts are possible, and the whole extract-and-compare pass
    // (which decrypts every record on both sides) can be skipped. Keeps the
    // manual [s] sync as cheap as the post-unlock one when nothing changed.
    if let (Some(local), Some(remote)) = (rev_parse(dir, "HEAD"), rev_parse(dir, "origin/main"))
        && local == remote
    {
        return Ok(Vec::new());
    }

    let remote_db_path = dir.join(format!("vault_remote_detect_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let base_db_path = dir.join(format!("vault_base_detect_{}_{}.db", std::process::id(), unique_tmp_suffix()));
    let _cleanup = TempCleanup(vec![remote_db_path.clone(), base_db_path.clone()]);

    let show_remote = git_command(dir)
        .arg("show")
        .arg("origin/main:vault.db")
        .output();

    let mut has_remote = false;
    if let Ok(output) = show_remote
        && output.status.success() && !output.stdout.is_empty()
            && fs::write(&remote_db_path, output.stdout).is_ok() {
                has_remote = true;
            }

    if !has_remote {
        return Ok(Vec::new());
    }

    let merge_base_output = git_command(dir)
        .arg("merge-base")
        .arg("HEAD")
        .arg("origin/main")
        .output();

    let mut has_base = false;
    if let Ok(output) = merge_base_output
        && output.status.success() {
            let ancestor_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let show_base = git_command(dir)
                .arg("show")
                .arg(format!("{}:vault.db", ancestor_hash))
                .output();

            if let Ok(base_out) = show_base
                && base_out.status.success() && !base_out.stdout.is_empty()
                    && fs::write(&base_db_path, base_out.stdout).is_ok() {
                        has_base = true;
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

            // title/category/username are compared too: they're mutable
            // payload under the sync_uuid identity (see the merge UPDATE in
            // git_sync_vault), so concurrent renames are conflicts exactly
            // like concurrent password edits.
            let differs = local_pw != remote_pw
                || local_notes != remote_notes
                || local_sec.url != remote_sec.url
                || local_sec.title != remote_sec.title
                || local_sec.category != remote_sec.category
                || local_sec.username != remote_sec.username;
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

                    let local_changed = local_pw != base_pw
                        || local_notes != base_notes
                        || local_sec.url != base_sec.url
                        || local_sec.title != base_sec.title
                        || local_sec.category != base_sec.category
                        || local_sec.username != base_sec.username;
                    let remote_changed = remote_pw != base_pw
                        || remote_notes != base_notes
                        || remote_sec.url != base_sec.url
                        || remote_sec.title != base_sec.title
                        || remote_sec.category != base_sec.category
                        || remote_sec.username != base_sec.username;

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
    use std::path::{Path, PathBuf};
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

    fn init_bare_origin(root: &Path) -> PathBuf {
        let origin = root.join("origin.git");
        let status = Command::new("git").arg("init").arg("--bare").arg(&origin).status().unwrap();
        assert!(status.success());
        origin
    }

    fn init_device(root: &Path, name: &str, origin: &Path) -> Device {
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
    /// 1. A second device must be able to derive the right key from what
    ///    `git pull` brings down alone -- since 0.3.6 that's vault.db itself
    ///    (the Argon2 salt lives in its header), with no sidecar involved.
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
            vec!["add", "-f", "vault.db"],
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

        // Device B must be able to open the vault A created, with A's password,
        // using only what `git pull` brought down -- the vault file alone.
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
                &resolved.remote_secret.title,
                &resolved.remote_secret.category,
                &resolved.remote_secret.username,
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
            vec!["add", "-f", "vault.db"],
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
        assert!(decrypted_passwords.contains(b"dup-v1-from-A".as_slice()));
        assert!(decrypted_passwords.contains(b"dup-v2-from-B".as_slice()));

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
            vec!["add", "-f", "vault.db"],
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
                &keep.title,
                &keep.category,
                &keep.username,
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

    /// Regression test for the silent rotation revert: a device that hadn't
    /// yet seen a master-password rotation used to hit the incompatible-remote
    /// path and push its own stale vault as the new source of truth --
    /// undoing the rotation on the remote while reporting success. With the
    /// salt embedded in the vault header, the stale device must now detect
    /// the salt mismatch, refuse to push, and leave the rotated remote
    /// untouched -- while the device that *performed* the rotation (whose
    /// HEAD already contains everything on the remote) must still be able to
    /// push it out.
    #[test]
    fn stale_device_refuses_to_push_over_a_rotated_remote() {
        let root = scratch_root("rotation_refusal");
        let origin = init_bare_origin(&root);

        // --- Device A: create, add a secret, push. ---
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "old-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clone and unlock with the old password. ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "old-master-password").unwrap();
        let stale_salt_b = super::read_file_head(&device_b.vault_path).unwrap();

        // --- Device A rotates, then syncs: its own rotation must push. ---
        let new_key_a =
            crate::db::change_master_password(&conn_a, &device_a.vault_path, &key_a, "new-master-password").unwrap();
        drop(conn_a);
        let rotated_salt = super::read_file_head(&device_a.vault_path).unwrap();
        assert_ne!(rotated_salt, stale_salt_b, "rotation must have produced a fresh salt");

        let push_rotation = super::git_sync_vault(&device_a.vault_path, &new_key_a);
        assert!(
            push_rotation.is_ok(),
            "the rotating device itself must be able to push its rotation: {:?}",
            push_rotation
        );

        // --- Device B syncs while stale: must refuse, changing nothing. ---
        let sync_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        let err = sync_b.expect_err("a stale device must refuse to push over a rotated remote");
        assert!(
            err.contains("different master password"),
            "refusal should explain the rotation, got: {}",
            err
        );
        assert_eq!(
            super::read_file_head(&device_b.vault_path).unwrap(),
            stale_salt_b,
            "the refusal must not touch Device B's local vault"
        );

        // The remote must still hold A's rotated vault: fetch it on B and
        // check its header salt.
        let fetch = Command::new("git").args(["fetch", "origin", "main"]).current_dir(&device_b.dir).status().unwrap();
        assert!(fetch.success());
        let show = Command::new("git")
            .args(["show", "origin/main:vault.db"])
            .current_dir(&device_b.dir)
            .output()
            .unwrap();
        assert!(show.status.success());
        assert_eq!(
            &show.stdout[..16],
            &rotated_salt[..],
            "the remote must still hold the rotated vault after the stale device's refused sync"
        );

        // --- And the refusal message's recovery procedure must work: delete
        // the local vault, sync to restore, unlock with the new password. ---
        std::fs::remove_file(&device_b.vault_path).unwrap();
        let restore = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(restore.is_ok(), "restore-from-remote failed: {:?}", restore);
        let (conn_b2, key_b2) = crate::db::open_vault(&device_b.vault_path, "new-master-password")
            .expect("Device B should unlock the restored vault with the NEW password");
        let secrets = crate::db::get_secrets(&conn_b2).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            &*crate::crypto::decrypt(&secrets[0].encrypted_password, &key_b2).unwrap(),
            b"alpha-v1"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `keystash sync` against a brand-new empty remote must perform the
    /// very first push itself instead of failing with "could not reach
    /// origin/main" -- a fetch of a nonexistent branch fails identically to
    /// a dead network, and the ls-remote probe is what tells them apart.
    #[test]
    fn first_sync_to_an_empty_remote_pushes_the_initial_backup() {
        let root = scratch_root("empty_remote");
        let origin = init_bare_origin(&root);

        // A device with a vault, git repo and remote configured -- but no
        // commit, no push, and an origin with no branches at all.
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        drop(conn_a);

        let msg = super::git_sync_vault(&device_a.vault_path, &key_a)
            .expect("the first sync to an empty remote must push, not fail");
        assert!(msg.contains("merged and updated"), "got: {}", msg);

        // The branch now exists and a second device can set up from it.
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, _key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();
        assert_eq!(crate::db::get_secrets(&conn_b).unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Password history rides sync: union-merged by (sync_uuid, replaced_at)
    /// so both devices converge on the same set, no duplicates on repeated
    /// syncs -- and a remote pushed by a version without the table (the
    /// no-floor-bump compatibility case) is skipped gracefully instead of
    /// erroring the merge.
    #[test]
    fn password_history_unions_across_devices_and_tolerates_legacy_remotes() {
        let root = scratch_root("history_sync");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Site", "Cat", "user", "", "v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();

        std::thread::sleep(Duration::from_millis(20));

        // A changes the password (v1 -> v2): one history entry, pushed.
        let a_sql = crate::crypto::derive_sqlcipher_key(&key_a);
        {
            let conn = crate::db::open_keyed_connection(&device_a.vault_path, &a_sql).unwrap();
            let s = crate::db::get_secrets(&conn).unwrap();
            crate::db::update_secret(&conn, s[0].id, "Site", "Cat", "user", "", "v2", None, &key_a).unwrap();
        }
        assert!(super::git_sync_vault(&device_a.vault_path, &key_a).is_ok());

        // B merges: must receive the history entry, decrypting to v1.
        assert!(super::git_sync_vault(&device_b.vault_path, &key_b).is_ok());
        let b_sql = crate::crypto::derive_sqlcipher_key(&key_b);
        let uuid = {
            let conn = crate::db::open_keyed_connection(&device_b.vault_path, &b_sql).unwrap();
            let s = crate::db::get_secrets(&conn).unwrap();
            let h = crate::db::get_password_history(&conn, &s[0].sync_uuid).unwrap();
            assert_eq!(h.len(), 1, "B must receive A's history entry");
            assert_eq!(&*crate::crypto::decrypt(&h[0].0, &key_b).unwrap(), b"v1");
            s[0].sync_uuid.clone()
        };

        std::thread::sleep(Duration::from_millis(20));

        // B changes it again (v2 -> v3); both entries must land on A, and a
        // repeat sync must not duplicate anything.
        {
            let conn = crate::db::open_keyed_connection(&device_b.vault_path, &b_sql).unwrap();
            let s = crate::db::get_secrets(&conn).unwrap();
            crate::db::update_secret(&conn, s[0].id, "Site", "Cat", "user", "", "v3", None, &key_b).unwrap();
        }
        assert!(super::git_sync_vault(&device_b.vault_path, &key_b).is_ok());
        assert!(super::git_sync_vault(&device_a.vault_path, &key_a).is_ok());
        assert!(super::git_sync_vault(&device_a.vault_path, &key_a).is_ok(), "repeat sync");
        {
            let conn = crate::db::open_keyed_connection(&device_a.vault_path, &a_sql).unwrap();
            let h = crate::db::get_password_history(&conn, &uuid).unwrap();
            assert_eq!(h.len(), 2, "A must hold both history entries exactly once");
            let plains: Vec<Vec<u8>> = h.iter().map(|(b, _)| crate::crypto::decrypt(b, &key_a).unwrap().to_vec()).collect();
            assert!(plains.contains(&b"v1".to_vec()) && plains.contains(&b"v2".to_vec()));
        }

        // Legacy-remote tolerance: push a copy WITHOUT the history table
        // (as a pre-history version would) and confirm the next merge
        // skips the history step instead of failing. open_keyed_connection
        // deliberately doesn't run ensure_schema, so the drop sticks. B
        // pulls first (A pushed since), and the explicit checkpoint matters:
        // _conn_b above is still open, so the drop connection's close won't
        // checkpoint the WAL on its own and the drop would never reach the
        // main file git stages.
        pull(&device_b);
        {
            let conn = crate::db::open_keyed_connection(&device_b.vault_path, &b_sql).unwrap();
            conn.execute_batch("DROP TABLE password_history; PRAGMA wal_checkpoint(TRUNCATE);")
                .unwrap();
        }
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "simulated pre-history push"],
            vec!["push", "origin", "main"],
        ] {
            let out = Command::new("git").args(&args).current_dir(&device_b.dir).output().unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}{}",
                args,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let sync = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(sync.is_ok(), "merging a remote without the history table must not fail: {:?}", sync);
        {
            let conn = crate::db::open_keyed_connection(&device_a.vault_path, &a_sql).unwrap();
            assert_eq!(
                crate::db::get_password_history(&conn, &uuid).unwrap().len(),
                2,
                "A's local history must survive a legacy-remote merge untouched"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    /// History retention: after each push, history older than the newest
    /// `keep` snapshots collapses into a squash root and the rewritten
    /// (still linear) history is force-pushed with lease. Verified from the
    /// outside: origin's commit count stays bounded, content stays intact,
    /// and -- the part that must never break -- a device whose clone
    /// predates the squash (its HEAD no longer exists anywhere in the
    /// rewritten history) still merges and pushes without data loss.
    #[test]
    fn history_retention_bounds_origin_and_keeps_old_devices_working() {
        let root = scratch_root("retention");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Base", "Cat", "user", "", "base-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // Device B clones NOW -- before any squash -- so its history later
        // shares no commit with the rewritten one.
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();

        let origin_commits = |dir: &Path| -> u64 {
            let out = Command::new("git")
                .args(["rev-list", "--count", "origin/main"])
                .current_dir(dir)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
        };

        // Five more snapshots with keep=3 (the config floor is 10; the
        // function takes any value, and 3 keeps the test fast). Count can
        // never exceed keep+1 before the squash runs, and lands on keep.
        let a_key_sql = crate::crypto::derive_sqlcipher_key(&key_a);
        for i in 0..5 {
            {
                let conn = crate::db::open_keyed_connection(&device_a.vault_path, &a_key_sql).unwrap();
                crate::db::add_secret(&conn, &format!("Item{}", i), "Cat", "user", "", &format!("pw-{}", i), None, &key_a).unwrap();
            }
            let msg = super::git_sync_vault_with_retention(&device_a.vault_path, &key_a, 3).unwrap();
            if origin_commits(&device_a.dir) > 3 {
                panic!("origin exceeded the retention bound after: {}", msg);
            }
        }
        assert_eq!(origin_commits(&device_a.dir), 3, "history must be squashed to the keep window");

        // The squash root's snapshot is complete: a fresh clone holds all 6
        // records even though only 3 commits exist.
        let device_c = init_device(&root, "device_c", &origin);
        pull(&device_c);
        let (conn_c, _key_c) = crate::db::open_vault(&device_c.vault_path, "shared-master-password").unwrap();
        assert_eq!(crate::db::get_secrets(&conn_c).unwrap().len(), 6);
        drop(conn_c);

        // Device B -- whose entire local history predates the squash --
        // edits and syncs. Its merge base is gone (has_base = false is the
        // designed degradation); the sync itself must still merge and push
        // with nothing lost.
        {
            let conn_b = crate::db::open_keyed_connection(
                &device_b.vault_path,
                &crate::crypto::derive_sqlcipher_key(&key_b),
            )
            .unwrap();
            crate::db::add_secret(&conn_b, "FromOldB", "Cat", "user", "", "old-b-v1", None, &key_b).unwrap();
        }
        let sync_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(sync_b.is_ok(), "a pre-squash device must still sync: {:?}", sync_b);
        let conn_b2 = crate::db::open_keyed_connection(
            &device_b.vault_path,
            &crate::crypto::derive_sqlcipher_key(&key_b),
        )
        .unwrap();
        assert_eq!(
            crate::db::get_secrets(&conn_b2).unwrap().len(),
            7,
            "B must end with all 6 remote records plus its own -- nothing resurrected, nothing lost"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// End-to-end for `setup_sync_repo` -- the core behind `keystash sync
    /// setup`: a first device with an existing vault gets repo+gitignore+
    /// remote+identity and pushes the initial backup; an additional device
    /// with an empty directory pulls the vault down and can unlock and sync
    /// it. Also pins the guard rails: refusing to touch an existing repo,
    /// and refusing first-device mode with no vault to push.
    #[test]
    fn sync_setup_wizard_core_configures_both_device_kinds() {
        let root = scratch_root("setup_wizard");
        let origin = init_bare_origin(&root);
        let origin_url = origin.to_str().unwrap();

        // --- First device: plain directory with a vault, no git anything. ---
        let dir_a = root.join("device_a");
        std::fs::create_dir_all(&dir_a).unwrap();
        let vault_a = dir_a.join("vault.db");
        let (conn_a, key_a) = crate::db::create_vault(&vault_a, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        drop(conn_a);

        // First-device mode with no vault must refuse (guard rail).
        let dir_empty = root.join("device_empty");
        std::fs::create_dir_all(&dir_empty).unwrap();
        let err = super::setup_sync_repo(&dir_empty.join("vault.db"), origin_url, true)
            .expect_err("first-device setup without a vault must refuse");
        assert!(err.contains("keystash init"), "should point at init, got: {}", err);

        let msg = super::setup_sync_repo(&vault_a, origin_url, true).expect("first-device setup failed");
        assert!(msg.contains("pushed"), "got: {}", msg);
        assert_eq!(
            std::fs::read_to_string(dir_a.join(".gitignore")).unwrap(),
            "*\n!vault.db\n",
            "setup must write the two-line .gitignore"
        );

        // Re-running setup on a configured repo must refuse, not re-init.
        let err = super::setup_sync_repo(&vault_a, origin_url, true)
            .expect_err("setup must not touch an existing repo");
        assert!(err.contains("already a git repository"), "got: {}", err);

        // --- Additional device: empty directory, pulls the vault. ---
        let dir_b = root.join("device_b");
        std::fs::create_dir_all(&dir_b).unwrap();
        let vault_b = dir_b.join("vault.db");
        let msg = super::setup_sync_repo(&vault_b, origin_url, false).expect("additional-device setup failed");
        assert!(msg.contains("pulled"), "got: {}", msg);
        assert!(vault_b.exists());

        // The pulled vault unlocks with the shared password and syncs.
        let (conn_b, key_b) = crate::db::open_vault(&vault_b, "shared-master-password")
            .expect("the pulled vault must unlock with the first device's password");
        crate::db::add_secret(&conn_b, "FromB", "Cat", "user", "", "b-v1", None, &key_b).unwrap();
        drop(conn_b);
        let push_b = super::git_sync_vault(&vault_b, &key_b);
        assert!(push_b.is_ok(), "post-setup sync failed: {:?}", push_b);

        // And it round-trips back to A through a normal sync.
        let sync_a = super::git_sync_vault(&vault_a, &key_a);
        assert!(sync_a.is_ok(), "A's merge failed: {:?}", sync_a);
        let conn_a2 = crate::db::open_keyed_connection(&vault_a, &crate::crypto::derive_sqlcipher_key(&key_a)).unwrap();
        assert_eq!(crate::db::get_secrets(&conn_a2).unwrap().len(), 2, "A must see Alpha and FromB");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The rotation *race*, distinct from the plain stale-device case: A
    /// rotates but hasn't pushed yet, B pushes an ordinary edit first, then
    /// A syncs. Refusing is correct either way, but the refusal used to
    /// misdiagnose the direction -- telling A the vault "was rotated on
    /// another device" and to unlock the remote "with the NEW master
    /// password", when A itself rotated and the remote actually holds the
    /// OLD one; following those steps quietly un-rotated A's vault. The
    /// salt recorded in HEAD:vault.db (A's last-synced state) is what
    /// arbitrates whose salt changed.
    #[test]
    fn rotation_race_refusal_names_the_local_rotation() {
        let root = scratch_root("rotation_race");
        let origin = init_bare_origin(&root);

        // --- Device A: create, push. ---
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "old-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clone, then push an ordinary edit (old salt). ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "old-master-password").unwrap();
        std::thread::sleep(Duration::from_millis(20));

        // --- A rotates but does NOT sync yet (the race window). ---
        let new_key_a =
            crate::db::change_master_password(&conn_a, &device_a.vault_path, &key_a, "new-master-password").unwrap();
        drop(conn_a);
        let rotated_salt = super::read_file_head(&device_a.vault_path).unwrap();

        // --- B's ordinary edit lands on the remote first. ---
        crate::db::add_secret(&conn_b, "FromB", "Cat", "user", "", "b-v1", None, &key_b).unwrap();
        drop(conn_b);
        let push_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(push_b.is_ok(), "B's ordinary push failed: {:?}", push_b);

        // --- A syncs: must refuse, and must name A's OWN rotation. ---
        let err = super::git_sync_vault(&device_a.vault_path, &new_key_a)
            .expect_err("A must refuse to push its rotation over B's unseen edit");
        assert!(
            err.contains("this device recently changed its master password"),
            "refusal must name the local rotation, got: {}",
            err
        );
        assert!(
            err.contains("OLD master password"),
            "recovery must say the remote unlocks with the OLD password, got: {}",
            err
        );
        assert!(
            !err.contains("rotated (or re-initialized) on another device"),
            "must not misattribute the rotation to another device, got: {}",
            err
        );

        // Neither side was touched: A still holds its rotated vault, the
        // remote still holds B's edit under the old salt.
        assert_eq!(super::read_file_head(&device_a.vault_path).unwrap(), rotated_salt);
        let fetch = Command::new("git").args(["fetch", "origin", "main"]).current_dir(&device_a.dir).status().unwrap();
        assert!(fetch.success());
        let show = Command::new("git")
            .args(["show", "origin/main:vault.db"])
            .current_dir(&device_a.dir)
            .output()
            .unwrap();
        assert!(show.status.success());
        assert_ne!(&show.stdout[..16], &rotated_salt[..], "the remote must still be on the old salt");

        // And the message's recovery procedure genuinely works: restore the
        // remote, unlock with the OLD password, find B's edit intact.
        std::fs::remove_file(&device_a.vault_path).unwrap();
        let restore = super::git_sync_vault(&device_a.vault_path, &new_key_a);
        assert!(restore.is_ok(), "restore-from-remote failed: {:?}", restore);
        let (conn_a2, _) = crate::db::open_vault(&device_a.vault_path, "old-master-password")
            .expect("the restored remote must unlock with the OLD master password, exactly as the refusal says");
        let titles: Vec<String> = crate::db::get_secrets(&conn_a2).unwrap().iter().map(|s| s.title.clone()).collect();
        assert!(titles.contains(&"FromB".to_string()), "B's edit must be in the restored vault, got: {:?}", titles);

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
            vec!["add", "-f", "vault.db"],
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

    /// detect_sync_conflicts must find conflicts that landed on the remote
    /// since the last local fetch -- it fetches for itself now. Previously
    /// it compared against whatever ref the prelock fetch had left behind
    /// (note: no manual `git fetch` anywhere in this test's device-B steps),
    /// so a conflict pushed after that moment bypassed the resolver and got
    /// silently last-write-wins-merged. This is what makes the manual [s]
    /// sync's conflict detection real rather than dependent on startup
    /// timing.
    #[test]
    fn detect_sync_conflicts_fetches_the_remote_itself() {
        let root = scratch_root("detect_fetches");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Common", "Cat", "user", "", "common-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();

        std::thread::sleep(Duration::from_millis(20));

        // A edits and pushes AFTER B's pull -- from B's point of view this
        // conflict exists only on the remote, invisible until a fetch.
        {
            let conn_a = crate::db::open_keyed_connection(
                &device_a.vault_path,
                &crate::crypto::derive_sqlcipher_key(&key_a),
            )
            .unwrap();
            let s = crate::db::get_secrets(&conn_a).unwrap();
            crate::db::update_secret(&conn_a, s[0].id, "Common", "Cat", "user", "", "common-v2-from-A", None, &key_a).unwrap();
        }
        let push_a = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(push_a.is_ok(), "A's push failed: {:?}", push_a);

        std::thread::sleep(Duration::from_millis(20));

        // B edits the same record, then detection runs with NO manual fetch.
        {
            let s = crate::db::get_secrets(&conn_b).unwrap();
            crate::db::update_secret(&conn_b, s[0].id, "Common", "Cat", "user", "", "common-v2-from-B", None, &key_b).unwrap();
        }
        drop(conn_b);

        let conflicts = super::detect_sync_conflicts(&device_b.vault_path, &key_b).unwrap();
        assert_eq!(
            conflicts.len(),
            1,
            "detection must fetch and see the conflict A pushed after B's last fetch, got: {:?}",
            conflicts.iter().map(|c| &c.title).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Pins the sync short-circuit: when origin/main equals HEAD, a sync
    /// with no local changes returns up-to-date after the fetch alone (no
    /// merge, no commit, no push -- observable as the origin's commit count
    /// not moving), local-only changes still push (skipping just the merge),
    /// and a remote that actually moved takes the full merge path (covered
    /// by every other two-device test in this suite; asserted here via the
    /// commit counts advancing exactly when they should).
    #[test]
    fn noop_syncs_short_circuit_after_the_fetch() {
        let root = scratch_root("short_circuit");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        let origin_commits = |dir: &Path| -> usize {
            let out = Command::new("git")
                .args(["rev-list", "--count", "origin/main"])
                .current_dir(dir)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().parse().unwrap()
        };
        assert_eq!(origin_commits(&device_a.dir), 1);

        // 1. Nothing changed anywhere: up-to-date, no new commit.
        let msg = super::git_sync_vault(&device_a.vault_path, &key_a).unwrap();
        assert!(msg.contains("up-to-date"), "expected short-circuit up-to-date, got: {}", msg);
        assert_eq!(origin_commits(&device_a.dir), 1, "a no-op sync must not create a commit");

        // 2. Local-only change (made through a connection held open across
        //    the sync, so it's WAL-resident at check time -- the dirtiness
        //    check must see it via the checkpoint, not wrongly short-circuit
        //    to "up-to-date" and leave it unpushed).
        let held_conn = crate::db::open_keyed_connection(
            &device_a.vault_path,
            &crate::crypto::derive_sqlcipher_key(&key_a),
        )
        .unwrap();
        crate::db::add_secret(&held_conn, "Beta", "Cat", "user", "", "beta-v1", None, &key_a).unwrap();
        let msg = super::git_sync_vault(&device_a.vault_path, &key_a).unwrap();
        assert!(msg.contains("merged and updated"), "local-only changes must still push, got: {}", msg);
        assert_eq!(origin_commits(&device_a.dir), 2);
        drop(held_conn);

        // 3. And a device whose remote genuinely moved takes the full merge
        //    path: B (cloned at commit 1) syncs against A's commit 2.
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();
        let msg = super::git_sync_vault(&device_b.vault_path, &key_b).unwrap();
        assert!(msg.contains("up-to-date"), "B pulled the latest before syncing, so the merge is a no-op: {}", msg);
        let conn_b = crate::db::open_keyed_connection(
            &device_b.vault_path,
            &crate::crypto::derive_sqlcipher_key(&key_b),
        )
        .unwrap();
        assert_eq!(crate::db::get_secrets(&conn_b).unwrap().len(), 2, "B must have Alpha and Beta");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for the no-op-sync failure: with a connection still
    /// open against the vault (exactly what the TUI always has), the
    /// untracked -wal/-shm sidecars used to make `git status --porcelain`
    /// dirty on every sync when no .gitignore existed -- and the commit
    /// exit-status check then turned a plain nothing-changed sync into a
    /// misleading "git commit failed" error ("nothing to commit" exits
    /// nonzero). Also pins the new self-sufficiency behavior: sync writes
    /// the two-line .gitignore itself when absent.
    #[test]
    fn noop_sync_with_open_connection_and_no_gitignore_reports_up_to_date() {
        let root = scratch_root("noop_open_conn");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Alpha", "Cat", "user", "", "alpha-v1", None, &key_a).unwrap();
        drop(conn_a);
        // Deliberately NO .gitignore here -- simulating a setup that skipped
        // that README step.
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // Hold a connection open across the sync, like the TUI does, and
        // touch it so the -wal/-shm sidecars exist on disk.
        let held_conn = crate::db::open_keyed_connection(
            &device_a.vault_path,
            &crate::crypto::derive_sqlcipher_key(&key_a),
        )
        .unwrap();
        let _: i64 = held_conn.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0)).unwrap();

        // Nothing has changed since the push: this must be a clean
        // "up-to-date", not a commit failure.
        let result = super::git_sync_vault(&device_a.vault_path, &key_a);
        let msg = result.expect("a no-op sync with an open connection and no .gitignore must succeed");
        assert!(
            msg.contains("up-to-date"),
            "expected the up-to-date message, got: {}",
            msg
        );

        // Sync made itself self-sufficient: the .gitignore now exists with
        // the README's exact two lines.
        let gitignore = std::fs::read_to_string(device_a.dir.join(".gitignore"))
            .expect("sync should have written a .gitignore");
        assert_eq!(gitignore, "*\n!vault.db\n");

        // And it stays clean on repeat, connection still open.
        let again = super::git_sync_vault(&device_a.vault_path, &key_a).unwrap();
        assert!(again.contains("up-to-date"), "second no-op sync: {}", again);
        drop(held_conn);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The staged vault.db must contain changes that were still WAL-resident
    /// when sync ran: a record added through a connection that stays open
    /// across the sync (the TUI's situation) has its frames in vault.db-wal,
    /// which is never staged -- the explicit pre-`git add` checkpoint is
    /// what guarantees the main file is complete. Verified from the outside:
    /// a second device pulling the pushed commit must see the record.
    #[test]
    fn wal_resident_changes_reach_the_remote() {
        let root = scratch_root("wal_staging");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "First", "Cat", "user", "", "first-v1", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // Write through a connection that stays open across the sync, so the
        // new record's pages sit in the WAL at staging time.
        let held_conn = crate::db::open_keyed_connection(
            &device_a.vault_path,
            &crate::crypto::derive_sqlcipher_key(&key_a),
        )
        .unwrap();
        crate::db::add_secret(&held_conn, "Second", "Cat", "user", "", "second-v1", None, &key_a).unwrap();

        let push = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(push.is_ok(), "sync with WAL-resident changes failed: {:?}", push);
        drop(held_conn);

        // Device B clones what was actually pushed -- both records must be
        // there, including the one that was WAL-resident during staging.
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();
        let secrets = crate::db::get_secrets(&conn_b).unwrap();
        let titles: Vec<&str> = secrets.iter().map(|s| s.title.as_str()).collect();
        assert_eq!(secrets.len(), 2, "expected First and Second on the remote, got: {:?}", titles);
        assert!(titles.contains(&"Second"), "the WAL-resident record must have been staged and pushed, got: {:?}", titles);
        assert_eq!(
            &*crate::crypto::decrypt(&secrets.iter().find(|s| s.title == "Second").unwrap().encrypted_password, &key_b).unwrap(),
            b"second-v1"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression test for B6: title/category/username edits must propagate
    /// through the merge like every other field. The merge UPDATE used to
    /// carry only url/password/notes/updated_at -- a rename on device A
    /// reached device B as the new *timestamp* with the old *name*, and
    /// since both sides then held equal timestamps, no later sync ever
    /// reconciled them: permanent split-brain with "Sync complete" on both.
    #[test]
    fn renames_propagate_between_devices() {
        let root = scratch_root("rename_propagation");
        let origin = init_bare_origin(&root);

        // --- Device A: create and push a record. ---
        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Old Name", "old-tag", "olduser", "", "the-password", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        // --- Device B: clone it. ---
        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (_conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();

        std::thread::sleep(Duration::from_millis(20));

        // --- Device A renames the record: title, tags, and username all
        // change; the password stays the same. Exactly what the Edit form
        // does. ---
        let a_sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_a);
        let renamed_uuid;
        {
            let conn_a = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
            let secrets = crate::db::get_secrets(&conn_a).unwrap();
            renamed_uuid = secrets[0].sync_uuid.clone();
            crate::db::update_secret(
                &conn_a,
                secrets[0].id,
                "New Name",
                "new-tag, work",
                "newuser",
                "https://renamed.example",
                "the-password",
                None,
                &key_a,
            )
            .unwrap();
        }

        let push_a = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(push_a.is_ok(), "Device A's post-rename sync failed: {:?}", push_a);

        // --- Device B merges: the rename must arrive whole, not just its
        // timestamp. ---
        let sync_b = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(sync_b.is_ok(), "Device B's merge failed: {:?}", sync_b);

        let conn_b = crate::db::open_keyed_connection(&device_b.vault_path, &crate::crypto::derive_sqlcipher_key(&key_b)).unwrap();
        let secrets_b = crate::db::get_secrets(&conn_b).unwrap();
        assert_eq!(secrets_b.len(), 1, "the rename must not duplicate the record");
        let r = &secrets_b[0];
        assert_eq!(r.sync_uuid, renamed_uuid, "same record identity");
        assert_eq!(r.title, "New Name", "title must propagate through the merge");
        assert_eq!(r.category, "new-tag, work", "tags/category must propagate through the merge");
        assert_eq!(r.username, "newuser", "username must propagate through the merge");
        assert_eq!(r.url, "https://renamed.example");
        assert_eq!(&*crate::crypto::decrypt(&r.encrypted_password, &key_b).unwrap(), b"the-password");
        drop(conn_b);

        // --- And a second sync on either side is a genuine no-op: equal
        // timestamps must now mean equal *content*, not hidden divergence. ---
        let resync_a = super::git_sync_vault(&device_a.vault_path, &key_a).unwrap();
        let conn_a_final = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
        let secrets_a = crate::db::get_secrets(&conn_a_final).unwrap();
        assert_eq!(secrets_a[0].title, "New Name", "the rename must survive A's next sync (got clobbered back: {})", resync_a);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Companion to the test above: *concurrent* renames of the same record
    /// on two devices are a genuine conflict and must surface in
    /// detect_sync_conflicts (differs/base comparison now include the
    /// triple), and resolving "keep remote" must apply the remote's rename.
    #[test]
    fn concurrent_renames_surface_as_conflict_and_resolve() {
        let root = scratch_root("rename_conflict");
        let origin = init_bare_origin(&root);

        let device_a = init_device(&root, "device_a", &origin);
        let (conn_a, key_a) = crate::db::create_vault(&device_a.vault_path, "shared-master-password").unwrap();
        crate::db::add_secret(&conn_a, "Original", "Cat", "user", "", "same-password", None, &key_a).unwrap();
        drop(conn_a);
        for args in [
            vec!["add", "-f", "vault.db"],
            vec!["commit", "-m", "Initial vault backup"],
            vec!["push", "-u", "origin", "main"],
        ] {
            let status = Command::new("git").args(&args).current_dir(&device_a.dir).status().unwrap();
            assert!(status.success(), "git {:?} failed", args);
        }

        let device_b = init_device(&root, "device_b", &origin);
        pull(&device_b);
        let (conn_b, key_b) = crate::db::open_vault(&device_b.vault_path, "shared-master-password").unwrap();

        std::thread::sleep(Duration::from_millis(20));

        // A renames and pushes; B renames differently *before* seeing A's
        // push -- both sides diverge from the shared base on the title only.
        let a_sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_a);
        {
            let conn_a = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
            let s = crate::db::get_secrets(&conn_a).unwrap();
            crate::db::update_secret(&conn_a, s[0].id, "Renamed-by-A", "Cat", "user", "", "same-password", None, &key_a).unwrap();
        }
        let push_a = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(push_a.is_ok(), "Device A's push failed: {:?}", push_a);

        std::thread::sleep(Duration::from_millis(20));
        {
            let s = crate::db::get_secrets(&conn_b).unwrap();
            crate::db::update_secret(&conn_b, s[0].id, "Renamed-by-B", "Cat", "user", "", "same-password", None, &key_b).unwrap();
        }
        drop(conn_b);

        // B fetches and must see exactly one conflict -- a pure rename, no
        // password/notes/url difference involved.
        let fetch = Command::new("git").args(["fetch", "origin", "main"]).current_dir(&device_b.dir).status().unwrap();
        assert!(fetch.success());
        let conflicts = super::detect_sync_conflicts(&device_b.vault_path, &key_b).unwrap();
        assert_eq!(
            conflicts.len(),
            1,
            "a concurrent rename must surface as a conflict, got: {:?}",
            conflicts.iter().map(|c| &c.title).collect::<Vec<_>>()
        );
        assert_eq!(conflicts[0].local_secret.title, "Renamed-by-B");
        assert_eq!(conflicts[0].remote_secret.title, "Renamed-by-A");

        std::thread::sleep(Duration::from_millis(20));

        // Resolve keep-remote exactly like the TUI's 'r' handler: remote's
        // triple applied, fresh "now" stamp.
        let resolved = &conflicts[0];
        let b_sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_b);
        {
            let conn_b = crate::db::open_keyed_connection(&device_b.vault_path, &b_sqlcipher_key).unwrap();
            let now = crate::db::now_timestamp(&conn_b).unwrap();
            crate::db::update_secret_raw(
                &conn_b,
                resolved.local_secret.id,
                &resolved.remote_secret.title,
                &resolved.remote_secret.category,
                &resolved.remote_secret.username,
                &resolved.remote_secret.url,
                &resolved.remote_secret.encrypted_password,
                resolved.remote_secret.encrypted_notes.as_deref(),
                &now,
            )
            .unwrap();
        }
        let final_sync = super::git_sync_vault(&device_b.vault_path, &key_b);
        assert!(final_sync.is_ok(), "post-resolution sync failed: {:?}", final_sync);

        // Both the local vault and (via A's next merge) the shared repo
        // agree on the chosen name.
        let conn_b_final = crate::db::open_keyed_connection(&device_b.vault_path, &b_sqlcipher_key).unwrap();
        assert_eq!(crate::db::get_secrets(&conn_b_final).unwrap()[0].title, "Renamed-by-A");
        drop(conn_b_final);
        let sync_a = super::git_sync_vault(&device_a.vault_path, &key_a);
        assert!(sync_a.is_ok());
        let conn_a_final = crate::db::open_keyed_connection(&device_a.vault_path, &a_sqlcipher_key).unwrap();
        assert_eq!(crate::db::get_secrets(&conn_a_final).unwrap()[0].title, "Renamed-by-A");

        let _ = std::fs::remove_dir_all(&root);
    }
}
