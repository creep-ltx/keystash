pub mod crypto;
pub mod db;
pub mod tui;
pub mod forms;
pub mod modals;
pub mod render;
pub mod import;
pub mod sync;
pub mod generator;
pub mod audit;
pub mod config;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use rpassword::read_password;
use zeroize::{Zeroize, Zeroizing};
use std::process::{Command, Stdio};

#[cfg(unix)]
fn set_dir_permissions<P: AsRef<Path>>(path: P) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_permissions<P: AsRef<Path>>(_path: P) {}

/// Every file/directory KeyStash creates (vault.db, vault.salt, the config
/// directory, exported CSVs) is created first under the process's default
/// umask and only `chmod`'d to its intended restrictive mode afterward --
/// leaving a brief window, on a permissive umask, where it could be readable
/// by other local users before that follow-up chmod lands. Restricting the
/// umask once at startup, before any of those files exist, means every one of
/// them is created with the restrictive mode from the very first byte written,
/// closing that window everywhere at once instead of at each call site.
#[cfg(unix)]
fn set_restrictive_umask() {
    // SAFETY: umask(2) is a simple side-effect-only libc call operating purely
    // on integers (the process's file-creation mask) -- no pointers, no
    // aliasing or lifetime concerns.
    unsafe extern "C" {
        fn umask(mask: u32) -> u32;
    }
    unsafe {
        umask(0o077);
    }
}

#[cfg(not(unix))]
fn set_restrictive_umask() {}

/// A panic (or a non-panic crash like SIGSEGV in a C dependency such as
/// SQLCipher/OpenSSL) can otherwise trigger a core dump containing the
/// entire process address space -- master key, SQLCipher key, and any
/// decrypted passwords/notes currently in memory -- written to disk in
/// plaintext, persistently, outside the app's control. Disabling core dumps
/// at startup closes that off regardless of what crashes later.
#[cfg(unix)]
fn disable_core_dumps() {
    #[repr(C)]
    struct RLimit {
        rlim_cur: u64,
        rlim_max: u64,
    }
    // SAFETY: setrlimit(2) is a simple libc call taking a pointer to a
    // plain-old-data struct we own for the duration of the call; no aliasing
    // or lifetime concerns.
    unsafe extern "C" {
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }
    const RLIMIT_CORE: i32 = 4; // Linux and macOS agree on this value.
    let zero = RLimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        setrlimit(RLIMIT_CORE, &zero);
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}

/// Takes ownership as `Zeroizing<String>` rather than a plain `String` so the
/// plaintext is wiped when this function returns, regardless of which branch
/// below is taken -- a plain `String` parameter would just drop normally,
/// leaving its contents intact in already-freed heap memory.
fn copy_to_clipboard(text: Zeroizing<String>, label: &str) {
    if text.trim().is_empty() {
        eprintln!("Cannot copy: {} is empty!", label);
        return;
    }

    let delay = crate::config::AppConfig::load().clipboard_clear_seconds;

    if let Ok(exe) = env::current_exe() {
        let child = Command::new(exe)
            .arg("__internal-clear-clipboard")
            .arg(delay.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut child_proc) => {
                if let Some(mut stdin) = child_proc.stdin.take() {
                    let _ = stdin.write_all(text.as_bytes());
                }
                println!("Copied {} to clipboard! Will clear in {}s.", label, delay);
            }
            Err(_) => {
                eprintln!("Failed to spawn clipboard manager process.");
            }
        }
    } else {
        eprintln!("Failed to locate KeyStash executable path.");
    }
}

pub fn get_db_path() -> PathBuf {
    // KEYSTASH_CONFIG_DIR overrides the entire directory resolution below:
    // it names the directory vault.db (and config.json) live in directly --
    // no `keystash/` subdirectory is appended. It exists so tests can give
    // each test its own isolated vault directory without mutating the
    // process-wide HOME (the reason two regression tests used to be
    // #[ignore]d), and doubles as an escape hatch for unusual setups; a
    // future --profile flag can build on this same seam.
    if let Ok(dir) = env::var("KEYSTASH_CONFIG_DIR") {
        let mut path = PathBuf::from(dir);
        let _ = fs::create_dir_all(&path);
        set_dir_permissions(&path);
        path.push("vault.db");
        return path;
    }
    // XDG_CONFIG_HOME, when set, is the correct place to look first (it
    // already points at a config dir, so keystash/ is appended directly
    // instead of assuming a .config subdirectory of it). Falling back
    // silently to the current working directory when HOME is unset used to
    // be an accident, not a decision: for a password manager, a vault that
    // silently lands in a different place depending on which directory you
    // happened to run the command from is a real hazard, not a convenience
    // -- so that fallback now at least warns loudly instead of staying quiet.
    let mut path = if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = env::var("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".config");
        p
    } else {
        eprintln!(
            "Warning: neither XDG_CONFIG_HOME nor HOME is set -- using ./.config/keystash \
             relative to the current directory. This vault will only be found again if \
             keystash is run from this same directory every time."
        );
        PathBuf::from("./.config")
    };
    path.push("keystash");
    let _ = fs::create_dir_all(&path);
    set_dir_permissions(&path);
    path.push("vault.db");
    path
}

fn prompt_password(prompt: &str) -> zeroize::Zeroizing<String> {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    zeroize::Zeroizing::new(read_password().unwrap_or_default())
}

/// Truncates to at most `max_chars` Unicode scalar values. Slicing a `&str` by
/// raw byte index (e.g. `&s[..22]`) panics if that byte offset falls in the
/// middle of a multi-byte character -- reachable with any title/category/
/// username containing non-ASCII text.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Parses `keystash search`'s args (everything after "search" itself) into
/// (query, reveal). A `--` sentinel marks an explicit end of flags --
/// whatever follows it is the query verbatim, even if it looks like a flag
/// itself (a real search term starting with '-'). Without one, only args
/// matching a *known* flag are skipped -- previously any arg starting with
/// '-' at all was skipped outright, so a query like "-test" could never be
/// found no matter how it was passed.
fn parse_search_args(rest: &[String]) -> (Option<&String>, bool) {
    let reveal = rest.iter().any(|a| a == "--reveal" || a == "-r");
    let query = if let Some(dash_dash) = rest.iter().position(|a| a == "--") {
        rest.get(dash_dash + 1)
    } else {
        rest.iter().find(|a| a.as_str() != "--reveal" && a.as_str() != "-r")
    };
    (query, reveal)
}

/// Prompts for the master password and opens the vault at `db_path`, transparently
/// migrating a pre-SQLCipher legacy vault (encrypted-columns-only, plaintext
/// schema) to the new whole-database SQLCipher format first if needed. Shared by
/// every CLI subcommand that operates on an existing vault, since opening it now
/// requires the key up front rather than being possible before a password prompt.
fn open_or_migrate_vault(db_path: &Path) -> Option<(rusqlite::Connection, zeroize::Zeroizing<[u8; 32]>)> {
    match db::detect_vault_state(db_path) {
        db::VaultState::New => {
            eprintln!("Vault is not initialized. Run `keystash init` first.");
            None
        }
        db::VaultState::InterruptedMigration => {
            eprintln!("{}", db::interrupted_migration_message(db_path));
            None
        }
        db::VaultState::InterruptedRotation => {
            eprintln!("{}", db::interrupted_rotation_message(db_path));
            None
        }
        db::VaultState::NeedsMigration => {
            println!("Legacy vault detected -- migrating to the new encrypted database format.");
            let master_pass = prompt_password("Enter Master Password: ");
            match db::migrate_legacy_vault(db_path, &master_pass) {
                Ok(pair) => {
                    println!("Migration complete. The previous vault file was kept as a backup.");
                    Some(pair)
                }
                Err(e) => {
                    eprintln!("Migration failed: {}", e);
                    None
                }
            }
        }
        db::VaultState::Ready => {
            let master_pass = prompt_password("Enter Master Password: ");
            match db::open_vault(db_path, &master_pass) {
                Ok(pair) => {
                    // Same unlock-time tombstone pruning as the TUI (see
                    // handle_lock_input): git-less users need a prune site
                    // too, and sync's own pre-push prune covers the rest.
                    let _ = db::prune_old_tombstones(&pair.0);
                    Some(pair)
                }
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    None
                }
            }
        }
    }
}

/// Interactive `keystash sync setup`: figures out which side of the setup
/// this device is on (a local vault exists -> first device, push it; no
/// local vault -> additional device, pull from the remote), asks for the
/// remote URL, shows the plan, and hands off to `sync::setup_sync_repo`.
/// Needs no master password -- it never opens the vault, only moves the
/// (encrypted) file around.
fn run_sync_setup_wizard(db_path: &Path) {
    let dir = match db_path.parent() {
        Some(d) => d,
        None => {
            eprintln!("Invalid vault directory.");
            return;
        }
    };
    println!("KeyStash sync setup");
    println!("-------------------");
    if dir.join(".git").exists() {
        println!("This directory is already a git repository: {:?}", dir);
        println!("To change its remote: git remote set-url origin <url>");
        println!("To sync now:          keystash sync");
        return;
    }

    let first_device = db_path.exists();
    if first_device {
        println!("A local vault exists -- setting up as the FIRST device:");
        println!("  the local vault will be pushed to the remote as the initial backup.");
    } else {
        println!("No local vault here -- setting up as an ADDITIONAL device:");
        println!("  the existing vault will be pulled down from the remote.");
    }
    println!();
    println!("Any git remote works (it only ever stores the encrypted vault file):");
    println!("  - a private GitHub/GitLab repo:  git@github.com:you/my-vault.git");
    println!("  - any machine you can SSH into:  you@server:vault.git   (create with `git init --bare vault.git` there)");
    println!("  - a NAS mount or USB stick:      /mnt/nas/vault.git     (same, `git init --bare`)");
    println!();
    print!("Remote URL: ");
    let _ = io::stdout().flush();
    let mut url = String::new();
    let _ = io::stdin().read_line(&mut url);
    let url = url.trim();
    if url.is_empty() {
        eprintln!("No URL entered -- nothing was changed.");
        return;
    }

    print!(
        "Set up {:?} as a git repo synced to '{}' ({} device)? (y/N): ",
        dir,
        url,
        if first_device { "first" } else { "additional" }
    );
    let _ = io::stdout().flush();
    let mut answer = String::new();
    let _ = io::stdin().read_line(&mut answer);
    if answer.trim().to_lowercase() != "y" {
        println!("Setup cancelled -- nothing was changed.");
        return;
    }

    match sync::setup_sync_repo(db_path, url, first_device) {
        Ok(msg) => println!("{}", msg),
        Err(e) => eprintln!("Setup failed: {}", e),
    }
}

fn print_help() {
    println!("KeyStash 🔑 - Secure Offline Password Manager");
    println!();
    println!("Storage Location:");
    println!("  ~/.config/keystash/vault.db");
    println!();
    println!("Usage:");
    println!("  keystash [tui]                            Start the interactive TUI (default)");
    println!("  keystash init                             Initialize the password vault");
    println!("  keystash add <title> <tags> <user> [url]  Add a new secret (tags: comma-separated, e.g. \"work,email\")");
    println!("  keystash list [--reveal]                  List stored credentials (passwords masked by default)");
    println!("  keystash search <query> [--reveal]        Search stored credentials (passwords masked by default)");
    println!("  keystash show <id> [--reveal]             Show detailed decrypted view of an entry");
    println!("  keystash copy <id> [username|password|url] Copy entry's field to clipboard (default: password)");
    println!("  keystash import <path>                    Import unencrypted logins (Bitwarden JSON; KeyStash, Brave/Chrome, Firefox, LastPass, KeePassXC, 1Password CSV)");
    println!("  keystash export <path>                    Export all vault credentials to an unencrypted CSV file");
    println!("  keystash delete <id>                      Delete a credential by its ID");
    println!("  keystash reset                            Delete/nuke the entire vault file");
    println!("  keystash sync                             Force manual Git sync/merge");
    println!("  keystash sync setup                       Interactive one-time git sync setup (first or additional device)");
    println!("  keystash audit [--hibp]                   Audit vault (optional HIBP check via --hibp)");
    println!("  keystash generate [-l <len>] [--words [n]] [--no-uppercase] [--no-numbers] [--no-symbols] [--save]");
    println!("                                            Generate a password (20 chars default, 4-256) or, with --words [n], a diceware passphrase (n words from the EFF large list, default 6); --save persists charset options");
    println!("  keystash change-password                  Change Master Password and rotate keys");
    println!("  keystash help                             Show this help message");
}

fn main() {
    set_restrictive_umask();
    disable_core_dumps();
    let raw_args: Vec<String> = env::args().collect();
    if raw_args.len() >= 3 && raw_args[1] == "__internal-clear-clipboard" {
        use std::io::Read;
        let secs: u64 = raw_args[2].parse().unwrap_or(5);
        let mut password = String::new();
        if std::io::stdin().read_to_string(&mut password).is_ok() {
            let password_trimmed: Zeroizing<String> = Zeroizing::new(password.trim_end().to_string());
            password.zeroize();
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                // set_text takes `impl Into<Cow<str>>`, which a &str satisfies
                // directly -- no need to hand it an extra owned clone just to
                // meet its signature. Whatever copy the OS clipboard/X11
                // selection mechanism itself retains after that is outside
                // what Rust-side zeroizing can reach either way; that's true
                // of any clipboard manager, not specific to this call.
                if clipboard.set_text(password_trimmed.as_str()).is_ok() {
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    if let Ok(mut current_text) = clipboard.get_text() {
                        if current_text == *password_trimmed {
                            let _ = clipboard.set_text("");
                        }
                        current_text.zeroize();
                    }
                }
            }
        }
        return;
    }
    let no_sync = raw_args.iter().any(|arg| arg == "--no-sync");
    let args: Vec<String> = raw_args.into_iter().filter(|arg| arg != "--no-sync").collect();
    let db_path = get_db_path();
    
    // Ensure parent directory of db_path exists
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
        set_dir_permissions(parent);
    }

    if args.len() < 2 {
        start_tui(no_sync);
        return;
    }

    match args[1].as_str() {
        "tui" => {
            start_tui(no_sync);
        }
        "init" => {
            match db::detect_vault_state(&db_path) {
                db::VaultState::Ready => {
                    println!("Vault is already initialized at {:?}", db_path);
                    return;
                }
                db::VaultState::NeedsMigration => {
                    // Reuse the same migration path as every other command; init's
                    // job here is just to get an old vault onto the new format.
                    if open_or_migrate_vault(&db_path).is_some() {
                        println!("Vault at {:?} is now on the new encrypted format.", db_path);
                    }
                    return;
                }
                db::VaultState::InterruptedMigration => {
                    // Refuse to init: falling through here would create a
                    // brand new empty vault right on top of recoverable data.
                    eprintln!("{}", db::interrupted_migration_message(&db_path));
                    return;
                }
                db::VaultState::InterruptedRotation => {
                    eprintln!("{}", db::interrupted_rotation_message(&db_path));
                    return;
                }
                db::VaultState::New => {}
            }
            let pass = prompt_password("Set Master Password: ");
            // Reject empty BEFORE the match check: two empty reads also
            // "match", which is exactly what happens when rpassword can't
            // read at all (stdin is a pipe, no tty) and prompt_password
            // falls back to "" -- previously that silently created a vault
            // whose master password is the empty string. The TUI setup
            // screen and `change-password` have always refused empty; init
            // was the one entry point that didn't.
            if pass.trim().is_empty() {
                eprintln!("Master password cannot be empty. (If you are piping input: keystash reads passwords from the terminal, not stdin.)");
                return;
            }
            let confirm = prompt_password("Confirm Master Password: ");
            if pass != confirm {
                eprintln!("Passwords do not match.");
                return;
            }
            match db::create_vault(&db_path, &pass) {
                Ok(_) => println!("Vault successfully initialized at {:?}", db_path),
                Err(e) => eprintln!("Initialization failed: {}", e),
            }
        }
        "add" => {
            if args.len() < 5 {
                eprintln!("Usage: keystash add <title> <tags> <username> [url]");
                return;
            }
            // Tags are stored normalized (split on commas, trimmed, deduped)
            // so CLI-added and TUI-added records land identically.
            let tags = db::normalize_tags(&args[3]);
            if tags.is_empty() {
                eprintln!("At least one tag is required (e.g. \"work\" or \"work,email\").");
                return;
            }
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            let pass = prompt_password("Enter Secret Password: ");
            // Same rule the TUI's Add/Edit form has always enforced -- and
            // the same no-tty fallback protection as `init` above: without
            // this, a failed prompt read stored a credential with an empty
            // password while reporting success.
            if pass.trim().is_empty() {
                eprintln!("Password cannot be empty.");
                return;
            }
            print!("Enter Notes (optional): ");
            let _ = io::stdout().flush();
            let mut notes: Zeroizing<String> = Zeroizing::new(String::new());
            let _ = io::stdin().read_line(&mut notes);
            let notes_clean = notes.trim();

            let url = if args.len() >= 6 { &args[5] } else { "" };

            match db::add_secret(
                &conn,
                &args[2],
                &tags,
                &args[4],
                url,
                &pass,
                if notes_clean.is_empty() { None } else { Some(notes_clean) },
                &key,
            ) {
                Ok(_) => println!("Secret successfully saved!"),
                Err(e) => eprintln!("Error saving secret: {}", e),
            }
        }
        "list" => {
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            let reveal = args.iter().any(|arg| arg == "--reveal" || arg == "-r");
            match db::get_secrets(&conn) {
                Ok(records) => {
                    let pass_header = if reveal { "Password" } else { "Password (Masked)" };
                    println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", "ID", "Title", "Tags", "Username", "URL", pass_header);
                    println!("{}", "-".repeat(100));
                    for r in records {
                        let decrypted_pass = if reveal {
                            crypto::decrypt(&r.encrypted_password, &key)
                                .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                                .unwrap_or_else(|_| Zeroizing::new("<Error>".to_string()))
                        } else {
                            Zeroizing::new("••••••••".to_string())
                        };
                        println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", r.id, r.title, r.category, r.username, r.url, *decrypted_pass);
                    }
                }
                Err(e) => eprintln!("Error fetching secrets: {}", e),
            }
        }
        "search" => {
            let rest = args.get(2..).unwrap_or(&[]);
            let (query_opt, reveal) = parse_search_args(rest);
            let query = match query_opt {
                Some(q) => q.to_lowercase(),
                None => {
                    eprintln!("Usage: keystash search <query> [--reveal]");
                    return;
                }
            };
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            match db::get_secrets(&conn) {
                Ok(records) => {
                    let filtered: Vec<db::SecretRecord> = records
                        .into_iter()
                        .filter(|r| {
                            r.title.to_lowercase().contains(&query)
                                || r.category.to_lowercase().contains(&query)
                                || r.username.to_lowercase().contains(&query)
                                || r.url.to_lowercase().contains(&query)
                        })
                        .collect();

                    if filtered.is_empty() {
                        println!("No credentials matching '{}' found.", query);
                    } else {
                        let pass_header = if reveal { "Password" } else { "Password (Masked)" };
                        println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", "ID", "Title", "Tags", "Username", "URL", pass_header);
                        println!("{}", "-".repeat(100));
                        for r in filtered {
                            let decrypted_pass = if reveal {
                                crypto::decrypt(&r.encrypted_password, &key)
                                    .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                                    .unwrap_or_else(|_| Zeroizing::new("<Error>".to_string()))
                            } else {
                                Zeroizing::new("••••••••".to_string())
                            };
                            println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", r.id, r.title, r.category, r.username, r.url, *decrypted_pass);
                        }
                    }
                }
                Err(e) => eprintln!("Error searching secrets: {}", e),
            }
        }
        "delete" => {
            if args.len() < 3 {
                eprintln!("Usage: keystash delete <id>");
                return;
            }
            let id: i64 = match args[2].parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("Invalid ID: {}", args[2]);
                    return;
                }
            };
            let (conn, _key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            match db::delete_secret(&conn, id) {
                Ok(_) => println!("Secret successfully deleted."),
                Err(e) => eprintln!("Error deleting secret: {}", e),
            }
        }
        "import" => {
            if args.len() < 3 {
                eprintln!("Usage: keystash import <file_path>");
                return;
            }
            let file_path = &args[2];
            if db::detect_vault_state(&db_path) == db::VaultState::New {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }

            // 1. Detect export format first before asking for master password
            let detected_format = match import::detect_format(file_path) {
                Ok(fmt) => fmt,
                Err(e) => {
                    eprintln!("Import failed: {}", e);
                    return;
                }
            };

            print!("Detected {} export format. Do you want to continue importing? (y/N): ", detected_format.name());
            let _ = io::stdout().flush();
            let mut answer = String::new();
            let _ = io::stdin().read_line(&mut answer);
            if answer.trim().to_lowercase() != "y" {
                println!("Import cancelled.");
                return;
            }

            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };

            // Bitwarden JSON items carry a type, so it reports a skipped
            // count (non-login items) alongside the imported one; every
            // other format is a flat login-only CSV with nothing to skip.
            let import_result = match detected_format {
                import::ImportFormat::BitwardenJson => import::import_bitwarden_json(&conn, file_path, &key),
                import::ImportFormat::BraveChromeCsv => import::import_brave_chrome_csv(&conn, file_path, &key).map(|c| (c, 0)),
                import::ImportFormat::FirefoxCsv => import::import_firefox_csv(&conn, file_path, &key).map(|c| (c, 0)),
                import::ImportFormat::LastPassCsv => import::import_lastpass_csv(&conn, file_path, &key).map(|c| (c, 0)),
                import::ImportFormat::KeePassXcCsv => import::import_keepassxc_csv(&conn, file_path, &key).map(|c| (c, 0)),
                import::ImportFormat::OnePasswordCsv => import::import_onepassword_csv(&conn, file_path, &key).map(|c| (c, 0)),
                import::ImportFormat::KeyStashCsv => import::import_keystash_csv(&conn, file_path, &key).map(|c| (c, 0)),
            };

            match import_result {
                Ok((count, skipped)) => {
                    println!("Success: Imported {} items from {}!", count, detected_format.name());
                    if skipped > 0 {
                        println!("Skipped {} non-login item(s) (secure notes, cards, or identities have no password field to import).", skipped);
                    }
                    if sync::is_git_configured(&db_path) {
                        println!("Syncing updates to Git remote...");
                        let _ = sync::git_sync_vault_with_retention(&db_path, &key, config::AppConfig::load().history_retention);
                    }
                }
                Err(e) => eprintln!("Import failed: {}", e),
            }
        }
        "export" => {
            if args.len() < 3 {
                eprintln!("Usage: keystash export <output_file_path>");
                return;
            }
            let output_path = &args[2];
            if db::detect_vault_state(&db_path) == db::VaultState::New {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }

            println!("WARNING: The exported CSV file will contain unencrypted plaintext passwords.");
            print!("Are you sure you want to export your vault? (y/N): ");
            let _ = io::stdout().flush();
            let mut answer = String::new();
            let _ = io::stdin().read_line(&mut answer);
            if answer.trim().to_lowercase() != "y" {
                println!("Export cancelled.");
                return;
            }

            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };

            println!("Decrypting and exporting vault records to CSV...");
            match import::export_vault_csv(&conn, output_path, &key, None) {
                Ok(count) => {
                    println!("Success: Exported {} secrets to '{}'!", count, output_path);
                    println!("Please delete this file securely as soon as you are done using it.");
                }
                Err(e) => eprintln!("Export failed: {}", e),
            }
        }
        "reset" => {
            println!("WARNING: This will permanently delete your database file at {:?}", db_path);
            print!("Are you sure you want to completely reset and delete your vault? (y/N): ");
            let _ = io::stdout().flush();
            let mut answer = String::new();
            let _ = io::stdin().read_line(&mut answer);
            if answer.trim().to_lowercase() == "y" {
                // Also remove the salt sidecar and WAL/SHM journal sidecars, so a
                // reset can't leave a stale vault.salt behind that would silently
                // make the next `init` create a blank vault under a mismatched key.
                let mut removed_any = false;
                for path in [
                    db_path.clone(),
                    db_path.with_file_name("vault.db-wal"),
                    db_path.with_file_name("vault.db-shm"),
                    db_path.with_file_name("vault.salt"),
                ] {
                    if path.exists() {
                        match fs::remove_file(&path) {
                            Ok(_) => removed_any = true,
                            Err(e) => eprintln!("Failed to delete {:?}: {}", path, e),
                        }
                    }
                }
                if removed_any {
                    println!("Vault database successfully deleted. You can run `keystash init` to create a new one.");
                } else {
                    println!("No database file existed at {:?}", db_path);
                }
            } else {
                println!("Reset cancelled.");
            }
        }
        "change-password" => {
            let (conn, old_key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };

            let new_pass = prompt_password("Enter New Master Password: ");
            if new_pass.trim().is_empty() {
                eprintln!("Password cannot be empty!");
                return;
            }
            let confirm_pass = prompt_password("Confirm New Master Password: ");
            if new_pass != confirm_pass {
                eprintln!("Passwords do not match!");
                return;
            }

            println!("Rotating encryption keys and re-encrypting vault records...");
            // change_master_password builds the re-keyed vault at a separate
            // temp path and swaps it in; `conn` (still open against whatever
            // is now at the pre-rotation backup path) is stale after this and
            // deliberately not reused -- this process exits right after anyway.
            match db::change_master_password(&conn, &db_path, &old_key, &new_pass) {
                Ok(new_key) => {
                    println!("Success: Master Password changed and vault records re-encrypted!");
                    if sync::is_git_configured(&db_path) {
                        println!("Syncing updates to Git remote...");
                        let _ = sync::git_sync_vault_with_retention(&db_path, &new_key, config::AppConfig::load().history_retention);
                    }
                }
                Err(e) => eprintln!("Failed to change Master Password: {}", e),
            }
        }
        "sync" => {
            if args.get(2).map(|s| s.as_str()) == Some("setup") {
                run_sync_setup_wizard(&db_path);
                return;
            }
            let (_conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            println!("Syncing vault with Git remote...");
            match sync::git_sync_vault_with_retention(&db_path, &key, config::AppConfig::load().history_retention) {
                Ok(msg) => println!("{}", msg),
                Err(err) => eprintln!("Sync Error: {}", err),
            }
        }
        "audit" => {
            let run_hibp = args.iter().any(|a| a == "--hibp");
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            let records = match db::get_secrets(&conn) {
                Ok(r) => r,
                Err(e) => { eprintln!("Error fetching secrets: {}", e); return; }
            };
            if records.is_empty() {
                println!("Vault is empty — nothing to audit.");
                return;
            }

            // Keep a copy of plaintext passwords for HIBP if needed. This can
            // sit in memory for a while (the HIBP loop below rate-limits at
            // 700ms/entry), so each password is wrapped so it's wiped once
            // this whole scope is done with it.
            let mut plaintext_for_hibp: Vec<(i64, Zeroizing<String>)> = Vec::new();
            let mut plaintext_records: Vec<(i64, String, String, String, String)> = records
                .iter()
                .filter_map(|r| {
                    crypto::decrypt(&r.encrypted_password, &key)
                        .ok()
                        .and_then(|dec| String::from_utf8(dec.to_vec()).ok())
                        .map(|pw| {
                            if run_hibp {
                                plaintext_for_hibp.push((r.id, Zeroizing::new(pw.clone())));
                            }
                            (r.id, r.title.clone(), r.category.clone(), r.username.clone(), pw)
                        })
                })
                .collect();

            let mut report = audit::audit_passwords(&mut plaintext_records, &key);

            // ── Optional HIBP check ──
            if run_hibp {
                let total = plaintext_for_hibp.len();
                println!("\n  Checking HaveIBeenPwned ({} entries)...", total);
                println!("  Note: only the first 5 chars of each SHA-1 hash are sent.");
                let mut pwned_count = 0u32;
                for (i, (id, pw)) in plaintext_for_hibp.iter().enumerate() {
                    print!("  [{}/{}]\r", i + 1, total);
                    let _ = io::stdout().flush();
                    match audit::check_hibp(pw) {
                        Ok(n) => {
                            if let Some(entry) = report.entries.iter_mut().find(|e| e.id == *id) {
                                entry.hibp_count = Some(n);
                                if n > 0 { pwned_count += 1; }
                            }
                        }
                        Err(e) => eprintln!("\n  HIBP check failed for ID {}: {}", id, e),
                    }
                    // Rate limiting: HIBP allows ~1.5 req/s; stay safe
                    std::thread::sleep(Duration::from_millis(700));
                }
                println!("  HIBP complete: {} password(s) found in known breaches.", pwned_count);
            }

            // ── Print report ──
            println!();
            println!("  KeyStash Security Audit");
            println!("  {} entries checked", report.critical_count + report.weak_count + report.good_count);
            println!(
                "  ✗ Critical: {}   ⚠ Weak: {}   ✓ Good: {}",
                report.critical_count, report.weak_count, report.good_count
            );
            if !report.duplicate_groups.is_empty() {
                println!("  ⚠ {} password reuse group(s) detected", report.duplicate_groups.len());
            }
            println!();

            let hibp_col = if run_hibp { "  HIBP Breaches" } else { "" };
            println!(
                "  {:<4}  {:<22}  {:<14}  {:<22}  {:<10}  Issues{}",
                "ID", "Title", "Tags", "Username", "Strength", hibp_col
            );
            println!("  {}", "-".repeat(if run_hibp { 115 } else { 100 }));

            for entry in &report.entries {
                let label = match entry.severity {
                    audit::Severity::Critical => "[CRITICAL]",
                    audit::Severity::Weak     => "[WEAK]    ",
                    audit::Severity::Good     => "[GOOD]    ",
                };
                let issue_str = if entry.issues.is_empty() {
                    "-".to_string()
                } else {
                    entry.issues.join("; ")
                };
                let hibp_str = if run_hibp {
                    match entry.hibp_count {
                        Some(0) => "  ✓ Clean".to_string(),
                        Some(n) => format!("  ✗ PWNED ({n}x)"),
                        None    => "  ? Error".to_string(),
                    }
                } else {
                    String::new()
                };
                println!(
                    "  {:<4}  {:<22}  {:<14}  {:<22}  {}  {}{}",
                    entry.id,
                    truncate_chars(&entry.title, 22),
                    truncate_chars(&entry.category, 14),
                    truncate_chars(&entry.username, 22),
                    label,
                    issue_str,
                    hibp_str
                );
            }
            println!();
        }

        "show" | "view" => {
            if args.len() < 3 {
                eprintln!("Usage: keystash show <id> [--reveal]");
                return;
            }
            let id: i64 = match args[2].parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("Invalid ID: {}", args[2]);
                    return;
                }
            };
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            let reveal = args.iter().any(|arg| arg == "--reveal" || arg == "-r");
            match db::get_secrets(&conn) {
                Ok(records) => {
                    if let Some(r) = records.into_iter().find(|rec| rec.id == id) {
                        let decrypted_pass = if reveal {
                            crypto::decrypt(&r.encrypted_password, &key)
                                .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                                .unwrap_or_else(|_| Zeroizing::new("<Error>".to_string()))
                        } else {
                            Zeroizing::new("••••••••".to_string())
                        };
                        let decrypted_notes = if let Some(enc_notes) = &r.encrypted_notes {
                            if reveal {
                                crypto::decrypt(enc_notes, &key)
                                    .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                                    .unwrap_or_else(|_| Zeroizing::new("<Error>".to_string()))
                            } else {
                                Zeroizing::new("••••••••".to_string())
                            }
                        } else {
                            Zeroizing::new("[No Notes]".to_string())
                        };

                        println!("Secret Details (ID: {}):", r.id);
                        println!("----------------------------------------");
                        println!("Title:    {}", r.title);
                        println!("Tags:     {}", r.category);
                        println!("Username: {}", r.username);
                        println!("URL:      {}", r.url);
                        println!("Password: {}", *decrypted_pass);
                        println!("Notes:    {}", *decrypted_notes);
                        println!("Updated:  {}", r.updated_at);
                        println!("----------------------------------------");
                    } else {
                        println!("Secret with ID {} not found.", id);
                    }
                }
                Err(e) => eprintln!("Error fetching secrets: {}", e),
            }
        }
        "copy" => {
            if args.len() < 3 {
                eprintln!("Usage: keystash copy <id> [username|password|url]");
                return;
            }
            let id: i64 = match args[2].parse() {
                Ok(n) => n,
                Err(_) => {
                    eprintln!("Invalid ID: {}", args[2]);
                    return;
                }
            };
            let field = if args.len() >= 4 { args[3].as_str() } else { "password" };
            let (conn, key) = match open_or_migrate_vault(&db_path) {
                Some(pair) => pair,
                None => return,
            };
            match db::get_secrets(&conn) {
                Ok(records) => {
                    if let Some(r) = records.into_iter().find(|rec| rec.id == id) {
                        let text_to_copy = match field {
                            "username" | "user" => Some(r.username.clone()),
                            "url" => Some(r.url.clone()),
                            "password" | "pass" => {
                                crypto::decrypt(&r.encrypted_password, &key)
                                    .map(|dec| String::from_utf8_lossy(&dec).to_string())
                                    .ok()
                            }
                            other => {
                                eprintln!("Unknown copy target '{}'. Choose from: username, password, url.", other);
                                None
                            }
                        };

                        if let Some(text) = text_to_copy {
                            copy_to_clipboard(Zeroizing::new(text), field);
                        }
                    } else {
                        println!("Secret with ID {} not found.", id);
                    }
                }
                Err(e) => eprintln!("Error fetching secrets: {}", e),
            }
        }
        "generate" | "gen" => {
            let mut options = generator::GeneratorOptions::load();
            let mut save_as_defaults = false;
            // Some(n) switches to diceware passphrase mode (n words from
            // the embedded EFF large list) instead of random characters.
            let mut passphrase_words: Option<usize> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--save" => {
                        save_as_defaults = true;
                        i += 1;
                    }
                    "--words" | "-w" => {
                        // Optional count: `--words 7` or bare `--words`.
                        if let Some(n) = args.get(i + 1).and_then(|a| a.parse::<usize>().ok()) {
                            passphrase_words = Some(n);
                            i += 2;
                        } else {
                            passphrase_words = Some(generator::DEFAULT_WORDS);
                            i += 1;
                        }
                    }
                    "-l" | "--length" => {
                        if i + 1 < args.len() {
                            if let Ok(l) = args[i + 1].parse::<usize>() {
                                options.length = l;
                            } else {
                                eprintln!("Invalid length: {}", args[i + 1]);
                                return;
                            }
                            i += 2;
                        } else {
                            eprintln!("Missing length value.");
                            return;
                        }
                    }
                    "--no-uppercase" => {
                        options.use_uppercase = false;
                        i += 1;
                    }
                    "--no-numbers" => {
                        options.use_numbers = false;
                        i += 1;
                    }
                    "--no-symbols" => {
                        options.use_symbols = false;
                        i += 1;
                    }
                    "--uppercase" => {
                        options.use_uppercase = true;
                        i += 1;
                    }
                    "--numbers" => {
                        options.use_numbers = true;
                        i += 1;
                    }
                    "--symbols" => {
                        options.use_symbols = true;
                        i += 1;
                    }
                    other => {
                        eprintln!("Unknown option: {}", other);
                        return;
                    }
                }
            }

            // Persisting is opt-in: a one-off `--no-symbols` for some
            // legacy site must not silently become the permanent default
            // for every future password (which is what happened before).
            // (--words is a per-run mode, never persisted.)
            if save_as_defaults {
                options.length = options.length.clamp(generator::MIN_LENGTH, generator::MAX_LENGTH);
                match options.save() {
                    Ok(()) => println!("Saved these options as your new generator defaults."),
                    Err(e) => eprintln!("Could not save generator defaults: {}", e),
                }
            }

            if let Some(words) = passphrase_words {
                let pass = generator::generate_passphrase(words);
                println!("{}", pass);
                copy_to_clipboard(Zeroizing::new(pass), "generated passphrase");
                return;
            }

            match generator::generate_password(&options) {
                Ok(pass) => {
                    println!("{}", pass);
                    copy_to_clipboard(Zeroizing::new(pass), "generated password");
                }
                Err(e) => {
                    eprintln!("Error generating password: {}", e);
                }
            }
        }
        "help" | "-h" | "--help" => {
            print_help();
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_help();
        }
    }
}

fn start_tui(no_sync: bool) {
    // TuiApp no longer needs (or can use) a pre-opened Connection: opening the
    // now SQLCipher-encrypted vault.db requires the key, which isn't known until
    // the user has entered their master password on the Setup/Lock screen. See
    // `tui::TuiApp::new` for how it defers the real connection until then, and
    // `tui::run_tui` for where the exit-time sync now lives (it also needs the
    // key, so it has to run from inside tui.rs after the app has one).
    let app = tui::TuiApp::new(no_sync);
    if let Err(e) = tui::run_tui(app) {
        eprintln!("Terminal application crashed: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_does_not_panic_on_multibyte_boundaries() {
        // 21 ASCII chars followed by a 2-byte character: byte-slicing at 22
        // would land inside that character's second byte and panic.
        let title = format!("{}\u{00e9}more text after", "a".repeat(21));
        assert_eq!(truncate_chars(&title, 22).chars().count(), 22);

        // Shorter than the limit: returned unchanged.
        assert_eq!(truncate_chars("short", 22), "short");

        // Entirely multi-byte (emoji, 4 bytes each): still truncates by
        // character count, not byte count.
        let emoji_title: String = std::iter::repeat_n('\u{1F511}', 30).collect();
        assert_eq!(truncate_chars(&emoji_title, 22).chars().count(), 22);
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_search_args_finds_a_plain_query() {
        let a = args(&["github"]);
        let (query, reveal) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("github"));
        assert!(!reveal);
    }

    #[test]
    fn parse_search_args_skips_known_flags_regardless_of_order() {
        let a = args(&["--reveal", "github"]);
        let (query, reveal) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("github"));
        assert!(reveal);

        let a = args(&["github", "-r"]);
        let (query, reveal) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("github"));
        assert!(reveal);
    }

    #[test]
    fn parse_search_args_accepts_a_query_starting_with_a_dash() {
        // The original bug: any arg starting with '-' was skipped outright,
        // so a query like "-test" could never be found at all.
        let a = args(&["-test"]);
        let (query, reveal) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("-test"));
        assert!(!reveal);
    }

    #[test]
    fn parse_search_args_dash_dash_forces_the_next_arg_to_be_the_query_verbatim() {
        // Covers the one case the "skip only known flags" rule alone can't:
        // a query that IS literally "-r" or "--reveal".
        let a = args(&["--", "-r"]);
        let (query, _) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("-r"));

        let a = args(&["--reveal", "--", "--reveal"]);
        let (query, reveal) = parse_search_args(&a);
        assert_eq!(query.map(|s| s.as_str()), Some("--reveal"));
        assert!(reveal, "a --reveal flag before -- should still count");
    }

    #[test]
    fn parse_search_args_no_query_returns_none() {
        let a = args(&["--reveal"]);
        let (query, _) = parse_search_args(&a);
        assert!(query.is_none());

        let a = args(&[]);
        let (query, _) = parse_search_args(&a);
        assert!(query.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umask_applies_to_newly_created_files_before_any_chmod() {
        use std::os::unix::fs::PermissionsExt;

        // umask(2) returns the *previous* mask, so this both applies a
        // deliberately permissive starting mask and captures it for restoring
        // afterward -- umask is process-wide state, and this runs alongside
        // other tests in the same process, so it must not leak.
        unsafe extern "C" {
            fn umask(mask: u32) -> u32;
        }
        let original_mask = unsafe { umask(0o022) };

        let dir = std::env::temp_dir().join(format!("keystash_umask_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("probe_file");

        set_restrictive_umask();
        // No chmod call here at all -- if the umask weren't actually applied,
        // this file would come out world/group-readable (mode & 0o022 bits
        // set), the exact window this fix closes.
        std::fs::write(&file_path, b"probe").unwrap();

        let mode = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;

        unsafe { umask(original_mask) };
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(mode, 0o600, "file created after set_restrictive_umask() should be owner-only, got {:o}", mode);
    }
}
