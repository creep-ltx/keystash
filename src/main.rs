pub mod crypto;
pub mod db;
pub mod tui;
pub mod import;
pub mod sync;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use rpassword::read_password;
use zeroize::Zeroize;
use std::process::{Command, Stdio};

#[cfg(unix)]
fn set_dir_permissions<P: AsRef<Path>>(path: P) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_permissions<P: AsRef<Path>>(_path: P) {}

fn copy_to_clipboard(text: String, label: &str) {
    if text.trim().is_empty() {
        eprintln!("Cannot copy: {} is empty!", label);
        return;
    }

    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if child.is_err() {
        child = Command::new("xclip")
            .arg("-selection")
            .arg("clipboard")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }

    if child.is_err() {
        child = Command::new("xsel")
            .arg("--clipboard")
            .arg("--input")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }

    match child {
        Ok(mut child_proc) => {
            if let Some(mut stdin) = child_proc.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child_proc.wait();
            println!("Copied {} to clipboard! Will clear in 10s.", label);

            // Spawn background shell job to clear the clipboard after 10 seconds
            let _ = Command::new("sh")
                .arg("-c")
                .arg("sleep 10 && (wl-copy -c || xclip -selection clipboard /dev/null || xsel --clipboard --clear)")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        Err(_) => {
            eprintln!("Failed to copy: No clipboard utility found (wl-copy, xclip, xsel).");
        }
    }
}

pub fn get_db_path() -> PathBuf {
    let mut path = if let Ok(home) = env::var("HOME") {
        PathBuf::from(home)
    } else {
        PathBuf::from(".")
    };
    path.push(".config");
    path.push("keystash");
    let _ = fs::create_dir_all(&path);
    set_dir_permissions(&path);
    path.push("vault.db");
    path
}

fn prompt_password(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    read_password().unwrap_or_default()
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
    println!("  keystash add <title> <category> <user> [url] Add a new secret to the database");
    println!("  keystash list [--reveal]                  List stored credentials (passwords masked by default)");
    println!("  keystash search <query> [--reveal]        Search stored credentials (passwords masked by default)");
    println!("  keystash show <id> [--reveal]             Show detailed decrypted view of an entry");
    println!("  keystash copy <id> [username|password|url] Copy entry's field to clipboard (default: password)");
    println!("  keystash import <path>                    Import unencrypted logins (supports Bitwarden, Brave/Chrome, Firefox)");
    println!("  keystash export <path>                    Export all vault credentials to an unencrypted CSV file");
    println!("  keystash delete <id>                      Delete a credential by its ID");
    println!("  keystash reset                            Delete/nuke the entire vault file");
    println!("  keystash sync                             Force manual Git sync/merge");
    println!("  keystash change-password                  Change Master Password and rotate keys");
    println!("  keystash help                             Show this help message");
}

fn main() {
    let raw_args: Vec<String> = env::args().collect();
    let no_sync = raw_args.iter().any(|arg| arg == "--no-sync");
    let args: Vec<String> = raw_args.into_iter().filter(|arg| arg != "--no-sync").collect();
    let db_path = get_db_path();
    
    // Ensure parent directory of db_path exists
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
        set_dir_permissions(parent);
    }

    if args.len() < 2 {
        start_tui(&db_path, no_sync);
        return;
    }

    match args[1].as_str() {
        "tui" => {
            start_tui(&db_path, no_sync);
        }
        "init" => {
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to initialize database: {}", e);
                    return;
                }
            };
            if !db::is_first_run(&conn).unwrap_or(true) {
                println!("Vault is already initialized at {:?}", db_path);
                return;
            }
            let pass = prompt_password("Set Master Password: ");
            let confirm = prompt_password("Confirm Master Password: ");
            if pass != confirm {
                eprintln!("Passwords do not match.");
                return;
            }
            match db::setup_vault(&conn, &pass) {
                Ok(_) => println!("Vault successfully initialized at {:?}", db_path),
                Err(e) => eprintln!("Initialization failed: {}", e),
            }
        }
        "add" => {
            if args.len() < 5 {
                eprintln!("Usage: keystash add <title> <category> <username> [url]");
                return;
            }
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
            };
            let pass = prompt_password("Enter Secret Password: ");
            print!("Enter Notes (optional): ");
            let _ = io::stdout().flush();
            let mut notes = String::new();
            let _ = io::stdin().read_line(&mut notes);
            let notes_clean = notes.trim();

            let url = if args.len() >= 6 { &args[5] } else { "" };

            match db::add_secret(
                &conn,
                &args[2],
                &args[3],
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
            };
            let reveal = args.iter().any(|arg| arg == "--reveal" || arg == "-r");
            match db::get_secrets(&conn) {
                Ok(records) => {
                    let pass_header = if reveal { "Password" } else { "Password (Masked)" };
                    println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", "ID", "Title", "Category", "Username", "URL", pass_header);
                    println!("{}", "-".repeat(100));
                    for r in records {
                        let decrypted_pass = if reveal {
                            crypto::decrypt(&r.encrypted_password, &key)
                                .map(|dec| String::from_utf8_lossy(&dec).to_string())
                                .unwrap_or_else(|_| "<Error>".to_string())
                        } else {
                            "••••••••".to_string()
                        };
                        println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", r.id, r.title, r.category, r.username, r.url, decrypted_pass);
                    }
                }
                Err(e) => eprintln!("Error fetching secrets: {}", e),
            }
        }
        "search" => {
            let reveal = args.iter().any(|arg| arg == "--reveal" || arg == "-r");
            // Find query by skipping flags
            let query_opt = args.iter().skip(2).find(|arg| *arg != "--reveal" && *arg != "-r" && !arg.starts_with('-'));
            let query = match query_opt {
                Some(q) => q.to_lowercase(),
                None => {
                    eprintln!("Usage: keystash search <query> [--reveal]");
                    return;
                }
            };
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
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
                        println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", "ID", "Title", "Category", "Username", "URL", pass_header);
                        println!("{}", "-".repeat(100));
                        for r in filtered {
                            let decrypted_pass = if reveal {
                                crypto::decrypt(&r.encrypted_password, &key)
                                    .map(|dec| String::from_utf8_lossy(&dec).to_string())
                                    .unwrap_or_else(|_| "<Error>".to_string())
                            } else {
                                "••••••••".to_string()
                            };
                            println!("{:<4} | {:<20} | {:<12} | {:<20} | {:<25} | {}", r.id, r.title, r.category, r.username, r.url, decrypted_pass);
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            let master_pass = prompt_password("Enter Master Password: ");
            if let Err(e) = db::unlock_vault(&conn, &master_pass) {
                eprintln!("Unlock failed: {}", e);
                return;
            }
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
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

            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
            };

            let import_result = match detected_format {
                import::ImportFormat::BitwardenJson => import::import_bitwarden_json(&conn, file_path, &key),
                import::ImportFormat::BraveChromeCsv => import::import_brave_chrome_csv(&conn, file_path, &key),
                import::ImportFormat::FirefoxCsv => import::import_firefox_csv(&conn, file_path, &key),
                import::ImportFormat::LastPassCsv => import::import_lastpass_csv(&conn, file_path, &key),
                import::ImportFormat::KeePassXcCsv => import::import_keepassxc_csv(&conn, file_path, &key),
                import::ImportFormat::OnePasswordCsv => import::import_onepassword_csv(&conn, file_path, &key),
            };

            match import_result {
                Ok(count) => {
                    println!("Success: Imported {} items from {}!", count, detected_format.name());
                    if sync::is_git_configured(&db_path) {
                        println!("Syncing updates to Git remote...");
                        let _ = sync::git_sync_vault(&db_path);
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
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

            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
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
                if db_path.exists() {
                    match fs::remove_file(&db_path) {
                        Ok(_) => println!("Vault database successfully deleted. You can run `keystash init` to create a new one."),
                        Err(e) => eprintln!("Failed to delete vault file: {}", e),
                    }
                } else {
                    println!("No database file existed at {:?}", db_path);
                }
            } else {
                println!("Reset cancelled.");
            }
        }
        "change-password" => {
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let old_pass = prompt_password("Enter Current Master Password: ");
            let old_key = match db::unlock_vault(&conn, &old_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
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
            match db::change_master_password(&conn, &old_key, &new_pass) {
                Ok(_) => {
                    println!("Success: Master Password changed and vault records re-encrypted!");
                    if sync::is_git_configured(&db_path) {
                        println!("Syncing updates to Git remote...");
                        let _ = sync::git_sync_vault(&db_path);
                    }
                }
                Err(e) => eprintln!("Failed to change Master Password: {}", e),
            }
        }
        "sync" => {
            println!("Syncing vault with Git remote...");
            match sync::git_sync_vault(&db_path) {
                Ok(msg) => println!("{}", msg),
                Err(err) => eprintln!("Sync Error: {}", err),
            }
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
            };
            let reveal = args.iter().any(|arg| arg == "--reveal" || arg == "-r");
            match db::get_secrets(&conn) {
                Ok(records) => {
                    if let Some(r) = records.into_iter().find(|rec| rec.id == id) {
                        let decrypted_pass = if reveal {
                            crypto::decrypt(&r.encrypted_password, &key)
                                .map(|dec| String::from_utf8_lossy(&dec).to_string())
                                .unwrap_or_else(|_| "<Error>".to_string())
                        } else {
                            "••••••••".to_string()
                        };
                        let decrypted_notes = if let Some(enc_notes) = &r.encrypted_notes {
                            if reveal {
                                crypto::decrypt(enc_notes, &key)
                                    .map(|dec| String::from_utf8_lossy(&dec).to_string())
                                    .unwrap_or_else(|_| "<Error>".to_string())
                            } else {
                                "••••••••".to_string()
                            }
                        } else {
                            "[No Notes]".to_string()
                        };

                        println!("Secret Details (ID: {}):", r.id);
                        println!("----------------------------------------");
                        println!("Title:    {}", r.title);
                        println!("Category: {}", r.category);
                        println!("Username: {}", r.username);
                        println!("URL:      {}", r.url);
                        println!("Password: {}", decrypted_pass);
                        println!("Notes:    {}", decrypted_notes);
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
            let conn = match db::init_db(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Database error: {}", e);
                    return;
                }
            };
            if db::is_first_run(&conn).unwrap_or(true) {
                eprintln!("Vault is not initialized. Run `keystash init` first.");
                return;
            }
            let master_pass = prompt_password("Enter Master Password: ");
            let key = match db::unlock_vault(&conn, &master_pass) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Unlock failed: {}", e);
                    return;
                }
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

                        if let Some(mut text) = text_to_copy {
                            copy_to_clipboard(text.clone(), field);
                            text.zeroize();
                        }
                    } else {
                        println!("Secret with ID {} not found.", id);
                    }
                }
                Err(e) => eprintln!("Error fetching secrets: {}", e),
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

fn start_tui(db_path: &Path, no_sync: bool) {
    // Auto-sync at startup if Git is configured and sync is not disabled
    // This must run before db::init_db so that a missing local vault can be restored in its entirety
    if !no_sync && sync::is_git_configured(db_path) {
        println!("Syncing vault with Git remote...");
        match sync::git_sync_vault(db_path) {
            Ok(msg) => println!("{}", msg),
            Err(err) => eprintln!("Sync Warning: {}", err),
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let conn = match db::init_db(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open vault database: {}", e);
            return;
        }
    };

    let app = tui::TuiApp::new(conn, no_sync);
    if let Err(e) = tui::run_tui(app) {
        eprintln!("Terminal application crashed: {}", e);
    }

    // Auto-sync updates on exit if Git is configured and sync is not disabled
    if !no_sync && sync::is_git_configured(db_path) {
        println!("Syncing vault updates on exit...");
        match sync::git_sync_vault(db_path) {
            Ok(msg) => println!("{}", msg),
            Err(err) => eprintln!("Sync Warning: {}", err),
        }
    }
}
