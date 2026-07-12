use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use zeroize::{Zeroize, Zeroizing};
use std::cell::RefCell;

use rusqlite::Connection;
use std::{
    io,
    time::{Duration, Instant},
    collections::HashSet,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::db::{self, SecretRecord};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveBlock {
    Categories,
    Secrets,
    Details,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    DeleteMarked,
    DeleteSingle(i64),
}



#[derive(Clone)]
pub struct DuplicateGroup {
    pub title: String,
    pub username: String,
    pub url: String,
    pub records: Vec<SecretRecord>,
    pub decrypted_passwords: Vec<Zeroizing<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Lock,
    Setup,
    InterruptedMigration,
    InterruptedRotation,
    Dashboard,
    AddSecret,
    EditSecret,
    ErrorDialog,
    ConfirmationDialog(ConfirmAction),
    HelpDialog,
    ChangePassword,
    ImportDialog,
    ExportTypeDialog,
    ExportDialog,
    GeneratorDialog,
    DeduplicateScreen,
    SettingsScreen,
    SyncConflictScreen,
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusType {
    Normal,
    Copied,
    Cleared,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormField {
    Title,
    Category,
    Username,
    Url,
    Password,
    Notes,
}

pub struct TuiApp {
    conn: Connection,
    key: Option<Zeroizing<[u8; 32]>>,
    screen: Screen,
    
    // Auth State
    password_input: String,
    password_confirm_input: String,
    error_message: String,

    // Dashboard State
    secrets: Vec<SecretRecord>,
    filtered_secrets: Vec<SecretRecord>,
    categories: Vec<String>,
    selected_category_idx: usize,
    selected_secret_idx: usize,
    active_block: ActiveBlock,
    search_query: String,
    searching: bool,
    reveal_password: bool,
    copied_message: Option<(String, Instant, StatusType)>,

    // Form State
    active_form_field: FormField,
    form_title: String,
    form_category: String,
    form_username: String,
    form_url: String,
    form_password: String,
    form_notes: String,
    edit_id: Option<i64>,

    // Deletion / Confirmation state
    pub marked_secrets: HashSet<i64>,
    confirmation_message: String,

    // Stateful widget controls
    pub category_list_state: RefCell<ListState>,
    pub secrets_list_state: RefCell<ListState>,

    // Key rotation form state
    pub change_pass_field: usize,
    pub no_sync: bool,
    pub import_path_input: String,
    pub export_path_input: String,
    pub export_only_marked: bool,

    // Password Generator State
    pub gen_options: crate::generator::GeneratorOptions,
    pub gen_password: String,

    // Help dialog scroll
    pub help_scroll: u16,

    // Audit screen state
    pub audit_report: Option<crate::audit::AuditReport>,

    pub last_activity: Instant,
    pub config: crate::config::AppConfig,

    // Deduplication screen state
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub selected_dup_group_idx: usize,
    pub selected_dup_item_idx: usize,

    // Settings screen state
    pub settings_idle_timeout: String,
    pub settings_clipboard_clear: String,
    pub settings_auto_sync: bool,
    pub settings_gen_length: String,
    pub settings_gen_lowercase: bool,
    pub settings_gen_uppercase: bool,
    pub settings_gen_numbers: bool,
    pub settings_gen_symbols: bool,
    pub active_settings_field: usize,

    // HIBP background worker
    pub hibp_progress: Arc<Mutex<Option<(usize, usize)>>>,
    pub hibp_abort: Arc<AtomicBool>,
    pub checked_hashes_this_session: Arc<Mutex<HashSet<String>>>,

    // Sync conflict state
    pub sync_conflicts: Vec<crate::sync::ConflictGroup>,
    pub selected_conflict_idx: usize,
    pub sync_conflicts_detected: Arc<Mutex<Option<Vec<crate::sync::ConflictGroup>>>>,

    // Whether the vault at db_path predates SQLCipher and needs one-time migration
    // on next successful password entry (see `handle_lock_input`).
    needs_migration: bool,

    // Handle to whatever background sync thread is currently in flight (from
    // `trigger_postunlock_sync`), if any. `run_tui`'s exit-time sync joins this
    // before running its own git_sync_vault call, so the two can never run
    // concurrently against the same working directory / SQLite file -- letting
    // them race is what caused a real vault to revert to its pre-migration,
    // unencrypted format with no error ever being shown.
    pending_sync_thread: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
}



impl TuiApp {
    /// Constructs the app without touching vault.db at all: opening it now
    /// requires the SQLCipher key, which isn't known until the user has typed
    /// their master password on the Setup/Lock screen. `conn` starts out pointing
    /// at a throwaway in-memory database -- it's replaced with the real, keyed
    /// connection in `handle_setup_input`/`handle_lock_input` on success, and no
    /// screen reachable before that ever reads from `conn`.
    pub fn new(no_sync: bool) -> Self {
        let db_path = crate::get_db_path();
        let vault_state = db::detect_vault_state(&db_path);
        let screen = match vault_state {
            db::VaultState::New => Screen::Setup,
            db::VaultState::NeedsMigration | db::VaultState::Ready => Screen::Lock,
            db::VaultState::InterruptedMigration => Screen::InterruptedMigration,
            db::VaultState::InterruptedRotation => Screen::InterruptedRotation,
        };
        let placeholder_conn = Connection::open_in_memory()
            .expect("failed to open in-memory placeholder database");

        let app = Self {
            conn: placeholder_conn,
            needs_migration: vault_state == db::VaultState::NeedsMigration,
            key: None,
            screen,
            password_input: String::with_capacity(128),
            password_confirm_input: String::with_capacity(128),
            error_message: String::new(),
            secrets: Vec::new(),
            filtered_secrets: Vec::new(),
            categories: vec!["All".to_string()],
            selected_category_idx: 0,
            selected_secret_idx: 0,
            active_block: ActiveBlock::Secrets,
            search_query: String::new(),
            searching: false,
            reveal_password: false,
            copied_message: None,
            active_form_field: FormField::Title,
            form_title: String::new(),
            form_category: String::new(),
            form_username: String::new(),
            form_url: String::new(),
            form_password: String::with_capacity(128),
            form_notes: String::new(),
            edit_id: None,
            marked_secrets: HashSet::new(),
            confirmation_message: String::new(),
            category_list_state: RefCell::new(ListState::default()),
            secrets_list_state: RefCell::new(ListState::default()),
            change_pass_field: 0,
            no_sync,
            import_path_input: String::new(),
            export_path_input: String::new(),
            export_only_marked: false,
            gen_options: crate::generator::GeneratorOptions::load(),
            gen_password: String::new(),
            help_scroll: 0,
            audit_report: None,
            last_activity: Instant::now(),
            config: crate::config::AppConfig::load(),
            duplicate_groups: Vec::new(),
            selected_dup_group_idx: 0,
            selected_dup_item_idx: 0,
            settings_idle_timeout: String::new(),
            settings_clipboard_clear: String::new(),
            settings_auto_sync: true,
            settings_gen_length: String::new(),
            settings_gen_lowercase: true,
            settings_gen_uppercase: true,
            settings_gen_numbers: true,
            settings_gen_symbols: true,
            active_settings_field: 0,
            hibp_progress: Arc::new(Mutex::new(None)),
            hibp_abort: Arc::new(AtomicBool::new(false)),
            checked_hashes_this_session: Arc::new(Mutex::new(HashSet::new())),
            sync_conflicts: Vec::new(),
            selected_conflict_idx: 0,
            sync_conflicts_detected: Arc::new(Mutex::new(None)),
            pending_sync_thread: Arc::new(Mutex::new(None)),
        };
        app.trigger_prelock_fetch();
        app
    }

    pub fn lock_vault(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }

        // The keyed SQLCipher connection must not survive locking: it holds
        // the derived page key inside SQLite's own connection state, so
        // wiping the master key above still leaves every whole-database-
        // encrypted metadata field (titles, usernames, URLs, categories,
        // and the raw HIBP hashes) readable through this handle for as
        // long as the app sits on the Lock screen. Swap it for a fresh
        // in-memory placeholder -- exactly what TuiApp::new starts with
        // before the first unlock -- and let the old connection drop.
        // Background threads that already cloned the master key before
        // this call (an in-flight HIBP scan, a pending sync) keep working
        // regardless; that's an accepted property of letting in-flight
        // work finish, not an oversight.
        self.conn = Connection::open_in_memory()
            .expect("failed to open in-memory placeholder database");

        self.password_input.zeroize();
        self.password_input.clear();
        self.password_confirm_input.zeroize();
        self.password_confirm_input.clear();
        self.form_password.zeroize();
        self.form_password.clear();
        // Notes are an equally sensitive encrypted field as the password --
        // clear() alone only resets the length, it doesn't wipe the buffer.
        self.form_notes.zeroize();
        self.form_notes.clear();

        // Reset form variables to prevent leaving secret text in memory
        self.form_title.clear();
        self.form_category.clear();
        self.form_username.clear();
        self.form_url.clear();
        self.edit_id = None;

        // Clear cached secrets
        self.secrets.clear();
        self.filtered_secrets.clear();

        // Duplicate-scan results hold decrypted passwords for as long as they're
        // cached; wipe them rather than letting the Vec just get dropped/replaced
        // with its contents intact in already-freed heap memory.
        for group in &mut self.duplicate_groups {
            for pw in &mut group.decrypted_passwords {
                pw.zeroize();
            }
        }
        self.duplicate_groups.clear();

        self.gen_password.zeroize();
        self.gen_password.clear();

        // Clear active screen states and redirect to lock
        self.screen = Screen::Lock;
    }

    pub fn reset_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn find_duplicate_groups(&mut self) {
        let key = match &self.key {
            Some(k) => k,
            None => return,
        };
        
        let mut groups: Vec<DuplicateGroup> = Vec::new();
        let mut processed_ids = HashSet::new();

        for i in 0..self.secrets.len() {
            let r1 = &self.secrets[i];
            if processed_ids.contains(&r1.id) {
                continue;
            }

            let mut group_records = vec![r1.clone()];
            let pw1: Zeroizing<String> = crate::crypto::decrypt(&r1.encrypted_password, key)
                .ok()
                .and_then(|dec| String::from_utf8(dec.to_vec()).ok())
                .map(Zeroizing::new)
                .unwrap_or_default();
            let mut group_pws = vec![pw1];

            for j in (i + 1)..self.secrets.len() {
                let r2 = &self.secrets[j];
                if processed_ids.contains(&r2.id) {
                    continue;
                }

                let match_username = !r1.username.is_empty() && r1.username.to_lowercase() == r2.username.to_lowercase();
                let match_url = !r1.url.is_empty() && r1.url.to_lowercase() == r2.url.to_lowercase();
                let match_title = !r1.title.is_empty() && r1.title.to_lowercase() == r2.title.to_lowercase();

                if match_username && (match_url || match_title) {
                    let pw2: Zeroizing<String> = crate::crypto::decrypt(&r2.encrypted_password, key)
                        .ok()
                        .and_then(|dec| String::from_utf8(dec.to_vec()).ok())
                        .map(Zeroizing::new)
                        .unwrap_or_default();
                    group_records.push(r2.clone());
                    group_pws.push(pw2);
                }
            }

            if group_records.len() > 1 {
                for r in &group_records {
                    processed_ids.insert(r.id);
                }
                groups.push(DuplicateGroup {
                    title: r1.title.clone(),
                    username: r1.username.clone(),
                    url: r1.url.clone(),
                    records: group_records,
                    decrypted_passwords: group_pws,
                });
            }
        }
        
        // Wipe the previous scan's decrypted passwords before the Vec they live
        // in is replaced wholesale -- otherwise they're just dropped with their
        // contents intact in already-freed heap memory.
        for group in &mut self.duplicate_groups {
            for pw in &mut group.decrypted_passwords {
                pw.zeroize();
            }
        }
        self.duplicate_groups = groups;
        self.selected_dup_group_idx = 0;
        self.selected_dup_item_idx = 0;
    }


    fn refresh_secrets(&mut self) {

        if let Some(key) = self.key.clone() {
            if let Ok(records) = db::get_secrets(&self.conn) {
                self.secrets = records;
                
                // Get unique categories
                let mut cats = std::collections::HashSet::new();
                for r in &self.secrets {
                    cats.insert(r.category.clone());
                }
                let mut sorted_cats: Vec<String> = cats.into_iter().collect();
                sorted_cats.sort();
                
                self.categories = vec!["All".to_string()];
                self.categories.extend(sorted_cats);
                
                self.apply_filter();

                // Run security audit on decrypted passwords
                let mut plaintext: Vec<(i64, String, String, String, String)> = self.secrets
                    .iter()
                    .filter_map(|r| {
                        crate::crypto::decrypt(&r.encrypted_password, &key)
                            .ok()
                            .and_then(|dec| String::from_utf8(dec.to_vec()).ok())
                            .map(|pw| (r.id, r.title.clone(), r.category.clone(), r.username.clone(), pw))
                    })
                    .collect();

                let mut report = crate::audit::audit_passwords(&mut plaintext, &key);

                // Restore HIBP status from the persisted cache using the
                // fingerprints audit_passwords already computed above -- no
                // second decrypt-every-password pass needed.
                if let Ok(db_checks) = db::get_all_hibp_checks(&self.conn) {
                    for entry in report.entries.iter_mut() {
                        if let Some(cached_count) = db_checks.get(&entry.hibp_fingerprint) {
                            entry.hibp_count = *cached_count;
                        }
                    }
                }

                self.audit_report = Some(report);
            }
        }
    }
    fn fuzzy_score(target: &str, query: &str) -> Option<isize> {
        if query.is_empty() {
            return Some(0);
        }
        let target_lower = target.to_lowercase();
        let query_lower = query.to_lowercase();

        if target_lower == query_lower {
            return Some(100);
        }
        if let Some(idx) = target_lower.find(&query_lower) {
            let score = if idx == 0 { 80 } else { 60 };
            return Some(score);
        }

        let mut query_chars = query_lower.chars().peekable();
        let mut match_indices = Vec::new();
        for (i, c) in target_lower.chars().enumerate() {
            if let Some(&qc) = query_chars.peek() {
                if c == qc {
                    query_chars.next();
                    match_indices.push(i);
                }
            }
        }

        if query_chars.peek().is_none() {
            let gap_penalty = if match_indices.len() > 1 {
                let total_span = match_indices.last().unwrap() - match_indices.first().unwrap() + 1;
                total_span as isize - query_lower.len() as isize
            } else {
                0
            };
            Some(std::cmp::max(10, 40 - gap_penalty))
        } else {
            None
        }
    }

    fn apply_filter(&mut self) {
        let current_cat = self.categories.get(self.selected_category_idx).cloned().unwrap_or("All".to_string());
        let query = self.search_query.to_lowercase();

        if query.is_empty() {
            self.filtered_secrets = self.secrets
                .iter()
                .filter(|r| current_cat == "All" || r.category == current_cat)
                .cloned()
                .collect();
        } else {
            let mut scored_secrets = Vec::new();
            for r in &self.secrets {
                if current_cat != "All" && r.category != current_cat {
                    continue;
                }

                let title_score = Self::fuzzy_score(&r.title, &query);
                let user_score = Self::fuzzy_score(&r.username, &query);
                let cat_score = Self::fuzzy_score(&r.category, &query);
                let url_score = Self::fuzzy_score(&r.url, &query);

                let max_score = [title_score, user_score, cat_score, url_score]
                    .iter()
                    .filter_map(|&s| s)
                    .max();

                if let Some(score) = max_score {
                    scored_secrets.push((score, r.clone()));
                }
            }

            scored_secrets.sort_by(|a, b| b.0.cmp(&a.0));
            self.filtered_secrets = scored_secrets.into_iter().map(|(_, r)| r).collect();
        }

        if self.selected_secret_idx >= self.filtered_secrets.len() {
            self.selected_secret_idx = if self.filtered_secrets.is_empty() { 0 } else { self.filtered_secrets.len() - 1 };
        }
    }

    /// Takes ownership as `Zeroizing<String>` rather than a plain `String` so
    /// the plaintext is wiped when this returns, regardless of which branch is
    /// taken -- a plain `String` parameter would just drop normally, leaving
    /// its contents intact in already-freed heap memory.
    fn copy_to_clipboard(&mut self, text: Zeroizing<String>, label: &str) {
        if text.trim().is_empty() {
            self.copied_message = Some((
                format!("Cannot copy: {} is empty!", label),
                Instant::now(),
                StatusType::Normal,
            ));
            return;
        }

        let delay = self.config.clipboard_clear_seconds;

        if let Ok(exe) = std::env::current_exe() {
            let child = Command::new(exe)
                .arg("__internal-clear-clipboard")
                .arg(delay.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();

            match child {
                Ok(mut child_proc) => {
                    use std::io::Write;
                    if let Some(mut stdin) = child_proc.stdin.take() {
                        let _ = stdin.write_all(text.as_bytes());
                    }
                    self.copied_message = Some((
                        format!("Copied {} to clipboard! Will clear in {}s.", label, delay),
                        Instant::now(),
                        StatusType::Copied,
                    ));
                }
                Err(_) => {
                    self.copied_message = Some((
                        "Failed to spawn clipboard manager process.".to_string(),
                        Instant::now(),
                        StatusType::Normal,
                    ));
                }
            }
        } else {
            self.copied_message = Some((
                "Failed to locate KeyStash executable path.".to_string(),
                Instant::now(),
                StatusType::Normal,
            ));
        }
    }

    fn clear_clipboard_if_expired(&mut self) {
        if let Some((_, instant, status)) = &self.copied_message {
            match status {
                StatusType::Copied => {
                    if instant.elapsed() >= Duration::from_secs(self.config.clipboard_clear_seconds) {
                        self.copied_message = Some((
                            "Clipboard cleared securely.".to_string(),
                            Instant::now(),
                            StatusType::Cleared,
                        ));
                    }
                }
                StatusType::Cleared => {
                    if instant.elapsed() >= Duration::from_secs(3) {
                        self.copied_message = None;
                    }
                }
                StatusType::Normal => {
                    if instant.elapsed() >= Duration::from_secs(5) {
                        self.copied_message = None;
                    }
                }
            }
        }
    }

    /// Runs at construction time, before the vault is unlocked -- so before any
    /// key exists. SQLCipher means the actual logical merge (which needs to open
    /// and ATTACH the encrypted database) can no longer happen this early; only
    /// the network fetch can run with no key at all. This still hides the fetch's
    /// network latency behind the password prompt exactly as before -- the merge
    /// itself is fast and local, and runs immediately after a successful unlock
    /// in `trigger_postunlock_sync`, reusing the ref this fetch just updated.
    fn trigger_prelock_fetch(&self) {
        if self.no_sync {
            return;
        }
        let db_path = crate::get_db_path();
        std::thread::spawn(move || {
            let dir = match db_path.parent() {
                Some(d) => d,
                None => return,
            };
            if !dir.join(".git").exists() {
                return;
            }
            // Uses the same flag set as every other git invocation in
            // sync.rs (GIT_TERMINAL_PROMPT=0, low-speed timeouts, null
            // stdin) -- this one used to be built by hand and drifted,
            // missing exactly those flags, which let a credential-prompting
            // HTTPS remote hang this background thread or write a prompt
            // into the raw-mode TUI screen.
            let _ = crate::sync::git_command(dir)
                .arg("fetch")
                .arg("origin")
                .arg("main")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        });
    }

    /// Runs right after a successful unlock/setup/migration, once a key exists.
    /// Detects conflicts against the ref `trigger_prelock_fetch` already updated;
    /// if none are found, performs the normal full logical merge + push.
    fn trigger_postunlock_sync(&self) {
        if self.no_sync {
            return;
        }
        let key = match &self.key {
            Some(k) => k.clone(),
            None => return,
        };
        let db_path = crate::get_db_path();
        let detected_clone = Arc::clone(&self.sync_conflicts_detected);
        // Take the previous handle out and hand it to the new thread so the
        // join happens *before* this sync touches any files, rather than
        // racing against it: spawning first and joining after (the previous
        // ordering here) let two `git_sync_vault` runs execute concurrently
        // against the same working directory, which has corrupted a real
        // vault before (see the comment in `run_tui`'s exit-time sync).
        let previous = self.pending_sync_thread.lock().ok().and_then(|mut s| s.take());
        let handle = std::thread::spawn(move || {
            if let Some(prev) = previous {
                let _ = prev.join();
            }
            match crate::sync::detect_sync_conflicts(&db_path, &key) {
                Ok(conflicts) => {
                    if !conflicts.is_empty() {
                        *detected_clone.lock().unwrap() = Some(conflicts);
                        return;
                    }
                }
                Err(_) => {}
            }
            let _ = crate::sync::git_sync_vault(&db_path, &key);
        });
        if let Ok(mut slot) = self.pending_sync_thread.lock() {
            *slot = Some(handle);
        }
    }

    /// Runs once every conflict in `sync_conflicts` has been resolved. Previously
    /// this only staged/committed/pushed whatever was on disk -- which silently
    /// dropped any *other* remote change (new records, non-conflicting edits,
    /// deletions) that wasn't part of the conflict set, since it never re-ran the
    /// real merge. It now calls the same `git_sync_vault` merge used everywhere
    /// else instead, relying on the conflict handlers above having already
    /// re-stamped each resolved record with a fresh "now" timestamp so the
    /// ordinary last-write-wins merge logic doesn't immediately re-clobber them.
    fn trigger_postconflict_sync(&self) {
        if self.no_sync {
            return;
        }
        let key = match &self.key {
            Some(k) => k.clone(),
            None => return,
        };
        let db_path = crate::get_db_path();
        // See trigger_postunlock_sync: join the previous handle inside the
        // new thread, before it touches any files, rather than after spawning.
        let previous = self.pending_sync_thread.lock().ok().and_then(|mut s| s.take());
        let handle = std::thread::spawn(move || {
            if let Some(prev) = previous {
                let _ = prev.join();
            }
            let _ = crate::sync::git_sync_vault(&db_path, &key);
        });
        if let Ok(mut slot) = self.pending_sync_thread.lock() {
            *slot = Some(handle);
        }
    }
}

pub fn run_tui(mut app: TuiApp) -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let mut stdout = std::io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
        let _ = disable_raw_mode();
        original_hook(panic_info);
    }));

    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("TUI Error: {:?}", err);
    }

    // Wait for any background sync still in flight (from trigger_postunlock_sync,
    // e.g. right after an unlock/migration/import) to finish *before* possibly
    // running our own git_sync_vault call below. Two git_sync_vault invocations
    // running concurrently against the same working directory and SQLite file --
    // both doing `git reset`/`add`/`commit`/`push` -- is exactly what corrupted a
    // real vault back to its pre-migration format with no error ever surfacing,
    // when the app was unlocked and quit again quickly.
    if let Ok(mut slot) = app.pending_sync_thread.lock() {
        if let Some(handle) = slot.take() {
            let _ = handle.join();
        }
    }

    // Auto-sync updates on exit if Git is configured and sync is not disabled.
    // Only possible if the vault was actually unlocked at some point during this
    // session -- git_sync_vault needs the key to open/attach the now
    // SQLCipher-encrypted database, and there's nothing to merge otherwise.
    if !app.no_sync {
        if let Some(key) = app.key.clone() {
            let db_path = crate::get_db_path();
            if crate::sync::is_git_configured(&db_path) {
                println!("Syncing vault updates on exit...");
                match crate::sync::git_sync_vault(&db_path, &key) {
                    Ok(msg) => println!("{}", msg),
                    Err(err) => eprintln!("Sync Warning: {}", err),
                }
            }
        }
    }

    Ok(())
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> io::Result<()> {
    loop {
        if let Ok(mut detected_lock) = app.sync_conflicts_detected.lock() {
            if let Some(conflicts) = detected_lock.take() {
                app.sync_conflicts = conflicts;
                app.selected_conflict_idx = 0;
                app.screen = Screen::SyncConflictScreen;
            }
        }

        app.clear_clipboard_if_expired();
        
        // Check for idle timeout auto-lock
        if app.key.is_some() && app.screen != Screen::Lock && app.screen != Screen::Setup {
            if app.last_activity.elapsed() >= Duration::from_secs(app.config.idle_timeout_seconds) {
                app.lock_vault();
            }
        }
        
        terminal.draw(|f| draw_ui(f, app))?;

        // Poll for inputs, checking clipboard expiration and idle timeout every 250ms
        if event::poll(Duration::from_millis(250))? {
            let ev = event::read()?;
            app.reset_activity();
            if let Event::Key(key) = ev {
                if key.kind == event::KeyEventKind::Press {
                    let checking_active = app.hibp_progress.lock().map(|p| p.is_some()).unwrap_or(false);
                    if checking_active {
                        if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                            app.hibp_abort.store(true, Ordering::SeqCst);
                        }
                        continue;
                    }
                    match app.screen {

                        Screen::Lock => {
                            if handle_lock_input(app, key.code) {
                                return Ok(());
                            }
                        }
                        Screen::Setup => {
                            if handle_setup_input(app, key.code) {
                                return Ok(());
                            }
                        }
                        Screen::InterruptedMigration | Screen::InterruptedRotation => {
                            if handle_interrupted_migration_input(key.code) {
                                return Ok(());
                            }
                        }
                        Screen::Dashboard => {
                            if handle_dashboard_input(app, key.code, key.modifiers) {
                                return Ok(());
                            }
                        }
                        Screen::AddSecret | Screen::EditSecret => handle_form_input(app, key.code, key.modifiers),
                        Screen::ConfirmationDialog(action) => handle_confirmation_input(app, key.code, action),
                        Screen::HelpDialog => handle_help_input(app, key.code),
                        Screen::ChangePassword => handle_change_password_input(app, key.code),
                        Screen::ImportDialog => handle_import_input(app, key.code),
                        Screen::ExportTypeDialog => handle_export_type_input(app, key.code),
                        Screen::ExportDialog => handle_export_input(app, key.code),
                        Screen::GeneratorDialog => handle_generator_input(app, key.code),
                        Screen::DeduplicateScreen => handle_deduplicate_input(app, key.code),
                        Screen::SettingsScreen => handle_settings_input(app, key.code),
                        Screen::SyncConflictScreen => handle_sync_conflict_input(app, key.code),
                        Screen::ErrorDialog => {
                            if key.code == KeyCode::Enter || key.code == KeyCode::Esc {
                                app.screen = Screen::Dashboard;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn handle_lock_input(app: &mut TuiApp, code: KeyCode) -> bool {
    match code {
        KeyCode::Char(c) => app.password_input.push(c),
        KeyCode::Backspace => {
            app.password_input.pop();
        }
        KeyCode::Enter => {
            let db_path = crate::get_db_path();
            let result = if app.needs_migration {
                db::migrate_legacy_vault(&db_path, &app.password_input)
            } else {
                db::open_vault(&db_path, &app.password_input)
            };
            match result {
                Ok((conn, derived_key)) => {
                    app.conn = conn;
                    app.needs_migration = false;
                    app.key = Some(derived_key);
                    app.screen = Screen::Dashboard;
                    app.password_input.zeroize();
                    app.password_input.clear();
                    app.refresh_secrets();
                    app.trigger_postunlock_sync();
                }
                Err(err) => {
                    app.error_message = err;
                    app.password_input.zeroize();
                    app.password_input.clear();
                }
            }
        }
        KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

fn handle_setup_input(app: &mut TuiApp, code: KeyCode) -> bool {
    match code {
        KeyCode::Tab | KeyCode::BackTab => {
            app.active_form_field = match app.active_form_field {
                FormField::Title => FormField::Password,
                _ => FormField::Title, // Setup uses Title for Confirm password field toggling metaphorically
            };
        }
        KeyCode::Char(c) => {
            match app.active_form_field {
                FormField::Title => app.password_input.push(c),
                _ => app.password_confirm_input.push(c),
            }
        }
        KeyCode::Backspace => {
            match app.active_form_field {
                FormField::Title => { app.password_input.pop(); }
                _ => { app.password_confirm_input.pop(); }
            }
        }
        KeyCode::Enter => {
            if app.password_input.is_empty() {
                app.error_message = "Password cannot be empty!".to_string();
                return false;
            }
            if app.password_input != app.password_confirm_input {
                app.error_message = "Passwords do not match!".to_string();
                return false;
            }
            let db_path = crate::get_db_path();
            match db::create_vault(&db_path, &app.password_input) {
                Ok((conn, derived_key)) => {
                    app.conn = conn;
                    app.key = Some(derived_key);
                    app.screen = Screen::Dashboard;
                    app.password_input.zeroize();
                    app.password_confirm_input.zeroize();
                    app.password_input.clear();
                    app.password_confirm_input.clear();
                    app.error_message = String::new();
                    app.refresh_secrets();
                    app.trigger_postunlock_sync();
                }
                Err(err) => {
                    app.error_message = err;
                }
            }
        }
        KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

/// Spawns the background HIBP-scan thread over exactly `records`, wiring up
/// the same progress/abort/cache machinery for both the single/marked-entry
/// (`h`) and full-vault (`H`) checks -- so a single check gets the same
/// keyed-connection persistence, progress dialog, and abort key that
/// previously only the full scan had.
fn spawn_hibp_scan(app: &TuiApp, records: Vec<crate::db::SecretRecord>) {
    let key = match &app.key {
        Some(k) => k,
        None => return,
    };
    let already_running = app.hibp_progress.lock().map(|p| p.is_some()).unwrap_or(false);
    let total_checks = records.len();
    if already_running || total_checks == 0 {
        return;
    }

    *app.hibp_progress.lock().unwrap() = Some((0, total_checks));
    app.hibp_abort.store(false, Ordering::SeqCst);

    let progress_clone = Arc::clone(&app.hibp_progress);
    let abort_clone = Arc::clone(&app.hibp_abort);
    let key_clone = key.clone();
    let checked_hashes_clone = Arc::clone(&app.checked_hashes_this_session);

    std::thread::spawn(move || {
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_clone);
        if let Ok(conn) = crate::db::open_keyed_connection(crate::get_db_path(), &sqlcipher_key) {
            let cached_checks = crate::db::get_all_hibp_checks(&conn).unwrap_or_default();
            for (i, record) in records.iter().enumerate() {
                if abort_clone.load(Ordering::SeqCst) {
                    break;
                }

                let mut checked_online = false;
                if let Ok(dec) = crate::crypto::decrypt(&record.encrypted_password, &key_clone) {
                    if let Ok(mut pw) = String::from_utf8(dec.to_vec()) {
                        let hash_hex = crate::crypto::hibp_cache_fingerprint(pw.as_bytes(), &key_clone);

                        if let Ok(checked_lock) = checked_hashes_clone.lock() {
                            if checked_lock.contains(&hash_hex) {
                                pw.zeroize();
                                if let Ok(mut progress_lock) = progress_clone.lock() {
                                    if let Some(p) = &mut *progress_lock {
                                        p.0 = i + 1;
                                    }
                                }
                                continue;
                            }
                        }

                        if let Some(Some(count)) = cached_checks.get(&hash_hex) {
                            if *count > 0 {
                                pw.zeroize();
                                if let Ok(mut progress_lock) = progress_clone.lock() {
                                    if let Some(p) = &mut *progress_lock {
                                        p.0 = i + 1;
                                    }
                                }
                                continue;
                            }
                        }

                        let result = crate::audit::check_hibp(&pw);
                        pw.zeroize();
                        checked_online = true;

                        let count = match result {
                            Ok(n) => {
                                if let Ok(mut checked_lock) = checked_hashes_clone.lock() {
                                    checked_lock.insert(hash_hex.clone());
                                }
                                Some(n)
                            }
                            Err(_) => None,
                        };
                        let _ = crate::db::save_hibp_check(&conn, &hash_hex, count);
                    }
                }

                if let Ok(mut progress_lock) = progress_clone.lock() {
                    if let Some(p) = &mut *progress_lock {
                        p.0 = i + 1;
                    }
                }

                if checked_online && total_checks > 1 && i + 1 < total_checks {
                    std::thread::sleep(Duration::from_millis(700));
                }
            }
        }
        *progress_clone.lock().unwrap() = None;
    });
}

fn handle_dashboard_input(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) -> bool {
    // If in search mode, intercept text keys
    if app.searching {
        match code {
            KeyCode::Char(c) => {
                app.search_query.push(c);
                app.apply_filter();
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                app.apply_filter();
            }
            KeyCode::Esc | KeyCode::Enter => {
                app.searching = false;
            }
            _ => {}
        }
        return false;
    }

    match code {
        KeyCode::Esc => return true, // Exit App
        KeyCode::Char('q') if modifiers == KeyModifiers::CONTROL => return true,
        KeyCode::Char('/') => {
            app.searching = true;
        }
        KeyCode::Char('a') => {
            app.screen = Screen::AddSecret;
            app.active_form_field = FormField::Title;
            app.form_title.clear();
            app.form_category.clear();
            app.form_username.clear();
            app.form_url.clear();
            app.form_password.zeroize();
            app.form_password.clear();
            app.form_notes.zeroize();
            app.form_notes.clear();
            app.edit_id = None;
        }
        KeyCode::Char('e') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.screen = Screen::EditSecret;
                app.active_form_field = FormField::Title;
                app.form_title = record.title.clone();
                app.form_category = record.category.clone();
                app.form_username = record.username.clone();
                app.form_url = record.url.clone();
                app.edit_id = Some(record.id);

                // Wipe whatever the previous form held before overwriting it.
                app.form_password.zeroize();
                app.form_password.clear();
                app.form_notes.zeroize();
                app.form_notes.clear();

                // Decrypt password & notes for editing
                if let Some(key) = &app.key {
                    if let Ok(dec_pass) = crate::crypto::decrypt(&record.encrypted_password, key) {
                        app.form_password = String::from_utf8_lossy(&dec_pass).to_string();
                    }
                    if let Some(enc_notes) = &record.encrypted_notes {
                        if let Ok(dec_notes) = crate::crypto::decrypt(enc_notes, key) {
                            app.form_notes = String::from_utf8_lossy(&dec_notes).to_string();
                        }
                    }
                }
            }
        }
        KeyCode::Char('d') => {
            if !app.marked_secrets.is_empty() {
                app.confirmation_message = format!(
                    "Are you sure you want to delete the {} marked credentials? This cannot be undone.",
                    app.marked_secrets.len()
                );
                app.screen = Screen::ConfirmationDialog(ConfirmAction::DeleteMarked);
            } else if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.confirmation_message = format!(
                    "Are you sure you want to delete '{}'? This cannot be undone.",
                    record.title
                );
                app.screen = Screen::ConfirmationDialog(ConfirmAction::DeleteSingle(record.id));
            }
        }
        KeyCode::Char(' ') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                if app.marked_secrets.contains(&record.id) {
                    app.marked_secrets.remove(&record.id);
                } else {
                    app.marked_secrets.insert(record.id);
                }
            }
        }
        KeyCode::Char('v') => {
            app.reveal_password = !app.reveal_password;
        }
        KeyCode::Char('c') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.copy_to_clipboard(Zeroizing::new(record.username.clone()), "username");
            }
        }
        KeyCode::Char('m') => {
            app.password_input.zeroize();
            app.password_input.clear();
            app.password_confirm_input.zeroize();
            app.password_confirm_input.clear();
            app.form_password.zeroize();
            app.form_password.clear();
            app.change_pass_field = 0;
            app.error_message.clear();
            app.screen = Screen::ChangePassword;
        }
        KeyCode::Char('i') => {
            app.import_path_input.clear();
            app.screen = Screen::ImportDialog;
        }
        KeyCode::Char('x') => {
            app.export_path_input.clear();
            app.screen = Screen::ExportTypeDialog;
        }
        KeyCode::Char('g') => {
            app.gen_options = crate::generator::GeneratorOptions::load();
            app.gen_password.zeroize();
            if let Ok(pass) = crate::generator::generate_password(&app.gen_options) {
                app.gen_password = pass;
            }
            app.screen = Screen::GeneratorDialog;
        }
        KeyCode::Char(',') => {
            app.settings_idle_timeout = app.config.idle_timeout_seconds.to_string();
            app.settings_clipboard_clear = app.config.clipboard_clear_seconds.to_string();
            app.settings_auto_sync = app.config.auto_sync;
            app.settings_gen_length = app.config.generator.length.to_string();
            app.settings_gen_lowercase = app.config.generator.use_lowercase;
            app.settings_gen_uppercase = app.config.generator.use_uppercase;
            app.settings_gen_numbers = app.config.generator.use_numbers;
            app.settings_gen_symbols = app.config.generator.use_symbols;
            app.active_settings_field = 0;
            app.screen = Screen::SettingsScreen;
        }
        KeyCode::Char('s') => {
            // The help screen has advertised this key since before it was
            // ever wired up. Reuses trigger_postconflict_sync's machinery
            // (join the previous pending sync thread, then run the same
            // full logical merge git_sync_vault does everywhere else) --
            // there's nothing conflict-specific about it, it's just the
            // existing "run a sync now" entry point.
            if app.no_sync {
                app.copied_message = Some(("Sync is disabled (--no-sync).".to_string(), Instant::now(), StatusType::Normal));
            } else if !crate::sync::is_git_configured(crate::get_db_path()) {
                app.copied_message = Some(("Sync not configured -- no git remote set up in ~/.config/keystash.".to_string(), Instant::now(), StatusType::Normal));
            } else {
                app.trigger_postconflict_sync();
                app.copied_message = Some(("Syncing with git remote...".to_string(), Instant::now(), StatusType::Normal));
            }
        }

        KeyCode::Char('D') => {
            app.find_duplicate_groups();
            if app.duplicate_groups.is_empty() {
                app.error_message = "No duplicates found based on matching username and title/URL!".to_string();
                app.screen = Screen::ErrorDialog;
            } else {
                app.screen = Screen::DeduplicateScreen;
            }
        }

        KeyCode::Char('u') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.copy_to_clipboard(Zeroizing::new(record.url.clone()), "URL");
            }
        }
        KeyCode::Char('p') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                if let Some(key) = &app.key {
                    if let Ok(dec) = crate::crypto::decrypt(&record.encrypted_password, key) {
                        if let Ok(plaintext) = String::from_utf8(dec.to_vec()) {
                            app.copy_to_clipboard(Zeroizing::new(plaintext), "password");
                        }
                    }
                }
            }
        }
        KeyCode::Tab => {
            app.active_block = match app.active_block {
                ActiveBlock::Categories => ActiveBlock::Secrets,
                ActiveBlock::Secrets => ActiveBlock::Details,
                ActiveBlock::Details => ActiveBlock::Categories,
            };
        }
        KeyCode::BackTab => {
            app.active_block = match app.active_block {
                ActiveBlock::Categories => ActiveBlock::Details,
                ActiveBlock::Secrets => ActiveBlock::Categories,
                ActiveBlock::Details => ActiveBlock::Secrets,
            };
        }
        KeyCode::Char('?') => {
            app.screen = Screen::HelpDialog;
        }
        KeyCode::Char('h') => {
            // Reuses the same background-scan machinery as `H` (progress
            // dialog, abort key, cache lookups, and -- since the earlier fix --
            // a properly keyed connection so results actually persist)
            // instead of checking synchronously on the UI thread: a handful of
            // marked entries against a slow HIBP response used to freeze the
            // whole TUI, unpaintable and unabortable, for seconds at a time.
            let mut ids_to_check: Vec<i64> = Vec::new();
            if !app.marked_secrets.is_empty() {
                ids_to_check.extend(app.marked_secrets.iter().copied());
            } else if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                ids_to_check.push(record.id);
            }
            let records: Vec<crate::db::SecretRecord> = ids_to_check
                .iter()
                .filter_map(|id| crate::db::get_secret_by_id(&app.conn, *id).ok().flatten())
                .collect();
            app.marked_secrets.clear();
            spawn_hibp_scan(app, records);
        }
        KeyCode::Char('H') => {
            if let Ok(records) = crate::db::get_secrets(&app.conn) {
                spawn_hibp_scan(app, records);
            }
        }

        KeyCode::Up => match app.active_block {
            ActiveBlock::Categories => {
                if app.selected_category_idx > 0 {
                    app.selected_category_idx -= 1;
                    app.apply_filter();
                }
            }
            ActiveBlock::Secrets => {
                if app.selected_secret_idx > 0 {
                    app.selected_secret_idx -= 1;
                }
            }
            _ => {}
        },
        KeyCode::Down => match app.active_block {
            ActiveBlock::Categories => {
                if app.selected_category_idx + 1 < app.categories.len() {
                    app.selected_category_idx += 1;
                    app.apply_filter();
                }
            }
            ActiveBlock::Secrets => {
                if app.selected_secret_idx + 1 < app.filtered_secrets.len() {
                    app.selected_secret_idx += 1;
                }
            }
            _ => {}
        },
        KeyCode::PageUp => match app.active_block {
            ActiveBlock::Categories => {
                app.selected_category_idx = app.selected_category_idx.saturating_sub(5);
                app.apply_filter();
            }
            ActiveBlock::Secrets => {
                app.selected_secret_idx = app.selected_secret_idx.saturating_sub(10);
            }
            _ => {}
        },
        KeyCode::PageDown => match app.active_block {
            ActiveBlock::Categories => {
                app.selected_category_idx = std::cmp::min(
                    app.selected_category_idx + 5,
                    if app.categories.is_empty() { 0 } else { app.categories.len() - 1 }
                );
                app.apply_filter();
            }
            ActiveBlock::Secrets => {
                app.selected_secret_idx = std::cmp::min(
                    app.selected_secret_idx + 10,
                    if app.filtered_secrets.is_empty() { 0 } else { app.filtered_secrets.len() - 1 }
                );
            }
            _ => {}
        },
        _ => {}
    }
    false
}

fn handle_form_input(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) {
    if modifiers.contains(KeyModifiers::CONTROL) && (code == KeyCode::Char('g') || code == KeyCode::Char('G')) {
        let opts = crate::generator::GeneratorOptions::load();
        if let Ok(pw) = crate::generator::generate_password(&opts) {
            app.form_password.zeroize();
            app.form_password = pw;
        }
        return;
    }

    match code {
        KeyCode::Tab => {
            app.active_form_field = match app.active_form_field {
                FormField::Title => FormField::Category,
                FormField::Category => FormField::Username,
                FormField::Username => FormField::Url,
                FormField::Url => FormField::Password,
                FormField::Password => FormField::Notes,
                FormField::Notes => FormField::Title,
            };
        }
        KeyCode::BackTab => {
            app.active_form_field = match app.active_form_field {
                FormField::Title => FormField::Notes,
                FormField::Category => FormField::Title,
                FormField::Username => FormField::Category,
                FormField::Url => FormField::Username,
                FormField::Password => FormField::Url,
                FormField::Notes => FormField::Password,
            };
        }
        KeyCode::Char(c) => {
            if !modifiers.contains(KeyModifiers::CONTROL) && !modifiers.contains(KeyModifiers::ALT) {
                match app.active_form_field {
                    FormField::Title => app.form_title.push(c),
                    FormField::Category => app.form_category.push(c),
                    FormField::Username => app.form_username.push(c),
                    FormField::Url => app.form_url.push(c),
                    FormField::Password => app.form_password.push(c),
                    FormField::Notes => app.form_notes.push(c),
                }
            }
        },
        KeyCode::Backspace => match app.active_form_field {
            FormField::Title => { app.form_title.pop(); }
            FormField::Category => { app.form_category.pop(); }
            FormField::Username => { app.form_username.pop(); }
            FormField::Url => { app.form_url.pop(); }
            FormField::Password => { app.form_password.pop(); }
            FormField::Notes => { app.form_notes.pop(); }
        },
        KeyCode::Enter => {
            if app.form_title.trim().is_empty()
                || app.form_category.trim().is_empty()
                || app.form_password.trim().is_empty()
            {
                app.error_message = "Title, Category and Password are required!".to_string();
                app.screen = Screen::ErrorDialog;
                return;
            }

            if let Some(key) = &app.key {
                let res = if let Some(id) = app.edit_id {
                    db::update_secret(
                        &app.conn,
                        id,
                        &app.form_title,
                        &app.form_category,
                        &app.form_username,
                        &app.form_url,
                        &app.form_password,
                        if app.form_notes.is_empty() { None } else { Some(&app.form_notes) },
                        key,
                    )
                } else {
                    db::add_secret(
                        &app.conn,
                        &app.form_title,
                        &app.form_category,
                        &app.form_username,
                        &app.form_url,
                        &app.form_password,
                        if app.form_notes.is_empty() { None } else { Some(&app.form_notes) },
                        key,
                    )
                };

                match res {
                    Ok(_) => {
                        app.form_password.zeroize();
                        app.form_password.clear();
                        app.form_notes.zeroize();
                        app.form_notes.clear();
                        app.screen = Screen::Dashboard;
                        app.refresh_secrets();
                    }
                    Err(err) => {
                        app.error_message = err;
                        app.screen = Screen::ErrorDialog;
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.form_password.zeroize();
            app.form_password.clear();
            app.form_notes.zeroize();
            app.form_notes.clear();
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

fn handle_confirmation_input(app: &mut TuiApp, code: KeyCode, action: ConfirmAction) {
    match code {
        KeyCode::Char('y') | KeyCode::Enter => {
            match action {
                ConfirmAction::DeleteMarked => {
                    for id in &app.marked_secrets {
                        let _ = db::delete_secret(&app.conn, *id);
                    }
                    app.marked_secrets.clear();
                }
                ConfirmAction::DeleteSingle(id) => {
                    let _ = db::delete_secret(&app.conn, id);
                    app.marked_secrets.remove(&id);
                }
            }
            app.screen = Screen::Dashboard;
            app.refresh_secrets();
        }
        KeyCode::Char('n') | KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

fn handle_change_password_input(app: &mut TuiApp, code: KeyCode) {
    match code {
        KeyCode::Tab => {
            app.change_pass_field = (app.change_pass_field + 1) % 3;
        }
        KeyCode::BackTab => {
            app.change_pass_field = if app.change_pass_field == 0 { 2 } else { app.change_pass_field - 1 };
        }
        KeyCode::Char(c) => {
            match app.change_pass_field {
                0 => app.password_input.push(c),
                1 => app.password_confirm_input.push(c),
                _ => app.form_password.push(c),
            }
        }
        KeyCode::Backspace => {
            match app.change_pass_field {
                0 => { app.password_input.pop(); }
                1 => { app.password_confirm_input.pop(); }
                _ => { app.form_password.pop(); }
            }
        }
        KeyCode::Enter => {
            if app.password_input.is_empty() || app.password_confirm_input.is_empty() || app.form_password.is_empty() {
                app.error_message = "All fields are required!".to_string();
                return;
            }
            if app.password_confirm_input != app.form_password {
                app.error_message = "New passwords do not match!".to_string();
                return;
            }

            // Verify old key
            let old_key = match &app.key {
                Some(k) => k,
                None => {
                    app.error_message = "Vault is locked!".to_string();
                    return;
                }
            };

            // Check if old password matches current active key
            let db_path = crate::get_db_path();
            if db::open_vault(&db_path, &app.password_input).is_err() {
                app.error_message = "Incorrect current password!".to_string();
                return;
            }

            // Rotate keys. change_master_password builds the re-keyed vault
            // at a separate temp path and swaps it into place at db_path, so
            // app.conn (left open against whatever the pre-rotation backup
            // path now is) must be replaced with a fresh connection to the
            // new file on success, not reused.
            match db::change_master_password(&app.conn, &db_path, old_key, &app.password_confirm_input) {
                Ok(new_key) => {
                    match db::open_vault(&db_path, &app.password_confirm_input) {
                        Ok((new_conn, _)) => {
                            app.conn = new_conn;
                            app.key = Some(new_key);
                            app.password_input.zeroize();
                            app.password_confirm_input.zeroize();
                            app.form_password.zeroize();
                            app.password_input.clear();
                            app.password_confirm_input.clear();
                            app.form_password.clear();
                            app.error_message = String::new();
                            app.screen = Screen::Dashboard;
                            app.refresh_secrets();
                        }
                        Err(err) => {
                            // change_master_password already confirmed the new
                            // vault opens before returning Ok, so this should
                            // be unreachable -- but surface it loudly rather
                            // than silently leaving app.conn stale if it ever
                            // does happen.
                            app.error_message = format!("Password changed but failed to reopen the vault: {}", err);
                        }
                    }
                }
                Err(err) => {
                    app.error_message = err;
                }
            }
        }
        KeyCode::Esc => {
            app.password_input.zeroize();
            app.password_confirm_input.zeroize();
            app.form_password.zeroize();
            app.password_input.clear();
            app.password_confirm_input.clear();
            app.form_password.clear();
            app.error_message = String::new();
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

fn handle_help_input(app: &mut TuiApp, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('h') | KeyCode::Char('?') => {
            app.help_scroll = 0;
            app.screen = Screen::Dashboard;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.help_scroll = app.help_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.help_scroll = app.help_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.help_scroll = app.help_scroll.saturating_sub(5);
        }
        KeyCode::PageDown => {
            app.help_scroll = app.help_scroll.saturating_add(5);
        }
        KeyCode::Home => {
            app.help_scroll = 0;
        }
        _ => {}
    }
}

fn handle_import_input(app: &mut TuiApp, code: KeyCode) {
    match code {
        KeyCode::Char(c) => {
            app.import_path_input.push(c);
        }
        KeyCode::Backspace => {
            app.import_path_input.pop();
        }
        KeyCode::Esc => {
            app.import_path_input.clear();
            app.screen = Screen::Dashboard;
        }
        KeyCode::Enter => {
            let file_path = app.import_path_input.trim();
            if file_path.is_empty() {
                return;
            }
            
            let detected_format = match crate::import::detect_format(file_path) {
                Ok(fmt) => fmt,
                Err(e) => {
                    app.error_message = format!("Import detection failed: {}", e);
                    app.screen = Screen::ErrorDialog;
                    return;
                }
            };

            let key_ref = match &app.key {
                Some(k) => k,
                None => {
                    app.error_message = "Vault key not found in memory. Please unlock again.".to_string();
                    app.screen = Screen::ErrorDialog;
                    return;
                }
            };

            let import_result = match detected_format {
                crate::import::ImportFormat::BitwardenJson => crate::import::import_bitwarden_json(&app.conn, file_path, key_ref),
                crate::import::ImportFormat::BraveChromeCsv => crate::import::import_brave_chrome_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
                crate::import::ImportFormat::FirefoxCsv => crate::import::import_firefox_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
                crate::import::ImportFormat::LastPassCsv => crate::import::import_lastpass_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
                crate::import::ImportFormat::KeePassXcCsv => crate::import::import_keepassxc_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
                crate::import::ImportFormat::OnePasswordCsv => crate::import::import_onepassword_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
                crate::import::ImportFormat::KeyStashCsv => crate::import::import_keystash_csv(&app.conn, file_path, key_ref).map(|c| (c, 0)),
            };

            match import_result {
                Ok((count, skipped)) => {
                    let skip_note = if skipped > 0 {
                        format!(" ({} non-login item(s) skipped)", skipped)
                    } else {
                        String::new()
                    };
                    app.copied_message = Some((format!("Success: Imported {} items from {}!{}", count, detected_format.name(), skip_note), Instant::now(), StatusType::Normal));
                    app.import_path_input.clear();
                    app.refresh_secrets();
                    app.trigger_postunlock_sync();
                    app.screen = Screen::Dashboard;
                }
                Err(e) => {
                    app.error_message = format!("Import failed: {}", e);
                    app.screen = Screen::ErrorDialog;
                }
            }
        }
        _ => {}
    }
}

fn handle_export_type_input(app: &mut TuiApp, code: KeyCode) {
    match code {
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app.export_only_marked = false;
            app.export_path_input.clear();
            app.screen = Screen::ExportDialog;
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            if !app.marked_secrets.is_empty() {
                app.export_only_marked = true;
                app.export_path_input.clear();
                app.screen = Screen::ExportDialog;
            }
        }
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

fn handle_export_input(app: &mut TuiApp, code: KeyCode) {
    match code {
        KeyCode::Char(c) => {
            app.export_path_input.push(c);
        }
        KeyCode::Backspace => {
            app.export_path_input.pop();
        }
        KeyCode::Esc => {
            app.export_path_input.clear();
            app.screen = Screen::Dashboard;
        }
        KeyCode::Enter => {
            let file_path = app.export_path_input.trim();
            if file_path.is_empty() {
                return;
            }

            let key_ref = match &app.key {
                Some(k) => k,
                None => {
                    app.error_message = "Vault key not found in memory. Please unlock again.".to_string();
                    app.screen = Screen::ErrorDialog;
                    return;
                }
            };

            let filter_set = if app.export_only_marked {
                Some(&app.marked_secrets)
            } else {
                None
            };

            match crate::import::export_vault_csv(&app.conn, file_path, key_ref, filter_set) {
                Ok(count) => {
                    app.copied_message = Some((format!("Success: Exported {} secrets to CSV!", count), Instant::now(), StatusType::Normal));
                    app.export_path_input.clear();
                    app.screen = Screen::Dashboard;
                }
                Err(e) => {
                    app.error_message = format!("Export failed: {}", e);
                    app.screen = Screen::ErrorDialog;
                }
            }
        }
        _ => {}
    }
}

fn draw_ui(f: &mut ratatui::Frame, app: &TuiApp) {
    match app.screen {
        Screen::Lock => draw_lock_screen(f, app),
        Screen::Setup => draw_setup_screen(f, app),
        Screen::InterruptedMigration => draw_interrupted_migration_screen(f),
        Screen::InterruptedRotation => draw_interrupted_rotation_screen(f),
        Screen::Dashboard => draw_dashboard(f, app),
        Screen::AddSecret | Screen::EditSecret => draw_form(f, app),
        Screen::ConfirmationDialog(_) => draw_confirmation_dialog(f, app),
        Screen::HelpDialog => draw_help_dialog(f, app),
        Screen::ChangePassword => draw_change_password_screen(f, app),
        Screen::ErrorDialog => draw_error_dialog(f, app),
        Screen::ImportDialog => draw_import_dialog(f, app),
        Screen::ExportTypeDialog => draw_export_type_dialog(f, app),
        Screen::ExportDialog => draw_export_dialog(f, app),
        Screen::GeneratorDialog => draw_generator_dialog(f, app),
        Screen::DeduplicateScreen => draw_deduplicate_screen(f, app),
        Screen::SettingsScreen => draw_settings_screen(f, app),
        Screen::SyncConflictScreen => draw_sync_conflict_screen(f, app),
    }

    if let Ok(progress_lock) = app.hibp_progress.lock() {
        if let Some((checked, total)) = *progress_lock {
            draw_hibp_progress_dialog(f, checked, total);
        }
    }
}

fn draw_lock_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(4)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(size);

    let title_text = if app.needs_migration {
        "KeyStash Password Vault (legacy vault -- will migrate to encrypted format)"
    } else {
        "KeyStash Password Vault"
    };
    let title = Paragraph::new(title_text)
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    let masked: String = "*".repeat(app.password_input.len());
    let pass_box = Paragraph::new(masked)
        .block(Block::default().borders(Borders::ALL).title("Enter Master Password"))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(pass_box, chunks[1]);

    if !app.error_message.is_empty() {
        let err = Paragraph::new(&*app.error_message)
            .style(Style::default().fg(Color::Red));
        f.render_widget(err, chunks[2]);
    } else if app.needs_migration {
        let hints = Paragraph::new("Press [Enter] to migrate & unlock | [Esc] to Exit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(hints, chunks[2]);
    } else {
        let hints = Paragraph::new("Press [Enter] to Unlock | [Esc] to Exit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(hints, chunks[2]);
    }
}

/// Terminal state for an interrupted `migrate_legacy_vault` run: nothing else
/// in the TUI is safe to do from here (there's no key, and no vault.db this
/// process should touch), so this just surfaces the recovery instructions and
/// waits for the user to quit, fix it from a shell, and relaunch.
fn draw_interrupted_migration_screen(f: &mut ratatui::Frame) {
    let size = f.size();
    f.render_widget(Clear, size);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Interrupted Migration -- Recovery Needed ")
        .border_style(Style::default().fg(Color::Red));

    let mut text = db::interrupted_migration_message(&crate::get_db_path());
    text.push_str("\n\nPress [Esc] or [q] to exit.");

    let paragraph = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(block)
        .style(Style::default().fg(Color::White));
    f.render_widget(paragraph, size);
}

fn handle_interrupted_migration_input(code: KeyCode) -> bool {
    matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter)
}

/// Same reasoning as `draw_interrupted_migration_screen`, for an interrupted
/// `change_master_password` run instead.
fn draw_interrupted_rotation_screen(f: &mut ratatui::Frame) {
    let size = f.size();
    f.render_widget(Clear, size);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Interrupted Password Change -- Recovery Needed ")
        .border_style(Style::default().fg(Color::Red));

    let mut text = db::interrupted_rotation_message(&crate::get_db_path());
    text.push_str("\n\nPress [Esc] or [q] to exit.");

    let paragraph = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(block)
        .style(Style::default().fg(Color::White));
    f.render_widget(paragraph, size);
}

fn draw_setup_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(4)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(size);

    let title = Paragraph::new("Welcome to KeyStash - Initial Setup")
        .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    let pass_focused = app.active_form_field == FormField::Title;
    let confirm_focused = app.active_form_field != FormField::Title;

    let pass_masked = "*".repeat(app.password_input.len());
    let pass_box = Paragraph::new(pass_masked)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Choose a Master Password")
                .border_style(if pass_focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        );
    f.render_widget(pass_box, chunks[1]);

    let confirm_masked = "*".repeat(app.password_confirm_input.len());
    let confirm_box = Paragraph::new(confirm_masked)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm Master Password")
                .border_style(if confirm_focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        );
    f.render_widget(confirm_box, chunks[2]);

    if !app.error_message.is_empty() {
        let err = Paragraph::new(&*app.error_message)
            .style(Style::default().fg(Color::Red));
        f.render_widget(err, chunks[3]);
    } else {
        let hints = Paragraph::new("Use [Tab] to switch fields | Press [Enter] to Initialize | [Esc] to Exit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(hints, chunks[3]);
    }
}

fn draw_dashboard(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    
    // Main vertical division: Body, Status Bar
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(size);

    // Body horizontal division: Sidebar (Categories & Search & Secrets List), Detail view
    let body_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_layout[0]);

    // Sidebar vertical division: Category/Search vs Secrets
    let sidebar_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Search bar
            Constraint::Length(8), // Categories list
            Constraint::Min(3),    // Secrets list
        ])
        .split(body_layout[0]);

    // Render Search
    let search_title = if app.searching { "Search (Editing)" } else { "Search (Press /)" };
    let search_box = Paragraph::new(app.search_query.as_str())
        .block(Block::default().borders(Borders::ALL).title(search_title).border_style(
            if app.searching { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) }
        ));
    f.render_widget(search_box, sidebar_layout[0]);

    // Render Categories
    let category_items: Vec<ListItem> = app.categories
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == app.selected_category_idx && app.active_block == ActiveBlock::Categories {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::REVERSED)
            } else if i == app.selected_category_idx {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!("  {}", c)).style(style)
        })
        .collect();

    let categories_list = List::new(category_items)
        .block(Block::default().borders(Borders::ALL).title("Categories").border_style(
            if app.active_block == ActiveBlock::Categories { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) }
        ));
    app.category_list_state.borrow_mut().select(Some(app.selected_category_idx));
    f.render_stateful_widget(
        categories_list,
        sidebar_layout[1],
        &mut *app.category_list_state.borrow_mut(),
    );

    // Render Secrets
    let secret_items: Vec<ListItem> = app.filtered_secrets
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let style = if i == app.selected_secret_idx && app.active_block == ActiveBlock::Secrets {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::REVERSED)
            } else if i == app.selected_secret_idx {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };
            let prefix = if app.marked_secrets.contains(&r.id) { "[x] " } else { "[ ] " };
            ListItem::new(format!("  {}{}", prefix, r.title)).style(style)
        })
        .collect();

    let secrets_list = List::new(secret_items)
        .block(Block::default().borders(Borders::ALL).title("Credentials").border_style(
            if app.active_block == ActiveBlock::Secrets { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) }
        ));
    app.secrets_list_state.borrow_mut().select(Some(app.selected_secret_idx));
    f.render_stateful_widget(
        secrets_list,
        sidebar_layout[2],
        &mut *app.secrets_list_state.borrow_mut(),
    );

    // Render Details
    let details_block = Block::default()
        .borders(Borders::ALL)
        .title("Detail View")
        .border_style(
            if app.active_block == ActiveBlock::Details { Style::default().fg(Color::Magenta) } else { Style::default().fg(Color::DarkGray) }
        );

    if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
        let password_str = if app.reveal_password {
            if let Some(key) = &app.key {
                crate::crypto::decrypt(&record.encrypted_password, key)
                    .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                    .unwrap_or_else(|_| Zeroizing::new("<Error Decrypting>".to_string()))
            } else {
                Zeroizing::new("<Locked>".to_string())
            }
        } else {
            Zeroizing::new("••••••••••••".to_string())
        };

        let notes_str = if let Some(enc_notes) = &record.encrypted_notes {
            if let Some(key) = &app.key {
                crate::crypto::decrypt(enc_notes, key)
                    .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                    .unwrap_or_else(|_| Zeroizing::new("<Error Decrypting>".to_string()))
            } else {
                Zeroizing::new("<Locked>".to_string())
            }
        } else {
            Zeroizing::new("[No Notes]".to_string())
        };

        let details_text = vec![
            Line::from(vec![
                Span::styled("Title:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.title, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Category: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.category, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Username: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.username, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("URL:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.url, Style::default().fg(Color::LightBlue)),
            ]),
            Line::from(vec![
                Span::styled("Password: ", Style::default().fg(Color::DarkGray)),
                Span::styled(password_str.as_str(), Style::default().fg(Color::LightRed)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Notes:", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(notes_str.as_str(), Style::default().fg(Color::White))),
            Line::from(""),
            Line::from(vec![
                Span::styled("Last Updated: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.updated_at, Style::default().fg(Color::DarkGray)),
            ]),
        ];

        let mut details_text = details_text;

        if let Some(report) = &app.audit_report {
            if let Some(entry) = report.entries.iter().find(|e| e.id == record.id) {
                let (sev_color, sev_label) = match entry.severity {
                    crate::audit::Severity::Critical => (Color::Red, "CRITICAL"),
                    crate::audit::Severity::Weak => (Color::Yellow, "WEAK"),
                    crate::audit::Severity::Good => (Color::Green, "GOOD"),
                };
                let score_bar = {
                    let filled = entry.score as usize;
                    let empty = 5usize.saturating_sub(filled);
                    format!("Score: {}/5  [{}{}]", entry.score, "█".repeat(filled), "░".repeat(empty))
                };
                details_text.push(Line::from(""));
                details_text.push(Line::from(Span::styled("Security Audit:", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))));
                details_text.push(Line::from(vec![
                    Span::styled("  Severity: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(sev_label, Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                ]));
                details_text.push(Line::from(vec![
                    Span::styled("  ", Style::default()),
                    Span::styled(score_bar, Style::default().fg(sev_color)),
                ]));
                
                // HaveIBeenPwned status
                details_text.push(Line::from(vec![
                    Span::styled("  HIBP:     ", Style::default().fg(Color::DarkGray)),
                    match entry.hibp_count {
                        None => Span::styled("Not checked (Press [h] to check online)", Style::default().fg(Color::DarkGray)),
                        Some(0) => Span::styled("✓ Clean (not found in breaches)", Style::default().fg(Color::Green)),
                        Some(n) => Span::styled(format!("✗ PWNED (found in {} breaches)", n), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    }
                ]));

                if !entry.issues.is_empty() {
                    details_text.push(Line::from("  Issues found:"));
                    for issue in &entry.issues {
                        details_text.push(Line::from(vec![
                            Span::styled("    • ", Style::default().fg(Color::Yellow)),
                            Span::styled(issue.clone(), Style::default().fg(Color::White)),
                        ]));
                    }
                }
            }
        }

        let details_paragraph = Paragraph::new(details_text)
            .block(details_block)
            .wrap(Wrap { trim: true });
        f.render_widget(details_paragraph, body_layout[1]);
    } else {
        let empty_p = Paragraph::new("No secret selected.")
            .style(Style::default().fg(Color::DarkGray))
            .block(details_block);
        f.render_widget(empty_p, body_layout[1]);
    }

    // Render Status / Help Bar
    let status_text = if let Some((msg, _, status_type)) = &app.copied_message {
        match status_type {
            StatusType::Copied => Line::from(Span::styled(msg, Style::default().fg(Color::Cyan))),
            StatusType::Cleared => Line::from(Span::styled(msg, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            StatusType::Normal => Line::from(Span::styled(msg, Style::default().fg(Color::Green))),
        }
    } else {
        Line::from(vec![
            Span::styled("[a] Add | ", Style::default().fg(Color::Green)),
            Span::styled("[e] Edit | ", Style::default().fg(Color::Yellow)),
            Span::styled("[v] View PW | ", Style::default().fg(Color::Magenta)),
            Span::styled("[c] Copy User | ", Style::default().fg(Color::Cyan)),
            Span::styled("[p] Copy PW | ", Style::default().fg(Color::Cyan)),
            Span::styled("[h] Check HIBP | ", Style::default().fg(Color::Green)),
            Span::styled("[?] Help | ", Style::default().fg(Color::Cyan)),
            Span::styled("[Esc] Exit", Style::default().fg(Color::White)),
        ])
    };

    let status_bar = Paragraph::new(status_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Actions")
                .title_bottom(Line::from(concat!("v", env!("CARGO_PKG_VERSION"))).right_aligned()),
        );
    f.render_widget(status_bar, main_layout[1]);
}

fn get_strength_bar(password: &str) -> (Span<'static>, Span<'static>) {
    if password.is_empty() {
        return (
            Span::styled(" [░░░░░░░░░░]", Style::default().fg(Color::DarkGray)),
            Span::styled(" Empty", Style::default().fg(Color::DarkGray))
        );
    }
    
    let mut score = 0;
    let len = password.len();
    
    if len >= 8 { score += 1; }
    if len >= 12 { score += 1; }
    if len >= 16 { score += 1; }
    
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    
    if has_lower { score += 1; }
    if has_upper { score += 1; }
    if has_digit { score += 1; }
    if has_special { score += 1; }
    
    let (bar, label, color) = match score {
        0..=2 => (" [██░░░░░░░░]", " Weak", Color::Red),
        3 => (" [████░░░░░░]", " Weak", Color::Red),
        4 => (" [██████░░░░]", " Medium", Color::Yellow),
        5 => (" [████████░░]", " Medium", Color::Yellow),
        6 => (" [█████████░]", " Strong", Color::Green),
        _ => (" [██████████]", " Very Strong", Color::Green),
    };
    
    (
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(label, Style::default().fg(color))
    )
}

fn check_local_hibp(conn: &rusqlite::Connection, password: &str, master_key: &[u8; 32]) -> Option<u64> {
    if password.is_empty() {
        return None;
    }
    let hash_hex = crate::crypto::hibp_cache_fingerprint(password.as_bytes(), master_key);
    conn.query_row(
        "SELECT hibp_count FROM hibp_checks WHERE password_hash = ?1",
        [hash_hex],
        |row| row.get::<_, Option<u64>>(0)
    ).ok().flatten()
}

fn draw_form(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let is_edit = app.screen == Screen::EditSecret;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if is_edit { "Edit Secret (Enter to save, Esc to cancel)" } else { "Add New Secret (Enter to save, Esc to cancel)" });

    let area = centered_rect(60, 85, size);
    f.render_widget(Clear, area); // clear background under popup

    let form_layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Category
            Constraint::Length(3), // Username
            Constraint::Length(3), // URL
            Constraint::Length(3), // Password
            Constraint::Length(1), // Password Strength Indicator
            Constraint::Length(2), // Audit Warnings (reused/breached)
            Constraint::Min(2),    // Notes
        ])
        .split(area);

    f.render_widget(block, area);

    let get_border_style = |field| {
        if app.active_form_field == field {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    };

    let title_box = Paragraph::new(app.form_title.as_str()).block(
        Block::default().borders(Borders::ALL).title("Title*").border_style(get_border_style(FormField::Title))
    );
    f.render_widget(title_box, form_layout[0]);

    let category_box = Paragraph::new(app.form_category.as_str()).block(
        Block::default().borders(Borders::ALL).title("Category*").border_style(get_border_style(FormField::Category))
    );
    f.render_widget(category_box, form_layout[1]);

    let username_box = Paragraph::new(app.form_username.as_str()).block(
        Block::default().borders(Borders::ALL).title("Username").border_style(get_border_style(FormField::Username))
    );
    f.render_widget(username_box, form_layout[2]);

    let url_box = Paragraph::new(app.form_url.as_str()).block(
        Block::default().borders(Borders::ALL).title("URL").border_style(get_border_style(FormField::Url))
    );
    f.render_widget(url_box, form_layout[3]);

    let password_title = if app.active_form_field == FormField::Password {
        "Password* (Press Ctrl+G to generate)"
    } else {
        "Password*"
    };
    let password_box = Paragraph::new(app.form_password.as_str()).block(
        Block::default().borders(Borders::ALL).title(password_title).border_style(get_border_style(FormField::Password))
    );
    f.render_widget(password_box, form_layout[4]);

    // Password strength indicator
    let (bar_span, label_span) = get_strength_bar(&app.form_password);
    let strength_paragraph = Paragraph::new(Line::from(vec![
        Span::styled("Password Strength:", Style::default().fg(Color::Gray)),
        bar_span,
        label_span,
    ])).wrap(Wrap { trim: true });
    f.render_widget(strength_paragraph, form_layout[5]);

    // Check reuse
    let mut reuse_count = 0;
    if !app.form_password.is_empty() {
        if let Some(ref key) = app.key {
            for r in &app.secrets {
                if let Some(edit_id) = app.edit_id {
                    if r.id == edit_id {
                        continue;
                    }
                }
                if let Ok(dec) = crate::crypto::decrypt(&r.encrypted_password, key) {
                    if let Ok(pw) = String::from_utf8(dec.to_vec()) {
                        let pw = Zeroizing::new(pw);
                        if *pw == app.form_password {
                            reuse_count += 1;
                        }
                    }
                }
            }
        }
    }

    // Build Audit Warnings line
    let mut warning_spans = vec![
        Span::styled("Audit Warnings:   ", Style::default().fg(Color::Gray))
    ];
    let mut has_warnings = false;

    if reuse_count > 0 {
        warning_spans.push(Span::styled(
            format!("⚠ Reused in {} other entry(ies)", reuse_count),
            Style::default().fg(Color::LightRed)
        ));
        has_warnings = true;
    }

    if let Some(hibp_count) = app.key.as_ref().and_then(|key| check_local_hibp(&app.conn, &app.form_password, key)) {
        if hibp_count > 0 {
            if has_warnings {
                warning_spans.push(Span::raw(" | "));
            }
            warning_spans.push(Span::styled(
                format!("⚠ Breached ({} times in HIBP database)", hibp_count),
                Style::default().fg(Color::LightRed)
            ));
            has_warnings = true;
        }
    }

    if !has_warnings {
        if app.form_password.is_empty() {
            warning_spans.push(Span::styled("None", Style::default().fg(Color::DarkGray)));
        } else {
            warning_spans.push(Span::styled("✓ Unique & not known pwned (in local cache)", Style::default().fg(Color::Green)));
        }
    }

    let warnings_paragraph = Paragraph::new(Line::from(warning_spans)).wrap(Wrap { trim: true });
    f.render_widget(warnings_paragraph, form_layout[6]);

    let notes_box = Paragraph::new(app.form_notes.as_str()).block(
        Block::default().borders(Borders::ALL).title("Notes").border_style(get_border_style(FormField::Notes))
    );
    f.render_widget(notes_box, form_layout[7]);
}



fn draw_error_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Error")
        .border_style(Style::default().fg(Color::Red));

    let area = centered_rect(50, 30, size);
    f.render_widget(Clear, area);

    let error_p = Paragraph::new(app.error_message.as_str())
        .style(Style::default().fg(Color::LightRed))
        .block(block)
        .wrap(Wrap { trim: true });

    f.render_widget(error_p, area);
}

fn draw_confirmation_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Confirmation Required")
        .border_style(Style::default().fg(Color::Yellow));

    let area = centered_rect(50, 30, size);
    f.render_widget(Clear, area);

    let content_text = vec![
        Line::from(Span::styled(&app.confirmation_message, Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::DarkGray)),
            Span::styled("[y] / [Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("to Confirm  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[n] / [Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled("to Cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ];

    let confirm_p = Paragraph::new(content_text)
        .block(block)
        .wrap(Wrap { trim: true })
        .alignment(ratatui::layout::Alignment::Center);

    f.render_widget(confirm_p, area);
}

fn draw_help_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let area = centered_rect(70, 85, size);
    f.render_widget(Clear, area);

    let help_text: Vec<Line> = vec![
        Line::from(Span::styled("Navigation & Selection:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [Tab]         ", Style::default().fg(Color::Yellow)),
            Span::styled("Cycle panels forward (Categories -> Secrets -> Details)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [Shift+Tab]   ", Style::default().fg(Color::Yellow)),
            Span::styled("Cycle panels backward", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [↑] / [↓]     ", Style::default().fg(Color::Yellow)),
            Span::styled("Scroll lists item-by-item", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [PgUp]/[PgDn] ", Style::default().fg(Color::Yellow)),
            Span::styled("Scroll lists page-by-page (10 items / 5 items)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [Space]       ", Style::default().fg(Color::Yellow)),
            Span::styled("Mark/Unmark selected item for mass actions", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [/]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Filter credentials by text search query", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("Vault Operations:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [a]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Add a new credential", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [e]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Edit the selected credential", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [d]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Delete selected credential (or marked items if any)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [v]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Toggle password visibility in Detail Pane", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [m]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Change Master Password and rotate encryption keys", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [i]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Import unencrypted credentials from backups", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [x]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Export credentials (all or selected) to CSV", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [g]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Open password generator (tweak & copy new passwords)", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [h]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Check the selected password on HaveIBeenPwned", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [H]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Check HIBP for all entries in the vault", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [D]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Scan for duplicate entries and resolve/merge them", Style::default().fg(Color::White)),
        ]),

        Line::from(""),
        Line::from(Span::styled("Clipboard Actions (clears automatically after 10s):", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [c]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Copy Username to clipboard", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [p]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Copy Password to clipboard", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [u]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Copy website URL to clipboard", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("Git Sync:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [s]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Force manual sync with Git remote", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("Other:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [?]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Open this help screen", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [,]           ", Style::default().fg(Color::Yellow)),
            Span::styled("Open interactive settings config screen", Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  [q] / [Esc]   ", Style::default().fg(Color::Yellow)),
            Span::styled("Quit KeyStash", Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Scroll with [↑]/[↓] · [PgUp]/[PgDn] · [Home]", Style::default().fg(Color::DarkGray))),
        Line::from(Span::styled("  Press [Esc] or [h] to close", Style::default().fg(Color::DarkGray))),
    ];

    // Calculate total lines and clamp scroll
    let total_lines = help_text.len() as u16;
    // inner height = area height minus 2 border rows minus 1 footer row
    let inner_h = area.height.saturating_sub(3);
    let max_scroll = total_lines.saturating_sub(inner_h);
    let scroll = app.help_scroll.min(max_scroll);

    // Build a dynamic title showing scroll position
    let title = if max_scroll > 0 {
        format!(" Help & Keybindings  [{}/{}] ", scroll + 1, total_lines)
    } else {
        " Help & Keybindings ".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Green));

    // Bottom hint bar
    let hint_area = ratatui::layout::Rect {
        x: area.x + 1,
        y: area.y + area.height - 2,
        width: area.width - 2,
        height: 1,
    };

    let scroll_hint = if max_scroll > 0 {
        Line::from(vec![
            Span::styled(" ↑/↓ ", Style::default().fg(Color::Cyan)),
            Span::styled("scroll  ", Style::default().fg(Color::DarkGray)),
            Span::styled("PgUp/PgDn ", Style::default().fg(Color::Cyan)),
            Span::styled("fast scroll  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Home ", Style::default().fg(Color::Cyan)),
            Span::styled("top  ", Style::default().fg(Color::DarkGray)),
            Span::styled("Esc ", Style::default().fg(Color::Red)),
            Span::styled("close", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(Color::Red)),
            Span::styled("/ ", Style::default().fg(Color::DarkGray)),
            Span::styled("h ", Style::default().fg(Color::Red)),
            Span::styled("to close", Style::default().fg(Color::DarkGray)),
        ])
    };

    // Content area excludes the last 1 row (hint bar)
    let content_area = ratatui::layout::Rect {
        height: area.height.saturating_sub(1),
        ..area
    };

    let help_p = Paragraph::new(help_text)
        .block(block)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(help_p, content_area);
    f.render_widget(Paragraph::new(scroll_hint), hint_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
        self.password_input.zeroize();
        self.password_confirm_input.zeroize();
        self.form_password.zeroize();
        self.form_notes.zeroize();
        self.gen_password.zeroize();
        for group in &mut self.duplicate_groups {
            for pw in &mut group.decrypted_passwords {
                pw.zeroize();
            }
        }
    }
}

fn draw_change_password_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Change Master Password")
        .border_style(Style::default().fg(Color::Magenta));

    let area = centered_rect(60, 70, size);
    f.render_widget(Clear, area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let field_0_focused = app.change_pass_field == 0;
    let field_1_focused = app.change_pass_field == 1;
    let field_2_focused = app.change_pass_field == 2;

    let mask_current = "*".repeat(app.password_input.len());
    let current_box = Paragraph::new(mask_current)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Current Master Password")
                .border_style(if field_0_focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        );
    f.render_widget(current_box, chunks[0]);

    let mask_new = "*".repeat(app.password_confirm_input.len());
    let new_box = Paragraph::new(mask_new)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("New Master Password")
                .border_style(if field_1_focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        );
    f.render_widget(new_box, chunks[1]);

    let mask_confirm = "*".repeat(app.form_password.len());
    let confirm_box = Paragraph::new(mask_confirm)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm New Master Password")
                .border_style(if field_2_focused { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) })
        );
    f.render_widget(confirm_box, chunks[2]);

    if !app.error_message.is_empty() {
        let err = Paragraph::new(&*app.error_message)
            .style(Style::default().fg(Color::Red));
        f.render_widget(err, chunks[3]);
    } else {
        let hints = Paragraph::new("Use [Tab] / [Shift+Tab] to switch fields | Press [Enter] to Save | [Esc] to Cancel")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hints, chunks[3]);
    }
}

fn draw_import_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Import Credentials")
        .border_style(Style::default().fg(Color::Cyan));

    let area = centered_rect(60, 35, size);
    f.render_widget(Clear, area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(1), // Intro
            Constraint::Length(3), // Input box
            Constraint::Min(0),    // Footnote/hints
        ])
        .split(area);

    let intro = Paragraph::new("Enter the absolute file path of the unencrypted export file:")
        .style(Style::default().fg(Color::White));
    f.render_widget(intro, chunks[0]);

    let input_box = Paragraph::new(app.import_path_input.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Backup File Path")
                .border_style(Style::default().fg(Color::Yellow))
        );
    f.render_widget(input_box, chunks[1]);

    let footnote = Paragraph::new(vec![
        Line::from(Span::styled("Supports: Bitwarden JSON, KeyStash/Brave/Chrome/Firefox/LastPass/KeePassXC/1Password CSV", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("to Import  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled("to Cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(footnote, chunks[2]);
}

fn draw_export_type_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Export Vault")
        .border_style(Style::default().fg(Color::Magenta));

    let area = centered_rect(50, 30, size);
    f.render_widget(Clear, area);

    let has_marked = !app.marked_secrets.is_empty();
    
    let mut options = vec![
        Line::from(vec![
            Span::styled("  [a] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled("Export All Vault Credentials", Style::default().fg(Color::White)),
        ]),
    ];

    if has_marked {
        options.push(Line::from(vec![
            Span::styled("  [s] ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(format!("Export Selected ({} Marked) Credentials", app.marked_secrets.len()), Style::default().fg(Color::White)),
        ]));
    } else {
        options.push(Line::from(vec![
            Span::styled("  [s] ", Style::default().fg(Color::DarkGray)),
            Span::styled("Export Selected (No items marked | Use [Space] to mark)", Style::default().fg(Color::DarkGray)),
        ]));
    }

    options.push(Line::from(""));
    options.push(Line::from(vec![
        Span::styled("Press ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled("to Cancel", Style::default().fg(Color::DarkGray)),
    ]));

    let p = Paragraph::new(options)
        .block(block)
        .alignment(ratatui::layout::Alignment::Center)
        .wrap(Wrap { trim: false });

    f.render_widget(p, area);
}

fn draw_export_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if app.export_only_marked { "Export Selected Credentials" } else { "Export All Credentials" })
        .border_style(Style::default().fg(Color::Magenta));

    let area = centered_rect(60, 40, size);
    f.render_widget(Clear, area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(1), // Intro
            Constraint::Length(3), // Input box
            Constraint::Min(0),    // Warnings/hints
        ])
        .split(area);

    let intro = Paragraph::new("Enter the destination path to write the unencrypted CSV file:")
        .style(Style::default().fg(Color::White));
    f.render_widget(intro, chunks[0]);

    let input_box = Paragraph::new(app.export_path_input.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Destination File Path (.csv)")
                .border_style(Style::default().fg(Color::Yellow))
        );
    f.render_widget(input_box, chunks[1]);

    let warnings = Paragraph::new(vec![
        Line::from(Span::styled("WARNING: Plaintext credentials will be written.", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("Unix file permissions will be restricted to 0600 (owner read-write only).", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("to Export  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled("to Cancel", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(warnings, chunks[2]);
}

// ─────────────────────────────────────────────
//  Password Generator Dialog
// ─────────────────────────────────────────────

fn handle_generator_input(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.gen_password.zeroize();
            app.screen = Screen::Dashboard;
        }
        // Toggle options
        KeyCode::Char('1') => {
            app.gen_options.use_uppercase = !app.gen_options.use_uppercase;
            let _ = app.gen_options.save();
            regenerate_in_place(app);
        }
        KeyCode::Char('2') => {
            app.gen_options.use_numbers = !app.gen_options.use_numbers;
            let _ = app.gen_options.save();
            regenerate_in_place(app);
        }
        KeyCode::Char('3') => {
            app.gen_options.use_symbols = !app.gen_options.use_symbols;
            let _ = app.gen_options.save();
            regenerate_in_place(app);
        }
        // Adjust length
        KeyCode::Left => {
            if app.gen_options.length > 4 {
                app.gen_options.length -= 1;
                let _ = app.gen_options.save();
                regenerate_in_place(app);
            }
        }
        KeyCode::Right => {
            if app.gen_options.length < 128 {
                app.gen_options.length += 1;
                let _ = app.gen_options.save();
                regenerate_in_place(app);
            }
        }
        // Regenerate with same options
        KeyCode::Char('r') | KeyCode::Enter => {
            regenerate_in_place(app);
        }
        // Copy to clipboard
        KeyCode::Char('c') => {
            let pass = Zeroizing::new(app.gen_password.clone());
            app.copy_to_clipboard(pass, "password");
        }
        // Fill current form field (if opened from form — future use)
        _ => {}
    }
}

fn regenerate_in_place(app: &mut TuiApp) {
    // Ensure at least one charset is enabled
    if !app.gen_options.use_uppercase
        && !app.gen_options.use_numbers
        && !app.gen_options.use_symbols
        && app.gen_options.length > 0
    {
        // lowercase is always the baseline — never all-disabled
    }
    app.gen_password.zeroize();
    match crate::generator::generate_password(&app.gen_options) {
        Ok(pass) => app.gen_password = pass,
        Err(e) => app.gen_password = format!("Error: {e}"),
    }
}

fn draw_generator_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let area = centered_rect(64, 50, size);
    f.render_widget(Clear, area);

    let block = Block::default()
        .title("  🎲 Password Generator  ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), // Generated password display
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Length row
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Toggle: uppercase
            Constraint::Length(1), // Toggle: numbers
            Constraint::Length(1), // Toggle: symbols
            Constraint::Min(0),    // Key hints
        ])
        .split(area);

    // ── Password display ──
    let pass_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let pass_widget = Paragraph::new(app.gen_password.as_str())
        .style(pass_style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(pass_widget, chunks[0]);

    // ── Length row ──
    let len_line = Line::from(vec![
        Span::styled("  Length: ", Style::default().fg(Color::DarkGray)),
        Span::styled("[←]", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("  {}  ", app.gen_options.length),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled("[→]", Style::default().fg(Color::Cyan)),
    ]);
    f.render_widget(Paragraph::new(len_line), chunks[2]);

    // ── Toggle rows ──
    let toggle = |enabled: bool, label: &str, key: &str| -> Line {
        let (icon, color) = if enabled {
            ("✓ ON ", Color::Green)
        } else {
            ("✗ OFF", Color::Red)
        };
        Line::from(vec![
            Span::styled(format!("  [{key}] "), Style::default().fg(Color::Cyan)),
            Span::styled(format!("{icon}"), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {label}"), Style::default().fg(Color::White)),
        ])
    };

    f.render_widget(
        Paragraph::new(toggle(app.gen_options.use_uppercase, "Uppercase  (A-Z)", "1")),
        chunks[4],
    );
    f.render_widget(
        Paragraph::new(toggle(app.gen_options.use_numbers, "Numbers    (0-9)", "2")),
        chunks[5],
    );
    f.render_widget(
        Paragraph::new(toggle(app.gen_options.use_symbols, "Symbols    (!@#$…)", "3")),
        chunks[6],
    );

    // ── Key hints ──
    let hints = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("[r/Enter] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("Regenerate  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[c] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled("Copy  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[Esc] ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled("Close", Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(hints, chunks[7]);
}



// ─────────────────────────────────────────────
//  Deduplication Screen
// ─────────────────────────────────────────────

/// Re-stamps a record's `updated_at` to now. Must be called *after* deleting
/// its duplicates, not before: each duplicate's tombstone carries that
/// duplicate's own sync_uuid, so the uuid-keyed merge can never mistake one
/// for the kept record -- but the legacy fallback merge (against a remote
/// still on the pre-sync_uuid format) matches tombstones by the shared
/// (title, category, username) triple, and if the kept record's timestamp
/// predates a duplicate's tombstone there, that merge treats the kept record
/// as deleted and destroys it on the next sync -- silently losing the entry
/// the user just chose to keep.
fn restamp_record(conn: &rusqlite::Connection, id: i64) {
    if let Ok(now) = crate::db::now_timestamp(conn) {
        if let Ok(Some(r)) = crate::db::get_secret_by_id(conn, id) {
            let _ = crate::db::update_secret_raw(
                conn,
                id,
                &r.url,
                &r.encrypted_password,
                r.encrypted_notes.as_deref(),
                &now,
            );
        }
    }
}

fn handle_deduplicate_input(app: &mut TuiApp, key: KeyCode) {
    let group_count = app.duplicate_groups.len();
    if group_count == 0 {
        app.screen = Screen::Dashboard;
        return;
    }

    let current_group = &app.duplicate_groups[app.selected_dup_group_idx];
    let item_count = current_group.records.len();

    match key {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.selected_dup_item_idx > 0 {
                app.selected_dup_item_idx -= 1;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.selected_dup_item_idx + 1 < item_count {
                app.selected_dup_item_idx += 1;
            }
        }
        KeyCode::Right | KeyCode::Char('n') => {
            if app.selected_dup_group_idx + 1 < group_count {
                app.selected_dup_group_idx += 1;
                app.selected_dup_item_idx = 0;
            }
        }
        KeyCode::Left | KeyCode::Char('p') => {
            if app.selected_dup_group_idx > 0 {
                app.selected_dup_group_idx -= 1;
                app.selected_dup_item_idx = 0;
            }
        }
        KeyCode::Enter => {
            let keep_id = current_group.records[app.selected_dup_item_idx].id;
            let ids_to_delete: Vec<i64> = current_group.records.iter()
                .filter(|r| r.id != keep_id)
                .map(|r| r.id)
                .collect();
            
            for id in ids_to_delete {
                let _ = crate::db::delete_secret(&app.conn, id);
            }
            restamp_record(&app.conn, keep_id);

            app.refresh_secrets();
            app.find_duplicate_groups();

            if app.duplicate_groups.is_empty() {
                app.screen = Screen::Dashboard;
            } else {
                if app.selected_dup_group_idx >= app.duplicate_groups.len() {
                    app.selected_dup_group_idx = app.duplicate_groups.len() - 1;
                }
                app.selected_dup_item_idx = 0;
            }
        }
        KeyCode::Char('m') => {
            let keep_idx = app.selected_dup_item_idx;
            let keep_record = &current_group.records[keep_idx];
            let mut merged_notes: Zeroizing<String> = Zeroizing::new(String::new());

            if let Some(key) = &app.key {
                if let Some(enc_notes) = &keep_record.encrypted_notes {
                    if let Ok(dec_notes) = crate::crypto::decrypt(enc_notes, key) {
                        *merged_notes = String::from_utf8_lossy(&dec_notes).to_string();
                    }
                }

                for (idx, r) in current_group.records.iter().enumerate() {
                    if idx == keep_idx {
                        continue;
                    }
                    if let Some(enc_notes) = &r.encrypted_notes {
                        if let Ok(dec_notes) = crate::crypto::decrypt(enc_notes, key) {
                            let other_note = Zeroizing::new(String::from_utf8_lossy(&dec_notes).to_string());
                            if !other_note.is_empty() {
                                if !merged_notes.is_empty() {
                                    merged_notes.push_str("\n---\n");
                                }
                                merged_notes.push_str(&format!("Merged from duplicate: {}", *other_note));
                            }
                        }
                    }
                }
                
                let key_bytes: &[u8; 32] = &**key;
                let _ = crate::db::update_secret(
                    &app.conn,
                    keep_record.id,
                    &keep_record.title,
                    &keep_record.category,
                    &keep_record.username,
                    &keep_record.url,
                    &current_group.decrypted_passwords[keep_idx],
                    if merged_notes.is_empty() { None } else { Some(&merged_notes) },
                    key_bytes,
                );
            }

            let keep_id = keep_record.id;
            let ids_to_delete: Vec<i64> = current_group.records.iter()
                .filter(|r| r.id != keep_id)
                .map(|r| r.id)
                .collect();
            
            for id in ids_to_delete {
                let _ = crate::db::delete_secret(&app.conn, id);
            }
            restamp_record(&app.conn, keep_id);

            app.refresh_secrets();
            app.find_duplicate_groups();

            if app.duplicate_groups.is_empty() {
                app.screen = Screen::Dashboard;
            } else {
                if app.selected_dup_group_idx >= app.duplicate_groups.len() {
                    app.selected_dup_group_idx = app.duplicate_groups.len() - 1;
                }
                app.selected_dup_item_idx = 0;
            }
        }
        _ => {}
    }
}

fn draw_deduplicate_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Deduplication Review")
        .border_style(Style::default().fg(Color::Magenta));
        
    f.render_widget(block, size);
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3), // Top header / stats
            Constraint::Min(10),   // Split pane body
            Constraint::Length(2), // Bottom hints
        ])
        .split(size);
        
    let group_count = app.duplicate_groups.len();
    if group_count == 0 {
        return;
    }
    
    let current_group = &app.duplicate_groups[app.selected_dup_group_idx];
    
    let header_text = format!(
        " Duplicate Group {} of {}  |  Key: {}  |  Username: {}",
        app.selected_dup_group_idx + 1,
        group_count,
        if !current_group.url.is_empty() { &current_group.url } else { &current_group.title },
        current_group.username
    );
    let header_p = Paragraph::new(Line::from(vec![
        Span::styled(header_text, Style::default().add_modifier(Modifier::BOLD).fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(header_p, chunks[0]);
    
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Left: list of entries in group
            Constraint::Percentage(60), // Right: details of highlighted entry
        ])
        .split(chunks[1]);
        
    let mut list_items = Vec::new();
    for (idx, r) in current_group.records.iter().enumerate() {
        let is_selected = idx == app.selected_dup_item_idx;
        let prefix = if is_selected { "➔ " } else { "  " };
        let item_style = if is_selected {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        
        let label = format!(
            "{}Entry #{} - [{}] (Modified: {})",
            prefix,
            idx + 1,
            r.category,
            r.updated_at
        );
        list_items.push(ListItem::new(label).style(item_style));
    }
    
    let entries_list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title("Entries in Group").border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(entries_list, body_chunks[0]);
    
    if let Some(r) = current_group.records.get(app.selected_dup_item_idx) {
        let pw = &current_group.decrypted_passwords[app.selected_dup_item_idx];
        let notes = if let Some(key) = &app.key {
            r.encrypted_notes.as_ref()
                .and_then(|enc| crate::crypto::decrypt(enc, key).ok())
                .and_then(|dec| String::from_utf8(dec.to_vec()).ok())
                .map(Zeroizing::new)
                .unwrap_or_else(|| Zeroizing::new(String::new()))
        } else {
            Zeroizing::new(String::new())
        };
        
        let mut detail_lines = vec![
            Line::from(vec![
                Span::styled("  Title:      ", Style::default().fg(Color::DarkGray)),
                Span::styled(r.title.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Category:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(r.category.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Username:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(r.username.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  URL:        ", Style::default().fg(Color::DarkGray)),
                Span::styled(r.url.clone(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Password:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(pw.as_str(), Style::default().fg(Color::LightCyan)),
            ]),
            Line::from(vec![
                Span::styled("  Updated At: ", Style::default().fg(Color::DarkGray)),
                Span::styled(r.updated_at.clone(), Style::default().fg(Color::Magenta)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  Notes:", Style::default().fg(Color::DarkGray))),
        ];
        
        for line in notes.lines() {
            detail_lines.push(Line::from(format!("    {}", line)));
        }
        
        let details_p = Paragraph::new(detail_lines)
            .block(Block::default().borders(Borders::ALL).title("Selected Entry Details").border_style(Style::default().fg(Color::DarkGray)));
        f.render_widget(details_p, body_chunks[1]);
    }
    
    let hints = Paragraph::new(Line::from(vec![
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Cyan)),
        Span::styled("Select entry  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" ←/→ p/n ", Style::default().fg(Color::Cyan)),
        Span::styled("Prev/Next Group  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Enter ", Style::default().fg(Color::Green)),
        Span::styled("Keep Highlighted  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" m ", Style::default().fg(Color::Yellow)),
        Span::styled("Merge Notes  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Esc/q ", Style::default().fg(Color::Red)),
        Span::styled("Back to Dashboard", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(hints, chunks[2]);
}


// ─────────────────────────────────────────────
//  Settings Screen
// ─────────────────────────────────────────────

fn handle_settings_input(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Up | KeyCode::BackTab => {
            if app.active_settings_field > 0 {
                app.active_settings_field -= 1;
            } else {
                app.active_settings_field = 7;
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            if app.active_settings_field < 7 {
                app.active_settings_field += 1;
            } else {
                app.active_settings_field = 0;
            }
        }
        KeyCode::Char(c) => {
            match app.active_settings_field {
                0 => {
                    if c.is_ascii_digit() {
                        app.settings_idle_timeout.push(c);
                    }
                }
                1 => {
                    if c.is_ascii_digit() {
                        app.settings_clipboard_clear.push(c);
                    }
                }
                3 => {
                    if c.is_ascii_digit() {
                        app.settings_gen_length.push(c);
                    }
                }
                2 | 4 | 5 | 6 | 7 => {
                    if c == ' ' {
                        match app.active_settings_field {
                            2 => app.settings_auto_sync = !app.settings_auto_sync,
                            4 => app.settings_gen_lowercase = !app.settings_gen_lowercase,
                            5 => app.settings_gen_uppercase = !app.settings_gen_uppercase,
                            6 => app.settings_gen_numbers = !app.settings_gen_numbers,
                            7 => app.settings_gen_symbols = !app.settings_gen_symbols,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.active_settings_field {
                0 => { app.settings_idle_timeout.pop(); }
                1 => { app.settings_clipboard_clear.pop(); }
                3 => { app.settings_gen_length.pop(); }
                _ => {}
            }
        }
        KeyCode::Enter => {
            // Clamped rather than accepted as-typed: an idle timeout of 0 makes
            // `last_activity.elapsed() >= Duration::from_secs(0)` always true,
            // locking the vault on the very next tick -- including right after
            // this save, soft-locking the user out of the TUI (settings screen
            // included) until they hand-edit config.json.
            let timeout = app.settings_idle_timeout.parse::<u64>().unwrap_or(300).max(10);
            let clip = app.settings_clipboard_clear.parse::<u64>().unwrap_or(10).clamp(1, 3600);
            let gen_len = app.settings_gen_length.parse::<usize>().unwrap_or(20).clamp(4, 256);

            app.config.idle_timeout_seconds = timeout;
            app.config.clipboard_clear_seconds = clip;
            app.config.auto_sync = app.settings_auto_sync;
            app.config.generator.length = gen_len;
            app.config.generator.use_lowercase = app.settings_gen_lowercase;
            app.config.generator.use_uppercase = app.settings_gen_uppercase;
            app.config.generator.use_numbers = app.settings_gen_numbers;
            app.config.generator.use_symbols = app.settings_gen_symbols;

            let _ = app.config.save();
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

/// Number of on-screen grid rows the 8 settings fields occupy at 2 fields
/// per row. Kept as a named constant since draw_settings_screen and
/// settings_grid_scroll both need to agree on it.
const SETTINGS_GRID_ROWS: usize = 4;

/// How many of the 4 field-grid rows actually fit in a settings box this
/// tall, and which row to start drawing from so `active_settings_field`'s
/// row is always among the visible ones. Pure function of height and the
/// active field, not app state, so there's nothing to keep in sync -- the
/// scroll position just falls out of "what's focused" on every frame.
fn settings_grid_scroll(area_height: u16, active_settings_field: usize) -> (usize, usize) {
    const ROW_HEIGHT: u16 = 3;
    const RESERVED_FOR_HINTS: u16 = 3;

    // Mirrors the margin(2) applied to `area` below.
    let usable_height = area_height.saturating_sub(4);
    let rows_that_fit = ((usable_height.saturating_sub(RESERVED_FOR_HINTS)) / ROW_HEIGHT)
        .max(1)
        .min(SETTINGS_GRID_ROWS as u16) as usize;

    let active_row = active_settings_field / 2;
    let max_scroll = SETTINGS_GRID_ROWS.saturating_sub(rows_that_fit);
    let scroll_offset = active_row
        .saturating_sub(rows_that_fit.saturating_sub(1))
        .min(max_scroll);

    (rows_that_fit, scroll_offset)
}

fn draw_settings_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    let area = centered_rect(85, 90, size);
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" KeyStash Settings ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(block, area);

    // Laid out 2 fields per grid row (4 rows for 8 fields) rather than the
    // old 1-per-row stack: a single column of 8 individually-bordered
    // fields needed 24+ rows just for the boxes, which silently lost
    // content rows -- ratatui's constraint solver shrinks Length(3) boxes
    // to fit when there isn't room, and a box shrunk to 2 rows has nowhere
    // left to draw its value line -- on anything close to a standard
    // 80x24 terminal. Even the 2-column grid additionally scrolls (see
    // settings_grid_scroll) so no terminal size, however small, can hide
    // a field's value entirely; it'll just take more Tab presses to reach.
    let fields: [(&str, String, bool); 8] = [
        ("1. Idle Timeout (s)", app.settings_idle_timeout.clone(), app.active_settings_field == 0),
        ("2. Clipboard Delay (s)", app.settings_clipboard_clear.clone(), app.active_settings_field == 1),
        ("3. Auto Sync (Y/N)", if app.settings_auto_sync { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 2),
        ("4. Gen Length", app.settings_gen_length.clone(), app.active_settings_field == 3),
        ("5. Gen Lowercase (Y/N)", if app.settings_gen_lowercase { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 4),
        ("6. Gen Uppercase (Y/N)", if app.settings_gen_uppercase { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 5),
        ("7. Gen Numbers (Y/N)", if app.settings_gen_numbers { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 6),
        ("8. Gen Symbols (Y/N)", if app.settings_gen_symbols { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 7),
    ];

    let (rows_that_fit, scroll_offset) = settings_grid_scroll(area.height, app.active_settings_field);
    let max_scroll = SETTINGS_GRID_ROWS.saturating_sub(rows_that_fit);

    let mut constraints: Vec<Constraint> = (0..rows_that_fit).map(|_| Constraint::Length(3)).collect();
    constraints.push(Constraint::Min(2)); // hints (+ scroll indicator)

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(constraints)
        .split(area);

    let render_field = |label: &str, value: &str, active: bool, frame: &mut ratatui::Frame, rect: Rect| {
        let border_color = if active { Color::Green } else { Color::DarkGray };
        let text_style = if active { Style::default().fg(Color::Green) } else { Style::default().fg(Color::White) };
        let p = Paragraph::new(Span::styled(value, text_style))
            .block(Block::default().borders(Borders::ALL).title(label).border_style(Style::default().fg(border_color)));
        frame.render_widget(p, rect);
    };

    for visible_idx in 0..rows_that_fit {
        let row_idx = scroll_offset + visible_idx;
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[visible_idx]);

        if let Some((label, value, active)) = fields.get(row_idx * 2) {
            render_field(label, value, *active, f, cols[0]);
        }
        if let Some((label, value, active)) = fields.get(row_idx * 2 + 1) {
            render_field(label, value, *active, f, cols[1]);
        }
    }

    let mut hint_spans = vec![
        Span::styled(" Tab/Arrows ", Style::default().fg(Color::Cyan)),
        Span::styled("navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Enter ", Style::default().fg(Color::Green)),
        Span::styled("Save & Exit  ", Style::default().fg(Color::DarkGray)),
        Span::styled(" Esc ", Style::default().fg(Color::Red)),
        Span::styled("Cancel", Style::default().fg(Color::DarkGray)),
    ];
    if max_scroll > 0 {
        hint_spans.push(Span::styled(
            format!("  (row {}/{}, scroll with Tab/Arrows)", scroll_offset + 1, SETTINGS_GRID_ROWS),
            Style::default().fg(Color::Yellow),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(hint_spans)), chunks[rows_that_fit]);
}

#[cfg(test)]
mod settings_layout_tests {
    use super::*;

    // The original bug (some settings fields rendered with no value
    // visible at all) came from a single-column layout needing 32
    // rows minimum while a standard terminal offers 24 -- ratatui's
    // constraint solver silently shrinks some Length(3) boxes down to 2
    // rows, which have no room left for the value line. These tests pin
    // down the 2-column, scrolling replacement so that regression can't
    // come back quietly: whatever the terminal height, every field must
    // eventually be reachable and, once reachable, fully visible.

    #[test]
    fn all_four_rows_fit_on_a_generously_sized_terminal() {
        let (rows_that_fit, scroll_offset) = settings_grid_scroll(40, 0);
        assert_eq!(rows_that_fit, SETTINGS_GRID_ROWS);
        assert_eq!(scroll_offset, 0);
    }

    #[test]
    fn a_standard_80x24_terminal_shows_at_least_one_full_row() {
        // area.height here is centered_rect(85, 90, 24)'s output, but the
        // function only needs the resulting height -- exercise it directly
        // at the kind of height a 24-row terminal actually yields.
        let (rows_that_fit, _) = settings_grid_scroll(21, 0);
        assert!(rows_that_fit >= 1, "must always show at least one full row, never a half-visible one");
    }

    #[test]
    fn scroll_never_leaves_less_than_a_full_row_visible() {
        // Across every plausible height and every field a user could have
        // focused, rows_that_fit must never be 0 (a 0-height row shows
        // nothing, same failure mode as the original bug) and the active
        // field's row must always fall inside the visible window.
        for height in 0..=60u16 {
            for active_field in 0..8usize {
                let (rows_that_fit, scroll_offset) = settings_grid_scroll(height, active_field);
                assert!(rows_that_fit >= 1, "height={height}: rows_that_fit must never be 0");

                let active_row = active_field / 2;
                assert!(
                    active_row >= scroll_offset && active_row < scroll_offset + rows_that_fit,
                    "height={height} active_field={active_field}: active row {active_row} not in visible window [{scroll_offset}, {})",
                    scroll_offset + rows_that_fit
                );
                assert!(
                    scroll_offset + rows_that_fit <= SETTINGS_GRID_ROWS,
                    "height={height} active_field={active_field}: visible window runs past the last row"
                );
            }
        }
    }

    #[test]
    fn tabbing_through_every_field_on_a_tiny_terminal_eventually_shows_each_one() {
        // Simulates a terminal too short to show all 4 rows at once (only
        // 1 fits) and confirms Tab-ing through every field (0..8, matching
        // handle_settings_input's linear navigation) brings each field's
        // row into view at some point -- nothing is permanently unreachable.
        let tiny_height = 10; // rows_that_fit == 1 at this height
        let (rows_that_fit, _) = settings_grid_scroll(tiny_height, 0);
        assert_eq!(rows_that_fit, 1, "test assumes a height that only fits one row -- adjust tiny_height if settings_grid_scroll's constants change");

        let mut rows_seen = std::collections::HashSet::new();
        for active_field in 0..8usize {
            let (fit, offset) = settings_grid_scroll(tiny_height, active_field);
            for r in offset..offset + fit {
                rows_seen.insert(r);
            }
        }
        assert_eq!(rows_seen, (0..SETTINGS_GRID_ROWS).collect(), "every grid row must be reachable by tabbing through all 8 fields");
    }
}

fn draw_hibp_progress_dialog(f: &mut ratatui::Frame, checked: usize, total: usize) {
    let size = f.size();
    let area = centered_rect(60, 25, size);
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Checking HaveIBeenPwned Breach Status ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(block.clone(), area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(1), // Spacer
            Constraint::Length(3), // Progress Info / Bar
            Constraint::Min(1),    // Cancel Hint
        ])
        .split(area);

    let percentage = if total > 0 { (checked * 100) / total } else { 0 };
    let width = chunks[1].width.saturating_sub(6) as usize; // account for margins
    let filled_width = (width * percentage) / 100;
    let empty_width = width.saturating_sub(filled_width);
    let bar_text = format!("{}{}", "█".repeat(filled_width), "░".repeat(empty_width));

    let progress_bar = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(format!("  Checked: {} / {}  ({}%)", checked, total, percentage), Style::default().fg(Color::White)),
        ]),
        Line::from(Span::styled(format!("  [{}]", bar_text), Style::default().fg(Color::Green))),
    ]);
    f.render_widget(progress_bar, chunks[1]);

    let cancel_hint = Paragraph::new(Line::from(vec![
        Span::styled("  Press ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Red)),
        Span::styled(" or ", Style::default().fg(Color::DarkGray)),
        Span::styled("q", Style::default().fg(Color::Red)),
        Span::styled(" to abort check", Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(cancel_hint, chunks[2]);
}

fn handle_sync_conflict_input(app: &mut TuiApp, code: KeyCode) {
    if app.sync_conflicts.is_empty() {
        app.screen = Screen::Dashboard;
        return;
    }

    match code {
        KeyCode::Up => {
            if app.selected_conflict_idx > 0 {
                app.selected_conflict_idx -= 1;
            }
        }
        KeyCode::Down => {
            if app.selected_conflict_idx + 1 < app.sync_conflicts.len() {
                app.selected_conflict_idx += 1;
            }
        }
        KeyCode::Char('l') | KeyCode::Left => {
            let resolved = app.sync_conflicts.remove(app.selected_conflict_idx);
            // Re-stamp local's own data with a fresh "now" timestamp rather than
            // leaving it untouched. Otherwise the subsequent full merge (which
            // uses ordinary last-write-wins semantics) has no way to know this
            // record was just deliberately kept, and could overwrite it again
            // with the remote version if remote's original timestamp happened
            // to be newer than local's.
            if let Ok(now) = crate::db::now_timestamp(&app.conn) {
                let _ = crate::db::update_secret_raw(
                    &app.conn,
                    resolved.local_secret.id,
                    &resolved.local_secret.url,
                    &resolved.local_secret.encrypted_password,
                    resolved.local_secret.encrypted_notes.as_deref(),
                    &now,
                );
            }
            if app.selected_conflict_idx >= app.sync_conflicts.len() && !app.sync_conflicts.is_empty() {
                app.selected_conflict_idx = app.sync_conflicts.len() - 1;
            }
            app.refresh_secrets();
            if app.sync_conflicts.is_empty() {
                app.trigger_postconflict_sync();
                app.screen = Screen::Dashboard;
            }
        }
        KeyCode::Char('r') | KeyCode::Right => {
            let resolved = app.sync_conflicts.remove(app.selected_conflict_idx);
            // Stamp with "now", not remote's original updated_at -- see the
            // comment in the 'l' branch above for why.
            if let Ok(now) = crate::db::now_timestamp(&app.conn) {
                let _ = crate::db::update_secret_raw(
                    &app.conn,
                    resolved.local_secret.id,
                    &resolved.remote_secret.url,
                    &resolved.remote_secret.encrypted_password,
                    resolved.remote_secret.encrypted_notes.as_deref(),
                    &now,
                );
            }
            if app.selected_conflict_idx >= app.sync_conflicts.len() && !app.sync_conflicts.is_empty() {
                app.selected_conflict_idx = app.sync_conflicts.len() - 1;
            }
            app.refresh_secrets();
            if app.sync_conflicts.is_empty() {
                app.trigger_postconflict_sync();
                app.screen = Screen::Dashboard;
            }
        }
        KeyCode::Char('m') => {
            let resolved = app.sync_conflicts.remove(app.selected_conflict_idx);
            if let Some(key) = &app.key {
                let local_notes: Zeroizing<String> = crate::crypto::decrypt(&resolved.local_secret.encrypted_notes.clone().unwrap_or_default(), key)
                    .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                    .unwrap_or_default();
                let remote_notes: Zeroizing<String> = crate::crypto::decrypt(&resolved.remote_secret.encrypted_notes.clone().unwrap_or_default(), key)
                    .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
                    .unwrap_or_default();

                let merged: Zeroizing<String> = if local_notes.is_empty() {
                    remote_notes
                } else if remote_notes.is_empty() {
                    local_notes
                } else {
                    Zeroizing::new(format!("{}\n---\n{}", *local_notes, *remote_notes))
                };

                let enc_notes = if merged.is_empty() {
                    None
                } else {
                    crate::crypto::encrypt(merged.as_bytes(), key).ok()
                };

                // Stamp with "now", not remote's original updated_at -- see the
                // comment in the 'l' branch above for why.
                if let Ok(now) = crate::db::now_timestamp(&app.conn) {
                    let _ = crate::db::update_secret_raw(
                        &app.conn,
                        resolved.local_secret.id,
                        &resolved.local_secret.url,
                        &resolved.local_secret.encrypted_password,
                        enc_notes.as_deref(),
                        &now,
                    );
                }
            }
            if app.selected_conflict_idx >= app.sync_conflicts.len() && !app.sync_conflicts.is_empty() {
                app.selected_conflict_idx = app.sync_conflicts.len() - 1;
            }
            app.refresh_secrets();
            if app.sync_conflicts.is_empty() {
                app.trigger_postconflict_sync();
                app.screen = Screen::Dashboard;
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            app.sync_conflicts.clear();
            // Discarding here (rather than resolving each conflict) means
            // trigger_postunlock_sync returned early without merging or
            // pushing -- sync is silently stalled until the next unlock or
            // exit unless the user is told.
            app.copied_message = Some((
                "Sync postponed -- unresolved conflicts remain".to_string(),
                Instant::now(),
                StatusType::Normal,
            ));
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
}

fn draw_sync_conflict_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.size();
    f.render_widget(Clear, size);

    let main_block = Block::default()
        .borders(Borders::ALL)
        .title(" Sync Conflict Resolver (3-way Merge) ")
        .border_style(Style::default().fg(Color::LightRed));
    f.render_widget(main_block, size);

    let inner_area = size.inner(&ratatui::layout::Margin { horizontal: 1, vertical: 1 });

    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(70),
        ])
        .split(inner_area);

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title(" Conflicting Credentials ");
    let mut list_items = Vec::new();
    for (i, c) in app.sync_conflicts.iter().enumerate() {
        let style = if i == app.selected_conflict_idx {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(Color::White)
        };
        list_items.push(ListItem::new(format!("  {} > {} ({})", c.category, c.title, c.username)).style(style));
    }
    let list = List::new(list_items).block(left_block);
    f.render_widget(list, main_layout[0]);

    if app.sync_conflicts.is_empty() {
        let empty_block = Block::default().borders(Borders::ALL).title(" Resolution details ");
        f.render_widget(Paragraph::new("No conflicts remaining.").block(empty_block), main_layout[1]);
        return;
    }

    let current_conflict = &app.sync_conflicts[app.selected_conflict_idx];

    let right_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(main_layout[1]);

    let key = app.key.as_ref().unwrap();

    let local_pw: Zeroizing<String> = crate::crypto::decrypt(&current_conflict.local_secret.encrypted_password, key)
        .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
        .unwrap_or_default();
    let local_notes: Zeroizing<String> = crate::crypto::decrypt(&current_conflict.local_secret.encrypted_notes.clone().unwrap_or_default(), key)
        .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
        .unwrap_or_default();

    let remote_pw: Zeroizing<String> = crate::crypto::decrypt(&current_conflict.remote_secret.encrypted_password, key)
        .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
        .unwrap_or_default();
    let remote_notes: Zeroizing<String> = crate::crypto::decrypt(&current_conflict.remote_secret.encrypted_notes.clone().unwrap_or_default(), key)
        .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
        .unwrap_or_default();

    let mut base_pw: Zeroizing<String> = Zeroizing::new(String::new());
    let mut base_notes: Zeroizing<String> = Zeroizing::new(String::new());
    let mut base_url = String::new();
    if let Some(base_sec) = &current_conflict.base_secret {
        base_pw = crate::crypto::decrypt(&base_sec.encrypted_password, key)
            .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
            .unwrap_or_default();
        base_notes = crate::crypto::decrypt(&base_sec.encrypted_notes.clone().unwrap_or_default(), key)
            .map(|d| Zeroizing::new(String::from_utf8_lossy(&d).into_owned()))
            .unwrap_or_default();
        base_url = base_sec.url.clone();
    }

    let local_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" [L] Local Version (Updated: {}) ", current_conflict.local_secret.updated_at))
        .border_style(Style::default().fg(Color::Cyan));

    let local_text = vec![
        Line::from(vec![
            Span::styled("  URL:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(&current_conflict.local_secret.url, if current_conflict.local_secret.url != base_url { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
        Line::from(vec![
            Span::styled("  Password: ", Style::default().fg(Color::DarkGray)),
            Span::styled(local_pw.as_str(), if local_pw != base_pw { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
        Line::from(vec![
            Span::styled("  Notes:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(local_notes.as_str(), if local_notes != base_notes { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
    ];
    let local_p = Paragraph::new(local_text).block(local_block);
    f.render_widget(local_p, right_layout[0]);

    let remote_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" [R] Remote Version (Updated: {}) ", current_conflict.remote_secret.updated_at))
        .border_style(Style::default().fg(Color::Green));

    let remote_text = vec![
        Line::from(vec![
            Span::styled("  URL:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(&current_conflict.remote_secret.url, if current_conflict.remote_secret.url != base_url { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
        Line::from(vec![
            Span::styled("  Password: ", Style::default().fg(Color::DarkGray)),
            Span::styled(remote_pw.as_str(), if remote_pw != base_pw { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
        Line::from(vec![
            Span::styled("  Notes:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(remote_notes.as_str(), if remote_notes != base_notes { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::White) }),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [l / Left] Keep Local  |  ", Style::default().fg(Color::Cyan)),
            Span::styled(" [r / Right] Keep Remote  |  ", Style::default().fg(Color::Green)),
            Span::styled(" [m] Merge Notes  |  ", Style::default().fg(Color::Yellow)),
            Span::styled(" [Esc/q] Cancel", Style::default().fg(Color::White)),
        ]),
    ];
    let remote_p = Paragraph::new(remote_text).block(remote_block);
    f.render_widget(remote_p, right_layout[1]);
}




