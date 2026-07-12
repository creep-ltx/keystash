use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    widgets::ListState,
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
use crate::forms::*;
use crate::modals::*;
use crate::render::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveBlock {
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

pub(crate) enum Screen {
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
    Deduplicate,
    Settings,
    SyncConflict,
}


#[derive(Clone, Copy, PartialEq, Eq, Debug)]

pub enum StatusType {
    Normal,
    Copied,
    Cleared,
}

#[derive(Clone, Copy, PartialEq, Eq)]

pub(crate) enum FormField {
    Title,
    Category,
    Username,
    Url,
    Password,
    Notes,
}


pub struct TuiApp {
    pub(crate) conn: Connection,
    pub(crate) key: Option<Zeroizing<[u8; 32]>>,
    pub(crate) screen: Screen,

    // Auth State
    pub(crate) password_input: String,
    pub(crate) password_confirm_input: String,
    pub(crate) error_message: String,

    // Dashboard State
    pub(crate) secrets: Vec<SecretRecord>,
    pub(crate) filtered_secrets: Vec<SecretRecord>,
    pub(crate) categories: Vec<String>,
    pub(crate) selected_category_idx: usize,
    pub(crate) selected_secret_idx: usize,
    pub(crate) active_block: ActiveBlock,
    pub(crate) search_query: String,
    pub(crate) searching: bool,
    pub(crate) reveal_password: bool,
    pub(crate) copied_message: Option<(String, Instant, StatusType)>,

    // Form State
    pub(crate) active_form_field: FormField,
    pub(crate) form_title: String,
    pub(crate) form_category: String,
    pub(crate) form_username: String,
    pub(crate) form_url: String,
    pub(crate) form_password: String,
    pub(crate) form_notes: String,
    pub(crate) edit_id: Option<i64>,

    // Deletion / Confirmation state
    pub marked_secrets: HashSet<i64>,
    pub(crate) confirmation_message: String,

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

    // Add/Edit form audit cache: computed once when the form opens (see
    // refresh_form_audit_cache), not re-decrypted from every secret in the
    // vault on every single render frame. form_reuse_fingerprints maps each
    // *other* secret's password fingerprint to how many entries share it;
    // form_hibp_cache is a snapshot of the local HIBP cache table, looked up
    // by the same fingerprint. Both keyed on crypto::hibp_cache_fingerprint,
    // so checking the live form_password against either is just a cheap
    // single-hash-plus-hashmap-lookup per frame instead of a full-vault
    // decrypt or a database round trip. Trade-off, accepted deliberately: if
    // a background sync lands new/changed secrets while the form is still
    // open, these snapshots go stale until the form is reopened -- narrow
    // window, and reuse/HIBP warnings are advisory, not something save
    // blocks on.
    pub(crate) form_reuse_fingerprints: std::collections::HashMap<String, usize>,
    pub(crate) form_hibp_cache: std::collections::HashMap<String, Option<u64>>,

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
    pub settings_history_retention: String,
    pub active_settings_field: usize,
    /// True once the current numeric field (Idle Timeout, Clipboard Delay,
    /// Gen Length) has actually been edited since navigating to it. False
    /// means "fresh" -- the next digit or Backspace clears the field first
    /// instead of appending to/trimming whatever was already there, the
    /// same "select all on focus" behavior most form fields have. Without
    /// this, typing a replacement value without first manually backspacing
    /// away the old one silently concatenates them (e.g. an old "10" plus a
    /// typed "5" "2" becomes "1052", accepted with no warning since it's
    /// still a valid number).
    pub settings_field_touched: bool,

    // HIBP background worker
    pub hibp_progress: Arc<Mutex<Option<(usize, usize)>>>,
    pub hibp_abort: Arc<AtomicBool>,
    pub checked_hashes_this_session: Arc<Mutex<HashSet<String>>>,
    /// Set by spawn_hibp_scan's worker thread right before it clears
    /// hibp_progress; run_loop polls it once per tick and, if set, clears it
    /// and calls refresh_secrets() -- otherwise the detail pane kept showing
    /// stale "Not checked"/breach status until some unrelated action (add,
    /// edit, delete, unlock) happened to call refresh_secrets anyway.
    pub hibp_scan_completed: Arc<AtomicBool>,

    // Sync conflict state
    pub sync_conflicts: Vec<crate::sync::ConflictGroup>,
    pub selected_conflict_idx: usize,
    pub sync_conflicts_detected: Arc<Mutex<Option<Vec<crate::sync::ConflictGroup>>>>,

    /// True when this session has modified the vault (add/edit/delete,
    /// import, dedup, conflict resolution, rotation) since the last sync
    /// was *started*. `run_tui`'s exit-time sync is skipped when false: its
    /// only job is pushing local edits -- pulling remote changes is the
    /// next unlock's job -- so a session that changed nothing has nothing
    /// to push and shouldn't cost a fetch+push on quit. Set back to true
    /// when a sync reports failure (retry at exit) or when detected
    /// conflicts are postponed (the old exit-time LWW push remains their
    /// fallback). Cleared when a sync thread is actually spawned, not on
    /// completion: an edit landing while a sync is in flight re-sets it
    /// afterward on this same thread, so the worst case is one redundant
    /// exit sync, never a skipped push.
    pub vault_modified_since_sync: bool,

    /// Outcome of the most recent background sync (post-unlock, post-import,
    /// post-conflict, or the manual [s] key), written by the worker thread
    /// and consumed by run_loop. Without this, background sync results --
    /// including the rotation-refusal message, whose entire value is its
    /// step-by-step recovery instructions -- were silently discarded
    /// (`let _ = git_sync_vault(...)`): a stale device's user could unlock,
    /// have sync refuse, and keep working for a whole session believing
    /// they were synced. Same mailbox shape as sync_conflicts_detected.
    /// Only consumed while on the Dashboard, so a failure dialog can't
    /// hijack the screen out from under a half-typed form.
    pub sync_result: Arc<Mutex<Option<Result<String, String>>>>,

    // Whether the vault at db_path predates SQLCipher and needs one-time migration
    // on next successful password entry (see `handle_lock_input`).
    pub(crate) needs_migration: bool,

    // Handle to whatever background sync thread is currently in flight (from
    // `trigger_postunlock_sync`), if any. `run_tui`'s exit-time sync joins this
    // before running its own git_sync_vault call, so the two can never run
    // concurrently against the same working directory / SQLite file -- letting
    // them race is what caused a real vault to revert to its pre-migration,
    // unencrypted format with no error ever being shown.
    pub(crate) pending_sync_thread: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
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
            form_reuse_fingerprints: std::collections::HashMap::new(),
            form_hibp_cache: std::collections::HashMap::new(),
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
            settings_history_retention: String::new(),
            active_settings_field: 0,
            settings_field_touched: false,
            hibp_progress: Arc::new(Mutex::new(None)),
            hibp_abort: Arc::new(AtomicBool::new(false)),
            checked_hashes_this_session: Arc::new(Mutex::new(HashSet::new())),
            hibp_scan_completed: Arc::new(AtomicBool::new(false)),
            sync_conflicts: Vec::new(),
            selected_conflict_idx: 0,
            vault_modified_since_sync: false,
            sync_conflicts_detected: Arc::new(Mutex::new(None)),
            sync_result: Arc::new(Mutex::new(None)),
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


    pub(crate) fn refresh_secrets(&mut self) {

        if let Some(key) = self.key.clone()
            && let Ok(records) = db::get_secrets(&self.conn) {
                self.secrets = records;
                
                // Build the sidebar tag list: each record's stored tags
                // string is split into individual tags, so a record tagged
                // "work, email" appears under both.
                let mut cats = std::collections::HashSet::new();
                for r in &self.secrets {
                    for tag in db::parse_tags(&r.category) {
                        cats.insert(tag);
                    }
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

    /// Populates form_reuse_fingerprints and form_hibp_cache once, when the
    /// Add/Edit form opens -- see those fields' own doc comment for why.
    /// Must be called after self.edit_id is set (it excludes that record's
    /// own password from the reuse count, same exclusion draw_form's old
    /// per-frame loop already applied).
    pub(crate) fn refresh_form_audit_cache(&mut self) {
        self.form_reuse_fingerprints.clear();
        self.form_hibp_cache = db::get_all_hibp_checks(&self.conn).unwrap_or_default();

        let Some(key) = self.key.clone() else { return };
        for r in &self.secrets {
            if Some(r.id) == self.edit_id {
                continue;
            }
            if let Ok(dec) = crate::crypto::decrypt(&r.encrypted_password, &key)
                && let Ok(mut pw) = String::from_utf8(dec.to_vec()) {
                    let fp = crate::crypto::hibp_cache_fingerprint(pw.as_bytes(), &key);
                    pw.zeroize();
                    *self.form_reuse_fingerprints.entry(fp).or_insert(0) += 1;
                }
        }
    }

    pub(crate) fn fuzzy_score(target: &str, query: &str) -> Option<isize> {
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
            if let Some(&qc) = query_chars.peek()
                && c == qc {
                    query_chars.next();
                    match_indices.push(i);
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

    pub(crate) fn apply_filter(&mut self) {
        let current_cat = self.categories.get(self.selected_category_idx).cloned().unwrap_or("All".to_string());
        let query = self.search_query.to_lowercase();

        if query.is_empty() {
            self.filtered_secrets = self.secrets
                .iter()
                .filter(|r| current_cat == "All" || db::record_has_tag(&r.category, &current_cat))
                .cloned()
                .collect();
        } else {
            let mut scored_secrets = Vec::new();
            for r in &self.secrets {
                if current_cat != "All" && !db::record_has_tag(&r.category, &current_cat) {
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

            scored_secrets.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
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
    pub(crate) fn copy_to_clipboard(&mut self, text: Zeroizing<String>, label: &str) {
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

    pub(crate) fn clear_clipboard_if_expired(&mut self) {
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
    pub(crate) fn trigger_prelock_fetch(&self) {
        // config.auto_sync gates every *automatic* sync action (this fetch,
        // the post-unlock/post-import sync, and the exit-time sync) but not
        // the manual [s] key or `keystash sync` -- that's the distinction
        // from --no-sync, which disables everything. The setting existed in
        // the Settings screen before this check did; it was saved and
        // displayed but read by nothing, so toggling it changed no behavior
        // at all.
        if self.no_sync || !self.config.auto_sync {
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
    /// Automatic trigger -- gated on Auto Sync (see trigger_prelock_fetch);
    /// the manual [s] key calls spawn_detect_then_sync directly instead, so
    /// an explicit user request works even with Auto Sync switched off.
    pub(crate) fn trigger_postunlock_sync(&mut self) {
        if self.no_sync || !self.config.auto_sync {
            return;
        }
        self.spawn_detect_then_sync();
    }

    /// The actual work shared by the post-unlock/post-import trigger and the
    /// manual [s] key: detect conflicts against a freshly fetched
    /// origin/main (detect_sync_conflicts fetches for itself) and surface
    /// them in the resolver screen -- otherwise run the full logical
    /// merge + push. Callers gate this, not the function: the automatic
    /// trigger on Auto Sync, the manual key only on --no-sync.
    pub(crate) fn spawn_detect_then_sync(&mut self) {
        if self.no_sync {
            return;
        }
        // A sync is being spawned for the current state -- see the field's
        // doc for why this clears on spawn rather than on completion.
        self.vault_modified_since_sync = false;
        let key = match &self.key {
            Some(k) => k.clone(),
            None => return,
        };
        let db_path = crate::get_db_path();
        let retention = self.config.history_retention;
        let detected_clone = Arc::clone(&self.sync_conflicts_detected);
        let result_clone = Arc::clone(&self.sync_result);
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
            if let Ok(conflicts) = crate::sync::detect_sync_conflicts(&db_path, &key)
                && !conflicts.is_empty() {
                    // The conflict screen is the outcome here; no
                    // separate status message needed.
                    *detected_clone.lock().unwrap() = Some(conflicts);
                    return;
                }
            let result = crate::sync::git_sync_vault_with_retention(&db_path, &key, retention);
            if let Ok(mut slot) = result_clone.lock() {
                *slot = Some(result);
            }
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
    ///
    /// Deliberately does NOT go through spawn_detect_then_sync: re-running
    /// conflict detection immediately after a resolution would re-flag the
    /// records the user just resolved (their local copy and the remote both
    /// still differ from the merge base until this push lands), trapping
    /// them in a resolve-detect-resolve loop.
    pub(crate) fn trigger_postconflict_sync(&mut self) {
        if self.no_sync {
            return;
        }
        self.vault_modified_since_sync = false;
        let key = match &self.key {
            Some(k) => k.clone(),
            None => return,
        };
        let db_path = crate::get_db_path();
        let retention = self.config.history_retention;
        let result_clone = Arc::clone(&self.sync_result);
        // See trigger_postunlock_sync: join the previous handle inside the
        // new thread, before it touches any files, rather than after spawning.
        let previous = self.pending_sync_thread.lock().ok().and_then(|mut s| s.take());
        let handle = std::thread::spawn(move || {
            if let Some(prev) = previous {
                let _ = prev.join();
            }
            let result = crate::sync::git_sync_vault_with_retention(&db_path, &key, retention);
            if let Ok(mut slot) = result_clone.lock() {
                *slot = Some(result);
            }
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
    if let Ok(mut slot) = app.pending_sync_thread.lock()
        && let Some(handle) = slot.take() {
            let _ = handle.join();
        }

    // Auto-sync updates on exit if Git is configured and sync is not disabled.
    // Only possible if the vault was actually unlocked at some point during this
    // session -- git_sync_vault needs the key to open/attach the now
    // SQLCipher-encrypted database, and there's nothing to merge otherwise.
    // Gated on Auto Sync like every automatic trigger (a manual [s] sync
    // that's still in flight was already joined above regardless), and on
    // the session having actually modified the vault: the exit sync's only
    // job is pushing local edits (pulling is the next unlock's job), so a
    // look-only session skips the exit fetch+push entirely.
    //
    // Deliberately plain last-write-wins git_sync_vault, not the
    // detect-then-resolve path every in-session sync now uses: the terminal
    // is already restored and the app is exiting -- there's no UI left to
    // resolve conflicts in. Conflicts that were detected and postponed
    // during the session re-armed vault_modified_since_sync, so this LWW
    // push is their documented fallback.
    if !app.no_sync && app.config.auto_sync && app.vault_modified_since_sync
        && let Some(key) = app.key.clone() {
            let db_path = crate::get_db_path();
            if crate::sync::is_git_configured(&db_path) {
                println!("Syncing vault updates on exit...");
                match crate::sync::git_sync_vault_with_retention(&db_path, &key, app.config.history_retention) {
                    Ok(msg) => println!("{}", msg),
                    Err(err) => eprintln!("Sync Warning: {}", err),
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
        if let Ok(mut detected_lock) = app.sync_conflicts_detected.lock()
            && let Some(conflicts) = detected_lock.take() {
                app.sync_conflicts = conflicts;
                app.selected_conflict_idx = 0;
                app.screen = Screen::SyncConflict;
            }
        // Ordered after the take() above so the borrow on the mutex guard has
        // ended. The sync that detected conflicts returned without pushing:
        // if the user resolves them, the post-conflict sync takes over, but
        // if they postpone (Esc), this keeps the exit-time sync as the
        // fallback push instead of it being skipped as "nothing modified".
        if !app.sync_conflicts.is_empty() {
            app.vault_modified_since_sync = true;
        }

        // Surface the outcome of a finished background sync. Consumed only
        // on the Dashboard: an error dialog popping over a half-typed form
        // (or the Lock screen, whose dismissal path leads to the Dashboard)
        // would be worse than the message waiting a few ticks -- the slot
        // holds it until the user is back somewhere it can safely show.
        if app.screen == Screen::Dashboard {
            let finished_sync = app.sync_result.lock().ok().and_then(|mut slot| slot.take());
            match finished_sync {
                Some(Ok(msg)) => {
                    app.copied_message = Some((msg, Instant::now(), StatusType::Normal));
                    // A successful sync may have merged remote changes into
                    // the vault this session is currently showing.
                    app.refresh_secrets();
                }
                Some(Err(err)) => {
                    // The error dialog, not the one-line status bar: sync
                    // failures include the multi-line rotation refusal whose
                    // recovery steps must actually be readable.
                    app.error_message = format!("Sync failed: {}", err);
                    app.screen = Screen::ErrorDialog;
                    // The spawn optimistically cleared the modified flag;
                    // the sync didn't land, so the exit sync must retry.
                    app.vault_modified_since_sync = true;
                }
                None => {}
            }
        }

        if app.hibp_scan_completed.swap(false, Ordering::SeqCst) {
            app.refresh_secrets();
        }

        app.clear_clipboard_if_expired();
        
        // Check for idle timeout auto-lock
        if app.key.is_some() && app.screen != Screen::Lock && app.screen != Screen::Setup
            && app.last_activity.elapsed() >= Duration::from_secs(app.config.idle_timeout_seconds) {
                app.lock_vault();
            }
        
        terminal.draw(|f| draw_ui(f, app))?;

        // Poll for inputs, checking clipboard expiration and idle timeout every 250ms
        if event::poll(Duration::from_millis(250))? {
            let ev = event::read()?;
            app.reset_activity();
            if let Event::Key(key) = ev
                && key.kind == event::KeyEventKind::Press {
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
                        Screen::Deduplicate => handle_deduplicate_input(app, key.code),
                        Screen::Settings => handle_settings_input(app, key.code),
                        Screen::SyncConflict => handle_sync_conflict_input(app, key.code),
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


