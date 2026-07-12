use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use zeroize::{Zeroize, Zeroizing};
use std::{
    time::{Duration, Instant},
    sync::Arc,
    sync::atomic::Ordering,
};
use crate::db;
use crate::tui::{TuiApp, Screen, ActiveBlock, ConfirmAction, StatusType, FormField, PendingDerive};
use crate::forms::*;
use crate::modals::*;

pub(crate) fn handle_lock_input(app: &mut TuiApp, code: KeyCode) -> bool {
    match code {
        KeyCode::Char(c) => app.password_input.push(c),
        KeyCode::Backspace => {
            app.password_input.pop();
        }
        KeyCode::Enter => {
            // The actual unlock is an Argon2id derivation (deliberately
            // slow) -- defer it one frame so the "Deriving key..." notice
            // is on screen while the terminal blocks. See PendingDerive.
            app.error_message.clear();
            app.pending_derive = Some(PendingDerive::Unlock);
        }
        KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

/// The deferred half of the Lock screen's Enter -- runs from run_loop, one
/// frame after PendingDerive::Unlock was set.
pub(crate) fn perform_unlock(app: &mut TuiApp) {
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
            // Prune expired tombstones on unlock, not only during
            // git sync: an offline-only user (no git configured)
            // otherwise keeps deleted credentials' titles/usernames
            // in the vault forever -- the exact privacy issue
            // pruning exists to fix. Best-effort, like sync's call.
            let _ = db::prune_old_tombstones(&app.conn);
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


pub(crate) fn handle_setup_input(app: &mut TuiApp, code: KeyCode) -> bool {
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
            // Cheap validation done; the Argon2id derivation inside
            // create_vault is deferred a frame -- see PendingDerive.
            app.error_message.clear();
            app.pending_derive = Some(PendingDerive::Setup);
        }
        KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

/// The deferred half of the Setup screen's Enter -- runs from run_loop, one
/// frame after PendingDerive::Setup was set.
pub(crate) fn perform_setup(app: &mut TuiApp) {
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
    let completed_clone = Arc::clone(&app.hibp_scan_completed);

    std::thread::spawn(move || {
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key_clone);
        if let Ok(conn) = crate::db::open_keyed_connection(crate::get_db_path(), &sqlcipher_key) {
            let cached_checks = crate::db::get_all_hibp_checks(&conn).unwrap_or_default();
            for (i, record) in records.iter().enumerate() {
                if abort_clone.load(Ordering::SeqCst) {
                    break;
                }

                let mut checked_online = false;
                if let Ok(dec) = crate::crypto::decrypt(&record.encrypted_password, &key_clone)
                    && let Ok(mut pw) = String::from_utf8(dec.to_vec()) {
                        let hash_hex = crate::crypto::hibp_cache_fingerprint(pw.as_bytes(), &key_clone);

                        if let Ok(checked_lock) = checked_hashes_clone.lock()
                            && checked_lock.contains(&hash_hex) {
                                pw.zeroize();
                                if let Ok(mut progress_lock) = progress_clone.lock()
                                    && let Some(p) = &mut *progress_lock {
                                        p.0 = i + 1;
                                    }
                                continue;
                            }

                        if let Some(Some(count)) = cached_checks.get(&hash_hex)
                            && *count > 0 {
                                pw.zeroize();
                                if let Ok(mut progress_lock) = progress_clone.lock()
                                    && let Some(p) = &mut *progress_lock {
                                        p.0 = i + 1;
                                    }
                                continue;
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

                if let Ok(mut progress_lock) = progress_clone.lock()
                    && let Some(p) = &mut *progress_lock {
                        p.0 = i + 1;
                    }

                if checked_online && total_checks > 1 && i + 1 < total_checks {
                    std::thread::sleep(Duration::from_millis(700));
                }
            }
        }
        *progress_clone.lock().unwrap() = None;
        completed_clone.store(true, Ordering::SeqCst);
    });
}


pub(crate) fn handle_dashboard_input(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) -> bool {
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
        // Plain `q` quits too, matching the help screen's documented
        // "[q] / [Esc] Quit KeyStash" -- it used to do nothing on the
        // dashboard, only Ctrl+q and Esc actually worked.
        KeyCode::Char('q') => return true,
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
            app.refresh_form_audit_cache();
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
                    if let Some(enc_notes) = &record.encrypted_notes
                        && let Ok(dec_notes) = crate::crypto::decrypt(enc_notes, key) {
                            app.form_notes = String::from_utf8_lossy(&dec_notes).to_string();
                        }
                }
                app.refresh_form_audit_cache();
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
            app.settings_history_retention = app.config.history_retention.to_string();
            app.active_settings_field = 0;
            app.settings_field_touched = false;
            app.screen = Screen::Settings;
        }
        KeyCode::Char('s') => {
            // The manual sync gets the same detect-then-merge treatment as
            // the post-unlock sync (it used to run a blind last-write-wins
            // merge -- the one sync the user explicitly asked for had
            // weaker protection than the automatic one). Deliberately only
            // gated on --no-sync, not on the Auto Sync setting: pressing
            // the key IS the request.
            if app.no_sync {
                app.copied_message = Some(("Sync is disabled (--no-sync).".to_string(), Instant::now(), StatusType::Normal));
            } else if !crate::sync::is_git_configured(crate::get_db_path()) {
                app.copied_message = Some(("Sync not configured -- no git remote set up in ~/.config/keystash.".to_string(), Instant::now(), StatusType::Normal));
            } else {
                app.spawn_detect_then_sync();
                app.copied_message = Some(("Syncing with git remote...".to_string(), Instant::now(), StatusType::Normal));
            }
        }

        KeyCode::Char('D') => {
            app.find_duplicate_groups();
            if app.duplicate_groups.is_empty() {
                app.error_message = "No duplicates found based on matching username and title/URL!".to_string();
                app.screen = Screen::ErrorDialog;
            } else {
                app.screen = Screen::Deduplicate;
            }
        }

        KeyCode::Char('u') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.copy_to_clipboard(Zeroizing::new(record.url.clone()), "URL");
            }
        }
        KeyCode::Char('p') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx)
                && let Some(key) = &app.key
                    && let Ok(dec) = crate::crypto::decrypt(&record.encrypted_password, key)
                        && let Ok(plaintext) = String::from_utf8(dec.to_vec()) {
                            app.copy_to_clipboard(Zeroizing::new(plaintext), "password");
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
            // Marks are a separate, persistent selection (used by mass
            // delete etc.) -- checking HIBP status shouldn't silently
            // consume them as a side effect. Only Space or a completed
            // mass action should ever clear a mark.
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
            ActiveBlock::Secrets
                if app.selected_secret_idx > 0 => {
                    app.selected_secret_idx -= 1;
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
            ActiveBlock::Secrets
                if app.selected_secret_idx + 1 < app.filtered_secrets.len() => {
                    app.selected_secret_idx += 1;
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


pub(crate) fn draw_ui(f: &mut ratatui::Frame, app: &TuiApp) {
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
        Screen::Deduplicate => draw_deduplicate_screen(f, app),
        Screen::Settings => draw_settings_screen(f, app),
        Screen::SyncConflict => draw_sync_conflict_screen(f, app),
    }

    if let Ok(progress_lock) = app.hibp_progress.lock()
        && let Some((checked, total)) = *progress_lock {
            draw_hibp_progress_dialog(f, checked, total);
        }
}


fn draw_lock_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.area();
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

    let mut title_text = if app.needs_migration {
        "KeyStash Password Vault (legacy vault -- will migrate to encrypted format)".to_string()
    } else {
        "KeyStash Password Vault".to_string()
    };
    // Which vault is this? With profiles, "the vault" is ambiguous --
    // showing the active one on the lock screen prevents typing the work
    // password at the personal vault and vice versa.
    if let Some(profile) = crate::active_profile() {
        title_text.push_str(&format!("  [profile: {}]", profile));
    }
    let title = Paragraph::new(title_text)
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    let masked: String = "*".repeat(app.password_input.len());
    let pass_box = Paragraph::new(masked)
        .block(Block::default().borders(Borders::ALL).title("Enter Master Password"))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(pass_box, chunks[1]);

    if app.pending_derive.is_some() {
        // Rendered on the one frame before the blocking Argon2id derivation
        // runs -- without it, the frozen terminal reads as a hang.
        let busy = Paragraph::new("Deriving key (Argon2id), please wait...")
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(busy, chunks[2]);
    } else if !app.error_message.is_empty() {
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
    let size = f.area();
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


pub(crate) fn handle_interrupted_migration_input(code: KeyCode) -> bool {
    matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter)
}

/// Same reasoning as `draw_interrupted_migration_screen`, for an interrupted
/// `change_master_password` run instead.
fn draw_interrupted_rotation_screen(f: &mut ratatui::Frame) {
    let size = f.area();
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
    let size = f.area();
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

    if app.pending_derive.is_some() {
        let busy = Paragraph::new("Deriving key (Argon2id) and creating the vault, please wait...")
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(busy, chunks[3]);
    } else if !app.error_message.is_empty() {
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
    let size = f.area();
    
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
        .block(Block::default().borders(Borders::ALL).title("Tags").border_style(
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

        // Notes hide behind the same [v] toggle as the password: they're
        // the other field-layer-encrypted value, and recovery codes live
        // there -- rendering them unmasked by default undid for notes the
        // shoulder-surfing protection the password mask provides. Masked
        // notes aren't even decrypted, so the plaintext never exists.
        let notes_str = if let Some(enc_notes) = &record.encrypted_notes {
            if !app.reveal_password {
                Zeroizing::new("•••••••• (press [v] to reveal)".to_string())
            } else if let Some(key) = &app.key {
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
                Span::styled("Tags:     ", Style::default().fg(Color::DarkGray)),
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

        if let Some(report) = &app.audit_report
            && let Some(entry) = report.entries.iter().find(|e| e.id == record.id) {
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

pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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


