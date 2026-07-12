use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use zeroize::{Zeroize, Zeroizing};
use crate::db;
use crate::tui::{TuiApp, Screen, FormField};
use crate::render::*;


#[cfg(test)]
mod form_integration_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Serializes the tests in this module: they steer `get_db_path` via the
    /// KEYSTASH_CONFIG_DIR env var, and env vars are process-wide state --
    /// two tests setting it to different directories concurrently would race
    /// (the exact reason these tests used to be #[ignore]d back when they
    /// overrode HOME, which additionally raced every *other* test). Nothing
    /// outside this module reads the variable, so serializing just these
    /// against each other is sufficient to run them in the default parallel
    /// suite. `unwrap_or_else(into_inner)` keeps a panicked (poisoned) test
    /// from cascading into the other one failing on the lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Points KEYSTASH_CONFIG_DIR at a fresh per-test directory (removing it
    /// again on drop, so no other test can accidentally inherit it) and
    /// returns the guard keeping other tests in this module out.
    struct ConfigDirGuard {
        dir: std::path::PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    fn isolated_config_dir(name: &str) -> ConfigDirGuard {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("keystash_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY (edition 2024): set_var is process-global; ENV_LOCK above
        // guarantees no concurrent reader/writer of this variable exists
        // while the guard is alive.
        unsafe { std::env::set_var("KEYSTASH_CONFIG_DIR", &dir); }
        ConfigDirGuard { dir, _lock: lock }
    }

    impl Drop for ConfigDirGuard {
        fn drop(&mut self) {
            unsafe { std::env::remove_var("KEYSTASH_CONFIG_DIR"); }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn render_text(app: &TuiApp) -> String {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_form(f, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn form_reuse_and_strength_reflect_the_cache_not_live_decrypt() {
        let guard = isolated_config_dir("form_test");

        let db_path = crate::get_db_path();
        let (conn, key) = db::create_vault(&db_path, "master-pw").unwrap();
        db::add_secret(&conn, "One", "Cat", "u1", "", "hunter2", None, &key).unwrap();
        db::add_secret(&conn, "Two", "Cat", "u2", "", "hunter2", None, &key).unwrap();
        db::add_secret(&conn, "Three", "Cat", "u3", "", "SoloPassword1!", None, &key).unwrap();
        drop(conn);

        let mut app = TuiApp::new(true);
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        app.conn = db::open_keyed_connection(&db_path, &sqlcipher_key).unwrap();
        app.key = Some(key);
        app.refresh_secrets();

        // Open the Add form exactly like pressing 'a' does, then type the
        // password two existing entries already share.
        handle_dashboard_input(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        app.active_form_field = FormField::Password;
        for c in "hunter2".chars() {
            handle_form_input(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }

        let rendered = render_text(&app);
        println!("{rendered}");
        assert!(
            rendered.contains("Reused in 2 other entry(ies)"),
            "expected reuse warning against the two pre-existing 'hunter2' entries (via the cache computed on form-open), got:\n{rendered}"
        );

        // Switch to a password no seeded entry uses at all -- the warning
        // must disappear (and the strength bar must reflect *that* password).
        app.form_password.clear();
        for c in "NeverUsedElsewhere99$".chars() {
            handle_form_input(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }
        let rendered2 = render_text(&app);
        assert!(
            !rendered2.contains("Reused in"),
            "a password used by no other entry must not show a reuse warning, got:\n{rendered2}"
        );

        drop(guard);
    }

    #[test]
    fn settings_numeric_field_replaces_stale_value_on_first_keystroke() {
        let guard = isolated_config_dir("settings_test");

        let mut app = TuiApp::new(true);

        // Simulate opening Settings on a field that already holds a stale
        // value (e.g. "10" from a previous config), same as the ',' handler
        // populates it from app.config.
        app.settings_clipboard_clear = "10".to_string();
        app.active_settings_field = 1;
        app.settings_field_touched = false;

        // Typing "5" without backspacing first must *replace* the stale
        // "10", not concatenate into "105" -- this is the exact bug that
        // let "10" plus a typed "5" "2" silently become "1052", accepted
        // with no warning since it's still a valid number.
        handle_settings_input(&mut app, KeyCode::Char('5'));
        assert_eq!(app.settings_clipboard_clear, "5", "first digit after navigating to a field must replace its stale value");

        handle_settings_input(&mut app, KeyCode::Char('2'));
        assert_eq!(app.settings_clipboard_clear, "52", "subsequent digits in the same edit must append normally");

        // Navigating away and back marks the field fresh again.
        handle_settings_input(&mut app, KeyCode::Tab);
        handle_settings_input(&mut app, KeyCode::BackTab);
        assert!(!app.settings_field_touched);
        handle_settings_input(&mut app, KeyCode::Char('9'));
        assert_eq!(app.settings_clipboard_clear, "9", "re-navigating to an already-edited field must still replace on the next keystroke");

        // Backspace on a fresh field clears it outright (the old value is
        // effectively "selected"), rather than trimming one digit off a
        // value the user hasn't started editing.
        app.settings_clipboard_clear = "300".to_string();
        app.settings_field_touched = false;
        handle_settings_input(&mut app, KeyCode::Backspace);
        assert_eq!(app.settings_clipboard_clear, "", "Backspace on a fresh field clears it entirely, not just the last digit");

        drop(guard);
    }
}


pub(crate) fn handle_form_input(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) {
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
            // Tags are stored normalized (split, trimmed, deduped, re-joined
            // -- see db::normalize_tags), so "work,email" and " work , email"
            // land identically and the sidebar never shows phantom variants.
            let normalized_tags = db::normalize_tags(&app.form_category);
            if app.form_title.trim().is_empty()
                || normalized_tags.is_empty()
                || app.form_password.trim().is_empty()
            {
                app.error_message = "Title, at least one Tag, and Password are required!".to_string();
                app.screen = Screen::ErrorDialog;
                return;
            }

            if let Some(key) = &app.key {
                let res = if let Some(id) = app.edit_id {
                    db::update_secret(
                        &app.conn,
                        id,
                        &app.form_title,
                        &normalized_tags,
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
                        &normalized_tags,
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
                        app.vault_modified_since_sync = true;
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


pub(crate) fn handle_change_password_input(app: &mut TuiApp, code: KeyCode) {
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
            if app.key.is_none() {
                app.error_message = "Vault is locked!".to_string();
                return;
            }
            // Everything slow -- verifying the current password and the
            // rotation itself are up to three Argon2id derivations plus a
            // full re-encryption -- is deferred a frame so the notice
            // renders first. See PendingDerive.
            app.error_message.clear();
            app.pending_derive = Some(crate::tui::PendingDerive::ChangePassword);
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

/// The deferred half of the Change Password screen's Enter -- runs from
/// run_loop, one frame after PendingDerive::ChangePassword was set. The
/// cheap validations already happened in the handler.
pub(crate) fn perform_change_password(app: &mut TuiApp) {
    let old_key = match app.key.clone() {
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
    match db::change_master_password(&app.conn, &db_path, &old_key, &app.password_confirm_input) {
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
                            app.vault_modified_since_sync = true;
                            app.refresh_secrets();
                            // Push the rotation out immediately (the CLI's
                            // change-password already does) instead of
                            // letting it sit local until exit -- every
                            // minute it stays unpushed widens the window in
                            // which another device's ordinary edit turns
                            // into the rotation-race refusal. Auto Sync off
                            // still means no automatic push, same contract
                            // as every other trigger.
                            app.trigger_postunlock_sync();
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


/// Delegates scoring to audit::check_strength -- the same entropy-based
/// scorer the CLI `audit` command and the dashboard's Security Audit panel
/// use -- instead of an independent, older additive-points scheme that used
/// to live here. The two used to disagree: a long random lowercase
/// passphrase could show up "Weak" while being typed into this form and
/// "Good" moments later in the audit report for that exact same password --
/// precisely the mis-scoring entropy-based scoring was introduced to fix in
/// the first place (see check_strength's own doc comment); this indicator
/// just hadn't been switched over when that fix landed. Bar/color/label now
/// match the Detail View pane's Security Audit summary exactly.
fn get_strength_bar(password: &str) -> (Span<'static>, Span<'static>) {
    if password.is_empty() {
        return (
            Span::styled(" [░░░░░░░░░░]", Style::default().fg(Color::DarkGray)),
            Span::styled(" Empty", Style::default().fg(Color::DarkGray))
        );
    }

    let (severity, _issues, score) = crate::audit::check_strength(password);
    let color = match severity {
        crate::audit::Severity::Critical => Color::Red,
        crate::audit::Severity::Weak => Color::Yellow,
        crate::audit::Severity::Good => Color::Green,
    };
    let filled = (score as usize) * 2; // score is 0..=5, bar is 10 chars wide
    let empty = 10usize.saturating_sub(filled);
    let bar = format!(" [{}{}]", "█".repeat(filled), "░".repeat(empty));

    (
        Span::styled(bar, Style::default().fg(color)),
        Span::styled(format!(" {}", severity.label()), Style::default().fg(color))
    )
}


pub(crate) fn draw_form(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.area();
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
        Block::default().borders(Borders::ALL).title("Tags* (comma-separated)").border_style(get_border_style(FormField::Category))
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
    // Masked behind the same [v] toggle the Detail View pane already uses --
    // the form password used to render in the clear unconditionally, the one
    // place in the whole TUI a password was ever shown on screen with no way
    // to hide it (shoulder-surfing, screen-share, screenshot). Zeroizing to
    // match the Detail View pane's own pattern for this same tradeoff --
    // ratatui's internal render buffer is out of reach either way, but our
    // own copy shouldn't drop unwiped on top of that.
    let password_display: Zeroizing<String> = if app.reveal_password {
        Zeroizing::new(app.form_password.clone())
    } else {
        Zeroizing::new("•".repeat(app.form_password.chars().count()))
    };
    let password_box = Paragraph::new(password_display.as_str()).block(
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

    // Check reuse against the fingerprints refresh_form_audit_cache computed
    // once when the form opened, instead of decrypting every other secret
    // in the vault again on every single render frame (every keystroke,
    // every 250ms idle-timeout poll tick). The current form password is the
    // only thing that changes frame to frame, and hashing just that one
    // value is cheap.
    let current_fingerprint = app.key.as_ref().and_then(|key| {
        if app.form_password.is_empty() {
            None
        } else {
            Some(crate::crypto::hibp_cache_fingerprint(app.form_password.as_bytes(), key))
        }
    });
    let reuse_count = current_fingerprint
        .as_ref()
        .and_then(|fp| app.form_reuse_fingerprints.get(fp))
        .copied()
        .unwrap_or(0);

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

    let hibp_lookup = current_fingerprint
        .as_ref()
        .and_then(|fp| app.form_hibp_cache.get(fp))
        .copied()
        .flatten();
    if let Some(hibp_count) = hibp_lookup
        && hibp_count > 0 {
            if has_warnings {
                warning_spans.push(Span::raw(" | "));
            }
            warning_spans.push(Span::styled(
                format!("⚠ Breached ({} times in HIBP database)", hibp_count),
                Style::default().fg(Color::LightRed)
            ));
            has_warnings = true;
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




pub(crate) fn draw_change_password_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.area();
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

    if app.pending_derive.is_some() {
        let busy = Paragraph::new("Verifying password, deriving new key, and re-encrypting the vault -- please wait...")
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        f.render_widget(busy, chunks[3]);
    } else if !app.error_message.is_empty() {
        let err = Paragraph::new(&*app.error_message)
            .style(Style::default().fg(Color::Red));
        f.render_widget(err, chunks[3]);
    } else {
        let hints = Paragraph::new("Use [Tab] / [Shift+Tab] to switch fields | Press [Enter] to Save | [Esc] to Cancel")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hints, chunks[3]);
    }
}


pub(crate) fn handle_generator_input(app: &mut TuiApp, key: KeyCode) {
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
        // Flip between random characters and diceware passphrases (drawn
        // from the embedded EFF large wordlist -- the better mode for
        // anything typed or memorized). Dialog-local, not persisted.
        KeyCode::Char('w') => {
            app.gen_passphrase_mode = !app.gen_passphrase_mode;
            regenerate_in_place(app);
        }
        // Adjust length (chars mode: same 4..=256 bounds generate_password
        // itself enforces; words mode: 3..=12 words).
        KeyCode::Left => {
            if app.gen_passphrase_mode {
                if app.gen_words > crate::generator::MIN_WORDS {
                    app.gen_words -= 1;
                    regenerate_in_place(app);
                }
            } else if app.gen_options.length > crate::generator::MIN_LENGTH {
                app.gen_options.length -= 1;
                let _ = app.gen_options.save();
                regenerate_in_place(app);
            }
        }
        KeyCode::Right => {
            if app.gen_passphrase_mode {
                if app.gen_words < crate::generator::MAX_WORDS {
                    app.gen_words += 1;
                    regenerate_in_place(app);
                }
            } else if app.gen_options.length < crate::generator::MAX_LENGTH {
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
    if app.gen_passphrase_mode {
        app.gen_password.zeroize();
        app.gen_password = crate::generator::generate_passphrase(app.gen_words);
        return;
    }
    // The generator dialog only exposes toggles for uppercase/numbers/symbols
    // -- lowercase can only be turned off from the Settings screen -- so
    // reaching all-four-disabled needs both: lowercase off in Settings, then
    // the other three toggled off here too. When it happens, generate_password
    // errors, and that error string used to become the displayed "password"
    // (and what [c] would copy to the clipboard) instead of an actual
    // password. Falling back to lowercase-only guarantees a real password
    // either way, and updates gen_options so the fallback is what's actually
    // shown/used, not a silent mismatch between state and output.
    if !app.gen_options.use_lowercase
        && !app.gen_options.use_uppercase
        && !app.gen_options.use_numbers
        && !app.gen_options.use_symbols
    {
        app.gen_options.use_lowercase = true;
    }
    app.gen_password.zeroize();
    match crate::generator::generate_password(&app.gen_options) {
        Ok(pass) => app.gen_password = pass,
        Err(e) => app.gen_password = format!("Error: {e}"),
    }
}


pub(crate) fn draw_generator_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.area();
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

    // ── Length / word-count row (mode-aware) ──
    let len_line = if app.gen_passphrase_mode {
        Line::from(vec![
            Span::styled("  Words:  ", Style::default().fg(Color::DarkGray)),
            Span::styled("[←]", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("  {}  ", app.gen_words),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled("[→]", Style::default().fg(Color::Cyan)),
            Span::styled("   [w] Mode: ", Style::default().fg(Color::DarkGray)),
            Span::styled("Passphrase (EFF wordlist)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  Length: ", Style::default().fg(Color::DarkGray)),
            Span::styled("[←]", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("  {}  ", app.gen_options.length),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled("[→]", Style::default().fg(Color::Cyan)),
            Span::styled("   [w] Mode: ", Style::default().fg(Color::DarkGray)),
            Span::styled("Random characters", Style::default().fg(Color::White)),
        ])
    };
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
            Span::styled(icon.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)),
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
//  Settings Screen
// ─────────────────────────────────────────────

pub(crate) fn handle_settings_input(app: &mut TuiApp, key: KeyCode) {
    match key {
        KeyCode::Esc => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab => {
            app.active_settings_field = settings_field_step(app.active_settings_field, key);
            // The field just arrived at hasn't been edited yet -- the next
            // digit/Backspace should replace its old value, not build on it.
            app.settings_field_touched = false;
        }
        KeyCode::Char(c) => {
            match app.active_settings_field {
                0 => {
                    if c.is_ascii_digit() {
                        if !app.settings_field_touched {
                            app.settings_idle_timeout.clear();
                            app.settings_field_touched = true;
                        }
                        app.settings_idle_timeout.push(c);
                    }
                }
                1 => {
                    if c.is_ascii_digit() {
                        if !app.settings_field_touched {
                            app.settings_clipboard_clear.clear();
                            app.settings_field_touched = true;
                        }
                        app.settings_clipboard_clear.push(c);
                    }
                }
                3 => {
                    if c.is_ascii_digit() {
                        if !app.settings_field_touched {
                            app.settings_gen_length.clear();
                            app.settings_field_touched = true;
                        }
                        app.settings_gen_length.push(c);
                    }
                }
                8 => {
                    if c.is_ascii_digit() {
                        if !app.settings_field_touched {
                            app.settings_history_retention.clear();
                            app.settings_field_touched = true;
                        }
                        app.settings_history_retention.push(c);
                    }
                }
                2 | 4 | 5 | 6 | 7
                    if c == ' ' => {
                        match app.active_settings_field {
                            2 => app.settings_auto_sync = !app.settings_auto_sync,
                            4 => app.settings_gen_lowercase = !app.settings_gen_lowercase,
                            5 => app.settings_gen_uppercase = !app.settings_gen_uppercase,
                            6 => app.settings_gen_numbers = !app.settings_gen_numbers,
                            7 => app.settings_gen_symbols = !app.settings_gen_symbols,
                            _ => {}
                        }
                    }
                _ => {}
            }
        }
        KeyCode::Backspace => {
            // A fresh (untouched-since-navigating-here) field's old value is
            // effectively "selected" -- Backspace clears the whole thing in
            // one press, same as it would on a pre-selected form field,
            // rather than trimming one digit off a value the user hasn't
            // actually started editing yet.
            match app.active_settings_field {
                0 => {
                    if app.settings_field_touched { app.settings_idle_timeout.pop(); } else { app.settings_idle_timeout.clear(); }
                }
                1 => {
                    if app.settings_field_touched { app.settings_clipboard_clear.pop(); } else { app.settings_clipboard_clear.clear(); }
                }
                3 => {
                    if app.settings_field_touched { app.settings_gen_length.pop(); } else { app.settings_gen_length.clear(); }
                }
                8 => {
                    if app.settings_field_touched { app.settings_history_retention.pop(); } else { app.settings_history_retention.clear(); }
                }
                _ => {}
            }
            app.settings_field_touched = true;
        }
        KeyCode::Enter => {
            // Clamped rather than accepted as-typed: an idle timeout of 0 makes
            // `last_activity.elapsed() >= Duration::from_secs(0)` always true,
            // locking the vault on the very next tick -- including right after
            // this save, soft-locking the user out of the TUI (settings screen
            // included) until they hand-edit config.json.
            let timeout = app.settings_idle_timeout.parse::<u64>().unwrap_or(300).max(10);
            let clip = app.settings_clipboard_clear.parse::<u64>().unwrap_or(5).clamp(1, 3600);
            let gen_len = app.settings_gen_length.parse::<usize>().unwrap_or(20).clamp(4, 256);
            // 0 = unlimited history; any enabled value is floored at 10 so
            // the recent snapshots that conflict detection's 3-way base
            // (and plain rollback) rely on can't be configured away.
            let retention = app.settings_history_retention.parse::<u64>().unwrap_or(0);
            let retention = if retention == 0 { 0 } else { retention.max(10) };

            app.config.idle_timeout_seconds = timeout;
            app.config.clipboard_clear_seconds = clip;
            app.config.auto_sync = app.settings_auto_sync;
            app.config.history_retention = retention;
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

/// Total number of settings fields, laid out row-major 2-per-row. Odd, so
/// the last grid row holds a single field in the left column.
const SETTINGS_FIELD_COUNT: usize = 9;

/// Where a settings-screen key press moves the active field, given the
/// 2-column grid layout (fields 0..8, laid out row-major 2-per-row -- see
/// draw_settings_screen; row 4 has only field 8 on the left). Up/Down move
/// by a full grid row, wrapping within the same column (a column with no
/// cell in the last row wraps past it); Left/Right toggle within the row
/// (field 8 has no right-hand neighbor and stays put); Tab/Shift+Tab remain
/// the plain linear cycle through all 9, independent of the grid shape.
fn settings_field_step(field: usize, key: KeyCode) -> usize {
    let last = SETTINGS_FIELD_COUNT - 1; // 8, the lone field on the last row
    match key {
        KeyCode::Up => {
            if field >= 2 {
                field - 2
            } else if field.is_multiple_of(2) {
                last // column 0 wraps to the bottom row's lone field
            } else {
                last - 1 // column 1's bottom-most cell is on the row above
            }
        }
        KeyCode::Down => {
            if field + 2 < SETTINGS_FIELD_COUNT {
                field + 2
            } else {
                field % 2 // wrap to the top of the same column
            }
        }
        KeyCode::Left | KeyCode::Right => {
            if field == last { field } else { field ^ 1 }
        }
        KeyCode::Tab => (field + 1) % SETTINGS_FIELD_COUNT,
        KeyCode::BackTab => (field + SETTINGS_FIELD_COUNT - 1) % SETTINGS_FIELD_COUNT,
        _ => field,
    }
}

/// Number of on-screen grid rows the settings fields occupy at 2 per row.
/// Kept as a named constant since draw_settings_screen and
/// settings_grid_scroll both need to agree on it.
const SETTINGS_GRID_ROWS: usize = SETTINGS_FIELD_COUNT.div_ceil(2);

/// How many of the field-grid rows actually fit in a settings box this
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


pub(crate) fn draw_settings_screen(f: &mut ratatui::Frame, app: &TuiApp) {
    let size = f.area();
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
    let fields: [(&str, String, bool); SETTINGS_FIELD_COUNT] = [
        ("1. Idle Timeout (s)", app.settings_idle_timeout.clone(), app.active_settings_field == 0),
        ("2. Clipboard Delay (s)", app.settings_clipboard_clear.clone(), app.active_settings_field == 1),
        ("3. Auto Sync (Y/N)", if app.settings_auto_sync { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 2),
        ("4. Gen Length", app.settings_gen_length.clone(), app.active_settings_field == 3),
        ("5. Gen Lowercase (Y/N)", if app.settings_gen_lowercase { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 4),
        ("6. Gen Uppercase (Y/N)", if app.settings_gen_uppercase { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 5),
        ("7. Gen Numbers (Y/N)", if app.settings_gen_numbers { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 6),
        ("8. Gen Symbols (Y/N)", if app.settings_gen_symbols { "Yes [Space to toggle]" } else { "No [Space to toggle]" }.to_string(), app.active_settings_field == 7),
        ("9. History Keep (0 = all)", app.settings_history_retention.clone(), app.active_settings_field == 8),
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
    fn all_grid_rows_fit_on_a_generously_sized_terminal() {
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
            for active_field in 0..SETTINGS_FIELD_COUNT {
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
        for active_field in 0..SETTINGS_FIELD_COUNT {
            let (fit, offset) = settings_grid_scroll(tiny_height, active_field);
            for r in offset..offset + fit {
                rows_seen.insert(r);
            }
        }
        assert_eq!(rows_seen, (0..SETTINGS_GRID_ROWS).collect(), "every grid row must be reachable by tabbing through all fields");
    }

    #[test]
    fn settings_field_step_matches_the_grid_layout() {
        // Fields are laid out row-major, 2 per row, with a lone field on
        // the last row:
        //   row 0: 0 1   row 1: 2 3   row 2: 4 5   row 3: 6 7   row 4: 8 -
        // (field, key, expected_next)
        let cases = [
            // Down moves one full row, wrapping within the same column.
            (1usize, KeyCode::Down, 3usize),
            (3, KeyCode::Down, 5),
            (6, KeyCode::Down, 8),
            (8, KeyCode::Down, 0),  // bottom of column 0 wraps to its top
            (7, KeyCode::Down, 1),  // column 1 has no row-4 cell -- wraps past it
            // Up is the mirror image.
            (3, KeyCode::Up, 1),
            (8, KeyCode::Up, 6),
            (0, KeyCode::Up, 8),    // top of column 0 wraps to the lone bottom field
            (1, KeyCode::Up, 7),    // top of column 1 wraps to its bottom-most cell
            // Left/Right toggle within the row; the lone last field has no
            // neighbor and stays put.
            (2, KeyCode::Left, 3),
            (1, KeyCode::Left, 0),
            (7, KeyCode::Right, 6),
            (8, KeyCode::Left, 8),
            (8, KeyCode::Right, 8),
            // Tab/Shift+Tab: unchanged linear cycle, independent of the grid.
            (8, KeyCode::Tab, 0),
            (0, KeyCode::BackTab, 8),
            (3, KeyCode::Tab, 4),
            (4, KeyCode::BackTab, 3),
        ];

        for (field, key, expected) in cases {
            let actual = settings_field_step(field, key);
            assert_eq!(
                actual, expected,
                "field {field} + {key:?} should move to {expected}, got {actual}"
            );
        }
    }

    #[test]
    fn settings_field_step_never_leaves_the_valid_range() {
        for field in 0..SETTINGS_FIELD_COUNT {
            for key in [KeyCode::Up, KeyCode::Down, KeyCode::Left, KeyCode::Right, KeyCode::Tab, KeyCode::BackTab] {
                assert!(settings_field_step(field, key) < SETTINGS_FIELD_COUNT);
            }
        }
    }
}


