use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use zeroize::Zeroizing;
use std::time::Instant;
use crate::db;
use crate::tui::{TuiApp, Screen, ConfirmAction, StatusType};
use crate::render::*;

pub(crate) fn handle_confirmation_input(app: &mut TuiApp, code: KeyCode, action: ConfirmAction) {
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


pub(crate) fn handle_help_input(app: &mut TuiApp, code: KeyCode) {
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


pub(crate) fn handle_import_input(app: &mut TuiApp, code: KeyCode) {
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


pub(crate) fn handle_export_type_input(app: &mut TuiApp, code: KeyCode) {
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


pub(crate) fn handle_export_input(app: &mut TuiApp, code: KeyCode) {
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


pub(crate) fn draw_error_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn draw_confirmation_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn draw_help_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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
        Line::from(Span::styled(
            format!("Clipboard Actions (clears automatically after {}s):", app.config.clipboard_clear_seconds),
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
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


pub(crate) fn draw_import_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn draw_export_type_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn draw_export_dialog(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn handle_deduplicate_input(app: &mut TuiApp, key: KeyCode) {
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


pub(crate) fn draw_deduplicate_screen(f: &mut ratatui::Frame, app: &TuiApp) {
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


pub(crate) fn draw_hibp_progress_dialog(f: &mut ratatui::Frame, checked: usize, total: usize) {
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


pub(crate) fn handle_sync_conflict_input(app: &mut TuiApp, code: KeyCode) {
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


pub(crate) fn draw_sync_conflict_screen(f: &mut ratatui::Frame, app: &TuiApp) {
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





