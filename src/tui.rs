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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Lock,
    Setup,
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
    copied_message: Option<(String, Instant)>,

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
}

impl TuiApp {
    pub fn new(conn: Connection, no_sync: bool) -> Self {
        let is_first = db::is_first_run(&conn).unwrap_or(true);
        let screen = if is_first { Screen::Setup } else { Screen::Lock };

        Self {
            conn,
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
            gen_options: crate::generator::GeneratorOptions::default(),
            gen_password: String::new(),
        }
    }

    fn refresh_secrets(&mut self) {
        if self.key.is_some() {
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
            }
        }
    }

    fn apply_filter(&mut self) {
        let current_cat = self.categories.get(self.selected_category_idx).cloned().unwrap_or("All".to_string());
        let query = self.search_query.to_lowercase();

        self.filtered_secrets = self.secrets
            .iter()
            .filter(|r| {
                let cat_match = current_cat == "All" || r.category == current_cat;
                let search_match = query.is_empty() 
                    || r.title.to_lowercase().contains(&query)
                    || r.username.to_lowercase().contains(&query)
                    || r.category.to_lowercase().contains(&query)
                    || r.url.to_lowercase().contains(&query);
                cat_match && search_match
            })
            .cloned()
            .collect();

        if self.selected_secret_idx >= self.filtered_secrets.len() {
            self.selected_secret_idx = if self.filtered_secrets.is_empty() { 0 } else { self.filtered_secrets.len() - 1 };
        }
    }

    fn copy_to_clipboard(&mut self, text: String, label: &str) {
        if text.trim().is_empty() {
            self.copied_message = Some((
                format!("Cannot copy: {} is empty!", label),
                Instant::now(),
            ));
            return;
        }

        if let Ok(exe) = std::env::current_exe() {
            let child = Command::new(exe)
                .arg("__internal-clear-clipboard")
                .arg("10")
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
                        format!("Copied {} to clipboard! Will clear in 10s.", label),
                        Instant::now(),
                    ));
                }
                Err(_) => {
                    self.copied_message = Some((
                        "Failed to spawn clipboard manager process.".to_string(),
                        Instant::now(),
                    ));
                }
            }
        } else {
            self.copied_message = Some((
                "Failed to locate KeyStash executable path.".to_string(),
                Instant::now(),
            ));
        }
    }

    fn clear_clipboard_if_expired(&mut self) {
        if let Some((_, instant)) = &self.copied_message {
            if instant.elapsed() >= Duration::from_secs(10) {
                self.copied_message = None;
            }
        }
    }

    fn trigger_background_sync(&self) {
        if self.no_sync {
            return;
        }
        let db_path = crate::get_db_path();
        std::thread::spawn(move || {
            let _ = crate::sync::git_sync_vault(db_path);
        });
    }
}

pub fn run_tui(mut app: TuiApp) -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

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
    Ok(())
}

fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> io::Result<()> {
    loop {
        app.clear_clipboard_if_expired();
        
        terminal.draw(|f| draw_ui(f, app))?;

        // Poll for inputs, checking clipboard expiration every 250ms
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == event::KeyEventKind::Press {
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
                        Screen::Dashboard => {
                            if handle_dashboard_input(app, key.code, key.modifiers) {
                                return Ok(());
                            }
                        }
                        Screen::AddSecret | Screen::EditSecret => handle_form_input(app, key.code),
                        Screen::ConfirmationDialog(action) => handle_confirmation_input(app, key.code, action),
                        Screen::HelpDialog => handle_help_input(app, key.code),
                        Screen::ChangePassword => handle_change_password_input(app, key.code),
                        Screen::ImportDialog => handle_import_input(app, key.code),
                        Screen::ExportTypeDialog => handle_export_type_input(app, key.code),
                        Screen::ExportDialog => handle_export_input(app, key.code),
                        Screen::GeneratorDialog => handle_generator_input(app, key.code),
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
            match db::unlock_vault(&app.conn, &app.password_input) {
                Ok(derived_key) => {
                    app.key = Some(derived_key);
                    app.screen = Screen::Dashboard;
                    app.password_input.zeroize();
                    app.password_input.clear();
                    app.refresh_secrets();
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
        KeyCode::Tab => {
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
            match db::setup_vault(&app.conn, &app.password_input) {
                Ok(derived_key) => {
                    app.key = Some(derived_key);
                    app.screen = Screen::Dashboard;
                    app.password_input.zeroize();
                    app.password_confirm_input.zeroize();
                    app.password_input.clear();
                    app.password_confirm_input.clear();
                    app.error_message = String::new();
                    app.refresh_secrets();
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
            app.form_password.clear();
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

                // Decrypt password & notes for editing
                if let Some(key) = &app.key {
                    if let Ok(dec_pass) = crate::crypto::decrypt(&record.encrypted_password, key) {
                        app.form_password = String::from_utf8_lossy(&dec_pass).to_string();
                    }
                    if let Some(enc_notes) = &record.encrypted_notes {
                        if let Ok(dec_notes) = crate::crypto::decrypt(enc_notes, key) {
                            app.form_notes = String::from_utf8_lossy(&dec_notes).to_string();
                        }
                    } else {
                        app.form_notes.clear();
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
                app.copy_to_clipboard(record.username.clone(), "username");
            }
        }
        KeyCode::Char('m') => {
            app.password_input.clear();
            app.password_confirm_input.clear();
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
            app.gen_options = crate::generator::GeneratorOptions::default();
            if let Ok(pass) = crate::generator::generate_password(&app.gen_options) {
                app.gen_password = pass;
            }
            app.screen = Screen::GeneratorDialog;
        }
        KeyCode::Char('u') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                app.copy_to_clipboard(record.url.clone(), "URL");
            }
        }
        KeyCode::Char('p') => {
            if let Some(record) = app.filtered_secrets.get(app.selected_secret_idx) {
                if let Some(key) = &app.key {
                    if let Ok(dec) = crate::crypto::decrypt(&record.encrypted_password, key) {
                        if let Ok(mut plaintext) = String::from_utf8(dec.to_vec()) {
                            app.copy_to_clipboard(plaintext.clone(), "password");
                            plaintext.zeroize();
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
        KeyCode::Char('h') | KeyCode::Char('?') => {
            app.screen = Screen::HelpDialog;
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

fn handle_form_input(app: &mut TuiApp, code: KeyCode) {
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
        KeyCode::Char(c) => match app.active_form_field {
            FormField::Title => app.form_title.push(c),
            FormField::Category => app.form_category.push(c),
            FormField::Username => app.form_username.push(c),
            FormField::Url => app.form_url.push(c),
            FormField::Password => app.form_password.push(c),
            FormField::Notes => app.form_notes.push(c),
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
                        app.screen = Screen::Dashboard;
                        app.refresh_secrets();
                        app.trigger_background_sync();
                    }
                    Err(err) => {
                        app.error_message = err;
                        app.screen = Screen::ErrorDialog;
                    }
                }
            }
        }
        KeyCode::Esc => {
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
            app.trigger_background_sync();
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
            if db::unlock_vault(&app.conn, &app.password_input).is_err() {
                app.error_message = "Incorrect current password!".to_string();
                return;
            }

            // Rotate keys
            match db::change_master_password(&app.conn, old_key, &app.password_confirm_input) {
                Ok(new_key) => {
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
                    app.trigger_background_sync();
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
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('h') | KeyCode::Char('?') | KeyCode::Char(' ') => {
            app.screen = Screen::Dashboard;
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
                crate::import::ImportFormat::BraveChromeCsv => crate::import::import_brave_chrome_csv(&app.conn, file_path, key_ref),
                crate::import::ImportFormat::FirefoxCsv => crate::import::import_firefox_csv(&app.conn, file_path, key_ref),
                crate::import::ImportFormat::LastPassCsv => crate::import::import_lastpass_csv(&app.conn, file_path, key_ref),
                crate::import::ImportFormat::KeePassXcCsv => crate::import::import_keepassxc_csv(&app.conn, file_path, key_ref),
                crate::import::ImportFormat::OnePasswordCsv => crate::import::import_onepassword_csv(&app.conn, file_path, key_ref),
            };

            match import_result {
                Ok(count) => {
                    app.copied_message = Some((format!("Success: Imported {} items from {}!", count, detected_format.name()), Instant::now()));
                    app.import_path_input.clear();
                    app.refresh_secrets();
                    app.trigger_background_sync();
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
                    app.copied_message = Some((format!("Success: Exported {} secrets to CSV!", count), Instant::now()));
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

    let title = Paragraph::new("KeyStash Password Vault")
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
    } else {
        let hints = Paragraph::new("Press [Enter] to Unlock | [Esc] to Exit")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(hints, chunks[2]);
    }
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
                    .map(|dec| String::from_utf8_lossy(&dec).to_string())
                    .unwrap_or_else(|_| "<Error Decrypting>".to_string())
            } else {
                "<Locked>".to_string()
            }
        } else {
            "••••••••••••".to_string()
        };

        let notes_str = if let Some(enc_notes) = &record.encrypted_notes {
            if let Some(key) = &app.key {
                crate::crypto::decrypt(enc_notes, key)
                    .map(|dec| String::from_utf8_lossy(&dec).to_string())
                    .unwrap_or_else(|_| "<Error Decrypting>".to_string())
            } else {
                "<Locked>".to_string()
            }
        } else {
            "[No Notes]".to_string()
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
                Span::styled(password_str, Style::default().fg(Color::LightRed)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Notes:", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(notes_str, Style::default().fg(Color::White))),
            Line::from(""),
            Line::from(vec![
                Span::styled("Last Updated: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&record.updated_at, Style::default().fg(Color::DarkGray)),
            ]),
        ];

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
    let status_text = if let Some((msg, _)) = &app.copied_message {
        Line::from(Span::styled(msg, Style::default().fg(Color::Green)))
    } else {
        Line::from(vec![
            Span::styled("[a] Add | ", Style::default().fg(Color::Green)),
            Span::styled("[e] Edit | ", Style::default().fg(Color::Yellow)),
            Span::styled("[v] View PW | ", Style::default().fg(Color::Magenta)),
            Span::styled("[c] Copy User | ", Style::default().fg(Color::Cyan)),
            Span::styled("[p] Copy PW | ", Style::default().fg(Color::Cyan)),
            Span::styled("[m] Change PW | ", Style::default().fg(Color::Magenta)),
            Span::styled("[h] Help | ", Style::default().fg(Color::Green)),
            Span::styled("[Esc] Exit", Style::default().fg(Color::White)),
        ])
    };

    let status_bar = Paragraph::new(status_text)
        .block(Block::default().borders(Borders::ALL).title("Actions"));
    f.render_widget(status_bar, main_layout[1]);
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
            Constraint::Min(3),    // Notes
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

    let password_box = Paragraph::new(app.form_password.as_str()).block(
        Block::default().borders(Borders::ALL).title("Password*").border_style(get_border_style(FormField::Password))
    );
    f.render_widget(password_box, form_layout[4]);

    let notes_box = Paragraph::new(app.form_notes.as_str()).block(
        Block::default().borders(Borders::ALL).title("Notes").border_style(get_border_style(FormField::Notes))
    );
    f.render_widget(notes_box, form_layout[5]);
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

fn draw_help_dialog(f: &mut ratatui::Frame, _app: &TuiApp) {
    let size = f.size();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Help & Keybindings")
        .border_style(Style::default().fg(Color::Green));

    let area = centered_rect(70, 75, size);
    f.render_widget(Clear, area);

    let help_text = vec![
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
        Line::from(Span::styled("Press [Esc] / [Enter] / [h] to close help dialog", Style::default().fg(Color::DarkGray))),
    ];

    let help_p = Paragraph::new(help_text)
        .block(block)
        .wrap(Wrap { trim: false });

    f.render_widget(help_p, area);
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
        Line::from(Span::styled("Supports: Bitwarden JSON, Brave/Chrome/Firefox/LastPass/KeePassXC/1Password CSV", Style::default().fg(Color::DarkGray))),
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
            regenerate_in_place(app);
        }
        KeyCode::Char('2') => {
            app.gen_options.use_numbers = !app.gen_options.use_numbers;
            regenerate_in_place(app);
        }
        KeyCode::Char('3') => {
            app.gen_options.use_symbols = !app.gen_options.use_symbols;
            regenerate_in_place(app);
        }
        // Adjust length
        KeyCode::Left => {
            if app.gen_options.length > 4 {
                app.gen_options.length -= 1;
                regenerate_in_place(app);
            }
        }
        KeyCode::Right => {
            if app.gen_options.length < 128 {
                app.gen_options.length += 1;
                regenerate_in_place(app);
            }
        }
        // Regenerate with same options
        KeyCode::Char('r') | KeyCode::Enter => {
            regenerate_in_place(app);
        }
        // Copy to clipboard
        KeyCode::Char('c') => {
            let pass = app.gen_password.clone();
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


