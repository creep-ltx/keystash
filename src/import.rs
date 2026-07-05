use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use rusqlite::Connection;

use crate::db;

#[derive(Deserialize, Debug)]
struct BwFolder {
    id: Option<String>,
    name: String,
}

#[derive(Deserialize, Debug)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Deserialize, Debug)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize, Debug)]
struct BwItem {
    #[serde(rename = "type")]
    item_type: i32,
    name: String,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    notes: Option<String>,
    login: Option<BwLogin>,
}

#[derive(Deserialize, Debug)]
struct BwExport {
    folders: Option<Vec<BwFolder>>,
    items: Option<Vec<BwItem>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    BitwardenJson,
    BraveChromeCsv,
    FirefoxCsv,
    LastPassCsv,
    KeePassXcCsv,
    OnePasswordCsv,
}

impl ImportFormat {
    pub fn name(&self) -> &'static str {
        match self {
            ImportFormat::BitwardenJson => "Bitwarden (JSON)",
            ImportFormat::BraveChromeCsv => "Brave / Chrome (CSV)",
            ImportFormat::FirefoxCsv => "Firefox (CSV)",
            ImportFormat::LastPassCsv => "LastPass (CSV)",
            ImportFormat::KeePassXcCsv => "KeePassXC (CSV)",
            ImportFormat::OnePasswordCsv => "1Password (CSV)",
        }
    }
}

/// Parses a simple CSV line into fields, handling optional quoting.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Extracts a clean domain or host name from a URL string.
fn extract_domain(url: &str) -> String {
    if url.is_empty() {
        return "Browser Login".to_string();
    }
    let without_prefix = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");
    let domain = without_prefix.split('/').next().unwrap_or(url);
    domain.to_string()
}

/// Detects the format of the export file.
pub fn detect_format(file_path: &str) -> Result<ImportFormat, String> {
    let mut file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    
    let mut header_buf = [0u8; 1024];
    let bytes_read = file.read(&mut header_buf).map_err(|e| format!("Read error: {}", e))?;
    let header_str = String::from_utf8_lossy(&header_buf[..bytes_read]);

    if header_str.trim_start().starts_with('{') {
        if header_str.contains("\"folders\"") || header_str.contains("\"items\"") {
            return Ok(ImportFormat::BitwardenJson);
        }
        return Err("Unsupported JSON export format.".to_string());
    }

    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    if reader.read_line(&mut first_line).is_ok() && !first_line.is_empty() {
        let headers = parse_csv_line(&first_line);
        let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
        
        if norm_headers.contains(&"name".to_string()) && norm_headers.contains(&"url".to_string()) && norm_headers.contains(&"username".to_string()) && norm_headers.contains(&"password".to_string()) {
            return Ok(ImportFormat::BraveChromeCsv);
        }
        
        if norm_headers.contains(&"url".to_string()) && norm_headers.contains(&"username".to_string()) && norm_headers.contains(&"password".to_string()) && norm_headers.contains(&"httprealm".to_string()) {
            return Ok(ImportFormat::FirefoxCsv);
        }

        if norm_headers.contains(&"url".to_string()) && norm_headers.contains(&"username".to_string()) && norm_headers.contains(&"password".to_string()) && norm_headers.contains(&"extra".to_string()) && norm_headers.contains(&"fav".to_string()) {
            return Ok(ImportFormat::LastPassCsv);
        }

        if norm_headers.contains(&"group".to_string()) && norm_headers.contains(&"title".to_string()) && norm_headers.contains(&"username".to_string()) && norm_headers.contains(&"password".to_string()) && norm_headers.contains(&"notes".to_string()) {
            return Ok(ImportFormat::KeePassXcCsv);
        }

        if norm_headers.contains(&"title".to_string()) && norm_headers.contains(&"username".to_string()) && norm_headers.contains(&"password".to_string()) && (norm_headers.contains(&"website".to_string()) || norm_headers.contains(&"url".to_string())) {
            if !norm_headers.contains(&"group".to_string()) {
                return Ok(ImportFormat::OnePasswordCsv);
            }
        }
    }

    Err("Unknown or unsupported export file format.".to_string())
}

/// Parses a Bitwarden unencrypted JSON export and inserts the entries into KeyStash database.
pub fn import_bitwarden_json(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    
    let export: BwExport = serde_json::from_reader(reader)
        .map_err(|e| format!("JSON parsing failed (is this a valid unencrypted Bitwarden JSON export?): {}", e))?;

    let mut folders_map = HashMap::new();
    if let Some(folders) = export.folders {
        for folder in folders {
            if let Some(id) = folder.id {
                folders_map.insert(id, folder.name);
            }
        }
    }

    let mut import_count = 0;

    if let Some(items) = export.items {
        for item in items {
            let category = item
                .folder_id
                .and_then(|fid| folders_map.get(&fid).cloned())
                .unwrap_or_else(|| "Imported".to_string());

            let mut username = String::new();
            let mut password = String::new();
            let mut url = String::new();

            if let Some(login) = &item.login {
                if let Some(u) = &login.username {
                    username = u.clone();
                }
                if let Some(p) = &login.password {
                    password = p.clone();
                }
                if let Some(uris) = &login.uris {
                    if !uris.is_empty() {
                        if let Some(uri) = &uris[0].uri {
                            url = uri.clone();
                        }
                    }
                }
            }

            if password.is_empty() && item.item_type != 1 {
                password = "[Secure Note]".to_string();
            }

            db::add_secret(
                conn,
                &item.name,
                &category,
                &username,
                &url,
                &password,
                item.notes.as_deref(),
                key,
            )?;
            import_count += 1;
        }
    }

    Ok(import_count)
}

/// Parses a Brave / Google Chrome unencrypted CSV export and inserts the entries.
pub fn import_brave_chrome_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let header_line = lines.next().ok_or("Empty CSV file")?.map_err(|e| e.to_string())?;
    let headers = parse_csv_line(&header_line);
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    
    let name_idx = norm_headers.iter().position(|h| h == "name").ok_or("Missing 'name' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    
    let mut count = 0;
    for line_result in lines {
        let line = line_result.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        if fields.len() <= std::cmp::max(name_idx, std::cmp::max(url_idx, std::cmp::max(user_idx, pass_idx))) {
            continue;
        }
        
        let title = &fields[name_idx];
        let url = &fields[url_idx];
        let username = &fields[user_idx];
        let password = &fields[pass_idx];
        
        if title.is_empty() && password.is_empty() {
            continue;
        }
        
        let display_title = if title.is_empty() { url } else { title };
        
        db::add_secret(
            conn,
            display_title,
            "Browser",
            username,
            url,
            password,
            None,
            key,
        )?;
        count += 1;
    }
    
    Ok(count)
}

/// Parses a Firefox unencrypted CSV export and inserts the entries.
pub fn import_firefox_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let header_line = lines.next().ok_or("Empty CSV file")?.map_err(|e| e.to_string())?;
    let headers = parse_csv_line(&header_line);
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    
    let mut count = 0;
    for line_result in lines {
        let line = line_result.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        if fields.len() <= std::cmp::max(url_idx, std::cmp::max(user_idx, pass_idx)) {
            continue;
        }
        
        let url = &fields[url_idx];
        let username = &fields[user_idx];
        let password = &fields[pass_idx];
        
        if url.is_empty() && password.is_empty() {
            continue;
        }
        
        let clean_title = extract_domain(url);
        
        db::add_secret(
            conn,
            &clean_title,
            "Browser",
            username,
            url,
            password,
            None,
            key,
        )?;
        count += 1;
    }
    
    Ok(count)
}

/// Parses a LastPass unencrypted CSV export and inserts the entries.
pub fn import_lastpass_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let header_line = lines.next().ok_or("Empty CSV file")?.map_err(|e| e.to_string())?;
    let headers = parse_csv_line(&header_line);
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    
    let name_idx = norm_headers.iter().position(|h| h == "name").ok_or("Missing 'name' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let extra_idx = norm_headers.iter().position(|h| h == "extra").ok_or("Missing 'extra' (notes) column")?;
    let group_idx = norm_headers.iter().position(|h| h == "grouping").ok_or("Missing 'grouping' column")?;
    
    let mut count = 0;
    for line_result in lines {
        let line = line_result.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        let max_idx = std::cmp::max(name_idx, std::cmp::max(url_idx, std::cmp::max(user_idx, std::cmp::max(pass_idx, std::cmp::max(extra_idx, group_idx)))));
        if fields.len() <= max_idx {
            continue;
        }
        
        let title = &fields[name_idx];
        let url = &fields[url_idx];
        let username = &fields[user_idx];
        let password = &fields[pass_idx];
        let notes = &fields[extra_idx];
        let category = &fields[group_idx];
        
        if title.is_empty() && password.is_empty() {
            continue;
        }
        
        let display_title = if title.is_empty() { url } else { title };
        let display_category = if category.is_empty() { "LastPass" } else { category };
        
        db::add_secret(
            conn,
            display_title,
            display_category,
            username,
            url,
            password,
            if notes.is_empty() { None } else { Some(notes) },
            key,
        )?;
        count += 1;
    }
    
    Ok(count)
}

/// Parses a KeePassXC unencrypted CSV export and inserts the entries.
pub fn import_keepassxc_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let header_line = lines.next().ok_or("Empty CSV file")?.map_err(|e| e.to_string())?;
    let headers = parse_csv_line(&header_line);
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    
    let group_idx = norm_headers.iter().position(|h| h == "group").ok_or("Missing 'group' column")?;
    let title_idx = norm_headers.iter().position(|h| h == "title").ok_or("Missing 'title' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let notes_idx = norm_headers.iter().position(|h| h == "notes").ok_or("Missing 'notes' column")?;
    
    let mut count = 0;
    for line_result in lines {
        let line = line_result.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        let max_idx = std::cmp::max(group_idx, std::cmp::max(title_idx, std::cmp::max(user_idx, std::cmp::max(pass_idx, std::cmp::max(url_idx, notes_idx)))));
        if fields.len() <= max_idx {
            continue;
        }
        
        let category = &fields[group_idx];
        let title = &fields[title_idx];
        let username = &fields[user_idx];
        let password = &fields[pass_idx];
        let url = &fields[url_idx];
        let notes = &fields[notes_idx];
        
        if title.is_empty() && password.is_empty() {
            continue;
        }
        
        let display_title = if title.is_empty() { url } else { title };
        let display_category = if category.is_empty() { "KeePassXC" } else { category };
        
        db::add_secret(
            conn,
            display_title,
            display_category,
            username,
            url,
            password,
            if notes.is_empty() { None } else { Some(notes) },
            key,
        )?;
        count += 1;
    }
    
    Ok(count)
}

/// Parses a 1Password unencrypted CSV export and inserts the entries.
pub fn import_onepassword_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    
    let header_line = lines.next().ok_or("Empty CSV file")?.map_err(|e| e.to_string())?;
    let headers = parse_csv_line(&header_line);
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    
    let title_idx = norm_headers.iter().position(|h| h == "title").ok_or("Missing 'title' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let notes_idx = norm_headers.iter().position(|h| h == "notes").ok_or("Missing 'notes' column")?;
    
    // 1Password might use either "url" or "website" as URL column
    let url_idx = norm_headers.iter().position(|h| h == "url")
        .or_else(|| norm_headers.iter().position(|h| h == "website"))
        .ok_or("Missing URL / Website column")?;
    
    let mut count = 0;
    for line_result in lines {
        let line = line_result.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        let max_idx = std::cmp::max(title_idx, std::cmp::max(user_idx, std::cmp::max(pass_idx, std::cmp::max(notes_idx, url_idx))));
        if fields.len() <= max_idx {
            continue;
        }
        
        let title = &fields[title_idx];
        let username = &fields[user_idx];
        let password = &fields[pass_idx];
        let notes = &fields[notes_idx];
        let url = &fields[url_idx];
        
        if title.is_empty() && password.is_empty() {
            continue;
        }
        
        let display_title = if title.is_empty() { url } else { title };
        
        db::add_secret(
            conn,
            display_title,
            "1Password",
            username,
            url,
            password,
            if notes.is_empty() { None } else { Some(notes) },
            key,
        )?;
        count += 1;
    }
    
    Ok(count)
}

/// Escapes fields containing commas, quotes, or newlines according to standard RFC 4180 CSV specifications.
fn escape_csv_cell(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        let escaped = val.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        val.to_string()
    }
}

/// Exports all decrypted vault secrets to an unencrypted CSV file.
pub fn export_vault_csv(
    conn: &Connection,
    output_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    use std::io::Write;
    let mut file = File::create(output_path).map_err(|e| format!("Could not create file: {}", e))?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    
    let secrets = db::get_secrets(conn)?;
    let mut count = 0;
    
    // Write header
    writeln!(file, "title,url,username,password,notes,category").map_err(|e| e.to_string())?;
    
    for r in secrets {
        let decrypted_pass = crate::crypto::decrypt(&r.encrypted_password, key)
            .map(|dec| String::from_utf8_lossy(&dec).to_string())
            .unwrap_or_else(|_| String::new());
            
        let decrypted_notes = match &r.encrypted_notes {
            Some(notes_blob) => crate::crypto::decrypt(notes_blob, key)
                .map(|dec| String::from_utf8_lossy(&dec).to_string())
                .unwrap_or_else(|_| String::new()),
            None => String::new(),
        };
        
        let row = format!(
            "{},{},{},{},{},{}",
            escape_csv_cell(&r.title),
            escape_csv_cell(&r.url),
            escape_csv_cell(&r.username),
            escape_csv_cell(&decrypted_pass),
            escape_csv_cell(&decrypted_notes),
            escape_csv_cell(&r.category)
        );
        
        writeln!(file, "{}", row).map_err(|e| e.to_string())?;
        count += 1;
    }
    
    Ok(count)
}

