use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::db;

/// Runs `body` (which inserts rows one at a time via `db::add_secret`, each
/// normally its own auto-committed statement) inside a single explicit
/// transaction, so a failure partway through an import rolls back everything
/// inserted so far instead of leaving a partial, silently-inconsistent import
/// while still reporting the whole operation as failed.
fn with_import_transaction<F>(conn: &Connection, body: F) -> Result<usize, String>
where
    F: FnOnce() -> Result<usize, String>,
{
    conn.execute("BEGIN TRANSACTION", []).map_err(|e| e.to_string())?;
    match body() {
        Ok(count) => {
            conn.execute("COMMIT", []).map_err(|e| e.to_string())?;
            Ok(count)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

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

/// Reads records from an RFC 4180 compliant CSV file using the csv crate.
fn read_csv_records(file_path: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let file = File::open(file_path).map_err(|e| format!("Could not open file: {}", e))?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false) // Read raw headers manually to obtain index positions
        .flexible(true)
        .from_reader(file);

    let mut records = Vec::new();
    for result in rdr.records() {
        let record = result.map_err(|e| format!("Failed to read CSV row: {}", e))?;
        let row_fields = record.iter().map(|f| f.to_string()).collect::<Vec<String>>();
        records.push(row_fields);
    }

    if records.is_empty() {
        return Err("Empty CSV file".to_string());
    }

    let headers = records.remove(0);
    Ok((headers, records))
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

    if let Ok((headers, _)) = read_csv_records(file_path) {
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

    with_import_transaction(conn, || {
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
    })
}

/// Parses a Brave / Google Chrome unencrypted CSV export and inserts the entries.
pub fn import_brave_chrome_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let name_idx = norm_headers.iter().position(|h| h == "name").ok_or("Missing 'name' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for fields in records {
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
    })
}

/// Parses a Firefox unencrypted CSV export and inserts the entries.
pub fn import_firefox_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for fields in records {
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
    })
}

/// Parses a LastPass unencrypted CSV export and inserts the entries.
pub fn import_lastpass_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let name_idx = norm_headers.iter().position(|h| h == "name").ok_or("Missing 'name' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let extra_idx = norm_headers.iter().position(|h| h == "extra").ok_or("Missing 'extra' (notes) column")?;
    let group_idx = norm_headers.iter().position(|h| h == "grouping").ok_or("Missing 'grouping' column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for fields in records {
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
    })
}

/// Parses a KeePassXC unencrypted CSV export and inserts the entries.
pub fn import_keepassxc_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let group_idx = norm_headers.iter().position(|h| h == "group").ok_or("Missing 'group' column")?;
    let title_idx = norm_headers.iter().position(|h| h == "title").ok_or("Missing 'title' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let notes_idx = norm_headers.iter().position(|h| h == "notes").ok_or("Missing 'notes' column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for fields in records {
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
    })
}

/// Parses a 1Password unencrypted CSV export and inserts the entries.
pub fn import_onepassword_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let title_idx = norm_headers.iter().position(|h| h == "title").ok_or("Missing 'title' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    // Not every 1Password export template includes a notes column, and
    // detect_format() never requires one either -- treat it as optional rather
    // than failing an otherwise-valid, correctly-detected import over its
    // absence (matching the leniency already given to url/website below).
    let notes_idx = norm_headers.iter().position(|h| h == "notes");

    // 1Password might use either "url" or "website" as URL column
    let url_idx = norm_headers.iter().position(|h| h == "url")
        .or_else(|| norm_headers.iter().position(|h| h == "website"))
        .ok_or("Missing URL / Website column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for fields in records {
            let mut max_idx = std::cmp::max(title_idx, std::cmp::max(user_idx, std::cmp::max(pass_idx, url_idx)));
            if let Some(idx) = notes_idx {
                max_idx = std::cmp::max(max_idx, idx);
            }
            if fields.len() <= max_idx {
                continue;
            }

            let title = &fields[title_idx];
            let username = &fields[user_idx];
            let password = &fields[pass_idx];
            let notes = notes_idx.map(|idx| fields[idx].as_str()).unwrap_or("");
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
    })
}

/// Escapes fields containing commas, quotes, or newlines according to standard RFC 4180 CSV specifications.
fn escape_csv_cell(val: &str) -> String {
    // A cell starting with =, +, -, or @ is interpreted as a formula by Excel/
    // LibreOffice/Google Sheets when the CSV is opened -- so a synced vault
    // entry planted on one device (title, username, or note) becomes code
    // execution on whichever device later exports and opens the CSV. Prefixing
    // with a single quote forces spreadsheet apps to treat it as literal text.
    let needs_formula_guard = matches!(
        val.as_bytes().first(),
        Some(b'=') | Some(b'+') | Some(b'-') | Some(b'@')
    );
    let val = if needs_formula_guard {
        format!("'{}", val)
    } else {
        val.to_string()
    };
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        let escaped = val.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        val
    }
}

/// Exports decrypted vault secrets to an unencrypted CSV file (optionally filtered by a set of record IDs).
pub fn export_vault_csv(
    conn: &Connection,
    output_path: &str,
    key: &[u8; 32],
    filter_ids: Option<&std::collections::HashSet<i64>>,
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
        if let Some(ids) = filter_ids {
            if !ids.contains(&r.id) {
                continue;
            }
        }
        
        let decrypted_pass: Zeroizing<String> = crate::crypto::decrypt(&r.encrypted_password, key)
            .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
            .unwrap_or_else(|_| Zeroizing::new(String::new()));

        let decrypted_notes: Zeroizing<String> = match &r.encrypted_notes {
            Some(notes_blob) => crate::crypto::decrypt(notes_blob, key)
                .map(|dec| Zeroizing::new(String::from_utf8_lossy(&dec).to_string()))
                .unwrap_or_else(|_| Zeroizing::new(String::new())),
            None => Zeroizing::new(String::new()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc4180_csv_import() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("test_import.csv");
        let file_path_str = file_path.to_str().unwrap();

        let csv_content = "\
url,username,password,httprealm
\"https://example.com\",\"my_user\",\"super,\"\"secret\"\"\",\"realm1\"
\"https://another.com\",\"user2\",\"pass\nwith\nnewlines\",\"realm2\"
";
        std::fs::write(&file_path, csv_content).unwrap();

        let key = [0u8; 32];
        let count = import_firefox_csv(&conn, file_path_str, &key).unwrap();
        assert_eq!(count, 2);

        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 2);

        let s1 = secrets.iter().find(|s| s.username == "my_user").unwrap();
        let dec1 = crate::crypto::decrypt(&s1.encrypted_password, &key).unwrap();
        assert_eq!(String::from_utf8(dec1.to_vec()).unwrap(), "super,\"secret\"");

        let s2 = secrets.iter().find(|s| s.username == "user2").unwrap();
        let dec2 = crate::crypto::decrypt(&s2.encrypted_password, &key).unwrap();
        assert_eq!(String::from_utf8(dec2.to_vec()).unwrap(), "pass\nwith\nnewlines");

        let _ = std::fs::remove_file(&file_path);
    }

    #[test]
    fn import_transaction_rolls_back_all_rows_on_failure() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        // Simulates a real importer that successfully inserts a couple of rows
        // before hitting a failure on a later one -- the whole batch should be
        // undone, not left half-committed while being reported as failed.
        let result = with_import_transaction(&conn, || {
            db::add_secret(&conn, "One", "Cat", "user", "", "pw1", None, &key)?;
            db::add_secret(&conn, "Two", "Cat", "user", "", "pw2", None, &key)?;
            Err("simulated failure partway through the import".to_string())
        });

        assert!(result.is_err());
        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert!(
            secrets.is_empty(),
            "expected the failed import to leave no rows behind, found: {:?}",
            secrets.iter().map(|s| &s.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn import_transaction_commits_all_rows_on_success() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let result = with_import_transaction(&conn, || {
            db::add_secret(&conn, "One", "Cat", "user", "", "pw1", None, &key)?;
            db::add_secret(&conn, "Two", "Cat", "user", "", "pw2", None, &key)?;
            Ok(2)
        });

        assert_eq!(result, Ok(2));
        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn onepassword_csv_without_notes_column_is_detected_and_imports() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_1password_no_notes_{}.csv", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        // No "notes" column, no "group" column -- detect_format() has always
        // classified this as 1Password since it never checks for notes; the
        // importer used to then fail on that same file with "Missing 'notes'
        // column" despite having just been confidently detected.
        let csv_content = "title,username,password,url\nGitHub,me,hunter2,https://github.com\n";
        std::fs::write(&file_path, csv_content).unwrap();

        assert_eq!(detect_format(file_path_str).unwrap(), ImportFormat::OnePasswordCsv);

        let count = import_onepassword_csv(&conn, file_path_str, &key).unwrap();
        assert_eq!(count, 1);

        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].encrypted_notes, None);

        let _ = std::fs::remove_file(&file_path);
    }
}

