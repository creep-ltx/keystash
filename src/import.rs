use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use rusqlite::Connection;
use zeroize::{Zeroize, Zeroizing};

use crate::db;

/// Runs `body` (which inserts rows one at a time via `db::add_secret`, each
/// normally its own auto-committed statement) inside a single explicit
/// transaction, so a failure partway through an import rolls back everything
/// inserted so far instead of leaving a partial, silently-inconsistent import
/// while still reporting the whole operation as failed.
fn with_import_transaction<T, F>(conn: &Connection, body: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
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
    KeyStashCsv,
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
            ImportFormat::KeyStashCsv => "KeyStash (CSV)",
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

/// Zeroizes every field of a parsed CSV row -- particularly the plaintext
/// password one of them holds -- instead of letting the whole row drop with
/// its contents intact in already-freed heap memory. Every field gets wiped
/// rather than just the password one: which index is the password varies
/// per format, and there's no downside to also wiping title/username/url/etc.
fn wipe_row(fields: &mut [String]) {
    for field in fields {
        field.zeroize();
    }
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
        let has = |name: &str| norm_headers.iter().any(|h| h == name);

        // Checked most-specific-first: some formats' header sets are strict
        // supersets of another's (a LastPass export contains all four
        // Brave/Chrome columns, a KeyStash export satisfies the 1Password
        // check), so a generic check running earlier would shadow the
        // specific format and silently route its rows through the wrong
        // importer -- dropping whatever columns the generic importer
        // doesn't read.

        // KeyStash's own export: the exact six columns export_vault_csv writes.
        if norm_headers.len() == 6 && has("title") && has("url") && has("username") && has("password") && has("notes") && has("category") {
            return Ok(ImportFormat::KeyStashCsv);
        }

        // LastPass: 'extra' (notes) + 'fav' appear in no other supported format.
        if has("url") && has("username") && has("password") && has("extra") && has("fav") {
            return Ok(ImportFormat::LastPassCsv);
        }

        // Firefox: 'httprealm' is unique to it.
        if has("url") && has("username") && has("password") && has("httprealm") {
            return Ok(ImportFormat::FirefoxCsv);
        }

        // KeePassXC: 'group' alongside title/username/password/notes.
        if has("group") && has("title") && has("username") && has("password") && has("notes") {
            return Ok(ImportFormat::KeePassXcCsv);
        }

        // Brave/Chrome: the generic name/url/username/password quartet.
        if has("name") && has("url") && has("username") && has("password") {
            return Ok(ImportFormat::BraveChromeCsv);
        }

        // 1Password: title-based, with either 'website' or 'url'.
        if has("title") && has("username") && has("password") && (has("website") || has("url")) && !has("group") {
            return Ok(ImportFormat::OnePasswordCsv);
        }
    }

    Err("Unknown or unsupported export file format.".to_string())
}

/// Parses a Bitwarden unencrypted JSON export and inserts the entries into
/// KeyStash database. Bitwarden items carry a type (1 = Login, 2 = Secure
/// Note, 3 = Card, 4 = Identity) -- KeyStash only has a `password`/`notes`
/// shape to put them in, so non-login items are skipped rather than
/// imported with a fabricated `[Secure Note]` password (which previously
/// mislabeled cards and identities too, and created a credential-shaped
/// record holding no actual credential). Returns `(imported, skipped)`.
pub fn import_bitwarden_json(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<(usize, usize), String> {
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
        let mut skipped_count = 0;

        if let Some(items) = export.items {
            for item in items {
                // item_type 1 is Login; everything else (Secure Note, Card,
                // Identity) has no password field to speak of.
                if item.item_type != 1 {
                    skipped_count += 1;
                    continue;
                }

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
                    if let Some(uris) = &login.uris
                        && !uris.is_empty()
                            && let Some(uri) = &uris[0].uri {
                                url = uri.clone();
                            }
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
                password.zeroize();
                import_count += 1;
            }
        }

        Ok((import_count, skipped_count))
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
        for mut fields in records {
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
            wipe_row(&mut fields);
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
        for mut fields in records {
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
            wipe_row(&mut fields);
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
        for mut fields in records {
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
            wipe_row(&mut fields);
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
        for mut fields in records {
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
            wipe_row(&mut fields);
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
        for mut fields in records {
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
            wipe_row(&mut fields);
            count += 1;
        }

        Ok(count)
    })
}

/// Parses a KeyStash CSV export (the exact file `export_vault_csv` writes) and
/// inserts the entries. Unlike the 1Password path these files used to be routed
/// through, this preserves each record's original category instead of
/// hardcoding one.
pub fn import_keystash_csv(
    conn: &Connection,
    file_path: &str,
    key: &[u8; 32],
) -> Result<usize, String> {
    let (headers, records) = read_csv_records(file_path)?;
    let norm_headers: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();

    let title_idx = norm_headers.iter().position(|h| h == "title").ok_or("Missing 'title' column")?;
    let url_idx = norm_headers.iter().position(|h| h == "url").ok_or("Missing 'url' column")?;
    let user_idx = norm_headers.iter().position(|h| h == "username").ok_or("Missing 'username' column")?;
    let pass_idx = norm_headers.iter().position(|h| h == "password").ok_or("Missing 'password' column")?;
    let notes_idx = norm_headers.iter().position(|h| h == "notes").ok_or("Missing 'notes' column")?;
    let cat_idx = norm_headers.iter().position(|h| h == "category").ok_or("Missing 'category' column")?;

    with_import_transaction(conn, || {
        let mut count = 0;
        for mut fields in records {
            let max_idx = std::cmp::max(title_idx, std::cmp::max(url_idx, std::cmp::max(user_idx, std::cmp::max(pass_idx, std::cmp::max(notes_idx, cat_idx)))));
            if fields.len() <= max_idx {
                continue;
            }

            let title = &fields[title_idx];
            let url = &fields[url_idx];
            let username = &fields[user_idx];
            let password = &fields[pass_idx];
            let notes = &fields[notes_idx];
            let category = &fields[cat_idx];

            if title.is_empty() && password.is_empty() {
                continue;
            }

            let display_title = if title.is_empty() { url } else { title };
            let display_category = if category.is_empty() { "Imported" } else { category };

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
            wipe_row(&mut fields);
            count += 1;
        }

        Ok(count)
    })
}

/// Escapes fields containing commas, quotes, or newlines according to standard
/// RFC 4180 CSV specifications. Applies the formula-injection guard below --
/// use `escape_csv_cell_password` instead for the password column, which must
/// not be silently mutated.
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
    escape_csv_quoting(&val)
}

/// Same RFC 4180 quoting as `escape_csv_cell`, but deliberately *without* the
/// formula-injection guard. Applying that guard to the password column
/// silently prepends a `'` to any password starting with =, +, -, or @ --
/// KeyStash never opens exported CSVs in a spreadsheet app itself, so the
/// guard buys nothing here, but it does mean a restore from that backup
/// restores a permanently wrong password with no warning (and `-` is a
/// common leading character for generated passwords, so this isn't exotic).
/// title/username/notes/url/category keep the guard via `escape_csv_cell`
/// since those routinely do get opened in spreadsheet tools.
fn escape_csv_cell_password(val: &str) -> Zeroizing<String> {
    Zeroizing::new(escape_csv_quoting(val))
}

fn escape_csv_quoting(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        let escaped = val.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        val.to_string()
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
        if let Some(ids) = filter_ids
            && !ids.contains(&r.id) {
                continue;
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
        
        // Built as Zeroizing<String> rather than a plain format! temporary --
        // it embeds the plaintext password, so it shouldn't drop unwiped any
        // more than decrypted_pass itself should (the destination file is
        // plaintext CSV either way, but the in-memory copy still shouldn't
        // linger past this point).
        let row: Zeroizing<String> = Zeroizing::new(format!(
            "{},{},{},{},{},{}",
            escape_csv_cell(&r.title),
            escape_csv_cell(&r.url),
            escape_csv_cell(&r.username),
            escape_csv_cell_password(&decrypted_pass).as_str(),
            escape_csv_cell(&decrypted_notes),
            escape_csv_cell(&r.category)
        ));

        writeln!(file, "{}", row.as_str()).map_err(|e| e.to_string())?;
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
    fn export_import_round_trip_preserves_formula_leading_password_and_category() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        // "=1+1" starts with '=' -- exactly what the formula-injection guard
        // used to (wrongly) prefix with a literal quote on export.
        db::add_secret(&conn, "Bank", "Finance", "alice", "https://bank.example", "=1+1", None, &key).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_export_roundtrip_{}.csv", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        export_vault_csv(&conn, file_path_str, &key, None).unwrap();

        let conn2 = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn2).unwrap();
        assert_eq!(detect_format(file_path_str).unwrap(), ImportFormat::KeyStashCsv);
        let count = import_keystash_csv(&conn2, file_path_str, &key).unwrap();
        assert_eq!(count, 1);

        let secrets = crate::db::get_secrets(&conn2).unwrap();
        assert_eq!(secrets.len(), 1);
        let dec = crate::crypto::decrypt(&secrets[0].encrypted_password, &key).unwrap();
        assert_eq!(
            String::from_utf8(dec.to_vec()).unwrap(),
            "=1+1",
            "an =-leading password must round-trip byte-equal, not pick up a formula-guard prefix"
        );
        assert_eq!(
            secrets[0].category, "Finance",
            "custom category must be preserved, not routed through the 1Password 'Imported' fallback"
        );

        let _ = std::fs::remove_file(&file_path);
    }

    #[test]
    fn bitwarden_import_skips_non_login_items_instead_of_faking_a_password() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_bitwarden_{}.json", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        // type 1 = Login, 2 = Secure Note, 3 = Card, 4 = Identity.
        let json = r#"{
            "folders": [],
            "items": [
                {"type": 1, "name": "GitHub", "folderId": null, "notes": null,
                 "login": {"username": "alice", "password": "hunter2", "uris": []}},
                {"type": 2, "name": "Wifi recovery codes", "folderId": null, "notes": "some secret text"},
                {"type": 3, "name": "Visa", "folderId": null, "notes": null},
                {"type": 4, "name": "Passport", "folderId": null, "notes": null}
            ]
        }"#;
        std::fs::write(&file_path, json).unwrap();

        let (imported, skipped) = import_bitwarden_json(&conn, file_path_str, &key).unwrap();
        assert_eq!(imported, 1, "only the Login item should be imported");
        assert_eq!(skipped, 3, "the note/card/identity items should be counted as skipped");

        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].title, "GitHub");
        let dec = crate::crypto::decrypt(&secrets[0].encrypted_password, &key).unwrap();
        assert_eq!(
            String::from_utf8(dec.to_vec()).unwrap(),
            "hunter2",
            "the imported login's real password must round-trip, not a fabricated placeholder"
        );

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
        let result: Result<usize, String> = with_import_transaction(&conn, || {
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
    fn detect_format_routes_each_supported_header_set_correctly() {
        let cases: &[(&str, ImportFormat)] = &[
            // LastPass headers contain all four Brave/Chrome columns; the old
            // generic-first check order routed these through the Brave
            // importer, silently dropping notes ('extra') and folders
            // ('grouping') from every LastPass import.
            ("url,username,password,totp,extra,name,grouping,fav", ImportFormat::LastPassCsv),
            ("name,url,username,password", ImportFormat::BraveChromeCsv),
            ("url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged", ImportFormat::FirefoxCsv),
            ("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"", ImportFormat::KeePassXcCsv),
            ("Title,Username,Password,Website,Notes", ImportFormat::OnePasswordCsv),
            // KeyStash's own export satisfies the 1Password check too (title +
            // username + password + url), so it must be matched exactly, first.
            ("title,url,username,password,notes,category", ImportFormat::KeyStashCsv),
        ];

        let temp_dir = std::env::temp_dir();
        for (i, (header, expected)) in cases.iter().enumerate() {
            let file_path = temp_dir.join(format!("test_detect_format_{}_{}.csv", std::process::id(), i));
            std::fs::write(&file_path, format!("{}\n", header)).unwrap();
            let detected = detect_format(file_path.to_str().unwrap());
            let _ = std::fs::remove_file(&file_path);
            assert_eq!(detected.unwrap(), *expected, "wrong format for header {:?}", header);
        }
    }

    #[test]
    fn lastpass_import_preserves_notes_and_folders() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_lastpass_{}.csv", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        let csv_content = "\
url,username,password,totp,extra,name,grouping,fav
https://bank.example.com,me,hunter2,,recovery codes: 1111 2222,Example Bank,Banking,0
";
        std::fs::write(&file_path, csv_content).unwrap();

        // End-to-end through detection, not just the importer: the regression
        // was detect_format handing this file to the Brave importer.
        assert_eq!(detect_format(file_path_str).unwrap(), ImportFormat::LastPassCsv);

        let count = import_lastpass_csv(&conn, file_path_str, &key).unwrap();
        let _ = std::fs::remove_file(&file_path);
        assert_eq!(count, 1);

        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].title, "Example Bank");
        assert_eq!(secrets[0].category, "Banking", "the 'grouping' folder must survive the import");
        let notes = crate::crypto::decrypt(secrets[0].encrypted_notes.as_ref().unwrap(), &key).unwrap();
        assert_eq!(&*notes, b"recovery codes: 1111 2222", "the 'extra' notes must survive the import");
    }

    #[test]
    fn keystash_csv_import_preserves_category_and_notes() {
        let key = [0u8; 32];
        let sqlcipher_key = crate::crypto::derive_sqlcipher_key(&key);
        let conn = crate::db::open_keyed_connection(":memory:", &sqlcipher_key).unwrap();
        crate::db::ensure_schema(&conn).unwrap();

        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("test_keystash_native_{}.csv", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        // Exactly the header export_vault_csv writes.
        let csv_content = "\
title,url,username,password,notes,category
GitHub,https://github.com,me,hunter2,my note,Dev
";
        std::fs::write(&file_path, csv_content).unwrap();

        assert_eq!(detect_format(file_path_str).unwrap(), ImportFormat::KeyStashCsv);

        let count = import_keystash_csv(&conn, file_path_str, &key).unwrap();
        let _ = std::fs::remove_file(&file_path);
        assert_eq!(count, 1);

        let secrets = crate::db::get_secrets(&conn).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].title, "GitHub");
        assert_eq!(secrets[0].category, "Dev", "round-trips must keep the original category, not hardcode one");
        assert_eq!(secrets[0].url, "https://github.com");
        let pass = crate::crypto::decrypt(&secrets[0].encrypted_password, &key).unwrap();
        assert_eq!(&*pass, b"hunter2");
        let notes = crate::crypto::decrypt(secrets[0].encrypted_notes.as_ref().unwrap(), &key).unwrap();
        assert_eq!(&*notes, b"my note");
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

