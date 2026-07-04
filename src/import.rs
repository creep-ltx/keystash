use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
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

    // Create folders map: folderId -> folderName
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

            // For secure notes (type 2) or other non-login items, they might not have passwords
            // We need a non-empty password to satisfy KeyStash requirements, so default to empty
            // (or note text if preferred, but keeping password as placeholder if it's empty)
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
