# KeyStash 🔑

`KeyStash` is a lightweight, secure, and completely offline Terminal User Interface (TUI) secret and password manager written in Rust. It stores credentials locally in an SQLite database, encrypts individual sensitive fields using XChaCha20-Poly1305, derives encryption keys with Argon2id, and supports unencrypted Bitwarden JSON exports.

---

## 🛠️ Features

### 🖥️ Interactive TUI Dashboard
- **Split-Pane Layout:** Sidebar for category filtering, text-based query search, and a rich credential detail panel.
- **Stateful Viewports:** Full list scrolling support (automatically keeps selected rows in view) with support for PageUp / PageDown.
- **Secure Copy Shortcuts:** Copy username, password, or website URLs directly to your clipboard.
- **Auto-Clearing Clipboard:** Clipboard data is automatically cleared after 10 seconds to mitigate memory leakage and snooping.
- **Multi-Select Mass Deletion:** Mark multiple secrets using the Spacebar and batch-delete them all at once.
- **Delete Confirmations:** Warning prompts on single or mass deletions to prevent accidental loss of data.
- **First-Time Setup Wizard:** Guides you through setting up a master password on your initial run.

### ⌨️ CLI Subcommands
For rapid scripts, pipeline automations, or terminal shortcuts, `KeyStash` exposes a full CLI module.

---

## 📥 Installation & Vault Path

### 1. Install via Crates.io (Recommended)
You can install the latest released binary directly from the official Rust package registry:
```bash
cargo install keystash
```

### 2. Install from Source
If you prefer to compile the latest development version from the repository:
```bash
# Clone the repository and navigate inside
git clone https://github.com/creep-ltx/keystash.git
cd keystash

# Install the binary to ~/.cargo/bin
cargo install --path .
```

To install the manual page (`man keystash`), copy it to your local man pages directory:
```bash
# Install the man page to your local user directory
mkdir -p ~/.local/share/man/man1
cp keystash.1 ~/.local/share/man/man1/
```

### 📂 Vault Database Storage Path
Your credentials database is stored offline inside your user config folder:
* **Linux/macOS:** `~/.config/keystash/vault.db`

---

## 🚀 Keyboard Shortcuts (TUI)

| Key | Action |
| :--- | :--- |
| **`[Tab]`** / **`[Shift+Tab]`** | Toggle focus between panels (Categories ➔ Credentials ➔ Details) forward/backward |
| **`[↑]` / `[↓]`** | Scroll up/down through lists |
| **`[PgUp]` / `[PgDn]`** | Page up/down (moves selection by 10 items in secrets, 5 items in categories) |
| **`[Space]`** | Mark / Unmark selected credential |
| **`[/]`** | Activate search bar (Type query ➔ Press `[Enter]` or `[Esc]` to exit search input) |
| **`[v]`** | Toggle password visibility in detail pane |
| **`[c]`** | Copy username to clipboard (clears in configured delay, default 10s) |
| **`[p]`** | Copy decrypted password to clipboard (clears in configured delay, default 10s) |
| **`[u]`** | Copy website URL to clipboard (clears in configured delay, default 10s) |
| **`[a]`** | Add new credential |
| **`[e]`** | Edit selected credential |
| **`[d]`** | Delete credential (opens verification modal) |
| **`[h]`** | Check selected (or marked) password on HaveIBeenPwned |
| **`[H]`** | Check all credentials in vault on HaveIBeenPwned (runs in background) |
| **`[D]`** | Open duplicate credential detector and interactive resolver |
| **`[,]`** | Open KeyStash settings screen (edit timeouts, delays, presets, etc.) |
| **`[i]`** | Import unencrypted credentials from backups |
| **`[x]`** | Export credentials (all or selected) to CSV |
| **`[?]`** | Open Help dialog |
| **`[Esc]`** | Cancel form, exit modal, or close the application |

---

## 💻 CLI Subcommand Reference

By default, executing `keystash` with no arguments starts the TUI. The following subcommands can be passed:

* **TUI Dashboard (Default):**
  ```bash
  keystash [--no-sync]
  ```
  *(Pass `--no-sync` to start in offline mode and disable remote sync)*
* **Initialize Vault:**
  ```bash
  keystash init
  ```
* **List Decrypted Credentials:**
  ```bash
  keystash list [--reveal]
  ```
  *(Passwords are masked by default. Pass `--reveal` or `-r` to show them in plaintext)*
  > [!WARNING]
  > Running `keystash list --reveal` outputs all decrypted credentials in plaintext directly into your terminal scrollback buffer. Use with caution or pipe it to `less` to prevent screen/scrollback logs exposure.
* **Search Vault:**
  ```bash
  keystash search <query> [--reveal]
  ```
  *(Passwords are masked by default. Pass `--reveal` or `-r` to show them in plaintext)*
* **Show Detailed Secret:**
  ```bash
  keystash show <ID> [--reveal]
  ```
  *(Shows detailed fields of a secret; passwords and notes are masked by default unless `--reveal` or `-r` is provided)*
* **Generate Password:**
  ```bash
  keystash generate [-l <length>] [--no-uppercase] [--no-numbers] [--no-symbols] [--uppercase] [--numbers] [--symbols]
  ```
  *(Generates a random secure password, avoiding visually ambiguous characters. Saves choices as your new defaults)*
* **Copy Secret Field to Clipboard:**
  ```bash
  keystash copy <ID> [username|password|url]
  ```
  *(Copies target field to system clipboard and automatically clears it after 10 seconds. Defaults to password)*
* **Insert a Secret:**
  ```bash
  keystash add <Title> <Category> <Username> [URL]
  ```
  *Note: Double quotes are mandatory for arguments containing spaces (e.g. `keystash add "My Google Account" "Email" "user@gmail.com"`)*
* **Import Credentials:**
  ```bash
  keystash import <path/to/backup_file>
  ```
  *(Detects and imports unencrypted formats: Bitwarden JSON, Brave/Chrome CSV, Firefox CSV, LastPass CSV, KeePassXC CSV, and 1Password CSV)*
* **Export Credentials:**
  ```bash
  keystash export <path/to/output_file.csv>
  ```
  *(Decrypts and exports all vault entries to an unencrypted CSV file with restricted 0600 file permissions)*
* **Delete a Secret:**
  ```bash
  keystash delete <ID>
  ```
* **Nuke/Reset Vault:**
  ```bash
  keystash reset
  ```
  *(Deletes the `vault.db` file completely after a verification prompt)*
* **Manual Git Sync:**
  ```bash
  keystash sync
  ```
  *(Triggers a manual logical merge and push to origin/main, or restores a missing local database)*
* **Change Master Password (Key Rotation):**
  ```bash
  keystash change-password
  ```
  *(Decrypts all vault items using your old password and re-encrypts them with a newly derived key and salt)*

---

## 🔒 Security & Cryptographic Model

1. **Symmetric Encryption Split (Plaintext vs Encrypted Fields):**
   To support logical merging and search across multiple devices, **only sensitive fields (`password` and `notes`) are encrypted**. Database metadata—specifically `title`, `category`, `username`, `url`, and transaction timestamps—are stored in **unencrypted plaintext** inside the SQLite file.
   > [!IMPORTANT]
   > Because metadata is stored in plaintext, users must be aware that repository names, websites, categories, and usernames will be visible to anyone with read access to their private Git backup repository.
2. **Argon2id Key Derivation:** When you supply your Master Password, a 256-bit symmetric key is derived using Argon2id. The unique salt is generated via the OS's cryptographically secure pseudo-random number generator (CSPRNG) and saved in the database.
3. **XChaCha20-Poly1305 AEAD:** The sensitive fields are encrypted individually before being stored. Every column write generates a unique 192-bit nonce to protect against patterns or dictionary attacks.
4. **Password Verification Token:** On setup, a static validation string is encrypted. KeyStash attempts to decrypt this string during unlock; if it fails, access is denied without exposing or keeping the master password in memory.
5. **Memory Cleansing:** Raw buffers, master password strings, and derived keys are zeroized immediately after use. TUI password inputs are pre-allocated at a fixed capacity and cleared/zeroized in-place to prevent heap reallocation remnants.
6. **Clipboard Security:** KeyStash automatically clears copied credentials from the clipboard after 10 seconds. Note that some clipboard history managers (like CopyQ, Greenclip, or desktop environment utilities) may intercept copied text immediately. For absolute security, configure your clipboard manager to ignore or blacklist the `keystash` binary.
7. **Schema Migrations:** Database schema integrity checks and upgrades are performed automatically on startup using a custom embedded migrations mechanism.

---

## 🔄 Git Synchronization & Logical Merging

> [!NOTE]
> KeyStash automatically detects if your database configuration folder has a Git repository and remote configured. If no Git repository is present, KeyStash defaults to local-only offline mode without showing any warnings. The `--no-sync` flag is optional and can be used to temporarily disable Git network sync actions even if a remote is configured.

If you configure your local config folder `~/.config/keystash` as a Git repository linked to a private remote, `keystash` will automatically synchronize your credentials database across all your devices using high-performance two-way logical database merging:

### 1. One-time Setup

#### **Device A (Your First/Existing Vault Device)**
To upload your existing vault database to GitHub for the first time:
```bash
cd ~/.config/keystash
git init

# Track only the encrypted database
echo "*" > .gitignore
echo "!vault.db" >> .gitignore

# Link your private remote (e.g. GitHub)
git remote add origin git@github.com:YOUR_USERNAME/my-keystash-vault.git
git branch -M main

# Stage and push the initial version
git add .
git commit -m "Initial vault backup"
git push -u origin main
```

#### **Device B (Adding a New/Secondary Device)**
> [!WARNING]
> **DO NOT run `keystash init` on a secondary device.** If you do, it will generate a new database salt and your master password keys will not match, causing decryption errors.
> 
> Instead, clone the existing database file from GitHub directly:

```bash
# Create and enter the config folder
mkdir -p ~/.config/keystash
cd ~/.config/keystash

# Initialize Git and link origin
git init
echo "*" > .gitignore
echo "!vault.db" >> .gitignore
git remote add origin git@github.com:YOUR_USERNAME/my-keystash-vault.git
git branch -M main

# Pull down the existing database (clones the salt/key structure)
git pull origin main
```
You can now run `keystash` on Device B, enter your existing Master Password, and sync. Both machines will sync and decrypt seamlessly!

### 2. How it operates
* **TUI Startup Sync:** When you run `keystash` in TUI mode, it starts a non-blocking background thread to pull and logically merge any remote changes concurrent with displaying the Master Password lock screen.
* **Background Change Sync:** Syncs updates on exit so your latest changes are immediately pushed to remote. Runs automatically after bulk CSV imports. Single changes inside the TUI are queued locally until exit to avoid redundant network calls.
* **Tombstones:** Deleted credentials write to a `deleted_secrets` database table, allowing deletions to sync across machines without restoring themselves as phantom items.
* **Logical Database Merge:** Compares records using natural keys (`Title + Category + Username`). If a record has changed on both sides, the version with the newer `updated_at` timestamp is kept.

---

## 📦 Dependencies

KeyStash relies exclusively on safe and audited Rust libraries:
- `ratatui` & `crossterm` for drawing interactive terminal screens.
- `rusqlite` for local SQLite database integrations.
- `chacha20poly1305` & `argon2` for modern cryptography.
- `arboard` for native Wayland and X11 clipboard integration.
- `rpassword` for secure CLI console prompt input masking.
- `serde` & `serde_json` for parsing JSON vault imports.
