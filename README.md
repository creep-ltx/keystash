# KeyStash 🔑

`KeyStash` is a lightweight, secure, and completely offline Terminal User Interface (TUI) secret and password manager written in Rust. It stores credentials locally in an SQLite database, encrypts individual sensitive fields using XChaCha20-Poly1305, derives encryption keys with Argon2id, and supports unencrypted Bitwarden JSON exports.

---

## 📂 Vault Database Storage Path

Your credentials database is stored offline inside your user config folder:
* **Linux/macOS:** `~/.config/keystash/vault.db`

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

## 🔒 Security & Cryptographic Model

1. **Argon2id Key Derivation:** When you supply your Master Password, a 256-bit symmetric key is derived using Argon2id. The unique salt is generated via the OS's cryptographically secure pseudo-random number generator (CSPRNG) and saved in the database.
2. **XChaCha20-Poly1305 AEAD:** Sensitive columns (`password` and `notes`) are encrypted individually before being stored. Every column write generates a unique 192-bit nonce to protect against patterns or dictionary attacks.
3. **Password Verification Token:** On setup, a static validation string is encrypted. KeyStash attempts to decrypt this string during unlock; if it fails, access is denied without exposing or keeping the master password in memory.
4. **Memory Cleansing:** Raw buffers, master password strings, and derived keys are zeroized immediately after use.

---

## 🚀 Keyboard Shortcuts (TUI)

| Key | Action |
|:---|:---|
| `[Tab]` | Toggle focus between panels (Categories ➔ Credentials ➔ Details) |
| `[↑]` / `[↓]` | Scroll up/down through lists |
| `[PgUp]` / `[PgDn]` | Page up/down (moves selection by 10 items in secrets, 5 items in categories) |
| `[Space]` | Mark / Unmark selected credential |
| `[/]` | Activate search bar (Type query ➔ Press `[Enter]` or `[Esc]` to exit search input) |
| `[v]` | Toggle password visibility in detail pane |
| `[c]` | Copy username to clipboard (clears in 10s) |
| `[p]` | Copy decrypted password to clipboard (clears in 10s) |
| `[u]` | Copy website URL to clipboard (clears in 10s) |
| `[a]` | Add new credential |
| `[e]` | Edit selected credential |
| `[d]` | Delete credential (opens verification modal) |
| `[Esc]` | Cancel form, exit modal, or close the application |

---

## 📥 Installation

To run `keystash` globally from anywhere on your system, build and install the binary using Cargo:

```bash
# Clone the repository and navigate inside
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

---

## 💻 CLI Subcommand Reference

By default, executing `keystash` with no arguments starts the TUI. The following subcommands can be passed:

* **TUI Dashboard (Default):**
  ```bash
  keystash
  ```
* **Initialize Vault:**
  ```bash
  keystash init
  ```
* **List Decrypted Credentials:**
  ```bash
  keystash list [--reveal]
  ```
  *(Passwords are masked by default. Pass `--reveal` or `-r` to show them in plaintext)*
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
* **Copy Secret Field to Clipboard:**
  ```bash
  keystash copy <ID> [username|password|url]
  ```
  *(Copies target field to system clipboard and automatically clears it after 10 seconds. Defaults to password)*
* **Insert a Secret:**
  ```bash
  keystash add <Title> <Category> <Username> [URL]
  ```
  *(Prompt will safely hide your password keystrokes during entry)*
* **Import from Bitwarden:**
  ```bash
  keystash import-bitwarden <path/to/bitwarden_export.json>
  ```
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
  *(Triggers a manual logical merge and push to origin/main)*
* **Change Master Password (Key Rotation):**
  ```bash
  keystash change-password
  ```
  *(Decrypts all vault items using your old password and re-encrypts them with a newly derived key and salt)*

---

## 🔄 Git Synchronization & Logical Merging

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
* **TUI Startup Sync:** When you run `keystash` in TUI mode, it fetches and logically merges any remote changes before showing you the Master Password lock screen.
* **Background Change Sync:** Adding, editing, or deleting a credential triggers a non-blocking background thread to merge and push changes instantly to GitHub.
* **TUI Exit Sync:** Syncs updates on exit so your latest changes are immediately pushed to remote.
* **Tombstones:** Deleted credentials write to a `deleted_secrets` database table, allowing deletions to sync across machines without restoring themselves as phantom items.
* **Logical Database Merge:** Compares records using natural keys (`Title + Category + Username`). If a record has changed on both sides, the version with the newer `updated_at` timestamp is kept.

---

## 📦 Dependencies

KeyStash relies exclusively on safe and audited pure-Rust libraries:
- `ratatui` & `crossterm` for drawing interactive terminal screens.
- `rusqlite` (with bundled features) for local SQLite database integrations.
- `chacha20poly1305` & `argon2` for modern cryptography.
- System clipboard utilities (`wl-copy`, `xclip`, `xsel`) for native Wayland and X11 clipboard integration.
- `rpassword` for secure CLI console prompt input masking.
- `serde` & `serde_json` for parsing JSON vault imports.
