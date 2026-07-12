# KeyStash 🔑

`KeyStash` is a lightweight, secure, and completely offline Terminal User Interface (TUI) secret and password manager written in Rust. It stores credentials locally in a SQLCipher-encrypted SQLite database (the entire file, not just individual fields), additionally encrypts `password`/`notes` with XChaCha20-Poly1305 as a second, independent layer, derives encryption keys with Argon2id, and supports unencrypted Bitwarden JSON exports.

Built with AI-assisted development, I handle the auditing, testing, and editorial judgment.

---

## 🛠️ Features

### 🖥️ Interactive TUI Dashboard
- **Split-Pane Layout:** Sidebar for tag filtering, text-based query search, and a rich credential detail panel.
- **Tags:** Every credential can carry multiple comma-separated tags (e.g. `work, email`); the sidebar lists each tag individually and filters on any of them. Tags live in the same field older versions treat as the single category, so vaults, exports, and shared Git remotes stay fully compatible in both directions — no migration, no minimum-version bump.
- **Stateful Viewports:** Full list scrolling support (automatically keeps selected rows in view) with support for PageUp / PageDown.
- **Secure Copy Shortcuts:** Copy username, password, or website URLs directly to your clipboard.
- **Auto-Clearing Clipboard:** Clipboard data is automatically cleared after a configurable delay (default 5 seconds) to mitigate memory leakage and snooping.
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
* If `XDG_CONFIG_HOME` is set, KeyStash uses `$XDG_CONFIG_HOME/keystash/vault.db` instead.
* If neither `HOME` nor `XDG_CONFIG_HOME` is set, KeyStash falls back to `./.config/keystash/vault.db` relative to the current directory, and prints a warning — the vault will only be found again if run from that same directory every time.
* `KEYSTASH_CONFIG_DIR`, if set, overrides all of the above and names the vault's directory directly (no `keystash/` subdirectory appended) — mainly an isolation seam for tests and unusual setups.

---

## 🚀 Keyboard Shortcuts (TUI)

| Key | Action |
| :--- | :--- |
| **`[Tab]`** / **`[Shift+Tab]`** | Toggle focus between panels (Tags ➔ Credentials ➔ Details) forward/backward |
| **`[↑]` / `[↓]`** | Scroll up/down through lists |
| **`[PgUp]` / `[PgDn]`** | Page up/down (moves selection by 10 items in secrets, 5 items in tags) |
| **`[Space]`** | Mark / Unmark selected credential |
| **`[/]`** | Activate search bar (Type query ➔ Press `[Enter]` or `[Esc]` to exit search input) |
| **`[v]`** | Toggle password visibility in detail pane |
| **`[c]`** | Copy username to clipboard (clears in configured delay, default 5s) |
| **`[p]`** | Copy decrypted password to clipboard (clears in configured delay, default 5s) |
| **`[u]`** | Copy website URL to clipboard (clears in configured delay, default 5s) |
| **`[a]`** | Add new credential |
| **`[e]`** | Edit selected credential |
| **`[d]`** | Delete credential (opens verification modal) |
| **`[h]`** | Check selected (or marked) password on HaveIBeenPwned |
| **`[H]`** | Check all credentials in vault on HaveIBeenPwned (runs in background) |
| **`[D]`** | Open duplicate credential detector and interactive resolver |
| **`[,]`** | Open KeyStash settings screen (edit timeouts, delays, presets, etc.) |
| **`[m]`** | Change master password (key rotation) |
| **`[s]`** | Force a manual sync with the Git remote (runs the same conflict detection as the automatic post-unlock sync; works even with Auto Sync off) |
| **`[i]`** | Import unencrypted credentials from backups |
| **`[x]`** | Export credentials (all or selected) to CSV |
| **`[?]`** | Open Help dialog |
| **`[Esc]`** | Cancel form, exit modal, or close the application |
| **`[q]`** | Same as `[Esc]`, except in text-entry fields (Add/Edit form, Change Password, Settings), where it types the letter instead |

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
  *(Passwords are masked by default. Pass `--reveal` or `-r` to show them in plaintext. A query starting with `-` is matched literally as long as it isn't `--reveal`/`-r` themselves; use `keystash search -- -yourquery` to search for a query that collides with a flag name)*
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
  *(Copies target field to system clipboard and automatically clears it after the configured delay (default 5 seconds). Defaults to password)*
* **Insert a Secret:**
  ```bash
  keystash add <Title> <Tags> <Username> [URL]
  ```
  *Note: Tags are comma-separated (e.g. `"work,email"`). Double quotes are mandatory for arguments containing spaces or commas (e.g. `keystash add "My Google Account" "email, personal" "user@gmail.com"`)*
* **Import Credentials:**
  ```bash
  keystash import <path/to/backup_file>
  ```
  *(Detects and imports unencrypted formats: Bitwarden JSON, KeyStash CSV, Brave/Chrome CSV, Firefox CSV, LastPass CSV, KeePassXC CSV, and 1Password CSV)*
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
* **One-time Sync Setup (wizard):**
  ```bash
  keystash sync setup
  ```
  *(Interactively configures the vault directory as a git repo synced to any remote — detects whether this is your first device (pushes the vault) or an additional one (pulls it), writes the `.gitignore`, and verifies the remote is reachable. No master password needed)*
* **Change Master Password (Key Rotation):**
  ```bash
  keystash change-password
  ```
  *(Decrypts all vault items using your old password and re-encrypts them with a newly derived key and salt)*

---

## 🔒 Security & Cryptographic Model

This section describes the mechanisms. For "given a specific compromise, what does an attacker actually get" — SQLCipher-only, field-layer, git-remote (read and write access), and HIBP network exposure — see [THREAT_MODEL.md](THREAT_MODEL.md).

1. **Full-Database Encryption (SQLCipher):** The entire `vault.db` file is encrypted via SQLCipher — schema, indexes, and every column, including `title`, `category` (the column your tags are stored in), `username`, and `url`. Without the correct master password, the file is an opaque blob, not a readable SQLite database; there is no plaintext metadata for anyone with read access to your Git backup repository (or the raw file) to see.
2. **Independent Column-Level Layer:** As defense in depth on top of full-database encryption, `password` and `notes` are *additionally* encrypted individually with XChaCha20-Poly1305, using a key derived independently (via HKDF-SHA256, with domain separation) from the same Argon2id master key. A compromise of the SQLCipher layer alone does not, by itself, expose these fields.
3. **Argon2id Key Derivation:** When you supply your Master Password, a 256-bit master key is derived using Argon2id. The unique salt is generated via the OS's cryptographically secure pseudo-random number generator (CSPRNG) and embedded in the first 16 bytes of `vault.db` itself (the SQLCipher header's salt slot, which is deliberately plaintext) — nothing inside the encrypted database can be read until the key derived from that salt is already known, so the salt must live somewhere readable up front, and keeping it in the file makes the vault a single self-contained unit. Vaults created before v0.3.6 kept the salt in a `vault.salt` sidecar file; they are converted automatically on their first unlock.
4. **XChaCha20-Poly1305 AEAD:** The column-level sensitive fields are encrypted individually before being stored. Every encryption generates a unique 192-bit nonce to protect against patterns or dictionary attacks.
5. **Password Verification Token:** On setup, a static validation string is encrypted. KeyStash attempts to decrypt this string during unlock; if it fails, access is denied without exposing or keeping the master password in memory.
6. **Memory Cleansing:** Raw buffers, master password strings, and derived keys are zeroized immediately after use. TUI password inputs are pre-allocated at a fixed capacity and cleared/zeroized in-place to prevent heap reallocation remnants. Locking the vault (idle timeout or manual lock) also drops the open, keyed SQLCipher connection itself, not just the in-memory key — so the whole-database-encrypted contents aren't left readable through a lingering connection handle while the app sits on the Lock screen.
7. **Clipboard Security:** KeyStash automatically clears copied credentials from the clipboard after the configured delay (default 5 seconds). Note that some clipboard history managers (like CopyQ, Greenclip, or desktop environment utilities) may intercept copied text immediately. For absolute security, configure your clipboard manager to ignore or blacklist the `keystash` binary.
8. **Schema Migrations & Crash Safety:** Database schema integrity checks and upgrades are performed automatically on startup. Both the one-time move to the encrypted database format and a master-password change build the new vault file at a temporary path and swap it into place atomically, rather than modifying the live file in place — if the process is interrupted partway through (crash, power loss), KeyStash detects the leftover backup/temp files on next launch and shows exact recovery instructions instead of mistaking your vault for a fresh install.
9. **Deletion Tombstone Pruning:** Deleting a credential leaves a "tombstone" record behind so the deletion can propagate correctly to your other devices on their next sync, instead of the credential silently reappearing. Tombstones older than 90 days are pruned automatically during sync, so a deleted credential's title and username don't live on in the vault forever. The 90-day window is intentionally generous — it exists to give any device that syncs infrequently enough time to see the deletion before its tombstone disappears.

---

## 🔄 Git Synchronization & Logical Merging

> [!NOTE]
> KeyStash automatically detects if your database configuration folder has a Git repository and remote configured. If no Git repository is present, KeyStash defaults to local-only offline mode without showing any warnings. The `--no-sync` flag is optional and can be used to temporarily disable Git network sync actions even if a remote is configured.

If you configure your local config folder `~/.config/keystash` as a Git repository linked to a private remote, `keystash` will automatically synchronize your credentials database across all your devices using high-performance two-way logical database merging.

> [!TIP]
> **You don't need GitHub.** Any git remote works, because it only ever stores the encrypted vault file: a private GitHub/GitLab repo, any machine you can SSH into (`you@server:vault.git`), or a plain folder on a NAS mount or USB stick (`/mnt/nas/vault.git`) — create the last two with `git init --bare vault.git` at the destination.

### 1. One-time Setup

The easy way, on every device:
```bash
keystash sync setup
```
The wizard detects whether this is your **first device** (a vault already exists locally → it gets pushed as the initial backup) or an **additional device** (no local vault → the existing one is pulled from the remote), asks for the remote URL, verifies it's reachable, and does the rest — including the `.gitignore` and a repo-local git identity if you have none configured. It never needs your master password.

The manual equivalent, if you prefer to see every step:

#### **Device A (Your First/Existing Vault Device)**
To upload your existing vault database to a private remote for the first time:
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
> [!NOTE]
> The Argon2 salt travels embedded inside `vault.db` itself (its first 16 bytes — not secret on its own, it only becomes meaningful combined with your master password), so the one database file is all that needs to sync. Repos created before v0.3.6 also track a `vault.salt` sidecar; KeyStash removes it from the repo automatically on the first sync after all your devices have converted. The `.gitignore` step is belt-and-braces: since v0.4.2, KeyStash writes that exact two-line file automatically on its first sync if it's missing (an existing customized one is never touched).

#### **Device B (Adding a New/Secondary Device)**
> [!WARNING]
> **DO NOT run `keystash init` on a secondary device.** If you do, it will generate a brand new vault (new salt, new empty database) instead of using your existing one, and your master password won't unlock the vault you meant to sync.
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

# Pull down the existing database
git pull origin main
```
You can now run `keystash` on Device B, enter your existing Master Password, and sync. Both machines will sync and decrypt seamlessly!

#### **Rotating your master password with multiple devices**
Changing the master password re-encrypts the whole vault under a fresh salt, so for a short window the remote and your other devices disagree about which password is current. To keep that window painless:

1. **Update KeyStash on every device first** (v0.3.6+). Older versions cannot detect a rotation and could silently push a stale vault over it.
2. Sync every device (open and quit KeyStash, or run `keystash sync`), so no device is holding unpushed changes.
3. Rotate on one device (`keystash change-password` or `[m]` in the TUI). It pushes the rotated vault to the remote automatically.
4. On each other device, run `keystash sync`. It will detect the rotation and refuse to push, printing the exact recovery steps: export any local changes, delete the local `vault.db`, sync again to restore the rotated vault, and unlock with the new password.

If a stale device ever syncs before you get to it, nothing is lost: the rotated remote is left untouched and that device keeps working locally until you walk it through step 4. The reverse race is handled too — if another device pushes an ordinary edit *before* your just-rotated device syncs, the rotating device refuses to push and its recovery steps correctly identify that the rotation was local (restore the remote, unlock with the **old** password, re-import, then redo the rotation), rather than telling you to delete your freshly rotated vault.

### 2. How it operates
* **TUI Startup Sync:** When you run `keystash` in TUI mode, it starts a non-blocking background thread to fetch (but not yet merge) remote changes concurrent with displaying the Master Password lock screen. The database itself is encrypted, so the actual logical merge needs the key and runs immediately after you unlock, before the dashboard appears.
* **Background Change Sync:** Syncs updates on exit so your latest changes are immediately pushed to remote. Runs automatically after bulk CSV imports. Single changes inside the TUI are queued locally until exit to avoid redundant network calls — and a session that changed nothing skips the exit sync entirely.
* **Cheap no-op syncs:** Every sync starts with a fetch and compares the remote's commit against the local one — if nothing moved on either side, the sync ends right there (one small network round trip; no merge work, no push). The remote-moved and local-changed cases run the full logical merge as always. The outcome of every background sync is reported in the TUI — success in the status bar, failures (including a refused push after a master-password rotation elsewhere, which comes with step-by-step recovery instructions) in a dialog.
* **Auto Sync setting:** The Settings screen's *Auto Sync* toggle controls the **automatic** sync actions only — the startup fetch, the post-unlock/post-import merge, and the exit-time push. With it off, KeyStash never touches the network on its own; the manual `[s]` key and `keystash sync` still work whenever you ask. (The `--no-sync` flag is stronger: it disables all sync, manual included, for that session.)
* **Tombstones:** Deleted credentials write to a `deleted_secrets` database table, allowing deletions to sync across machines without restoring themselves as phantom items.
* **Logical Database Merge:** Every record carries a stable, randomly generated sync ID (independent of its title/tags/username, which are freely editable and can coincidentally repeat between records) that merges, updates, and tombstones are all matched on. Every field — title, tags, username, URL, password, notes — is carried through the merge, so renames and re-taggings propagate like any other edit. If a record has changed on both sides, the version with the newer `updated_at` timestamp is kept; if *both* sides changed it since their last common state, the interactive conflict resolver opens instead.
> [!NOTE]
> Syncing requires every device to be on a KeyStash version that supports this sync ID. If one device is still on an older version, syncing from an updated device produces a clear "update KeyStash on the other device first" message rather than merging incorrectly — update the older device and sync it at least once, then sync resumes normally everywhere.

---

## 📦 Dependencies

KeyStash relies exclusively on safe and audited Rust libraries:
- `ratatui` & `crossterm` for drawing interactive terminal screens.
- `rusqlite`, with SQLCipher and OpenSSL statically vendored in, for the full-database-encrypted local SQLite store.
- `chacha20poly1305`, `argon2`, & `hkdf` for the column-level encryption layer and key derivation.
- `arboard` for native Wayland and X11 clipboard integration.
- `rpassword` for secure CLI console prompt input masking.
- `serde` & `serde_json` for parsing JSON vault imports.
- `ureq` for the HaveIBeenPwned breach-check HTTP requests, via `native-tls` so its HTTPS connection reuses the same vendored OpenSSL as SQLCipher above instead of statically linking a second, independent TLS stack.
