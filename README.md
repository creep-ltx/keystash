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

To run `KeyStash` globally from anywhere on your system, build and install the binary using Cargo:

```bash
# Clone the repository and navigate inside
cd KeyStash

# Install the binary to ~/.cargo/bin
cargo install --path .
```

*Note: Ensure `~/.cargo/bin` is in your system's `$PATH` environment variable.*

Alternatively, you can manually symlink the release binary to your local bin path:
```bash
# Build the release profile
cargo build --release

# Symlink it as lowercase 'keystash'
ln -s $(pwd)/target/release/KeyStash ~/.local/bin/keystash
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
  keystash list
  ```
* **Search Vault:**
  ```bash
  keystash search <query>
  ```
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

---

## 📦 Dependencies

KeyStash relies exclusively on safe and audited pure-Rust libraries:
- `ratatui` & `crossterm` for drawing interactive terminal screens.
- `rusqlite` (with bundled features) for local SQLite database integrations.
- `chacha20poly1305` & `argon2` for modern cryptography.
- `copypasta` for cross-platform clipboard access.
- `rpassword` for secure CLI console prompt input masking.
- `serde` & `serde_json` for parsing JSON vault imports.
