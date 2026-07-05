# KeyStash 🔑 - Feature Roadmap & TODO List

This document outlines planned improvements, security enhancements, and user suggestions to be implemented in future releases.

---

## 📋 Planned Roadmap

### 1. 🔒 Auto-Lock Idle Timeout (Security)
* **Description**: Automatically lock the vault after a period of user inactivity to prevent unauthorized access if the terminal is left open.
* **Implementation Plan**:
  * Track the time of the last keypress in the TUI event loop.
  * If the duration exceeds a configurable threshold (e.g. 5 minutes), zeroize the decrypted key from memory, clear secrets data vectors, and redirect the user back to the `Screen::Lock` screen.

### 2. ⚔️ Conflict Merge UI with Timestamps (Sync)
* **Description**: Visual split-pane diff screen inside the TUI for resolving concurrent database modifications.
* **Implementation Plan**:
  * Instead of automatically selecting the newest record based on the `updated_at` millisecond timestamp, detect if changes conflict.
  * Display a dedicated conflict resolution screen comparing:
    * Title, Category, Username
    * Decrypted differences (if readable)
    * Creation/Modification timestamps for both local and remote states.
  * Let the user interactively choose which state to keep.

### 3. ⌨️ Desktop Environment Auto-Fill Helpers (`contrib/`)
* **Description**: Offer integration templates and wrapper scripts for system-wide password auto-typing.
* **Implementation Plan**:
  * Add a `contrib/` directory containing wrapper scripts utilizing system tools (like `rofi` or `dmenu` for entry selection, and `xdotool` or `wtype`/`ydotool` for simulated keyboard input typing).

### 4. ☁️ Alternative Cloud & SFTP Backups
* **Description**: Provide alternative synchronization mechanisms for users who do not want to use Git.
* **Implementation Plan**:
  * Support backup and restore using SFTP/SSH.
  * Add a configurable pre-exit/post-startup shell command hook (enabling easy `rclone` or custom backup script integration).

### 5. 🗃️ RFC 4180 Compliant CSV Import Engine (Parser Update)
* **Description**: Upgrade the CSV import engine to robustly handle complex records containing double-quotes and cell newlines.
* **Implementation Plan**:
  * Replace the manual line-by-line custom CSV parser in `import.rs` with the standard `csv` crate.
  * Update logic to correctly parse fields containing double-quotes (`""`) and multi-line notes.

### 6. 👥 Multi-User Vault Profiles
* **Description**: Support maintaining multiple distinct vault databases (e.g. `work`, `personal`) within the configuration directory.
* **Implementation Plan**:
  * Add a `--profile <name>` CLI parameter to specify custom database filenames.
  * Integrate an interactive profile manager screen/dropdown inside the TUI.

---

## 🏁 Recently Completed

### Release v0.2.1 (Patches)
- **TUI Panic Terminal Restoration**: Implemented standard crossterm panic handler to restore terminal settings on crashes.
- **Clipboard Daemon Hardening**: Prevent overwriting clipboard if the user copies new text during the 10-second lifetime; zeroized sensitive buffers.
- **Sync Collision Prevention**: Appended process ID to remote sync temporary database paths to avoid parallel file locking collisions.

### Release v0.2.0 (Minor Features)
- **Persistent HIBP Database Cache**: Added `hibp_checks` SQLite table to remember HaveIBeenPwned check results across sessions.
- **Inline Security Auditing**: Retired the standalone audit screen and integrated security auditing summaries directly into the dashboard Detail Pane.
- **Bulk HIBP Checks via `[h]`**: Made `[h]` run a rate-limited lookup loop for all marked secrets, automatically unmarking them as they finish.
- **Password Generator Upgrades**:
  * Filtered ambiguous characters (`l`, `I`, `|`, `0`, `O`, `1`) out of charsets.
  * Added `generator.json` persistent configuration settings memory for both CLI and TUI.
  * Integrated inline `Ctrl+G` password generator in Add/Edit forms.
- **Non-blocking Startup Sync**: Moved initial Git sync off the TUI main thread to run asynchronously while users type their Master Password.
- **Backward Keyboard Navigation**: Added `Shift+Tab` focus backward navigation across setup and form inputs.
- **Zeroized Cryptographic Vectors**: Hardened heap safety using `Zeroizing<Vec<u8>>` wrappers for decrypted passwords.
