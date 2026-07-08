# Changelog

## Unreleased
- Feat: Full-database encryption via SQLCipher, replacing the previous scheme where only the `password`/`notes` fields were encrypted (`title`/`category`/`username`/`url` were plaintext columns). The whole vault file is now opaque at rest.
- Feat: Automatic one-time migration of existing vaults to the new encrypted format on first unlock; the pre-migration file is kept as a backup rather than deleted.
- Fix: Sync conflict resolution now re-runs the full logical merge afterward instead of only staging/committing/pushing directly, so unrelated concurrent changes from another device (new records, non-conflicting edits, deletions) are no longer silently dropped when a conflict is resolved.
- Fix: Background sync could race with the exit-time sync when the app was unlocked and quit again quickly, leaving the vault in an inconsistent state with no error shown. The two are now serialized.
- Fix: The Argon2id salt sidecar file is now synced via git alongside the vault database, so a second device can actually derive the right key to unlock an already-migrated vault (previously only the database file was tracked).
- Fix: Sync now recovers automatically when the remote copy can't be read with the current key (e.g. an unmigrated or otherwise incompatible copy) by backing it up locally and pushing the local vault as the new source of truth, instead of failing.
- Fix: `keystash audit` crashed on titles/categories/usernames containing multi-byte Unicode characters near the column-truncation boundary; truncation is now character-aware.
- Fix: Bulk imports (Bitwarden, Brave/Chrome, Firefox, LastPass, KeePassXC, 1Password) now run inside a single transaction, so a failure partway through rolls back the whole import instead of leaving a partial, inconsistent set of rows while reporting the import as failed.
- Fix: Decrypted passwords and notes are now wiped from memory much more consistently instead of just being dropped as ordinary (unzeroized) `String`s — covers clipboard copies, CLI reveal output, the HIBP audit check, form/dashboard/dedupe/sync-conflict screens, and the sync/export paths that decrypt purely for comparison.

## [0.2.5] - 2026-07-05
- Feat: Auto-lock idle timeout for persistent TuiApp sessions
- Feat: Real-time password strength meter in Add/Edit forms
- Feat: Real-time audit warning (reuse and pwned status check) during password creation/editing
- Feat: Interactive duplicate checker and resolver (merging notes/deleting duplicates) in TUI
- Fix: Add line wrapping and responsive constraints to TUI Add/Edit forms to prevent text truncation on small terminals
- Feat: Add [H] keybinding to run HaveIBeenPwned checks on all credentials in a background thread to prevent TUI lockups
- Feat: Real-time progress bar modal overlay showing checking status, with [Esc]/[q] abort support and bypass optimization for already-flagged breached passwords
- Feat: Dynamic fuzzy search and filtering in TUI (sorting results by match relevance score)
- Feat: Clipboard cleared secure visual confirmation (status changes to a yellow BOLD "Clipboard cleared securely" warning for 3s after clearing)
- Feat: RFC 4180 compliant CSV import engine (using standard csv crate) to handle double quotes, commas, and line breaks within fields
- Feat: Asynchronous sync conflict detector and interactive split-pane 3-way merge UI to resolve concurrent database modifications
- Refactor: Clean up and remove the retired standalone Audit screen assets (relying fully on inline dashboard audit details)
- Feat: Centralized configuration file (config.json) unifying idle timeouts and generator options
- Feat: Interactive Settings modal screen ([,] hotkey) to edit timeouts, clipboard delays, auto-sync, and default generator presets
- Feat: Copy passwords generated via CLI (`keystash generate`) to the clipboard, and dynamically load clipboard clear delays from `config.json` for both TUI and CLI copy operations
- Docs: Add [,], [H], and [D] keybindings to the help [?] screen

## v0.2.1
- Fix: TUI panic hook, clipboard daemon hardening, and sync collision fixes
- Docs: Add TODO.md feature roadmap

## v0.2.0
- Feat: Password security auditing (CLI + TUI)
- Feat: Password generator modal and CLI command
- Fix: Persistent HIBP, inline audit, generator settings, and UX fixes
- Fix: Audit was reporting all passwords as empty
- Fix: Make TUI help dialog scrollable
- Docs: Update README and man page structure and add security model disclosures

## v0.1.1
- Security: Implement TUI/CLI memory safety fixes for password buffers
- Feat: Native arboard system clipboard integration with background clear process
- Docs: Add MIT LICENSE file and clipboard manager mitigation guidelines to README

## v0.1.0
- Feat: Support TUI-based import and export (all/selected) popups
- Feat: Universal import/export CLI commands, --no-sync flag, and auto-restoring missing local DB
- Feat: Add show and copy subcommands to CLI
- Feat: WAL mode, zeroizing memory security, and Master Password rotation
- Feat: Implement Git synchronization and logical database merging
- Fix: Implement TUI background clipboard cleaning that persists after exit
- Fix: Restrict directory/file access permissions to 0700/0600
- Fix: Resolve non-fast-forward push failures during sync
- Performance: TuiApp memory zeroize Drop hooks and database indexing
- Performance: Add compilation profiles for binary size optimization
- Docs: Add Unix man page, multi-device sync guides, and update installation docs
- Initial commit: Full TUI password manager backend and dashboard
