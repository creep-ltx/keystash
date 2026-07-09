# Changelog

## [0.3.5] - 2026-07-09
- Fix: Deduplication could silently destroy the record a user chose to *keep*. Deleting the other duplicates writes a sync tombstone keyed on their shared title/category/username; since the kept record's timestamp predated that tombstone, the next sync (on either device) matched the kept record against its own tombstone and deleted it too. The kept record is now re-stamped with a fresh timestamp immediately after its duplicates are deleted.
- Fix: A full-vault HaveIBeenPwned scan (`H`) opened the database without the SQLCipher key, so every query against it failed silently -- the cache always looked empty (forcing a full re-scan every time) and no results were ever saved. The background thread now opens a properly keyed connection, so results persist as they should.
- Fix: Background sync could still race with itself: a new sync thread started running before the previous one's handle was joined, so two `git_sync_vault` runs could execute concurrently against the same working directory. Both sync trigger points now join the previous thread from inside the new one before touching any files.
- Fix: Removed `panic = "abort"` from the release profile and disabled core dumps at startup. With `panic = "abort"`, a panic (or a crash in a C dependency like SQLCipher/OpenSSL) skipped all `Drop`/zeroize cleanup and could dump the entire process memory -- master key, SQLCipher key, decrypted passwords -- to disk in a core file.
- Fix: The Settings screen accepted an idle timeout of `0`, which locks the vault on every tick, including immediately after saving -- soft-locking the user out of the TUI (settings screen included) until they hand-edited `config.json`. Timeout, clipboard-clear delay, and generator length are now clamped on save and again on config load.
- Fix: CSV export now guards cells starting with `=`, `+`, `-`, or `@` against spreadsheet formula injection -- previously, a malicious title/username/note synced from another device would execute as a formula the moment the export was opened in Excel/LibreOffice/Sheets.
- Fix: Temporary vault copies used during sync (`vault_remote_*.db`, `vault_base_detect_*.db`) could be left on disk if an error occurred partway through a sync or conflict-detection pass, since cleanup was only handled on specific success/error paths. A cleanup guard now removes them whenever the enclosing function returns, by any path.
- Fix: Dismissing the sync-conflict screen with Esc/`q` discarded the conflicts without merging or pushing, leaving sync silently stalled until the next unlock -- a status message now tells the user sync was postponed.
- Fix: A few remaining spots dropped decrypted passwords as plain, unwiped `String`s/`clear()`s instead of zeroizing first: regenerating a password over an existing one in the Add/Edit form (Ctrl+G), and clearing the change-password fields from the dashboard shortcut.
- Fix: `delete_secret`'s tombstone-insert and row-delete now run in a single transaction, so a crash between the two can no longer leave a tombstone written against a secret that's still present.
- Fix: If a legacy-vault migration was interrupted mid-way (crash, power loss), neither `vault.db` nor `vault.salt` existed afterward, so the app reported "no vault found" and invited the user to initialize a brand new one -- right on top of their still-recoverable pre-migration backup. The app now detects this state and shows the exact recovery command instead.
- Fix: Password strength scoring used additive points that topped out at 5 and required every character class to be present, so a 40-character random lowercase passphrase (genuinely excellent) scored only 2 and was flagged "Critical" right alongside `password123`. Scoring is now based on estimated brute-force entropy, so long passphrases are correctly rated Good and short-but-varied passwords like `Aa1!` correctly stay Critical.
- Fix: Checking a single/marked entry against HaveIBeenPwned (`h`) ran synchronously on the UI thread with a blocking network call and inter-request sleep, freezing the TUI (with no way to abort) for several seconds when multiple entries were marked. It now reuses the same background-scan machinery as the full-vault check (`H`), gaining the progress dialog, abort key, and keyed-connection persistence for free.
- Fix (structural): Sync merge logic, tombstones, and conflict detection were all keyed on the (title, category, username) triple, which is not actually unique -- nothing stops two records sharing it (the dedup screen exists to find exactly this case). An ambiguous triple could make merge steps silently pick an arbitrary row, and made it possible for one of two same-triple records to be dropped entirely during a merge instead of both surviving. Every record now carries a `sync_uuid`, generated on creation and backfilled once for existing vaults, and all merge/tombstone/conflict logic keys on that instead. Syncing against a vault last pushed by an older KeyStash version (no `sync_uuid` column yet) now transparently falls back to the previous triple-based merge for that one sync, then carries the new column forward on the next push -- so a shared vault upgrades the first time *any* device syncs after updating, with no need to coordinate updating every device first.
- Fix (structural): `change_master_password` re-keyed the live vault file in place via `PRAGMA rekey`, which commits immediately and can't be rolled back, and only wrote the new Argon2id salt to disk at the very end. A crash between those two points left the vault file re-keyed with a salt that existed nowhere but that process's memory -- permanently unrecoverable, with no backup to point to (unlike a botched migration). Password rotation now builds the newly re-keyed vault at a temp path first (same discipline `migrate_legacy_vault` already used) and atomically swaps it into place, so an interruption anywhere before the swap leaves the original file and salt untouched, and an interruption during the swap is recoverable the same way an interrupted migration is.
- Removed the unused `tokio` dependency -- pure compile-time and binary-size cost against the size-optimized release profile.
- Feat: Vaults now record the minimum KeyStash version that can safely read their current format (currently `0.3.0`, the last change -- full-database SQLCipher encryption -- that older code genuinely cannot read at all). Opening a vault, or syncing against a remote copy, requiring a newer version than the one currently running now fails with a clear "this vault/remote requires vX.Y.Z or newer" message instead of a confusing raw SQL/schema error. This floor only moves for a future change that can't be made backward-compatible -- it's untouched by the `sync_uuid` change above, which was deliberately designed so older code keeps working against it unmodified.

## [0.3.0] - 2026-07-08
- Feat: Full-database encryption via SQLCipher, replacing the previous scheme where only the `password`/`notes` fields were encrypted (`title`/`category`/`username`/`url` were plaintext columns). The whole vault file is now opaque at rest.
- Feat: Automatic one-time migration of existing vaults to the new encrypted format on first unlock; the pre-migration file is kept as a backup rather than deleted.
- Fix: Sync conflict resolution now re-runs the full logical merge afterward instead of only staging/committing/pushing directly, so unrelated concurrent changes from another device (new records, non-conflicting edits, deletions) are no longer silently dropped when a conflict is resolved.
- Fix: Background sync could race with the exit-time sync when the app was unlocked and quit again quickly, leaving the vault in an inconsistent state with no error shown. The two are now serialized.
- Fix: The Argon2id salt sidecar file is now synced via git alongside the vault database, so a second device can actually derive the right key to unlock an already-migrated vault (previously only the database file was tracked).
- Fix: Sync now recovers automatically when the remote copy can't be read with the current key (e.g. an unmigrated or otherwise incompatible copy) by backing it up locally and pushing the local vault as the new source of truth, instead of failing.
- Fix: `keystash audit` crashed on titles/categories/usernames containing multi-byte Unicode characters near the column-truncation boundary; truncation is now character-aware.
- Fix: Bulk imports (Bitwarden, Brave/Chrome, Firefox, LastPass, KeePassXC, 1Password) now run inside a single transaction, so a failure partway through rolls back the whole import instead of leaving a partial, inconsistent set of rows while reporting the import as failed.
- Fix: Decrypted passwords and notes are now wiped from memory much more consistently instead of just being dropped as ordinary (unzeroized) `String`s — covers clipboard copies, CLI reveal output, the HIBP audit check, form/dashboard/dedupe/sync-conflict screens, and the sync/export paths that decrypt purely for comparison.
- Fix: A 1Password CSV export missing a `notes` column would be confidently detected as 1Password format and then immediately fail to import; the column is now treated as optional.
- Fix: `vault.db`, `vault.salt`, the config directory, and exported CSVs were created under the process's default umask and `chmod`'d restrictive only afterward, leaving a brief window where they could be readable by other local users. The process umask is now restricted at startup instead.

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
