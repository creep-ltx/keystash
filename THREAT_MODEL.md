# KeyStash Threat Model

The README's Security & Cryptographic Model section describes the mechanisms
(SQLCipher, XChaCha20-Poly1305, Argon2id, HKDF domain separation). This
document instead answers a different question, one level up: **given each of
the compromises below, what does an attacker actually get, and what don't
they get?** Writing this down is what makes the *next* gap visible instead of
implicit — two previous bugs (an HMAC-less HIBP cache leaking a fast offline
oracle, and a stale device silently reverting a master-password rotation)
both came from a gap between what the code did and what this document now
states explicitly.

This is a living document. If a change alters what any of the scenarios
below yield, update this file in the same commit.

---

## 1. SQLCipher-only compromise

**Scenario:** An attacker obtains `vault.db` — a stolen backup, a
compromised sync remote with only read access, a lost/stolen device's disk
image — but does **not** have the master password and has not otherwise
obtained the derived SQLCipher page key.

**What they get:** Nothing. The entire file — schema, every table, every
column, including `title`, `category`, `username`, `url`, `updated_at`, and
the HMAC-keyed `hibp_checks.password_hash` values — is SQLCipher-encrypted
as a whole. Without the master password there is no way to derive the
Argon2id master key, and without the master key there is no way to derive
the SQLCipher page key (one-way HKDF, see `derive_sqlcipher_key`). The file
is an opaque blob.

**Residual risk:** Offline brute-force against the master password itself,
bounded by Argon2id's cost (64 MiB / 3 iterations / 4 lanes) and by how
weak the user's actual master password is — KeyStash cannot defend a weak
master password against unlimited offline guessing once an attacker has the
file. This is the one input entirely in the user's hands; the README's
install/setup guidance should keep emphasizing a strong, unique master
password for exactly this reason.

## 2. Field-layer compromise

**Scenario:** An attacker somehow obtains the *derived SQLCipher page key*
itself — not the master password, but the specific 256-bit key SQLCipher
uses to decrypt pages. This could be a bug in the page cipher, a key
recovered from process memory via a mechanism that doesn't also expose the
master key (e.g., a targeted memory scrape that happens to catch the page
key but not the shorter-lived master key), or some other SQLCipher-layer
break that doesn't imply full RAM access.

**What they get:** The whole-database contents Scenario 1 already covers —
titles, usernames, URLs, timestamps, HIBP hashes — *plus*, critically,
still nothing readable for `password` or `notes`. Those two fields are
encrypted a second, independent time with XChaCha20-Poly1305 under a key
derived from the master key via HKDF with different domain-separation info
than the SQLCipher key uses (see the doc comment on `derive_sqlcipher_key`).
The SQLCipher key cannot be used to derive the field-layer key or vice
versa — HKDF is one-way in both directions between sibling keys derived
from the same input.

**What they don't get:** The passwords and notes themselves — including
password-history entries, which are the original password ciphertexts and
carry the same field-level encryption as live passwords. This is the
entire point of the two-layer design, and the reason it's worth stating
explicitly: *"defense in depth"* in the README's Security Model section
means exactly this scenario, not a vaguer promise.

**Residual risk:** If the attacker's access extends to reading the *master
key* itself (not just the derived page key) — e.g., genuine full-process
memory access, not just an isolated SQLCipher-layer bug — both layers fall,
since the master key trivially re-derives both children. That's a strictly
larger compromise than this scenario describes, and no layered design
defends against full memory access to the key that seeded every layer.

## 3. Git-remote compromise

**Scenario A — read-only access to the git remote** (e.g., a leaked
personal access token with read scope, a misconfigured private repo made
public, a compromised git hosting account with read access only).

**What they get:** Every historical revision of `vault.db` ever pushed —
each one independently subject to Scenario 1 (nothing readable without the
master password of *that* revision). A rotation replaces the salt, so an
attacker who cracks one historical revision's master password gains
nothing about revisions before or after a rotation. What genuinely leaks:
**commit timestamps**, which reveal usage patterns (roughly when and how
often the vault is used, which can hint at timezone and habits) even
though content stays opaque. This is an accepted, currently undocumented-
until-now metadata leak inherent to using git as the sync transport at all.

**Scenario B — write access to the git remote** (a compromised git hosting
account, a leaked token with write scope, a malicious collaborator).

**What they get to attempt:**
- **Push a corrupted or garbage file as `vault.db`.** The next device to
  sync fails to open it as a valid SQLCipher database and, per the
  incompatible-remote path, backs up the bad copy locally and pushes the
  local vault as the new source of truth. Contained: no data loss beyond
  the attacker's own garbage being discarded, and a backup is kept.
- **Push a vault encrypted under a *different* salt** (impersonating a
  rotation the user never performed). Every device's next sync compares
  the fetched remote's header salt against its own; if the salts differ
  and the remote is not an ancestor of local history, sync refuses to push
  and instructs the user to back up, delete, and re-pull rather than
  silently accepting the attacker's vault as authoritative. This is
  exactly the class of attack the rotation-safety fix (salt-ancestry
  check) was built to close — see the CHANGELOG for the version that
  landed it.
- **Push an old, legitimate, previously-superseded revision of the real
  vault (a whole-file rollback).** Without the SQLCipher page key, the
  attacker can only replay an entire historical `vault.db` byte-for-byte —
  encrypted pages aren't malleable at the field level, so they cannot
  forge a single record's `updated_at` or resurrect a deletion with a
  hand-picked timestamp inside an otherwise-valid file. That constrains
  the attack more than it might first appear: the tombstone guard on the
  "insert new secrets from remote" merge step (`ld.deleted_at >=
  r.updated_at`) compares against each record's *genuine* historical
  timestamp, and causally a deletion always postdates that record's last
  real edit — so on any device that has already recorded the later
  (real) deletion or edit locally, its own next push simply overwrites
  the rolled-back remote again, self-healing. The actual residual effect
  is narrower and more like an availability/staleness issue than a
  lasting integrity break: a device that has **not yet** seen the later
  real state and happens to sync during the rollback window will
  legitimately look "behind," indistinguishable from that device having
  simply been offline — not a break sync's design promises to prevent,
  but worth naming so a future defense (a monotonically increasing
  counter or signed high-water-mark, independent of what the remote
  reports) is a deliberate choice, not a forgotten one.

**What they never get, in either scenario:** Any plaintext without also
compromising the master password (Scenario 1) or the master key
(Scenario 2's residual case). Write access to the remote is a data-
integrity and availability threat, not a confidentiality one.

## 4. HaveIBeenPwned network exposure

**Scenario:** A network observer (anyone between this device and
`api.pwnedpasswords.com` who can see connection metadata despite TLS —
an ISP, a coffee-shop network operator, the API provider itself) watches
outgoing HIBP k-anonymity requests.

**What they get:** The first 5 hex characters of a SHA-1 hash per query —
by design, k-anonymity means this narrows a password to one of roughly
tens of thousands of candidates sharing that prefix, not a specific one.
Request timing and count reveal roughly how many vault entries exist and
roughly when they were last edited (each check happens once per
password, cached locally in `hibp_checks` afterward via the HMAC-keyed
fingerprint — see Scenario 1 for why that cache doesn't itself leak
anything to an SQLCipher-only compromise). The `Add-Padding` header
requests response-size padding from the API specifically to blunt
correlating response size with which bucket was queried.

**What they never get:** A specific password, or even a specific
candidate-narrowed-to-one password, from the query alone.

## 5. Accepted sync tradeoffs (named so the next gap is visible)

Two deliberate design decisions in sync are worth stating explicitly,
because both trade a rare failure mode for simplicity, and an unstated
tradeoff is how previous gaps (the HIBP cache, the rotation revert) went
unnoticed:

**Last-write-wins rides wall-clock time.** When the same record changed on
both sides and only one side changed it since the common base, the merge
keeps the copy with the newer `updated_at` — a timestamp from whichever
device wrote it. A device with a skewed clock therefore silently wins (or
loses) those merges. The genuinely dangerous case — *both* sides changed
the same record — does not rely on timestamps: it goes to the interactive
conflict resolver. Vector clocks or CRDTs could remove the wall-clock
dependency, but for a single-user, few-device vault the added complexity
is a worse trade than "keep device clocks sane" (NTP, the default on
every modern OS, is sufficient).

**Deletion tombstones expire after 90 days.** Tombstones exist so other
devices learn about deletions instead of resurrecting the record; they are
pruned after 90 days so a deleted credential's title/username don't live
in the vault forever (a privacy cost paid indefinitely otherwise). The
consequence: a device that goes *longer than 90 days* without syncing can
re-introduce records deleted in the meantime — its copies look like new
records once the tombstones that would have deleted them are gone. The
horizon is deliberately generous; if a device has been offline longer
than that, review its vault contents after its first sync back.
