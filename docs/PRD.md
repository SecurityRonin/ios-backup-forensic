# Purpose & Scope — `ios-backup-forensic`

A library repository, so this is the lighter Purpose & Scope form rather than a
full product PRD (ADR-0003, fleet doc-naming conventions).

## The problem

iOS device backups are among the most common mobile-evidence artifacts an
examiner meets, and until now no fleet tool could open one. `4n6mount`
auto-detects filesystems, EWF/VMDK/AFF4 containers, AD1 and AFF4-Logical,
archives and memory dumps — but not the Apple backup format.

The gap bites hardest exactly where the evidence matters most. When a
full-file-system extraction is unavailable — an agent that caps below the
device's iOS version, a device state that blocks it — an extended logical
acquisition is the remaining route, and it produces an encrypted iTunes-style
backup. Pointed at one of those, every tool in the fleet reports

> `Manifest.db`: file is not a database

because in an encrypted backup the manifest is itself AES-encrypted. The evidence
is intact and unreadable.

## Who this is for

- **An examiner mounting a backup** to browse it as a file tree, via `4n6mount`.
- **A fleet analyzer** that wants a specific artifact out of a backup — a
  messaging database, a preferences plist — without knowing anything about the
  backup format.
- **`issen`**, correlating backup contents with other evidence.

## What it does

`ios-backup-core`

- Opens a backup directory: `Manifest.plist`, `Status.plist`, `Info.plist`.
- Reads the `Manifest.db` `Files` table into a typed file tree — domain, path,
  kind, size, mode, inode, timestamps, protection class.
- Decrypts, for an encrypted backup: keybag → password-derived key → class keys →
  per-file keys → AES-CBC, with the manifest decrypted **in memory**.
- Reads any file's bytes on demand, truncated to the manifest-recorded length.
- Projects the whole thing as a logical container (`logical::LogicalView`) shaped
  to drop into `disk_forensic::logical`.

`ios-backup-forensic`

- Encryption state and device provenance, recorded even when nothing is wrong.
- Manifest↔blob integrity, both directions: a row with no blob, a blob with no
  row.
- `fileID` verified against `SHA1(domain + "-" + relativePath)`.
- Expected domains that are absent, reported **unrated** (ADR-0006).
- Backup completeness from `Status.plist`.

## What it deliberately does not do

- **No interpretation of file contents.** A backup's `sms.db` is a SQLite
  database; reading it is `sqlite-forensic`'s job, and the messages inside are a
  parser's. This crate hands over bytes.
- **No password recovery.** No wordlists, no GPU, no cracking. It derives a key
  from a password an examiner supplies and reports whether it worked.
- **No writing.** Read-only, in every path.
- **No conclusions.** Findings are observations in consistent-with language.

## Non-goals for now

- An `iosbackup4n6` CLI. The consumer is `4n6mount`; a standalone triage binary
  can be added if it is wanted, and the reader/analyzer split means nothing has
  to move when it is.
- iCloud backups. A different acquisition path and a different keybag kind.
- Writing or re-encrypting a backup.

## Success criteria

1. `4n6mount` mounts an encrypted iOS backup given a password, with no
   format-specific branch in any consumer.
2. Byte-exact reads, verified against an independent implementation.
3. Never panics on malformed or hostile input.
4. A wrong password is always reported as a wrong password, never as an empty or
   corrupt backup.

Where each of these currently stands is in [`validation.md`](validation.md),
including the one that is not yet met.
