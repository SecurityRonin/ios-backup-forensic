# ios-backup-forensic — Design Note

- **Date:** 2026-08-21
- **Status:** Proposed
- **Tier:** CONTAINER (`components/container`) — surfaces as a filesystem via `forensic-vfs`
- **Repo shape:** Pattern A (single format) → `ios-backup-core` (reader) + `ios-backup-forensic` (analyzer)

## Motivation

iOS device backups (Finder / iTunes / MobileSync) are among the most common mobile-evidence
artifacts, yet the fleet cannot read them today. `4n6mount` auto-detects filesystems, EWF/VMDK/AFF4
containers, AD1 & AFF4-Logical, archives, and memory dumps — but not the Apple backup format.

Driving case: DCCJ4610/2023 (iPhone 12 Pro, iOS 26.2). Agent full-file-system extraction is blocked
(EIFT agent caps at iOS 26.0.1), so extended/advanced logical is the only route, and it produces an
**encrypted** iTunes-style backup. No fleet tool can open it — `Manifest.db` reads as *"file is not a
database"* because, in an encrypted backup, the manifest is itself AES-encrypted. This crate fills that
gap and makes such backups first-class, mountable evidence.

## What it is

A reader + analyzer for the iOS backup on-disk format. A backup is a directory keyed by device UDID:

- `Manifest.db` — SQLite index of every file (encrypted when the backup is)
- `Manifest.plist` — bplist: `IsEncrypted`, `BackupKeyBag`, version, date
- `Status.plist`, `Info.plist` — backup metadata
- content blobs at `<first-2-hex>/<fileID>`, where `fileID = SHA1(domain + "-" + relativePath)`

`Manifest.db` `Files` table: `fileID`, `domain`, `relativePath`, `flags` (1 = file, 2 = dir,
4 = symlink), `file` (bplist per-file metadata: size, mtime, mode, inode, and — when encrypted —
`EncryptionKey` + `ProtectionClass`).

## Architecture fit (binding ADRs)

- **Logical container, not a filesystem.** Same shape as AD1 / AFF4-Logical, which live in
  `components/container`. Placement: `components/container/ios-backup-forensic`. The `filesystem` tier
  is for real filesystems (apfs/ntfs/ext4fs…) plus the VFS/mount layer (`4n6mount`, `forensic-vfs`).
  [ADR-0011 logical containers via `disk_forensic::logical::open`; ADR-0014 containers-surface-as-filesystems.]
- **Reader/analyzer split (ADR-0008, ADR-0009).** Pattern A. `ios-backup-core` exposes the logical
  file tree (navigation + `Read + Seek` per file, decrypt-on-read), emits **no** findings.
  `ios-backup-forensic` audits and emits `forensicnomicon::report::Finding` via `impl Observation`.
- **Surfaces via the abstraction, no special-casing.** `ios-backup-core` registers a `logical::open`
  provider so `4n6mount` mounts it through `forensic-vfs` with zero `if ios_backup {…}` in any
  consumer (the exact smell ADR-0011 exists to catch).

## Decryption (encrypted backups)

`Manifest.plist.BackupKeyBag` holds the keybag; the backup password derives the wrapping keys:

1. PBKDF2 double-protection: `DPSL`/`DPIC`, then `SALT`/`ITER` → derived key
2. per-protection-class `WPKY` unwrapped (AES key-wrap, RFC 3394) → class keys
3. per file: unwrap `Files.file.EncryptionKey` with its `ProtectionClass` key → file key
4. decrypt blob with AES-CBC (per the Apple backup keybag spec)

Unencrypted backups skip the keybag; blobs are plaintext.

- **Never hand-roll crypto, never ship placeholder crypto** (CLAUDE.md). Use RustCrypto: `aes`, `cbc`,
  `pbkdf2`, `hmac`, `sha1`, `sha2`, `aes-kw`.
- **Validate byte-exact against an independent oracle** (Elcomsoft Phone Viewer / `iphone_backup_decrypt`
  / `iOSbackup`) on a known backup — this is the T1 lineage requirement; the keybag path is the crate's
  highest-risk surface.

## `ios-backup-core` API sketch

```rust
Backup::open(path) -> Result<Backup>                          // unencrypted
Backup::open_encrypted(path, password: &str) -> Result<Backup>
backup.files() -> impl Iterator<Item = BackupFile>           // domain, relative_path, kind, size, mtime, mode
backup.read(&BackupFile) -> Result<impl Read + Seek>         // decrypt-on-demand
// plus a `logical::open` provider registration for the VFS abstraction
```

## `ios-backup-forensic` findings (analyst-facing, not mechanism)

- `IsEncrypted` true but password absent/failed; leftover backup-password artifacts.
- **Expected-domain absent** — e.g. a secure-messenger domain
  (`AppDomainGroup-group.net.whatsapp.WhatsApp.shared`) missing on a modern-iOS backup (the exclusion
  that was case-relevant). Reported as an **observation**, never a conclusion.
- Manifest↔blob integrity: a `Files` row with no backing blob; an orphan blob with no row; a
  `fileID` that is not `SHA1(domain-relativePath)`.
- Last-backup date vs on-device timestamps; keybag/version anomalies.

## Security & robustness (ADR-0012 Paranoid Gatekeeper)

Parses untrusted, attacker-controllable images: never panic, never read OOB, never trust a length
field. `unsafe` forbidden except bounded mmap (`forbid`→`deny` + per-site allow). Every integer read
through the published `safe-read` crate (never a hand-rolled `bytes.rs`). Fuzz targets: the `Manifest.db`
(SQLite) reader, the bplist parser, the keybag parser, and a full-pipeline `fuzz_forensic`. 100% line
coverage over every test target; real-artifact CI validation.

## Dependencies (search-first / DRY)

- `forensicnomicon` (Finding/Observation), `safe-read`, `forensic-vfs` (surface as FS).
- **SQLite:** reuse the fleet SQLite reader if one exists (search `components/` before adding a dep);
  else a vetted crate.
- **plist/bplist:** a vetted parser (or a fleet crate if present).
- RustCrypto for the keybag path.
- Batteries-included (ADR-0013): compile all capabilities in; commit `Cargo.lock`; low CI-verified MSRV
  for the library.

## Test-data provenance (fleet standard)

- Matched fixtures: a small **unencrypted** backup and a small **encrypted** backup (known password),
  documented in `tests/data/README.md` (source, UDID, md5/sha256, contents, redistribution/license,
  consuming test).
- Large real backups gitignored + downloaded manually + env-gated; tiny synthetic backups committed.
- Ground-truth oracle: decrypt with Elcomsoft Phone Viewer / `iphone_backup_decrypt`, reconcile
  file-by-file.

## Naming decision

- `ios-backup` over `itunes-backup` (iTunes is retired — Finder / Apple Devices now) and over
  `mobilesync` (a path detail). Named by the analyst-facing artifact, not the mechanism (ADR-0009).
- Pattern A: repo `ios-backup-forensic`; crates `ios-backup-core` (reader) + `ios-backup-forensic`
  (analyzer). No separate binary — consumed by `4n6mount`; add an `iosbackup4n6` CLI only if standalone
  triage is wanted later.

## Open questions

- Reuse vs. first-party: is there a maintained Rust iOS-backup crate worth depending on for `-core`, or
  does the fleet norm (first-party reader, validated keybag crypto) apply? The keybag is the risk
  surface to validate either way.
- `flags` semantics and symlink handling across iOS versions.
- iOS 18.3+/26 domain-exclusion behaviour (which app data is actually present in a backup) — document
  empirically from real backups rather than assume.
