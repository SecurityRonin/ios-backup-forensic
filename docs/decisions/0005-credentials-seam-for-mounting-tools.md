# 5. A credentials seam for mounting tools

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

`4n6mount` mounts evidence without knowing one format from another. It reaches
logical file containers — AD1, AFF4-Logical, DAR — through
`disk_forensic::logical::open`, and raw disk images through
`disk_forensic::container::open`. ADR-0011 makes that indirection binding: a
consumer that grows an `if ios_backup {…}` branch is the exact smell the
abstraction exists to catch.

An encrypted iOS backup needs a password. Neither entry point can carry one:

```rust
pub fn open(path: &Path) -> Result<LogicalImage, LogicalError>
```

This is not an iOS problem. `logical::open` already turns away an encrypted AFF4
with a message that names the gap:

```rust
aff4::ContainerKind::Encrypted => {
    return Err(LogicalError::NotLogical(
        ContainerFormat::Aff4,
        "this AFF4 is encrypted (aff4:EncryptedStream) — needs a password".into(),
    ));
}
```

So the abstraction is already refusing work it has no way to accept. A second
format arriving with the same requirement makes it worth fixing rather than
routing around.

Surveyed before deciding:

- **`4n6mount` has no credential handling at all.** 7,336 lines of `src`, and
  `password`, `passphrase`, `decrypt` and `unlock` appear zero times. (Verified
  with a positive control on the same grep: `key` matches 20+ times, so the
  search was working.)
- **`forensic-vfs` 0.7 *does* have a credential seam** — `CredentialSource`,
  offering `Credential::Password` per `EncryptionScheme`, injected at resolve
  time and deliberately kept out of a serialized `Locator` so an address never
  carries keys. But it is built for full-disk encryption: an `EncryptionLayer`
  consumes ciphertext *sectors* and presents a decrypted `DynSource`. An iOS
  backup has no sectors — it is a directory of individually-encrypted files —
  so it is not an `EncryptionLayer`, and every `*Open` trait in the registry
  takes a `DynSource` rather than a directory.

## Decision

**`ios-backup-core` owns a `Credentials` type and takes it at open time; the
upstream abstraction grows one credential-carrying entry point.**

Concretely, in this crate (done):

```rust
Backup::open(path)                        // = open_with(path, &Credentials::None)
Backup::open_with(path, &Credentials)
logical::LogicalView::open(path, &Credentials)
```

`LogicalView` projects the backup as `{ path, is_dir, size }` entries plus
read-by-index — field-for-field `disk_forensic::logical::LogicalEntry` and
`LogicalImage::read_file` — so the upstream adapter is a `map` and a `match` arm.

And upstream, the change this is shaped to fit (not yet made):

```rust
// disk-forensic
pub fn open(path: &Path) -> Result<LogicalImage, LogicalError> {
    open_with(path, &Credentials::None)
}
pub fn open_with(path: &Path, creds: &Credentials) -> Result<LogicalImage, LogicalError>;
```

with an `IosBackup` arm in the private `Backend` enum, and a
`LogicalError::PasswordRequired` that `4n6mount` can act on. The existing
encrypted-AFF4 refusal becomes reachable work rather than a dead end.

`4n6mount` then grows the supply routes, in this order of preference:

| Route | Who else can see it |
|---|---|
| Interactive prompt, no echo | nobody |
| `--password-file <path>` | anyone who can read the file |
| `IOS_BACKUP_PASSWORD` | the process tree, `/proc`, crash dumps |
| `--password <pw>` | **every user on the machine**, via `ps` |

## Why not the alternatives

**Add the password to `Locator`/the path string.** Rejected for the reason
`forensic-vfs` already documents: a serialized address that carries a key leaks
it into session files, logs and shell history. Credentials belong in the call,
not the address.

**Model the backup as an `EncryptionLayer` over a `DynSource`.** It is not one.
There is no volume, no sector stream, and no single key — each file is wrapped
under its own protection class. Forcing the shape would mean synthesising a fake
byte source, which is a hack wearing an abstraction's clothes.

**Let `4n6mount` special-case iOS backups.** This is the option ADR-0011 exists
to forbid, and it does not scale: encrypted AFF4 needs the same seam today, and
an encrypted AD1 would need it tomorrow.

**Have `ios-backup-core` prompt for the password itself.** Rejected. A parsing
library that reads a terminal pulls a TTY crate into every downstream binary and
makes the library unusable from a daemon or a test. `Password::from_tty` exists
only to return `Error::NoTerminal`, so a front-end can report the failure in the
reader's own vocabulary while owning the prompt itself.

## Consequences

- A backup can be opened with credentials today, through this crate directly.
  The `disk_forensic` route is the small upstream change above, and until it
  lands `4n6mount` cannot mount an encrypted backup through the abstraction.
- `Password` zeroizes on drop and renders `Password(<redacted>)`, so a stray
  `{:?}` cannot put a credential in a log. A test asserts it.
- `Credentials::default()` is `None`: the zero-configuration path reads a
  plaintext backup and *asks* for a password on an encrypted one, rather than
  silently trying the empty string.
- A password supplied for an unencrypted backup is unused rather than an error,
  so a tool that always passes `--password` through does not fail on the backups
  that do not need it.
