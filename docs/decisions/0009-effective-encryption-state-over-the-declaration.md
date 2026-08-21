# 9. The effective encryption state, not the declaration

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

`Manifest.plist` carries `IsEncrypted`. Until this decision the reader took that
boolean as fact: `true` meant "decrypt", `false` meant "read as SQLite".

`IsEncrypted` is a **declaration**, not a measurement. It records what wrote the
plist, and a plist can be written separately from the data it describes — a
partial copy of a backup directory, a tool that rewrote metadata, an edited
property list. When they disagree, trusting the flag produces two failures with
no useful message:

- declared plaintext, actually encrypted → the reader hands ciphertext to a
  SQLite parser and reports **"Manifest.db is not a readable database"**, sending
  the examiner to look for damage to intact evidence;
- declared encrypted, actually plaintext → the reader demands a password for data
  that needs none, and blocks a readable backup on a stale flag.

Surfaced by comparing against MVT, which takes the opposite approach: it runs
`SELECT fileID FROM Files` and treats a `DatabaseError` as "encrypted". That
probes the effect rather than the claim, which is the better instinct — but it
collapses *encrypted* and *corrupt* into one answer, so a damaged manifest sends
an examiner hunting for a password that does not exist.

## Decision

Read the effective state, keep the declared one, and recover from a
disagreement.

The effective test is the SQLite magic on the raw `Manifest.db`:

```rust
let keybag_present = manifest.keybag.is_some();
let observed_encrypted = !is_plaintext_sqlite(&raw_manifest_db) && keybag_present;
```

Both values live on `EncryptionState { declared, observed, keybag_present }`,
reachable through `Backup::encryption_state()`.

`Backup::is_encrypted()` reports `observed`, because the question a caller is
actually asking is *must this be decrypted*, and only the bytes answer it.

## Three states, not two

The keybag is the tie-breaker, and it is what keeps this from being MVT's probe
with extra steps:

| `Manifest.db` parses | keybag | Verdict |
|---|---|---|
| yes | — | plaintext |
| no | present | encrypted — decrypt it |
| no | absent | **corrupt** — nothing to decrypt with |

A manifest that will not parse and carries no keys is damaged, not locked.
Reporting it as locked is a wrong answer that costs an examiner real time.

The remaining case — declared encrypted, unparseable, no keybag — is a plist that
contradicts *itself*, and gets `Error::MissingKeyBag`: it claims encryption while
carrying no keys.

## Consequences

- A backup declared plaintext but actually encrypted **opens**, given a password,
  and without one fails as `PasswordRequired` — the actionable error — rather
  than as a corrupt manifest.
- A backup declared encrypted but actually plaintext **opens** with no password.
- Verified that recovery yields the *right* bytes, not merely a successful open:
  `its_files_decrypt_to_the_same_bytes_as_the_honest_backup` compares a recovered
  read against the honest fixture.
- `ios-backup-forensic` reports the disagreement as
  `IOS-BACKUP-ENCRYPTION-STATE-CONTRADICTION`, graded **Medium**. Not High: a
  partial copy or metadata written separately from data explains it as well as
  tampering does, and the backup records nothing that distinguishes them. The
  finding says so rather than choosing.
- `Manifest.db` is now read once, up front, in both paths. That is what makes the
  survey possible, and it removed the old ordering quirk where a backup missing
  both its manifest and its keybag reported whichever failure happened first.

## What this does not do

It does not verify that the *blobs* match the declaration — only the manifest is
probed. A backup with a plaintext manifest and encrypted content blobs would open
and then fail per-file. That case has not been observed and no fixture exists for
it; it is recorded here rather than silently assumed away.
