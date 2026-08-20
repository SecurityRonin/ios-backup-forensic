# 3. Truncate to the recorded size; never strip padding

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

An encrypted content blob is AES-CBC ciphertext padded out to the 16-byte block
boundary. Recovering the plaintext length can be done two ways: strip the
padding, or truncate to the length `Manifest.db` records for that file.

Several published iOS-backup decryptors strip PKCS#7.

## Decision

`crypto::decrypt_aes_cbc` removes no padding at all. `Backup::read` truncates to
`BackupFile::size`.

## Rationale

**The manifest already states the length.** It is recorded evidence. Stripping
padding *derives* a value that is sitting right there — and a derivation that
replaces a correct recorded value with a computed one is a regression wearing
the costume of an improvement.

**Padding-stripping corrupts real files.** A file whose final plaintext byte
happens to equal its own pad length is indistinguishable from a padded one. A
32-byte file ending in `0x10` would be read as 16 bytes, and reported as a
success. `tests/data/*/AppDomain-com.example.app/Documents/exact.bin` is exactly
two blocks and exists to hold this behaviour in place.

**A blob shorter than its recorded size is left alone.** The shortfall is
evidence of a truncated backup; padding it out would manufacture bytes that were
never captured.

## Consequences

- Byte-exact reads for every file, including block-multiple lengths.
- A manifest that disagrees with the blob on disk stays visible as a
  disagreement, and `ios-backup-forensic` reports it.
