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

## Amended 2026-08-21, after comparison with a reference implementation

`datatags/mount-ios-backup` (which vendors `iphone-dataprotection`, the canonical
reverse-engineering reference) takes the other route: it calls `removePadding`
and never consults `Size` for content length.

Reviewing against it confirmed the decision **and exposed a defect in how it was
implemented here.**

Confirmed: the reference's `removePadding` raises `Invalid CBC padding` on a
malformed trailer, losing the whole file. Truncating to a recorded length has no
such failure, and it is immune to the padding scheme entirely — our fixtures were
switched from zero padding to PKCS#7 (what iOS actually writes) and every test
stayed green without a code change, which is the property in action.

The defect: `Size` was read with `unwrap_or_default()`, so a row whose metadata
records **no** `Size` became `0`, and the read truncated a real file to nothing
and returned `Ok`. Refusal counted as zero — and adversarially reachable, since a
crafted backup omitting `Size` makes a file disappear from an examiner's view
while every operation reports success. The reference implementation is immune
precisely because it never consults `Size`.

`BackupFile::size` is now `Option<u64>`; `None` is distinct from `Some(0)`, and
when it is `None` the reader falls back to stripping the PKCS#7 trailer — the
reference's only strategy becomes our fallback. Where the trailer is also
malformed the bytes are returned intact rather than erroring: with no recorded
length there is nothing to check against, and handing back slightly too many real
bytes beats discarding a file an examiner needs.

## Consequences

- Byte-exact reads for every file, including block-multiple lengths.
- Padding-scheme-agnostic: PKCS#7, zero padding, or none, the recorded length
  decides.
- A manifest that disagrees with the blob on disk stays visible as a
  disagreement, and `ios-backup-forensic` reports it.
- An absent size is reported as absent, all the way to the exhibit: a
  `BlobMissing` finding prints `(not recorded)` rather than a `0` the manifest
  never claimed.
