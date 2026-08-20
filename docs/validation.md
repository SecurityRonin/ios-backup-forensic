# Validation

What this crate's correctness rests on, tier by tier, and — as importantly —
what it does not yet rest on.

## Summary

| Surface | Strongest evidence | Tier |
|---|---|---|
| AES key unwrap (RFC 3394) | RFC 3394 §4.1–§4.6 vectors | **T1** |
| PBKDF2-HMAC-SHA1 | RFC 6070 §2 vectors | **T1** |
| PBKDF2-HMAC-SHA256 | RFC 7914 §11 vectors | **T1** |
| AES-256-CBC | NIST SP 800-38A §F.2.6 vector | **T1** |
| `fileID` derivation | A published constant for `HomeDomain-Library/SMS/sms.db` | **T1** |
| Keybag TLV grammar | A real 1388-byte `BackupKeyBag` | **T2** |
| Full decrypt pipeline | Fixture encrypted by Python `cryptography`, decrypted by this crate | **T2** |
| Format rules (keybag, KDF, key unwrap, IV, prefixes) | Cross-read against `iphone-dataprotection` via datatags/mount-ios-backup — agrees rule for rule | **T2** |
| Production KDF parameters | Real backup: 10,000,000 + 10,000 rounds, wrong password correctly rejected | **T2** |
| **End-to-end decrypt of real evidence** | **not yet performed** | **gap** |

## T1 — third party authored artifact *and* answer key

`core/tests/rfc_vectors.rs`. Eleven cases, all passing.

These pin **our usage**, not the RustCrypto crates. That distinction is the
point: every primitive below is individually correct inside a *wrong* keybag
implementation too. What the vectors actually catch is which digest pairs with
which salt, which key width goes where, and whether the integrity check is
honoured.

- **RFC 3394 §4.6** is the backup's own shape — a 32-byte key wrapped to 40
  bytes under a 32-byte KEK.
- **The load-bearing negative:** unwrapping under a wrong KEK must *fail*. RFC
  3394 prepends a known `A6A6A6A6A6A6A6A6` value, and that check is the only
  thing standing between a wrong password and 32 bytes of plausible garbage
  being used to "decrypt" evidence.
- **Two PBKDF2 digests, deliberately separate cases.** The backup runs SHA-256
  over `DPSL`/`DPIC` and then SHA-1 over `SALT`/`ITER`. Swapping them produces a
  wrong key that is indistinguishable from a wrong password.

`fileID = SHA1(domain + "-" + relativePath)` is checked against
`3d0d7e5fb2ce288813306e4d4636395e047a3d28`, the published identifier for
`HomeDomain-Library/SMS/sms.db` in every iOS backup — a value this crate did not
choose.

## T2 — real artifacts and an independent oracle

### The keybag, read from real evidence

`core/tests/real_backup.rs`, env-gated on `IOS_BACKUP_DIR`. Against a genuine
encrypted backup the parser yields version 5, `ITER` 10,000, `DPIC` 10,000,000,
and **11 class keys** of exactly 40 bytes each. Eleven is the expected count for
iOS protection classes 1–11; a wrong block-splitting rule gives 12 or 0, which is
precisely what a synthetic fixture built on the same misreading would not reveal.

### The decrypt pipeline, cross-implemented

`core/tests/backup.rs`. The fixtures are minted by
`tools/mint_encrypted_backup.py`, whose cryptography is Python's `cryptography`
(OpenSSL-backed) and whose property lists come from `plistlib`. Neither shares
lineage with RustCrypto or the `plist` crate. Both fixtures are minted from one
seed, so the plain backup holds byte-identical plaintext and serves as the answer
key: **a decrypt is correct exactly when it reproduces it**, and all four files
do.

### Production KDF parameters

A real backup runs ten million SHA-256 rounds before the SHA-1 round begins. The
fixture, at a thousand, cannot tell us that path terminates or that a wrong
password is rejected at real cost. Measured: **3.16 s** to derive and reject.

That test asserts a *lower bound* on elapsed time. A derivation returning
instantly did not run ten million rounds — absent work leaves a timing signature,
and without the bound a skipped derivation would read as a pass.

### Cross-read against an independent implementation

Reviewed 2026-08-21 against
[`datatags/mount-ios-backup`](https://github.com/datatags/mount-ios-backup),
which vendors `iphone-dataprotection` — the canonical reverse-engineering
reference, a lineage independent of both our Rust and our Python generator.

Comparing against source is T2 (executing on the same artifact and reconciling
output would be T1, and needs a backup password we do not have).

**Agrees, rule for rule:**

| | Theirs | Ours |
|---|---|---|
| TLV grammar | `_loopTLVBlocks`: 4-byte tag, 4-byte BE length | same |
| Header vs class `UUID`/`WRAP` | first is the bag's, later `UUID` opens a class | same |
| Class-only tags | `CLAS WRAP WPKY KTYP PBKY` | same |
| Derivation | `pbkdf2(sha256, DPSL, DPIC, 32)` → `pbkdf2(sha1, SALT, ITER, 32)` | same |
| Passcode-wrapped test | `WRAP & 2` | same |
| Integrity check | `A != 0xa6a6a6a6a6a6a6a6` → fail | RFC 3394 via `aes-kw` |
| Wrapped key width | `0x28` (40) | same |
| `ManifestKey` | `<l` class prefix + `[4:]` | same |
| `Manifest.db` IV | all-zero | same |
| Per-file key | `$objects[UID]['NS.data'][4:]` | same |
| Keybag kinds | System/Backup/Escrow/OTA (0–3) | same |

That is independent corroboration of the keybag rule my mutation control already
showed to be load-bearing.

**Differs deliberately, and ours is stricter:**

- A truncated trailing TLV: their loop (`while i + 8 <= len(blob)`) stops
  silently; we return `TruncatedKeyBag`.
- Any 4-byte value is coerced to an integer by them; we require the exact width
  per field and return `BadFieldWidth`.
- A `CLAS` tag before any `UUID` raises `TypeError` on a `None` subscript there;
  we open a block.
- `TYPE > 3` prints `FAIL` and continues there; we return `UnknownKeyBagType`.
- An absent class raises `KeyError` there; we return `NoKeyForClass`.
- They return "wrong password" if *any* passcode-wrapped class fails to unwrap;
  we recover every class that does unwrap. A partially-damaged keybag yields
  what it can rather than nothing.

**Differs, and it found a defect in ours.** They strip PKCS#7 and never consult
`Size`. We truncate to the recorded size — the better default, and confirmed so:
their `removePadding` raises on a malformed trailer and loses the whole file.
But `Size` was read with `unwrap_or_default()`, so a row recording **no** size
became `0` and truncated a real file to nothing while returning `Ok`. Refusal
counted as zero, and adversarially reachable: a crafted backup omitting `Size`
makes a file disappear while every operation reports success.

Fixed: `BackupFile::size` is `Option<u64>`, `None` distinct from `Some(0)`, with
PKCS#7 stripping as the fallback when nothing was recorded. Regression test:
`core/tests/missing_size.rs`. Recorded in ADR-0003.

**And it corrected a fixture.** Our generator padded with zeros; iOS writes
PKCS#7. The fixtures were regenerated, and every test stayed green with no code
change — which is the padding-agnostic property of ADR-0003 demonstrated rather
than asserted.

## Controls — evidence the tests can fail

A check that has never failed is not known to work.

**Mutation control (run 2026-08-21, reverted after).** Inverting the keybag's
header-UUID rule so that every `UUID` opens a class block:

| Suite | Result under mutation |
|---|---|
| `core/tests/keybag.rs` | **5 of 10 fail** |
| `core/tests/real_backup.rs` | **2 of 2 fail** (`MissingField("UUID")`) |

**Three-way control** on the real-backup suite:

| Control | Setup | Observed |
|---|---|---|
| **A** | `IOS_BACKUP_DIR` set, real backup present | Pass, 0.05 s (non-trivial) |
| **B** | Parser mutated | **Fail** — the positive control |
| **C** | `IOS_BACKUP_DIR` unset | Skip, 0.00 s |

C's near-zero duration is the fingerprint of work not done, which is why a green
run of this suite means nothing unless the variable was set.

## The gap, stated plainly

**No byte-exact decrypt of a real encrypted backup has been performed.** The
strongest available validation for this crate requires a real backup *and* its
password; we have the former and not the latter.

What is established without it: the primitives are right (T1), the keybag
grammar survives contact with real evidence (T2), the derivation completes on
production parameters and rejects a wrong password (T2), and the full pipeline
agrees byte-for-byte with an independent implementation (T2).

What is not established: that our reading of the format is right in some way that
both our Rust *and* our Python generator share. Only real ciphertext with a known
password closes that.

`a_real_backup_opens_and_reads_with_the_correct_password` is written, wired, and
skipping. Supplying `IOS_BACKUP_PASSWORD` alongside `IOS_BACKUP_DIR` runs it; it
asserts that `sms.db` decrypts to bytes beginning `SQLite format 3\0`, which a
wrong key cannot produce.

## Not fuzzed

ADR-0012 requires one fuzz target per parsed structure — the keybag, the
`NSKeyedArchiver` blob, the manifest reader — plus a full-pipeline
`fuzz_forensic`. **None exists.** There is no `fuzz/` directory.

What stands in its place is weaker and should not be mistaken for it: the lint
posture (`unsafe_code = "forbid"`, `unwrap_used`/`expect_used` denied in
production code), every integer read through `safe-read`'s bounded readers, and
13 hand-written malformed-input cases in `core/tests/hostile_input.rs` plus 5 in
`core/tests/keybag.rs`.

Hand-written cases test the malformations someone thought of. That is the whole
difference: no fuzzer has failed to break this parser, because none has been
pointed at it. The panic-free property is **argued from construction, not
demonstrated by search.**

This is the largest outstanding gap in fleet compliance for these crates.

## Coverage

89.81% line coverage (`cargo llvm-cov --workspace --all-features`), against
ADR-0008's 100% requirement for a `*-core`/`*-forensic` pair. The CI gate is a
floor at the measured 89 — a regression backstop, not the standard met.

Uncovered, by file: `nskeyed.rs` and `backup.rs` hold most of it,
chiefly defensive arms needing malformed archive shapes not yet in the corpus —
which is the same hole fuzzing would fill.

## What is not validated at all

- **iTunes-for-Windows backups** — assumed identical, untested.
- **iOS 18.3+/26.x domain exclusion** — the `EXPECTED_DOMAINS` list is reasoned
  from documentation, not measured against modern backups.
- **`flags` values other than 1, 2 and 4** — carried verbatim as
  `FileKind::Unknown` rather than guessed at, but never observed.
- **Keybag kinds other than Backup** — parsed, never exercised.
