# Census of iOS-backup implementations

A comparison of `ios-backup-core` against independent implementations, run
2026-08-21. Recorded here rather than in `validation.md` because it is a
*method* with limits worth stating, not a result.

## The question

Does `ios-backup-core` disagree with any independent implementation on a
load-bearing format decision, and does each disagreement indicate a defect in
**our** code, in theirs, or a legitimate divergence?

## How the population was enumerated, and why it is a floor

Two differently-shaped instruments, because one instrument's blind spot is
invisible from inside it.

**Instrument 1 — GitHub repository search**, ten query phrasings, union of 23
repositories. **It missed every implementation already known to exist**:
`jsharkey13/iphone_backup_decrypt`, `avibrazil/iOSbackup`,
`dinosec/iphone-dataprotection`, `mvt-project/mvt`, `datatags/mount-ios-backup`.
Repo search matches names and descriptions, so it finds projects that *describe*
themselves as backup tools and misses libraries that merely *are* one. Reported
here as a failed instrument, not as a population.

**Instrument 2 — GitHub code search on format-internal constants** (`WPKY`,
`DPSL`, `BackupKeyBag`, `ManifestKey`). A parser cannot implement the keybag
without these strings whatever it calls itself, so this does not depend on
self-description. It surfaced ~153 repositories touching keybag or manifest
internals, of which perhaps 25 are genuine implementations (the rest are LLVM
and AWS-SDK forks matching the tokens incidentally).

**This is a floor, not a census, and the reason is mechanical: every query
returned exactly 60 results, which is the API's page limit.** A capped query
yields a lower bound on the population and never a total. No proportion,
percentage or "most implementations" claim is made anywhere in this document,
because the denominator is unknown.

## The corpus actually read

Nine implementations, chosen for **lineage diversity** rather than count.
Implementations descended from `iphone-dataprotection` are not independent
evidence of one another — agreement among five of them is one observation, not
five.

| Implementation | Language | Lineage |
|---|---|---|
| `dinosec/iphone-dataprotection` | Python | the root reference |
| `datatags/mount-ios-backup` | Python | vendors iphone-dataprotection |
| `mvt-project/mvt` | Python | delegates to `iOSbackup` |
| `avibrazil/iOSbackup` | Python | independent-ish |
| `jsharkey13/iphone_backup_decrypt` | Python | independent-ish |
| `jfarley248/iTunes_Backup_Reader` | Python | independent-ish |
| `MaxiHuHe04/iTunes-Backup-Explorer` | Java | **independent** |
| `richinfante/ibackuptool2` | JS/TS | **independent** |
| `kusaanko/iOSBackupBrowser` | Java | **independent** |
| `fox-it/dissect.target` | Python | **independent** (Fox-IT) |
| `philsmd/itunes_backup2hashcat` | Perl | **independent** (keybag only) |

## Where we agree

Every implementation read agrees with `ios-backup-core` on: the keybag TLV
grammar; the header-vs-class `UUID`/`WRAP` rule; the class-only tag set
(`CLAS WRAP WPKY KTYP PBKY`); the two-round derivation
(PBKDF2-SHA256 over `DPSL`/`DPIC`, then PBKDF2-SHA1 over `SALT`/`ITER`); the
`WRAP & 2` passcode test; the RFC 3394 integrity check; the 40-byte wrapped-key
width; the `ManifestKey` 4-byte little-endian class prefix; the all-zero IV for
`Manifest.db`; and `EncryptionKey` as `NS.data[4:]` behind an `NSKeyedArchiver`
UID.

## Where we deliberately differ

| Decision | Population | Ours | Why |
|---|---|---|---|
| Plaintext length | strip PKCS#7 | truncate to recorded `Size`, PKCS#7 only as fallback | the manifest states the length; padding is not evidence (ADR-0003) |
| Decrypted data | written to disk (MVT, `iOSbackup`) | held in memory | no plaintext copy of evidence with an untracked lifetime (ADR-0002) |
| Encryption detection | probe whether `Manifest.db` parses (MVT) | declaration **and** probe, kept separately | distinguishes encrypted from *corrupt*, which a probe alone cannot (ADR-0009) |
| Partial keybag unwrap | fail whole (`iphone-dataprotection`) | recover every class that unwraps | a damaged keybag should yield what it can |
| Malformed input | exceptions / silent skips | typed errors carrying the offending value | ADR-0012 |

## Defects the comparison found in **our** code

Three, all of the same family — *a refusal counted as zero* — and all now fixed
with regression tests:

1. **Path traversal via `fileID`** (from MVT). `Path::join` replaces the whole
   path on an absolute argument, so a `fileID` of `/etc/passwd` addressed the
   examiner's filesystem. → ADR-0008, `core/tests/path_traversal.rs`.
2. **Absent `Size` read as zero** (from `mount-ios-backup`). A row recording no
   `Size` truncated a real file to nothing and returned `Ok`. → ADR-0003 as
   amended, `core/tests/missing_size.rs`.
3. **Manifest rows silently dropped** (from this census). `fileID` stored as a
   BLOB is legal — SQLite enforces affinity, not type — and such a row vanished
   from the tree with no trace. → `core/tests/row_loss.rs`,
   `Backup::unreadable_rows()`.

The third is the worst of the three: the loss was at the *collection* stage, so
no analyzer could flag it and no examiner could know to look.

## What this comparison cannot support

- **It is not a census.** The population is capped at the API page limit, so no
  proportion is claimed and "most implementations" appears nowhere.
- **Comparing against source is T2, not T1.** Executing another implementation
  on the same artifact and reconciling the output would be T1; that needs a real
  backup and its password, which is the gap `validation.md` already records.
- **The regex matrix understates.** `itunes_backup2hashcat` scored zero on every
  dimension and in fact implements the KDF — its Perl uses
  `index($data, "SALT", …)`, which the patterns could not see. That is a Type II
  in the *instrument*, and it means every absent cell in that matrix is
  unreliable. The agreements above rest on reading the source, not on the grep.
- **Elusion is unmeasured.** No sample was drawn from the ~130 repositories the
  code search surfaced and this corpus did not read, so the rate of
  disagreements missed is unknown. "We agree with the population" is bounded to
  the eleven implementations listed.
