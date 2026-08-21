# ios-backup-forensic

Native, read-only, panic-free reading of iOS device backups — encrypted ones
included.

- **[Purpose & Scope](PRD.md)** — what this is for, and what it deliberately is not.
- **[Implementation census](implementation-census.md)** — how we compare with eleven independent implementations, and the three defects it found in ours.
- **[Validation](validation.md)** — what correctness rests on, tier by tier, and the gap that is still open.
- **[Decisions](decisions/0001-reader-analyzer-two-crate-split.md)** — the ADRs.
- **[Test data](https://github.com/SecurityRonin/ios-backup-forensic/blob/main/tests/data/README.md)** — fixture provenance.

## The decisions

| ADR | |
|---|---|
| [0001](decisions/0001-reader-analyzer-two-crate-split.md) | Reader and analyzer are two crates |
| [0002](decisions/0002-sqlite-core-reads-the-manifest.md) | `sqlite-core` reads `Manifest.db` |
| [0003](decisions/0003-no-padding-strip-truncate-to-manifest-size.md) | Truncate to the recorded size; never strip padding |
| [0004](decisions/0004-unwrap-failure-is-a-wrong-password.md) | A failed unwrap is a wrong password |
| [0005](decisions/0005-credentials-seam-for-mounting-tools.md) | A credentials seam for mounting tools |
| [0006](decisions/0006-absent-domains-are-unrated.md) | An absent domain is reported unrated |
| [0007](decisions/0007-msrv-is-inherited-from-plist.md) | The 1.88 MSRV is inherited, not ours |
| [0008](decisions/0008-file-id-shape-is-validated-not-sanitised.md) | A `fileID` is validated, never sanitised |
| [0009](decisions/0009-effective-encryption-state-over-the-declaration.md) | The effective encryption state, not the declaration |
