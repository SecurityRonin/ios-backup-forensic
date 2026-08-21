# 10. Mounting goes through the VFS tree seam, not disk-forensic

- **Status:** Accepted
- **Date:** 2026-08-21
- **Supersedes:** [ADR-0005](0005-credentials-seam-for-mounting-tools.md)

## Context

ADR-0005 recorded how a mounting tool would reach an encrypted backup. Its
analysis of *this* crate was sound and still stands: a backup is a logical file
container, credentials belong in the call rather than in a serialized address,
and a backup is not an `EncryptionLayer` because each file is wrapped under its
own protection-class key.

Its **route was wrong**, and the error was load-bearing. ADR-0005 opens:

> `4n6mount` mounts evidence without knowing one format from another. It reaches
> logical file containers — AD1, AFF4-Logical, DAR — through
> `disk_forensic::logical::open`

`4n6mount` does not depend on `disk-forensic` at all. Its manifest on `origin/main`
carries `forensic-vfs`, `forensic-vfs-engine`, `forensic-vfs-resolver` and
`archive-core`, and `disk-forensic` appears zero times. Building
`disk_forensic::logical::open_with` exactly as ADR-0005 specified would have
delivered a correct, tested, well-documented change that gave `4n6mount`
precisely nothing.

The claim was never observed. It was written once, read as fact, and repeated in
this crate's own `logical.rs` module documentation, where it justified the shape
of `LogicalView`. Re-deriving it took one `grep` over the consumer's manifest.

Two further things the ADR assumed had to be built already existed in
`forensic-vfs` 0.7:

- `CredentialSource` is already threaded through resolution —
  `SourceOpen::open_with_credentials(source, spec, depth, &dyn CredentialSource)`;
- `VfsError::NeedCredentials` already names the locked-evidence condition.

ADR-0005 proposed inventing both downstream as `LogicalError::PasswordRequired`.

## Decision

**A backup is mounted through `forensic_vfs::TreeOpen`, the directory-rooted
opener seam, implemented in this crate behind the `vfs` feature.**

The real gap was narrower and more structural than ADR-0005 described. Every
opener in the VFS registry — `ContainerOpen`, `VolumeSystemOpen`,
`EncryptionOpen`, `FileSystemOpen`, `ArchiveOpen` — takes a `DynSource`, a byte
stream to sniff. A backup is a *directory*, and `Layer::File` is documented as
"the base file path". Nothing modelled a directory as an evidence root, so no
entry point could accept one.

`forensic-vfs` therefore grows:

```rust
pub trait TreeOpen: Send + Sync {
    fn probe(&self, root: &Path) -> Confidence;
    fn open(&self, root: &Path, creds: &dyn CredentialSource) -> VfsResult<DynFs>;
}
```

with `Layer::Directory`, a `dir:` URI tag, and
`SourceOpen::open_tree() -> Option<ResolvedTree>`.

Credentials go to `open` directly rather than through a layer beneath it, for
exactly the reason ADR-0005 gave for rejecting `EncryptionLayer`: there is no
sector stream to translate, so the mount itself is what needs the key.

This crate implements `TreeOpen`. `4n6mount` registers it and grows the password
supply routes; the ranking in ADR-0005 is unchanged and still correct:

| Route | Who else can see it |
|---|---|
| Interactive prompt, no echo | nobody |
| `--password-file <path>` | anyone who can read the file |
| `IOS_BACKUP_PASSWORD` | the process tree, `/proc`, crash dumps |
| `--password <pw>` | **every user on the machine**, via `ps` |

## Consequences

- `LogicalView` stays. Its shape is useful and its tests are real; only the
  sentence explaining *which upstream* consumes it was wrong, and that is
  corrected in `logical.rs` alongside this ADR.
- The `vfs` feature stops being a promise. It shipped declaring an optional
  `forensic-vfs` dependency and describing VFS integration, with **no** reference
  to `forensic_vfs` anywhere in the source — a feature flag that compiled and did
  nothing.
- A locked backup surfaces `NeedCredentials` rather than resolving to nothing.
  Reporting locked evidence as unrecognized is the failure an examiner is least
  able to argue with: *"nothing here"* reads as a finding.
- The seam is general. Encrypted AFF4-Logical and AD1 need the same directory
  root, so this is not an iOS-shaped hole cut in a shared crate.

## The part worth keeping

ADR-0005's reasoning survived; its premise did not. A design note describes the
world on the day it was written, and the sentence most likely to rot is the one
about *someone else's* code. Anything an ADR asserts about a consumer is a claim
to re-check before building on it, not a fact to inherit — the check here was one
command, and skipping it would have cost the entire change.
