# 1. Reader and analyzer are two crates

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

Fleet policy (ADR-0008, ADR-0009) is Pattern A for a single-format repository:
`<x>-core` reads, `<x>-forensic` audits. This repository handles one format, the
iOS backup, so it is Pattern A.

## Decision

`ios-backup-core` exposes the file tree and reads bytes, decrypting on demand. It
emits **no** findings. `ios-backup-forensic` depends on it and emits
`forensicnomicon::report::Finding` through `impl Observation`.

## Consequences

- `4n6mount` depends only on the reader. Mounting a backup does not drag the
  report model, its severity scale, or its dependency tree into the mount path.
- The analyzer can be re-run against an already-open `Backup` without re-reading
  or re-decrypting it: `audit(&Backup)` borrows.
- A finding is never manufactured inside the reader, where there is no context to
  grade it. The reader reports *errors*; the analyzer reports *observations*.
