# 2. `sqlite-core` reads `Manifest.db`

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

`Manifest.db` is a SQLite database, and in an encrypted backup it is
AES-256-CBC-encrypted as a whole file. Reading it needs a SQLite reader.

ADR-0010 makes preferring our own crates binding, so `sqlite-core` was the
starting assumption rather than `rusqlite`. Two properties settled it beyond the
policy:

1. **It opens from bytes.** `Database::open(bytes: Vec<u8>)` means a decrypted
   manifest is read from memory. With a path-only reader we would have to write
   the decrypted evidence to a temporary file — a plaintext copy of the material
   with a lifetime nobody is tracking, on a disk we do not control.
2. **It is a native, read-only, panic-free reader with no C dependency.** The
   manifest of an encrypted backup is attacker-controllable ciphertext; a wrong
   key produces high-entropy bytes that are then handed to a SQLite parser. That
   is precisely the input `libsqlite3-sys` should not be pointed at.

## Decision

`ios-backup-core` depends on `sqlite-core`, reads the `Files` table through
`Database::live_table_rows()`, and locates columns **by name**.

## The layering question, stated rather than glossed

`CLAUDE.md` says CONTAINER depends on FOUNDATION only, and `sqlite-core` is a
PARSER-tier crate. This dependency is therefore sideways in the layer map.

It is accepted deliberately, for a reason narrower than "it was convenient": the
rule's purpose is to keep PARSER crates **medium-agnostic**, so a parser never
learns where its bytes came from. That direction is preserved exactly —
`sqlite-core` is handed a `Vec<u8>` and learns nothing about backups. What the
rule forbids is a parser reaching *up* into a container; this is a container
reaching *down* for a decoder of its own internal index, which creates no cycle
and no medium coupling.

Recorded here rather than left implicit, so a future reader sees a decision and
not an oversight.

## Consequences

- No decrypted evidence ever reaches disk.
- Column-by-name means a `Files` table that gains a column does not silently
  shift reads onto the wrong field. A positional read would produce values that
  are individually plausible and collectively wrong — the worst failure shape.
- A wrong manifest key surfaces as `Error::Sqlite`, because that is genuinely
  what a wrong key looks like from here: not-a-database.
