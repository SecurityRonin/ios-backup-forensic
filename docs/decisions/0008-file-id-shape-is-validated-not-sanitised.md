# 8. A `fileID` is validated, never sanitised

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

`Manifest.db` is attacker-controllable. That is not a hypothetical for this
crate — it is the premise of ADR-0012, and an examiner is expected to point the
reader at a backup of unknown provenance.

`fileID` is read out of that database and used to build a filesystem path:
`<backup>/<first-2-chars>/<fileID>`. Until this decision, no check stood between
the two.

Found by reading MVT (Amnesty International Security Lab), which guards the same
path explicitly:

```python
if not Path(source_file_path).resolve().is_relative_to(Path(self.backup_path).resolve()):
    log.warning("Skipping unsafe file_id: %s", ...)
```

Reproduced before fixing, and there were **two** escapes, not one:

```text
"../../../../etc/passwd"  ->  /evidence/backup/../../../../../etc/passwd
"/etc/passwd"             ->  /etc/passwd
```

The second is the serious one and it is Rust-specific:
**`Path::join` REPLACES the whole path when its argument is absolute.** An
absolute `fileID` therefore does not climb out of the backup directory — it
addresses the examiner's filesystem directly, from the very first join. A
crafted backup could make `Backup::read` return the contents of any file the
examiner's process could read, with every operation reporting success.

## Decision

Validate the *shape* of `fileID` before any path is constructed. A `fileID` is
`SHA1(domain + "-" + relativePath)` rendered as hex, so:

```rust
pub fn is_file_id(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
```

Anything else resolves to `None` and `Backup::read` returns
`Error::UnsafeFileId`, carrying the offending value verbatim.

## Why validate rather than sanitise

**Sanitising is a blocklist, and a blocklist is a list of the attacks someone
thought of.** Strip `..`, and an absolute path still works. Reject absolute
paths, and a Windows drive-relative path (`C:evil`) or a UNC path remains. Every
round adds a rule and leaves the question open.

Validating closes it by construction. Hex contains no separator, no dot, no
drive letter and no colon, so a value that passes cannot express traversal in
any syntax on any platform. **There is no path to sanitise because no path is
built** — which is the secure-by-design test: can a competent caller who has not
read the docs use this incorrectly? Here they cannot, because the unsafe input
never reaches path construction.

## Consequences

- A traversing or absolute `fileID` is refused with its value shown, so an
  examiner sees that a backup tried to walk the reader out of its own directory
  rather than seeing a generic "blob not found".
- `Error::UnsafeFileId` is deliberately distinct from `Error::BlobMissing`.
  "Not present" and "refused to resolve" are different facts, and the second is
  the one that indicates tampering.
- **The row is kept, not dropped.** A malformed `fileID` is still evidence, so
  it stays in `files()` and `ios-backup-forensic` reports it through
  `IOS-BACKUP-FILEID-MISMATCH` — the same invariant catches it, since a value
  that is not a digest cannot equal `SHA1(domain-relativePath)`. Only path
  *resolution* is refused.
- Uppercase digests still resolve. Refusing them would drop a legitimate row
  over a case difference, which is its own way of losing evidence.
- Verified by mutation: neutering `is_file_id` to always return `true` turns
  three of the five traversal tests red.
