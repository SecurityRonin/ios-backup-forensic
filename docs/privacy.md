# Privacy

`ios-backup-forensic` is a Rust library. It has no network code, no telemetry,
and no analytics.

## What it does with your data

It reads the backup directory you point it at, and nothing else. Every operation
is read-only.

Decrypted content — including the decrypted `Manifest.db` — is held in memory and
never written to disk by this library. Nothing is written to a temporary file, a
cache, or a log.

A password you supply is held in a `Password`, which zeroizes its bytes on drop
and renders as `Password(<redacted>)` so it cannot reach a log through a `Debug`
format.

## What leaves your machine

Nothing.

## Contact

albert@securityronin.com
