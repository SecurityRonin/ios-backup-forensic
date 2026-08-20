# 4. A failed unwrap is a wrong password, never an empty result

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

RFC 3394 key unwrap carries an integrity check: an `A6A6A6A6A6A6A6A6` prefix that
must appear after unwrapping. If the key-encrypting key is wrong, it does not.
For a backup the KEK is a pure function of the password, so a failed check means a
wrong password.

The question is what the reader does with that.

## Decision

`crypto::unwrap_class_keys` returns `Error::WrongPassword` when no class key
unwraps, and `Backup::open` returns `Error::PasswordRequired` when an encrypted
backup is opened with no password at all. The two are deliberately distinct: one
means *ask the examiner*, the other means *the examiner already answered,
wrongly*.

Class keys not wrapped with `WRAP_PASSCODE` are **skipped, not counted as
failures** — a device-bound class is not derivable from a password and its
absence says nothing about whether the password was right.

## Rationale

Returning an empty `ClassKeys` would be refusal counted as zero. Downstream, an
empty key set produces an unreadable backup that looks exactly like an empty one,
and an examiner cannot tell "wrong password" from "nothing in this backup". That
is the `Ok(empty)`-on-failed-bootstrap shape ADR-0012 names as the worst bug
class for a forensic reader.

Reporting it as a corrupt keybag would be worse still: it sends the examiner
looking for damage to evidence that is intact.

## Consequences

- `Error::WrongPassword` is actionable: retry with a different password.
- A wrong password can never yield partial garbage. The integrity check is the
  only thing between a wrong key and 32 plausible bytes being used to "decrypt"
  evidence, and it is never bypassed.
- Verified on real evidence: against a backup with `DPIC` = 10,000,000, a wrong
  password is rejected in 3.16 s with `WrongPassword`.
