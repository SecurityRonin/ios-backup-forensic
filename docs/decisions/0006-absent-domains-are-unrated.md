# 6. An absent domain is reported unrated

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

The question most often asked of a phone backup is whether a messenger's data is
there. When a domain such as
`AppDomainGroup-group.net.whatsapp.WhatsApp.shared` is absent from a backup taken
from a phone that plainly ran the app, that absence is the finding.

`forensicnomicon::report::Finding` carries `Option<Severity>`, where `None` is
explicitly *not-scored* and distinct from `Some(Info)`.

## Decision

`AnomalyKind::ExpectedDomainAbsent` has `severity() == None`, and its note names
the alternatives without choosing between them.

## Rationale

A backup records what was captured. It does not record why something was not, and
at least three causes leave an identical trace:

- the app was never installed;
- the app's data was excluded from the backup;
- iOS declined to back it up on that version.

Grading the absence would import a judgement the evidence cannot support. `Info`
would say "unremarkable" and `High` would say "suspicious"; both are claims about
a cause, and the backup contains no fact that distinguishes them.

`None` says what is true: this was observed, this analyzer will not grade it, and
the question is open. It is a lead for the examiner, which is what it actually is.

## Consequences

- The list in `domains.rs` stays narrow. A domain earns a place only if a reader
  would want to know it was missing; padding it turns every backup into a wall of
  findings and trains the reader to skip them.
- Matching is by **prefix**, because app-group domains carry a bundle-identifier
  suffix and an exact match would report every one absent.
- A test asserts these findings are unrated, so a later change that grades them
  has to be deliberate.
- The same discipline governs every note in the analyzer: a test screens for
  verdict words ("proves", "deliberately", "tampered"), because that is how an
  observation becomes an unearned conclusion by the time it reaches a report.
