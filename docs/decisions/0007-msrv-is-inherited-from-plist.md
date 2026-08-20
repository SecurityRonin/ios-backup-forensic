# 7. The 1.88 MSRV is inherited, not ours

- **Status:** Accepted
- **Date:** 2026-08-21

## Context

Fleet policy is that a published library keeps a low, CI-verified `rust-version`
as a promise to downstream consumers. This repository was written declaring
`1.85`, matching its sibling container crates.

That declaration was **false**, and the check that caught it is worth recording
because a declared `rust-version` is a *claim* — cargo refuses on the
declaration, before compiling a line, so nothing about writing `1.85` tests it:

```
$ cargo +1.85 check --workspace --all-features
error: rustc 1.85.1 is not supported by the following packages:
  plist@1.10.0 requires rustc 1.88.0
  time@0.3.55 requires rustc 1.88.0
  time-core@0.1.9 requires rustc 1.88.0
```

## Separating our constraint from the inherited one

"Fails at 1.85" is not a result. *What refused, and was it our code or a
dependency's declaration* is the result, and they are different columns.

Measured, by pinning the graph down and re-running the same command:

```
$ cargo update -p plist --precise 1.7.4
$ cargo update -p time  --precise 0.3.41
$ cargo +1.85 check --workspace --all-features
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```

| | Floor |
|---|---|
| `ios-backup-core` + `ios-backup-forensic` own source | **≤ 1.85** (compiles green) |
| As resolved with current requirements | **1.88**, from `plist` via `time` |

So nothing in this crate's own code needs 1.88. The number is a shadow cast by a
dependency, and it will move when that dependency moves.

## Decision

Declare `rust-version = "1.88"` — the floor the crate's dependency graph actually
imposes — and record here that our own floor is lower.

## Why not keep 1.85

**Pinning the lockfile does not fix it.** A library's `Cargo.lock` does not
travel to consumers. A downstream crate resolving `plist = "1"` gets 1.10 and
1.88 no matter what we lock, so a 1.85 declaration would be a promise that fails
for everyone except us.

Of the two MSRV defects the fleet warns about, this is the worse one. An
overstated floor is merely conservative; a floor the crate's own graph cannot
satisfy is simply false, and it fails outward.

**Constraining the requirement** — `plist = ">=1.7, <1.8"` — would hold 1.85, at
the cost of pinning a dependency permanently behind, fighting Renovate's
`rangeStrategy: "bump"`, and turning the freshness gate permanently red. Trading
a true statement about compatibility for a stale dependency tree is the wrong
trade for a crate that parses untrusted input.

## Consequences

- Consumers on 1.85–1.87 cannot use this crate. That is a real cost, and it is
  the truth rather than a surprise at build time.
- **Lower this when the constraint lifts.** Two routes, either of which makes
  1.85 honest again with no change to our source:
  1. `plist` (or `time`) lowers its own floor;
  2. we replace `plist`. The `Date` field is the only thing pulling `time` in,
     and a first-party bplist reader — or a fleet one, if `blob-decoder` ever
     grows a public parser — would drop the constraint entirely.
- The MSRV CI job runs `cargo test` on the declared floor, not a bare build: a
  job that only compiles does not prove the crate *works* on the floor it
  promises.
