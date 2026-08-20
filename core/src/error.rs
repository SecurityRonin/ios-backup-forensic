//! The crate's error type.
//!
//! Every variant names the offending value or location: an error that says only
//! "unrecognised" sends the reader back to the hex editor for something the
//! parser already knew (CLAUDE.md, show-the-unrecognized-value).

/// Anything that can go wrong reading an iOS backup.
///
/// A malformed backup is always a typed error, never a panic and never a
/// silently-empty success — degrading to `Ok(empty)` when the cause is a failed
/// bootstrap is the worst bug class for a forensic reader (ADR-0012).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A TLV ran past the end of the keybag: its tag, length, or value window is
    /// not fully present. Carries the byte offset the read was attempted at.
    #[error("truncated keybag: read past end of buffer at offset {offset}")]
    TruncatedKeyBag {
        /// Offset into the keybag at which the out-of-range read was attempted.
        offset: usize,
    },

    /// A keybag `TYPE` field held a value that is not a known keybag kind.
    #[error("unrecognised keybag type {0} (known: 0 System, 1 Backup, 2 Escrow, 3 OTA)")]
    UnknownKeyBagType(u32),

    /// A fixed-width keybag field was declared with the wrong length. Reading it
    /// anyway would yield a plausible but wrong value — a wrong iteration count
    /// derives a wrong key and looks exactly like a wrong password.
    #[error("keybag field {tag} must be {expected} bytes, got {actual}")]
    BadFieldWidth {
        /// The four-character TLV tag.
        tag: &'static str,
        /// Width the format requires.
        expected: usize,
        /// Width actually declared.
        actual: usize,
    },

    /// A field the format requires was absent. Named so the caller can tell
    /// which, rather than receiving a default-constructed keybag.
    #[error("keybag is missing the required {0} field")]
    MissingField(&'static str),
}
