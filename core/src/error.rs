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

    /// A key width AES does not define. Carries the offending width.
    #[error("unsupported AES key width {0} bytes (expected 16, 24 or 32)")]
    UnsupportedKeyWidth(usize),

    /// A wrapped key was not a whole number of 64-bit semiblocks, or was too
    /// short to be an RFC 3394 wrapping. Carries the offending length.
    #[error("wrapped key of {0} bytes is not a valid RFC 3394 wrapping (need a multiple of 8, at least 24)")]
    BadWrappedKeyLength(usize),

    /// The RFC 3394 integrity check failed: the unwrapped value did not carry
    /// the expected `A6A6A6A6A6A6A6A6` prefix.
    ///
    /// For a backup this almost always means the key-encrypting key is wrong,
    /// which means the **password** is wrong. It never means "here is a key
    /// that might work" — a wrapped key either verifies or it does not.
    #[error("key unwrap failed the RFC 3394 integrity check (wrong key)")]
    KeyUnwrapFailed,

    /// No class key in the keybag could be unwrapped with the derived key.
    ///
    /// Distinct from an empty result: reporting zero recovered keys as success
    /// would be refusal counted as zero, and the caller could not tell a wrong
    /// password from a keybag that carries no passcode-wrapped class.
    #[error("wrong backup password: no class key in the keybag could be unwrapped")]
    WrongPassword,

    /// A file declares a protection class the keybag has no key for.
    #[error("no class key for protection class {0}")]
    NoKeyForClass(u32),

    /// A CBC ciphertext was not a whole number of 16-byte blocks. Carries the
    /// offending length.
    #[error("ciphertext of {0} bytes is not a whole number of AES blocks")]
    BadCiphertextLength(usize),

    /// An IV that was not 16 bytes. Carries the offending length.
    #[error("IV must be 16 bytes, got {0}")]
    BadIvLength(usize),
}
