//! Validation against a **real** iOS backup (T2 — genuine third-party artifact,
//! ground truth taken from the format spec and an independent decryptor).
//!
//! Real backups are personal evidence: they are never committed. Point
//! `IOS_BACKUP_DIR` at one to run these, e.g.
//!
//! ```text
//! IOS_BACKUP_DIR="$HOME/Library/Application Support/MobileSync/Backup/<UDID>" \
//!   cargo test -p ios-backup-core --test real_backup -- --nocapture
//! ```
//!
//! Absent the variable the tests skip in ~0.00s. That near-zero duration is the
//! fingerprint of work not done — do not read a green run here as validation
//! unless the variable was set (CLAUDE.md, the three-way control).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use ios_backup_core::keybag::{KeyBag, KeyBagKind};

/// The backup under test, or `None` when the env gate is unset.
fn backup_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("IOS_BACKUP_DIR")?);
    assert!(
        dir.join("Manifest.plist").is_file(),
        "IOS_BACKUP_DIR={} has no Manifest.plist — pointing the gate at the wrong \
         directory would skip silently and read as a pass",
        dir.display()
    );
    Some(dir)
}

/// The raw `BackupKeyBag` blob out of `Manifest.plist`.
fn raw_keybag(dir: &std::path::Path) -> Vec<u8> {
    let value = plist::Value::from_file(dir.join("Manifest.plist")).expect("Manifest.plist parses");
    let dict = value
        .as_dictionary()
        .expect("Manifest.plist is a dictionary");
    dict.get("BackupKeyBag")
        .expect("an encrypted backup carries BackupKeyBag")
        .as_data()
        .expect("BackupKeyBag is a data blob")
        .to_vec()
}

#[test]
fn real_keybag_parses_and_is_a_backup_keybag() {
    let Some(dir) = backup_dir() else {
        eprintln!("SKIP: IOS_BACKUP_DIR unset");
        return;
    };

    let bytes = raw_keybag(&dir);
    let kb = KeyBag::parse(&bytes).expect("a real BackupKeyBag must parse");

    assert_eq!(kb.kind, KeyBagKind::Backup);
    assert!(!kb.salt.is_empty(), "a backup keybag always carries SALT");
    assert!(kb.iterations > 0, "ITER must be a real iteration count");

    // Every backup keybag published since iOS 5 carries the file protection
    // classes; a bag that parsed into zero classes means the block-splitting
    // rule is wrong, which a synthetic fixture would not reveal.
    assert!(
        !kb.classes.is_empty(),
        "parsed {} bytes into zero class keys — the class-block rule is wrong",
        bytes.len()
    );

    eprintln!(
        "real keybag: {} bytes, version {}, iter {}, dp_iter {:?}, {} classes {:?}",
        bytes.len(),
        kb.version,
        kb.iterations,
        kb.double_protection_iterations,
        kb.classes.len(),
        kb.classes
            .iter()
            .map(|c| c.protection_class)
            .collect::<Vec<_>>()
    );
}

#[test]
fn real_keybag_class_keys_are_the_wrapped_width() {
    let Some(dir) = backup_dir() else {
        eprintln!("SKIP: IOS_BACKUP_DIR unset");
        return;
    };

    let kb = KeyBag::parse(&raw_keybag(&dir)).unwrap();

    for class in &kb.classes {
        // RFC 3394 wraps an n-byte key to n+8 bytes, so a 32-byte AES class key
        // is stored as 40. A different width here means the field was split at
        // the wrong boundary.
        assert_eq!(
            class.wrapped_key.len(),
            40,
            "class {} WPKY is {} bytes, expected a 40-byte wrapped AES-256 key",
            class.protection_class,
            class.wrapped_key.len()
        );
    }
}
