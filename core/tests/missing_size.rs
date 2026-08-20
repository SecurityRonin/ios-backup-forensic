//! A manifest row that records no `Size`.
//!
//! Found by comparing against `datatags/mount-ios-backup`, which strips PKCS#7
//! padding and so never consults `Size` for content length. This crate
//! truncates to the recorded size (ADR-0003), which is the better default —
//! padding is not evidence and the recorded length is — but it has a failure
//! mode the padding-stripping approach does not: an **absent** size read as
//! zero truncates a real file to nothing and reports success.
//!
//! That is refusal counted as zero, and it is adversarially reachable: a
//! crafted backup that omits `Size` would make a file disappear from an
//! examiner's view while every operation reported success.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use ios_backup_core::{Backup, Credentials};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data")
        .join(name)
}

#[test]
fn a_file_with_no_recorded_size_is_not_silently_read_as_empty() {
    let mut backup = Backup::open_with(&fixture("no-size-backup"), &Credentials::none()).unwrap();

    let entry = backup
        .find("HomeDomain", "Library/Preferences/com.apple.example.plist")
        .expect("the fixture carries the size-less file")
        .clone();

    assert_eq!(
        entry.size, None,
        "the manifest records no Size for this row"
    );

    let bytes = backup.read(&entry).unwrap();
    assert_eq!(
        bytes, b"tiny",
        "a file whose size the manifest omits must still yield its content; \
         returning empty would be refusal counted as zero"
    );
}

#[test]
fn a_recorded_size_is_still_honoured_over_padding() {
    // The ADR-0003 behaviour must be unchanged for the normal case: the
    // recorded length wins, and PKCS#7 padding is never consulted.
    let mut backup = Backup::open_with(&fixture("plain-backup"), &Credentials::none()).unwrap();
    let entry = backup
        .find("AppDomain-com.example.app", "Documents/exact.bin")
        .unwrap()
        .clone();

    assert_eq!(entry.size, Some(32));
    assert_eq!(backup.read(&entry).unwrap(), vec![b'B'; 32]);
}
