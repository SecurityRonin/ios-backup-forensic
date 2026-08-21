//! A manifest row must never disappear without being counted.
//!
//! Found while comparing against the population of iOS-backup implementations
//! on GitHub. `Manifest.db` declares `fileID TEXT PRIMARY KEY`, but SQLite has
//! column **affinity**, not type enforcement — a BLOB in that column is legal
//! and round-trips fine. A reader that matches only `Value::Text` therefore
//! drops the row.
//!
//! This crate did exactly that, with a `continue` and a comment explaining why
//! the row was not worth offering. The reasoning was half right: declining to
//! *offer* an unidentifiable file is defensible; declining to *record that a row
//! was dropped* is not. A file that never reaches the tree cannot be flagged by
//! any analyzer and cannot be looked for by any examiner — the loss is silent at
//! the collection stage, which is the worst place for it.
//!
//! The rule this pins: **the reader never reduces the row count without saying
//! so.**

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use ios_backup_core::{Backup, Credentials};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data")
        .join(name)
}

#[test]
fn a_file_id_stored_as_a_blob_is_still_read() {
    // Hex digits are ASCII, so a BLOB fileID decodes to exactly the same string.
    // Refusing it would lose a file over a storage-class detail that changes
    // nothing about the evidence.
    let backup = Backup::open_with(&fixture("blob-file-id"), &Credentials::none()).unwrap();

    let entry = backup
        .find("HomeDomain", "Library/Preferences/com.apple.example.plist")
        .expect("the row whose fileID is a BLOB must still be present");

    assert_eq!(entry.file_id, "237587581264bcaf56b49aa388e2de87551695f5");
}

#[test]
fn every_manifest_row_is_accounted_for() {
    // The count the reader offers must equal the count the manifest holds,
    // unless the difference is stated.
    let backup = Backup::open_with(&fixture("blob-file-id"), &Credentials::none()).unwrap();

    assert_eq!(backup.files().len(), 5, "four files plus one directory");
    assert_eq!(
        backup.unreadable_rows(),
        0,
        "a BLOB fileID is readable, so nothing should be counted as lost"
    );
}

#[test]
fn a_row_that_cannot_be_identified_is_counted_not_silently_dropped() {
    // A fileID that is neither text nor UTF-8-decodable bytes identifies
    // nothing, so it cannot be offered as a file. It must still be COUNTED —
    // an examiner needs to know the tree is smaller than the manifest.
    let dir = tempfile::tempdir().unwrap();
    let source = fixture("plain-backup");
    for name in ["Manifest.plist", "Status.plist", "Info.plist"] {
        std::fs::copy(source.join(name), dir.path().join(name)).unwrap();
    }
    // A manifest holding one good row and one whose fileID is invalid UTF-8.
    let db = build_manifest_with_an_unreadable_row();
    std::fs::write(dir.path().join("Manifest.db"), db).unwrap();

    let backup = Backup::open_with(dir.path(), &Credentials::none()).unwrap();

    assert_eq!(backup.files().len(), 1, "only the readable row is offered");
    assert_eq!(
        backup.unreadable_rows(),
        1,
        "the dropped row must be counted, or its loss is invisible"
    );
}

/// A minimal `Manifest.db` with one readable row and one whose `fileID` is
/// bytes that are not valid UTF-8.
fn build_manifest_with_an_unreadable_row() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.db");
    let conn = rusqlite_shim::create(&path);
    drop(conn);
    std::fs::read(&path).unwrap()
}

/// Building a SQLite file without a SQLite writer dependency: shell out to the
/// `sqlite3` binary, which every developer and CI runner has.
mod rusqlite_shim {
    pub fn create(path: &std::path::Path) {
        let sql = r"
CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
INSERT INTO Files VALUES ('3d0d7e5fb2ce288813306e4d4636395e047a3d28','HomeDomain','Library/SMS/sms.db',1,NULL);
INSERT INTO Files VALUES (x'FFFE0041','HomeDomain','Library/Other/x.db',1,NULL);
";
        let status = std::process::Command::new("sqlite3")
            .arg(path)
            .arg(sql)
            .status()
            .expect("sqlite3 binary is required for this test");
        assert!(status.success());
    }
}
