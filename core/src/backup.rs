//! The reader's front door.

use std::path::{Path, PathBuf};

use crate::credentials::Credentials;
use crate::crypto::{self, ClassKeys};
use crate::error::Error;
use crate::keybag::KeyBag;
use crate::manifest::{self, BackupFile};
use crate::metadata::{BackupMetadata, Manifest};

/// An opened iOS backup.
///
/// Holds the file tree and, for an encrypted backup, the unwrapped class keys.
/// Content blobs are read and decrypted on demand — opening a backup does not
/// decrypt it, and no plaintext is ever written to disk.
pub struct Backup {
    root: PathBuf,
    metadata: BackupMetadata,
    files: Vec<BackupFile>,
    /// `Some` only for an encrypted backup that was successfully unlocked.
    class_keys: Option<ClassKeys>,
}

/// A backup never renders its key material.
impl core::fmt::Debug for Backup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Backup")
            .field("root", &self.root)
            .field("files", &self.files.len())
            .field("encrypted", &self.metadata.is_encrypted)
            .field("unlocked", &self.class_keys.is_some())
            .finish_non_exhaustive()
    }
}

impl Backup {
    /// Open a backup with no credentials.
    ///
    /// # Errors
    /// [`Error::PasswordRequired`] when the backup is encrypted — the caller is
    /// told to supply a password, never handed an empty file list. Otherwise as
    /// [`Self::open_with`].
    pub fn open(path: &Path) -> Result<Self, Error> {
        Self::open_with(path, &Credentials::None)
    }

    /// Open a backup, offering `credentials`.
    ///
    /// A password supplied for an unencrypted backup is unused, not an error:
    /// a mounting tool that always passes `--password` through should not fail
    /// on the backups that do not need it.
    ///
    /// # Errors
    /// [`Error::NotABackup`] when `Manifest.plist` is absent,
    /// [`Error::PasswordRequired`] when the backup is encrypted and no password
    /// was offered, [`Error::WrongPassword`] when one was offered and no class
    /// key unwrapped, and [`Error::Sqlite`] when `Manifest.db` will not read.
    pub fn open_with(path: &Path, credentials: &Credentials) -> Result<Self, Error> {
        let manifest = Manifest::read(path)?;

        let (class_keys, manifest_bytes) = if manifest.metadata.is_encrypted {
            Self::unlock(path, &manifest, credentials)?
        } else {
            (None, read_file(&path.join("Manifest.db"))?)
        };

        let files = manifest::read_files(manifest_bytes)?;

        Ok(Self {
            root: path.to_path_buf(),
            metadata: manifest.metadata,
            files,
            class_keys,
        })
    }

    /// Derive the class keys and decrypt `Manifest.db` into memory.
    ///
    /// The decrypted manifest is returned as bytes and never written to disk:
    /// a temporary file would be a plaintext copy of the evidence with a
    /// lifetime nobody is tracking.
    fn unlock(
        root: &Path,
        manifest: &Manifest,
        credentials: &Credentials,
    ) -> Result<(Option<ClassKeys>, Vec<u8>), Error> {
        let Some(password) = credentials.as_password() else {
            return Err(Error::PasswordRequired);
        };
        let keybag_bytes = manifest.keybag.as_deref().ok_or(Error::MissingKeyBag)?;
        let keybag = KeyBag::parse(keybag_bytes)?;

        let backup_key = crypto::derive_backup_key(password.as_bytes(), &keybag);
        let class_keys = crypto::unwrap_class_keys(&keybag, &backup_key)?;

        let manifest_key = manifest
            .manifest_key
            .as_deref()
            .ok_or(Error::MissingManifestKey)?;

        // ManifestKey is a 4-byte little-endian protection class followed by
        // the wrapped key. Read the class from the blob rather than assuming
        // one: it is not the same class on every iOS version.
        let protection_class =
            safe_read::try_le_u32(manifest_key, 0).ok_or(Error::MissingManifestKey)?;
        let key = crypto::unwrap_file_key(&class_keys, protection_class, manifest_key)?;

        let ciphertext = read_file(&root.join("Manifest.db"))?;
        let plaintext = crypto::decrypt_aes_cbc_zero_iv(&key, &ciphertext)?;

        Ok((Some(class_keys), plaintext))
    }

    /// Whether `Manifest.plist` declares this backup encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.metadata.is_encrypted
    }

    /// The backup's own directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Device and backup metadata.
    #[must_use]
    pub fn metadata(&self) -> &BackupMetadata {
        &self.metadata
    }

    /// Every entry in the manifest, in the order the manifest records them.
    #[must_use]
    pub fn files(&self) -> &[BackupFile] {
        &self.files
    }

    /// The entry for `domain` and `relative_path`, or `None`.
    #[must_use]
    pub fn find(&self, domain: &str, relative_path: &str) -> Option<&BackupFile> {
        self.files
            .iter()
            .find(|f| f.domain == domain && f.relative_path == relative_path)
    }

    /// The entry with `file_id`, or `None`.
    #[must_use]
    pub fn find_by_id(&self, file_id: &str) -> Option<&BackupFile> {
        self.files.iter().find(|f| f.file_id == file_id)
    }

    /// Where `entry`'s content blob lives on disk.
    #[must_use]
    pub fn blob_path(&self, entry: &BackupFile) -> Option<PathBuf> {
        Some(self.root.join(entry.blob_relative_path()?))
    }

    /// Read `entry`'s content, decrypting it when the backup is encrypted.
    ///
    /// The result is truncated to the length the manifest records. That length
    /// is evidence; the padding on an encrypted blob is not, and guessing at it
    /// by stripping PKCS#7 would corrupt any file whose final plaintext byte
    /// happens to look like a pad.
    ///
    /// # Errors
    /// [`Error::NotAFile`] for a directory or symlink entry,
    /// [`Error::BlobMissing`] when the manifest names a blob that is not on
    /// disk, [`Error::NotUnlocked`] if the backup was never unlocked, and
    /// [`Error::KeyUnwrapFailed`] if the per-file key will not unwrap.
    pub fn read(&mut self, entry: &BackupFile) -> Result<Vec<u8>, Error> {
        if !entry.kind.has_content() {
            return Err(Error::NotAFile {
                path: format!("{}-{}", entry.domain, entry.relative_path),
                kind: format!("{:?}", entry.kind),
            });
        }
        let path = self
            .blob_path(entry)
            .ok_or_else(|| Error::BlobMissing(entry.file_id.clone()))?;

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::BlobMissing(entry.file_id.clone()));
            }
            Err(source) => {
                return Err(Error::Io {
                    path: path.display().to_string(),
                    source,
                })
            }
        };

        let plaintext = if self.metadata.is_encrypted {
            let class_keys = self.class_keys.as_ref().ok_or(Error::NotUnlocked)?;
            let wrapped = entry
                .encryption_key
                .as_deref()
                .ok_or_else(|| Error::NoFileKey(entry.file_id.clone()))?;
            let protection_class = entry
                .protection_class
                .ok_or_else(|| Error::NoFileKey(entry.file_id.clone()))?;

            let key = crypto::unwrap_file_key(class_keys, protection_class, wrapped)?;
            crypto::decrypt_aes_cbc_zero_iv(&key, &bytes)?
        } else {
            bytes
        };

        Ok(truncate_to_manifest_size(
            plaintext,
            entry.size,
            self.metadata.is_encrypted,
        ))
    }
}

/// Cut a decrypted blob back to the length the manifest records.
///
/// A blob shorter than its recorded size is left as it is: the shortfall is
/// evidence of a truncated backup, and padding it out would manufacture bytes
/// that were never captured.
///
/// When the manifest records **no** size, the recorded length cannot be used and
/// the PKCS#7 trailer is stripped instead — the fallback the reference
/// implementations use as their only strategy. Truncating to zero because
/// nothing was recorded would be refusal counted as zero.
fn truncate_to_manifest_size(mut bytes: Vec<u8>, size: Option<u64>, encrypted: bool) -> Vec<u8> {
    let Some(size) = size else {
        return if encrypted { strip_pkcs7(bytes) } else { bytes };
    };
    if let Ok(size) = usize::try_from(size) {
        if bytes.len() > size {
            bytes.truncate(size);
        }
    }
    bytes
}

/// Remove a PKCS#7 trailer, or leave the bytes untouched when it is not valid.
///
/// Only reached when the manifest recorded no size. A malformed trailer returns
/// the block intact rather than erroring: with no recorded length there is
/// nothing to check it against, and handing back slightly too many real bytes
/// beats discarding a file an examiner needs.
fn strip_pkcs7(mut bytes: Vec<u8>) -> Vec<u8> {
    let Some(&pad) = bytes.last() else {
        return bytes;
    };
    let pad = pad as usize;
    if pad == 0 || pad > 16 || pad > bytes.len() {
        return bytes;
    }
    // Every padding byte must equal the pad length, or this is not PKCS#7.
    if bytes[bytes.len() - pad..]
        .iter()
        .all(|&b| b as usize == pad)
    {
        bytes.truncate(bytes.len() - pad);
    }
    bytes
}

/// Read a file, reporting its path on failure.
fn read_file(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })
}
