use anyhow::{Result, anyhow, ensure};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{sync, validation};

pub fn atomic_write_private_text(path: &Path, content: &str) -> Result<()> {
    atomic_write_private_text_with_policy(path, content, usize::MAX, false)
}

pub fn atomic_write_private_text_bounded(
    path: &Path,
    content: &str,
    max_bytes: usize,
) -> Result<()> {
    atomic_write_private_text_with_policy(path, content, max_bytes, true)
}

fn atomic_write_private_text_with_policy(
    path: &Path,
    content: &str,
    max_bytes: usize,
    require_private_existing_file: bool,
) -> Result<()> {
    ensure!(
        content.len() <= max_bytes,
        "private state file exceeds its bounded size"
    );
    if require_private_existing_file {
        validation::ensure_private_state_parent(path)?;
    } else {
        validation::ensure_atomic_write_parent(path)?;
    }
    if let Some(metadata) = validation::state_marker_metadata(path)? {
        if require_private_existing_file {
            validation::validate_private_file_metadata(&metadata)?;
        } else {
            validation::validate_private_file_type_and_owner(&metadata)?;
        }
    }
    let tmp = sibling_temp_path(path);
    let write_result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|_| anyhow!("private state temporary file could not be created"))?;
        validation::apply_private_file_permissions(&file, &tmp)?;
        file.write_all(content.as_bytes())?;
        sync::file(&mut file)?;
        validation::validate_open_state_marker(&tmp, &file)?;
        drop(file);
        rename_into_place(&tmp, path)
            .map_err(|_| anyhow!("private state file could not be committed"))?;
        let committed = fs::symlink_metadata(path)
            .map_err(|_| anyhow!("private state file disappeared after commit"))?;
        validation::validate_private_file_metadata(&committed)?;
        sync::parent(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

pub(super) fn rename_into_place(tmp: &Path, path: &Path) -> Result<()> {
    validation::validate_regular_file_or_missing_no_follow(tmp, false)?;
    validation::validate_regular_file_or_missing_no_follow(path, true)?;
    match fs::rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            copy_cross_device_then_atomic_replace(tmp, path)
        }
        Err(error) => Err(error.into()),
    }
}

/// Whether the committed artifact's directory entry is confirmed durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDurability {
    /// The replacement and its parent-directory sync both completed.
    Confirmed,
    /// The replacement completed but the final directory sync did not: the artifact is
    /// in place and recoverable, while its durability is unconfirmed.
    Unconfirmed,
}

/// The outcome of abandoning a private atomic write before publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupOutcome {
    /// The temporary file is gone and its parent entry is confirmed durable.
    Removed,
    /// Removal completed, but syncing this parent directory failed.
    DurabilityUnconfirmed(PathBuf),
    /// The temporary file could not be removed and remains recoverable at this path.
    Retained(PathBuf),
}

/// A private atomic write that did not publish a new artifact.
///
/// The error is the cause; `cleanup` distinguishes retained scratch from removal whose
/// directory durability could not be confirmed. Neither state is a successful abort.
#[derive(Debug)]
pub struct AtomicWriteFailure {
    error: anyhow::Error,
    cleanup: CleanupOutcome,
}

impl AtomicWriteFailure {
    pub fn error(&self) -> &anyhow::Error {
        &self.error
    }

    pub fn cleanup(&self) -> &CleanupOutcome {
        &self.cleanup
    }

    pub fn into_parts(self) -> (anyhow::Error, CleanupOutcome) {
        (self.error, self.cleanup)
    }

    fn not_committed(error: anyhow::Error) -> Self {
        Self {
            error,
            cleanup: CleanupOutcome::Removed,
        }
    }

    fn from_cleanup(error: anyhow::Error, cleanup: CleanupOutcome) -> Self {
        Self { error, cleanup }
    }
}

/// Remove the operation's own temporary file with a checked outcome.
fn remove_checked(temp: &Path) -> CleanupOutcome {
    remove_with_sync(temp, sync::parent)
}

pub(super) fn remove_with_sync<F>(temp: &Path, mut sync_parent: F) -> CleanupOutcome
where
    F: FnMut(&Path) -> Result<()>,
{
    match fs::remove_file(temp) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return CleanupOutcome::Retained(temp.to_path_buf()),
    }
    match sync_parent(temp) {
        Ok(()) => CleanupOutcome::Removed,
        Err(_) => CleanupOutcome::DurabilityUnconfirmed(
            temp.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf(),
        ),
    }
}

/// Atomically replace `destination` with the synced sibling `temp`.
///
/// Every fallible check runs before the single rename, and the previous artifact stays
/// at its name until that replacement, so no window exists in which the artifact is
/// missing and a reported failure always leaves the previous artifact in place. After
/// the replacement only the parent-directory sync remains; if it fails, the artifact is
/// still published and the caller receives [`CommitDurability::Unconfirmed`] instead of
/// a misleading failure that would suggest nothing was written. The temporary file is
/// left for the caller's checked cleanup on failure.
pub(super) fn commit_with_sync<F>(
    temp: &Path,
    destination: &Path,
    mut sync_parent: F,
) -> Result<CommitDurability>
where
    F: FnMut(&Path) -> Result<()>,
{
    validation::validate_regular_file_or_missing_no_follow(temp, false)?;
    validation::validate_regular_file_or_missing_no_follow(destination, true)?;
    let temporary = fs::symlink_metadata(temp)?;
    validation::validate_private_file_metadata(&temporary)?;
    // Durability precondition before the replacement; a failure here leaves the
    // previous artifact untouched.
    sync_parent(destination)?;
    if fs::rename(temp, destination).is_err() {
        return Err(anyhow!("private state file could not be committed"));
    }
    match sync_parent(destination) {
        Ok(()) => Ok(CommitDurability::Confirmed),
        Err(_) => Ok(CommitDurability::Unconfirmed),
    }
}

/// A private file created beside `destination` and committed by rename.
///
/// This is the streamed sibling of [`atomic_write_private_text`] for binary output:
/// the caller writes through [`AtomicPrivateFile::file_mut`], flushes the data, and
/// calls [`AtomicPrivateFile::commit`], which syncs, validates and renames the private
/// temporary file into place. Every failure path removes the temporary file with a
/// checked outcome and reports a retained temporary instead of relying on `Drop`.
pub struct AtomicPrivateFile {
    file: fs::File,
    temp: PathBuf,
    destination: PathBuf,
    committed: bool,
}

impl AtomicPrivateFile {
    pub fn create(destination: &Path) -> Result<Self, AtomicWriteFailure> {
        create_private_file(destination)
    }

    /// The open private temporary file. It stays valid until `commit` consumes the writer.
    pub fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    /// Sync, validate and commit the temporary file as a transaction over the
    /// destination: a reported failure leaves the previous destination in place, and a
    /// published artifact whose final directory sync failed is reported as unconfirmed.
    pub fn commit(mut self) -> Result<CommitDurability, AtomicWriteFailure> {
        if let Err(error) = sync::file(&mut self.file) {
            return Err(self.abort(error));
        }
        if let Err(error) = validation::validate_open_state_marker(&self.temp, &self.file) {
            return Err(self.abort(error));
        }
        match commit_with_sync(&self.temp, &self.destination, sync::parent) {
            Ok(durability) => {
                self.committed = true;
                Ok(durability)
            }
            Err(error) => Err(self.abort(error)),
        }
    }

    /// Abandon the writer before committing, removing the private temporary file with a
    /// checked outcome.
    pub fn discard(mut self) -> CleanupOutcome {
        self.committed = true;
        remove_checked(&self.temp)
    }

    /// Remove the private temporary file with a checked outcome before returning the
    /// failure, so a retained temporary is reported instead of silently dropped.
    fn abort(mut self, error: anyhow::Error) -> AtomicWriteFailure {
        self.committed = true;
        AtomicWriteFailure::from_cleanup(error, remove_checked(&self.temp))
    }
}

fn create_private_file(destination: &Path) -> Result<AtomicPrivateFile, AtomicWriteFailure> {
    validation::ensure_atomic_write_parent(destination)
        .map_err(AtomicWriteFailure::not_committed)?;
    validation::validate_regular_file_or_missing_no_follow(destination, true)
        .map_err(AtomicWriteFailure::not_committed)?;
    let temp = sibling_temp_path(destination);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(&temp).map_err(|_| {
        AtomicWriteFailure::not_committed(anyhow!(
            "private state temporary file could not be created"
        ))
    })?;
    let setup = validation::apply_private_file_permissions(&file, &temp)
        .and_then(|()| validation::validate_open_state_marker(&temp, &file));
    if let Err(error) = setup {
        drop(file);
        return Err(AtomicWriteFailure::from_cleanup(
            error,
            remove_checked(&temp),
        ));
    }
    Ok(AtomicPrivateFile {
        file,
        temp,
        destination: destination.to_path_buf(),
        committed: false,
    })
}

impl Drop for AtomicPrivateFile {
    fn drop(&mut self) {
        if !self.committed {
            // Last resort for panics only; every normal path removes the temporary file
            // with a checked outcome before returning.
            let _ = fs::remove_file(&self.temp);
        }
    }
}

fn copy_cross_device_then_atomic_replace(tmp: &Path, path: &Path) -> Result<()> {
    let parent = sync::parent_or_current(path)?;
    validation::validate_private_path_ancestors(parent)?;
    let stage = sibling_temp_path(path);
    validation::validate_regular_file_or_missing_no_follow(&stage, true)?;

    let source_path_metadata = fs::symlink_metadata(tmp)?;
    validation::validate_private_file_type_and_owner(&source_path_metadata)?;
    let mut source_options = OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut source = source_options
        .open(tmp)
        .map_err(|_| anyhow!("atomic replacement source could not be opened"))?;
    validation::ensure_same_file(&source_path_metadata, &source.metadata()?)?;

    let result = (|| -> Result<()> {
        let mut stage_options = OpenOptions::new();
        stage_options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            stage_options
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW);
        }
        let mut staged = stage_options
            .open(&stage)
            .map_err(|_| anyhow!("atomic replacement stage could not be created"))?;
        validation::apply_private_file_permissions(&staged, &stage)?;
        io::copy(&mut source, &mut staged)?;
        sync::file(&mut staged)?;
        validation::validate_open_state_marker(&stage, &staged)?;
        drop(staged);

        validation::validate_private_path_ancestors(parent)?;
        validation::validate_regular_file_or_missing_no_follow(path, true)?;
        fs::rename(&stage, path).map_err(|_| anyhow!("atomic replacement commit failed"))?;
        sync::parent(path)?;
        let stable_source = fs::symlink_metadata(tmp)
            .map_err(|_| anyhow!("atomic replacement source changed before cleanup"))?;
        validation::ensure_same_file(&source_path_metadata, &stable_source)?;
        fs::remove_file(tmp)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&stage);
    }
    result
}

fn sibling_temp_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("acativa");
    path.with_extension(format!(
        "{}.tmp-{}-{}",
        extension,
        std::process::id(),
        stamp
    ))
}
