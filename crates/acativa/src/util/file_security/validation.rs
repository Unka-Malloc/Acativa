use anyhow::{Result, anyhow, ensure};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use super::sync;

pub(super) fn ensure_private_state_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("private security state marker parent is missing"))?;
    validate_private_path_ancestors(parent)?;
    let parent_existed = parent.try_exists()?;
    if parent_existed {
        validate_private_directory_type_and_owner(parent)?;
    } else {
        fs::create_dir_all(parent)?;
        validate_private_directory_type_and_owner(parent)?;
    }
    let before = fs::symlink_metadata(parent)?;
    apply_private_directory_permissions(parent)?;
    let after = fs::symlink_metadata(parent)?;
    validate_private_directory_metadata(&after)?;
    ensure_same_file(&before, &after)?;
    validate_private_path_ancestors(parent)?;
    if !parent_existed && let Some(grandparent) = parent.parent() {
        sync::directory(grandparent)?;
    }
    Ok(())
}

pub(super) fn ensure_atomic_write_parent(path: &Path) -> Result<()> {
    let parent = sync::parent_or_current(path)?;
    validate_private_path_ancestors(parent)?;
    if !parent.try_exists()? {
        // Record the missing chain before creating it, then sync each created
        // directory's parent so the new entries are durable, not only their contents.
        let mut missing = Vec::new();
        let mut current = parent.to_path_buf();
        while fs::symlink_metadata(&current).is_err() {
            missing.push(current.clone());
            match current.parent() {
                Some(next) if !next.as_os_str().is_empty() => current = next.to_path_buf(),
                _ => break,
            }
        }
        fs::create_dir_all(parent)?;
        for directory in &missing {
            sync::parent(directory)?;
        }
    }
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| anyhow!("private state file parent is unavailable"))?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.file_type().is_dir(),
        "private state file parent is not a stable directory"
    );
    validate_private_path_ancestors(parent)?;
    let stable = fs::symlink_metadata(parent)
        .map_err(|_| anyhow!("private state file parent changed during validation"))?;
    ensure_same_file(&metadata, &stable)?;
    Ok(())
}

#[cfg(unix)]
pub fn validate_private_path_ancestors(path: &Path) -> Result<()> {
    super::unix_hardening::validate_no_user_owned_symlink_ancestors(path)
}

#[cfg(not(unix))]
pub fn validate_private_path_ancestors(path: &Path) -> Result<()> {
    validate_no_symlink_ancestors(path)
}

pub(super) fn validate_private_directory_type_and_owner(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("private security state directory is unavailable"))?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.file_type().is_dir(),
        "private security state directory is not a stable directory"
    );
    validate_current_owner(&metadata)
}

pub(super) fn apply_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    super::unix_hardening::apply_directory_permissions(path)?;
    #[cfg(windows)]
    super::windows_acl::apply_owner_only(path)?;
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

pub(super) fn apply_private_file_permissions(file: &fs::File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    super::unix_hardening::apply_file_permissions(file)?;
    #[cfg(windows)]
    super::windows_acl::apply_owner_only(path)?;
    #[cfg(not(any(unix, windows)))]
    let _ = (file, path);
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

pub(super) fn state_marker_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(anyhow!(
            "private security state marker metadata is unavailable"
        )),
    }
}

pub(super) fn validate_open_state_marker(path: &Path, file: &fs::File) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("private security state marker changed while opening"))?;
    let opened_metadata = file.metadata()?;
    validate_private_file_metadata(&path_metadata)?;
    validate_private_file_metadata(&opened_metadata)?;
    ensure_same_file(&path_metadata, &opened_metadata)
}

pub(super) fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<()> {
    validate_private_file_type_and_owner(metadata)?;
    #[cfg(unix)]
    super::unix_hardening::validate_file_mode(metadata)?;
    Ok(())
}

pub(super) fn validate_private_file_type_and_owner(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink() && metadata.file_type().is_file(),
        "private security state marker is not a stable regular file"
    );
    validate_current_owner(metadata)
}

pub(super) fn validate_private_directory_metadata(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        !metadata.file_type().is_symlink() && metadata.file_type().is_dir(),
        "private security state directory is not a stable directory"
    );
    validate_current_owner(metadata)?;
    #[cfg(unix)]
    super::unix_hardening::validate_directory_mode(metadata)?;
    Ok(())
}

#[cfg(unix)]
fn validate_current_owner(metadata: &fs::Metadata) -> Result<()> {
    super::unix_hardening::validate_current_owner(metadata)
}

#[cfg(not(unix))]
fn validate_current_owner(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn validate_path_owner(metadata: &fs::Metadata) -> Result<()> {
    super::unix_hardening::validate_path_owner(metadata)
}

#[cfg(not(unix))]
pub fn validate_path_owner(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

pub fn validate_export_destination(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(anyhow!("export destination metadata is unavailable")),
    };
    let check = if metadata.is_some() {
        path
    } else {
        path.parent()
            .ok_or_else(|| anyhow!("export destination has no parent directory"))?
    };
    let metadata = fs::symlink_metadata(check)
        .map_err(|_| anyhow!("export destination metadata is unavailable"))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "export destination must not be a symlink"
    );
    validate_path_owner(&metadata)
}

pub fn validate_no_symlink_ancestors(path: &Path) -> Result<()> {
    ensure!(
        !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "path contains a parent traversal component"
    );
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "path contains a symbolic-link ancestor"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(_) => return Err(anyhow!("path ancestor metadata is unavailable")),
        }
    }
    Ok(())
}

pub(super) fn validate_regular_file_or_missing_no_follow(
    path: &Path,
    allow_missing: bool,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "atomic replacement path is not a stable regular file"
        ),
        Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn ensure_same_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<()> {
    super::unix_hardening::ensure_same_file(left, right)
}

#[cfg(not(unix))]
pub(super) fn ensure_same_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<()> {
    ensure!(
        left.file_type().is_file() == right.file_type().is_file()
            && left.file_type().is_dir() == right.file_type().is_dir()
            && left.file_type().is_symlink() == right.file_type().is_symlink()
            && left.len() == right.len()
            && left.created().ok() == right.created().ok(),
        "private path was replaced"
    );
    Ok(())
}

pub(super) fn open_read_no_follow(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|_| anyhow!("private security state marker could not be opened"))
}
