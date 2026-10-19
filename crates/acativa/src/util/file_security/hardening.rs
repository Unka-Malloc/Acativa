use anyhow::{Result, anyhow, ensure};
use std::fs;
use std::io;
use std::path::Path;

use super::validation;

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    validation::validate_private_path_ancestors(path)?;
    fs::create_dir_all(path)?;
    harden_private_path(path)?;
    validation::validate_private_path_ancestors(path)
}

pub fn harden_private_tree(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        !metadata.file_type().is_symlink(),
        "private tree contains a symbolic link"
    );
    if metadata.file_type().is_dir() {
        harden_private_path(path)?;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            harden_private_tree(&entry.path())?;
        }
        let stable = fs::symlink_metadata(path)?;
        ensure!(
            stable.file_type().is_dir() && !stable.file_type().is_symlink(),
            "private tree directory changed during hardening"
        );
        return validation::ensure_same_file(&metadata, &stable);
    }
    ensure!(
        metadata.file_type().is_file(),
        "private tree contains an unsupported node"
    );
    harden_private_path(path)?;
    let stable = fs::symlink_metadata(path)?;
    ensure!(
        stable.file_type().is_file() && !stable.file_type().is_symlink(),
        "private tree file changed during hardening"
    );
    validation::ensure_same_file(&metadata, &stable)
}

pub fn harden_private_path(path: &Path) -> Result<()> {
    validation::validate_private_path_ancestors(path)?;
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(anyhow!("private path metadata is unavailable")),
    };
    ensure!(
        !before.file_type().is_symlink()
            && (before.file_type().is_dir() || before.file_type().is_file()),
        "private path is not a stable file or directory"
    );
    #[cfg(unix)]
    super::unix_hardening::harden_path(path, before.file_type().is_dir())
        .map_err(|_| anyhow!("private path permissions could not be applied"))?;
    #[cfg(windows)]
    super::windows_acl::apply_owner_only(path)?;

    let after =
        fs::symlink_metadata(path).map_err(|_| anyhow!("private path changed during hardening"))?;
    ensure!(
        !after.file_type().is_symlink()
            && before.file_type().is_dir() == after.file_type().is_dir()
            && before.file_type().is_file() == after.file_type().is_file(),
        "private path changed during hardening"
    );
    validation::ensure_same_file(&before, &after)?;
    validation::validate_private_path_ancestors(path)
}
