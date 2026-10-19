use anyhow::{Result, anyhow};
use std::fs;
use std::io;
use std::path::Path;

pub(super) fn file(file: &mut fs::File) -> Result<()> {
    if let Err(error) = file.sync_all() {
        if unsupported(&error) {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

pub(super) fn parent(path: &Path) -> Result<()> {
    // A bare relative destination syncs its containing directory, the same directory the
    // rename committed into, instead of failing on an empty parent after the rename.
    let parent = parent_or_current(path)?;
    directory(parent)
}

/// Resolve the containing directory without depending on higher-level validation.
/// A bare relative destination belongs to the current directory.
pub(super) fn parent_or_current(path: &Path) -> Result<&Path> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) => Ok(Path::new(".")),
        None => Err(anyhow!("private state file parent is missing")),
    }
}

pub fn directory(directory: &Path) -> Result<()> {
    let file = match fs::File::open(directory) {
        Ok(file) => file,
        Err(error) if unsupported(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if let Err(error) = file.sync_all() {
        if unsupported(&error) {
            return Ok(());
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(windows)]
fn unsupported(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

#[cfg(not(windows))]
fn unsupported(_error: &io::Error) -> bool {
    false
}
