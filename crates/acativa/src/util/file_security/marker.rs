use anyhow::{Result, anyhow, ensure};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use super::{policy, sync, validation};

pub fn create_private_state_marker(path: &Path, content: &[u8]) -> Result<()> {
    validation::ensure_private_state_parent(path)?;
    ensure!(
        content.len() <= policy::PRIVATE_STATE_FILE_MAX_BYTES as usize,
        "private security state marker exceeds its bounded size"
    );

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| anyhow!("private security state marker could not be created"))?;
    validation::apply_private_file_permissions(&file, path)?;
    file.write_all(content)?;
    sync::file(&mut file)?;
    validation::validate_open_state_marker(path, &file)?;
    sync::parent(path)?;
    Ok(())
}

pub fn read_private_state_marker(path: &Path) -> Result<Option<Vec<u8>>> {
    read_private_bytes_bounded(path, policy::PRIVATE_STATE_FILE_MAX_BYTES as usize)
}

pub fn read_private_text_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    let Some(content) = read_private_bytes_bounded(path, max_bytes)? else {
        return Ok(None);
    };
    String::from_utf8(content)
        .map(Some)
        .map_err(|_| anyhow!("private state text is not UTF-8"))
}

pub fn read_existing_private_text_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    let Some(content) =
        read_private_bytes_bounded_with_parent(path, max_bytes, ParentAccess::ExistingReadOnly)?
    else {
        return Ok(None);
    };
    String::from_utf8(content)
        .map(Some)
        .map_err(|_| anyhow!("private state text is not UTF-8"))
}

pub fn open_private_text_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<std::io::BufReader<fs::File>>> {
    validation::ensure_private_state_parent(path)?;
    let Some(path_metadata) = validation::state_marker_metadata(path)? else {
        return Ok(None);
    };
    validation::validate_private_file_metadata(&path_metadata)?;
    let file = validation::open_read_no_follow(path)?;
    let opened_metadata = file.metadata()?;
    validation::validate_private_file_metadata(&opened_metadata)?;
    validation::ensure_same_file(&path_metadata, &opened_metadata)?;
    ensure!(
        opened_metadata.len() <= max_bytes as u64,
        "private state file exceeds its bounded size"
    );
    Ok(Some(std::io::BufReader::new(file)))
}

pub fn validate_private_file_unchanged(path: &Path, opened: &fs::Metadata) -> Result<()> {
    let stable_metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("private security state marker changed while opening"))?;
    validation::validate_private_file_metadata(&stable_metadata)?;
    validation::ensure_same_file(opened, &stable_metadata)
}

pub fn private_state_marker_exists(path: &Path) -> Result<bool> {
    read_private_state_marker(path).map(|content| content.is_some())
}

pub fn remove_private_state_marker(path: &Path) -> Result<bool> {
    validation::ensure_private_state_parent(path)?;
    let Some(path_metadata) = validation::state_marker_metadata(path)? else {
        return Ok(false);
    };
    validation::validate_private_file_metadata(&path_metadata)?;

    let file = validation::open_read_no_follow(path)?;
    validation::validate_open_state_marker(path, &file)?;
    let stable_metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("private security state marker changed before removal"))?;
    validation::ensure_same_file(&file.metadata()?, &stable_metadata)?;
    fs::remove_file(path)
        .map_err(|_| anyhow!("private security state marker could not be removed"))?;
    sync::parent(path)?;
    Ok(true)
}

fn read_private_bytes_bounded(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    read_private_bytes_bounded_with_parent(path, max_bytes, ParentAccess::EnsurePrivate)
}

#[derive(Clone, Copy)]
enum ParentAccess {
    EnsurePrivate,
    ExistingReadOnly,
}

fn read_private_bytes_bounded_with_parent(
    path: &Path,
    max_bytes: usize,
    parent_access: ParentAccess,
) -> Result<Option<Vec<u8>>> {
    match parent_access {
        ParentAccess::EnsurePrivate => validation::ensure_private_state_parent(path)?,
        ParentAccess::ExistingReadOnly => {
            let parent = path
                .parent()
                .ok_or_else(|| anyhow!("private security state marker parent is missing"))?;
            if !parent.try_exists()? {
                return Ok(None);
            }
            validation::validate_private_path_ancestors(parent)?;
            let parent_metadata = fs::symlink_metadata(parent)
                .map_err(|_| anyhow!("private security state directory is unavailable"))?;
            validation::validate_private_directory_metadata(&parent_metadata)?;
        }
    }
    let Some(path_metadata) = validation::state_marker_metadata(path)? else {
        return Ok(None);
    };
    validation::validate_private_file_metadata(&path_metadata)?;
    let mut file = validation::open_read_no_follow(path)?;
    let opened_metadata = file.metadata()?;
    validation::validate_private_file_metadata(&opened_metadata)?;
    validation::ensure_same_file(&path_metadata, &opened_metadata)?;
    ensure!(
        opened_metadata.len() <= max_bytes as u64,
        "private state file exceeds its bounded size"
    );
    let mut content = Vec::with_capacity(opened_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut content)?;
    ensure!(
        content.len() <= max_bytes,
        "private state file exceeds its bounded size"
    );
    let stable_metadata = fs::symlink_metadata(path)
        .map_err(|_| anyhow!("private security state marker changed while opening"))?;
    validation::validate_private_file_metadata(&stable_metadata)?;
    validation::ensure_same_file(&opened_metadata, &stable_metadata)?;
    Ok(Some(content))
}
