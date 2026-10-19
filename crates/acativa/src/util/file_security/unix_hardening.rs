use anyhow::{Result, anyhow, ensure};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) fn apply_directory_permissions(path: &Path) -> Result<()> {
    apply_path_mode(path, true, 0o700)
}

pub(super) fn apply_file_permissions(file: &fs::File) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(super) fn harden_path(path: &Path, is_directory: bool) -> Result<()> {
    apply_path_mode(path, is_directory, if is_directory { 0o700 } else { 0o600 })
}

fn apply_path_mode(path: &Path, is_directory: bool, mode: u32) -> Result<()> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::close;

    let mut flags = OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_RDONLY;
    if is_directory {
        flags |= OFlag::O_DIRECTORY;
    }
    let raw_fd = open(path, flags, Mode::empty())
        .map_err(|_| anyhow!("private path could not be opened for hardening"))?;
    let mode =
        nix::libc::mode_t::try_from(mode).map_err(|_| anyhow!("private path mode is invalid"))?;
    let permission_result = fchmod(raw_fd, Mode::from_bits_truncate(mode));
    let close_result = close(raw_fd);
    permission_result.map_err(|_| anyhow!("private path permissions could not be applied"))?;
    close_result.map_err(|_| anyhow!("private path could not be closed"))?;
    Ok(())
}

pub(super) fn validate_current_owner(metadata: &fs::Metadata) -> Result<()> {
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure!(
        metadata.uid() == effective_uid,
        "private security state path owner is invalid"
    );
    Ok(())
}

pub(super) fn validate_file_mode(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.mode() & 0o777 == 0o600,
        "private security state marker permissions are insecure"
    );
    Ok(())
}

pub(super) fn validate_directory_mode(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.mode() & 0o777 == 0o700,
        "private security state directory permissions are insecure"
    );
    Ok(())
}

pub(super) fn validate_path_owner(metadata: &fs::Metadata) -> Result<()> {
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    ensure!(
        metadata.uid() == effective_uid,
        "path owner is not the current user"
    );
    Ok(())
}

pub(super) fn ensure_same_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<()> {
    ensure!(
        left.dev() == right.dev() && left.ino() == right.ino(),
        "private security state marker path was replaced"
    );
    Ok(())
}

pub(super) fn validate_private_file_stat(stat: &nix::sys::stat::FileStat) -> Result<()> {
    ensure!(
        stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFREG,
        "private append file is not a regular file"
    );
    ensure!(
        stat.st_uid == nix::unistd::Uid::effective().as_raw(),
        "private append file owner is invalid"
    );
    ensure!(
        stat.st_mode & 0o777 == 0o600,
        "private append file permissions are insecure"
    );
    ensure!(stat.st_size >= 0, "private append file size is invalid");
    Ok(())
}

pub(super) fn ensure_metadata_matches_stat(
    metadata: &fs::Metadata,
    stat: &nix::sys::stat::FileStat,
) -> Result<()> {
    let stat_device =
        u64::try_from(stat.st_dev).map_err(|_| anyhow!("private append file device is invalid"))?;
    ensure!(
        metadata.dev() == stat_device && metadata.ino() == stat.st_ino,
        "private append file path was replaced"
    );
    Ok(())
}

pub(super) fn validate_no_user_owned_symlink_ancestors(path: &Path) -> Result<()> {
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
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => ensure!(
                metadata.uid() == 0,
                "path contains a user-controlled symbolic-link ancestor"
            ),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(anyhow!("path ancestor metadata is unavailable")),
        }
    }
    Ok(())
}
