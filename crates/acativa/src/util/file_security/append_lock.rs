use anyhow::{Result, anyhow, ensure};
use std::fs::{self, OpenOptions};
#[cfg(not(unix))]
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(not(unix))]
use super::sync;
use super::{marker, policy, validation};

pub fn append_private_line(path: &Path, line: &str) -> Result<()> {
    ensure!(
        line.len() <= policy::PRIVATE_APPEND_LINE_MAX_BYTES,
        "private append line exceeds its bounded size"
    );
    validation::ensure_private_state_parent(path)?;
    append_private_line_platform(path, line)
}

pub fn open_private_lock_file(path: &Path) -> Result<fs::File> {
    validation::ensure_private_state_parent(path)?;
    wait_for_private_lock_marker(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow!("private lock file could not be opened"))?;
    validation::validate_open_state_marker(path, &file)?;
    Ok(file)
}

fn wait_for_private_lock_marker(path: &Path) -> Result<()> {
    const INITIALIZATION_WAIT: Duration = Duration::from_millis(250);
    const INITIALIZATION_POLL: Duration = Duration::from_millis(5);
    let deadline = Instant::now() + INITIALIZATION_WAIT;
    loop {
        if validation::state_marker_metadata(path)?.is_none() {
            let _ = marker::create_private_state_marker(path, policy::PRIVATE_LOCK_MARKER);
        }
        match marker::read_private_state_marker(path)? {
            Some(content) if content.as_slice() == policy::PRIVATE_LOCK_MARKER => return Ok(()),
            Some(content)
                if policy::PRIVATE_LOCK_MARKER.starts_with(&content)
                    && Instant::now() < deadline =>
            {
                thread::sleep(INITIALIZATION_POLL);
            }
            Some(_) => return Err(anyhow!("private lock file marker is invalid")),
            None if Instant::now() < deadline => thread::sleep(INITIALIZATION_POLL),
            None => return Err(anyhow!("private lock file is missing")),
        }
    }
}

#[cfg(unix)]
fn append_private_line_platform(path: &Path, line: &str) -> Result<()> {
    use nix::fcntl::{FlockArg, OFlag, flock, openat};
    use nix::sys::stat::{Mode, fchmod, fstat};
    use nix::unistd::{close, fsync, write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow!("private append file parent is missing"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow!("private append file name is missing"))?;
    ensure!(
        !leaf.as_bytes().contains(&b'/') && leaf != "." && leaf != "..",
        "private append file name is invalid"
    );

    super::unix_hardening::validate_no_user_owned_symlink_ancestors(parent_path)?;
    let parent_path_metadata = fs::symlink_metadata(parent_path)?;
    validation::validate_private_directory_metadata(&parent_path_metadata)?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let parent = parent_options
        .open(parent_path)
        .map_err(|_| anyhow!("private append directory could not be opened"))?;
    validation::validate_private_directory_metadata(&parent.metadata()?)?;
    validation::ensure_same_file(&parent_path_metadata, &parent.metadata()?)?;

    let raw_fd = openat(
        parent.as_raw_fd(),
        Path::new(leaf),
        OFlag::O_APPEND | OFlag::O_CLOEXEC | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_WRONLY,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|_| anyhow!("private append file could not be opened"))?;
    fchmod(raw_fd, Mode::S_IRUSR | Mode::S_IWUSR)?;
    flock(raw_fd, FlockArg::LockExclusive)
        .map_err(|_| anyhow!("private append file could not be locked"))?;

    let result = (|| -> Result<()> {
        let opened_stat = fstat(raw_fd)?;
        super::unix_hardening::validate_private_file_stat(&opened_stat)?;
        let stable_parent = fs::symlink_metadata(parent_path)
            .map_err(|_| anyhow!("private append directory changed while opening"))?;
        super::unix_hardening::validate_no_user_owned_symlink_ancestors(parent_path)?;
        validation::validate_private_directory_metadata(&stable_parent)?;
        validation::ensure_same_file(&parent_path_metadata, &stable_parent)?;
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|_| anyhow!("private append file changed while opening"))?;
        validation::validate_private_file_metadata(&path_metadata)?;
        super::unix_hardening::ensure_metadata_matches_stat(&path_metadata, &opened_stat)?;
        let append_bytes =
            line.len()
                .checked_add(1)
                .ok_or_else(|| anyhow!("private append size overflow"))? as u64;
        ensure!(
            u64::try_from(opened_stat.st_size)
                .unwrap_or(u64::MAX)
                .checked_add(append_bytes)
                .is_some_and(|size| size <= policy::PRIVATE_APPEND_FILE_MAX_BYTES),
            "private append file exceeds its bounded size"
        );
        let mut record = Vec::with_capacity(line.len() + 1);
        record.extend_from_slice(line.as_bytes());
        record.push(b'\n');
        let mut remaining = record.as_slice();
        while !remaining.is_empty() {
            let written = write(raw_fd, remaining)?;
            ensure!(written > 0, "private append file write made no progress");
            remaining = &remaining[written..];
        }
        fsync(raw_fd)?;
        let stable_path = fs::symlink_metadata(path)
            .map_err(|_| anyhow!("private append file changed while writing"))?;
        validation::validate_private_file_metadata(&stable_path)?;
        super::unix_hardening::ensure_metadata_matches_stat(&stable_path, &fstat(raw_fd)?)
    })();
    let unlock_result = flock(raw_fd, FlockArg::Unlock);
    let close_result = close(raw_fd);
    result?;
    unlock_result.map_err(|_| anyhow!("private append file could not be unlocked"))?;
    close_result.map_err(|_| anyhow!("private append file could not be closed"))?;
    Ok(())
}

#[cfg(not(unix))]
fn append_private_line_platform(path: &Path, line: &str) -> Result<()> {
    if let Some(metadata) = validation::state_marker_metadata(path)? {
        validation::validate_private_file_type_and_owner(&metadata)?;
        let line_bytes = u64::try_from(line.len())
            .map_err(|_| anyhow!("private append line size is invalid"))?;
        ensure!(
            metadata
                .len()
                .checked_add(line_bytes.saturating_add(1))
                .is_some_and(|size| size <= policy::PRIVATE_APPEND_FILE_MAX_BYTES),
            "private append file exceeds its bounded size"
        );
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    validation::apply_private_file_permissions(&file, path)?;
    validation::validate_open_state_marker(path, &file)?;
    writeln!(file, "{line}")?;
    sync::file(&mut file)
}
