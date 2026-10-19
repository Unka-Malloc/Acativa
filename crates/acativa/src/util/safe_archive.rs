//! Safe archive extraction — streaming, bounded, and no-follow.
//!
//! Generic bounded-unzip machinery a host uses to accept strategy bundles:
//! path-traversal rejection, entry-type allowlisting, and configurable byte /
//! entry / depth limits, with the archive's own index reconciled against every
//! local record before extraction trusts it.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result, anyhow, ensure};
use zip::ZipArchive;

mod zip_structure;
pub(crate) use zip_structure::validate_zip_structure;

/// Default maximum total bytes extracted across all entries.
const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// Default maximum number of entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default maximum directory depth relative to destination root.
const DEFAULT_MAX_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipExtractionLimits {
    pub max_archive_bytes: u64,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_entries: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZipEntryInfo {
    pub path: PathBuf,
    pub size: u64,
    pub directory: bool,
}

/// The extractor's own defaults, exposed so callers reuse one policy rather than
/// inventing their own bounds.
pub fn default_zip_extraction_limits() -> ZipExtractionLimits {
    ZipExtractionLimits {
        max_archive_bytes: DEFAULT_MAX_TOTAL_BYTES,
        max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        max_file_bytes: DEFAULT_MAX_TOTAL_BYTES,
        max_entries: DEFAULT_MAX_ENTRIES,
        max_depth: DEFAULT_MAX_DEPTH,
    }
}

/// Extract a ZIP from memory below one no-follow destination root.
///
/// All names must be UTF-8 POSIX-relative paths. Duplicate normalized names,
/// case-colliding names, links and special entries are rejected before a file
/// can be published outside the private staging directory.
pub fn extract_zip_safe(
    bytes: &[u8],
    destination: &Path,
    limits: ZipExtractionLimits,
) -> Result<Vec<ZipEntryInfo>> {
    ensure!(
        bytes.len() as u64 <= limits.max_archive_bytes,
        "zip_archive_byte_limit_exceeded"
    );
    ensure!(limits.max_entries > 0, "zip_entry_limit_invalid");
    validate_zip_structure(bytes, limits)?;
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|_| anyhow!("zip_archive_invalid"))?;
    ensure!(
        archive.len() <= limits.max_entries,
        "zip_entry_count_limit_exceeded"
    );

    let extraction_root = ExtractionRoot::open(destination)?;
    let mut total_bytes = 0_u64;
    let mut exact_names = std::collections::BTreeSet::new();
    let mut folded_names = std::collections::BTreeSet::new();
    let mut result = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| anyhow!("zip_entry_unreadable"))?;
        let raw_name = entry.name_raw();
        let name = std::str::from_utf8(raw_name).map_err(|_| anyhow!("zip_entry_name_invalid"))?;
        ensure!(
            !name.is_empty()
                && !name.contains('\0')
                && !name.contains('\\')
                && !name.starts_with('/')
                && !name.contains(':'),
            "zip_entry_path_invalid"
        );
        let directory = entry.is_dir();
        ensure!(directory || entry.is_file(), "zip_entry_type_unsupported");
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & 0o170000;
            ensure!(
                file_type == 0
                    || (directory && file_type == 0o040000)
                    || (!directory && file_type == 0o100000),
                "zip_entry_type_unsupported"
            );
        }
        let path_name = name.trim_end_matches('/');
        ensure!(!path_name.is_empty(), "zip_entry_path_invalid");
        let relative = sanitize_entry_path(Path::new(path_name), limits.max_depth)?;
        let canonical = relative
            .iter()
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        ensure!(exact_names.insert(canonical.clone()), "zip_entry_duplicate");
        ensure!(
            folded_names.insert(canonical.to_lowercase()),
            "zip_entry_case_collision"
        );

        if directory {
            // A directory body is never legitimate: the member is a directory, so its
            // declared size must be zero. The stream is consumed and the checksum compared
            // as well, because a crafted central directory can claim an empty directory
            // while the member still carries a body.
            ensure!(entry.size() == 0, "zip_entry_directory_body_unsupported");
            let mut sink = std::io::sink();
            let body = std::io::copy(&mut entry, &mut sink)?;
            ensure!(body == 0, "zip_entry_directory_body_unsupported");
            ensure!(entry.crc32() == 0, "zip_entry_directory_body_unsupported");
            extraction_root.create_directory(&relative)?;
            result.push(ZipEntryInfo {
                path: relative,
                size: 0,
                directory: true,
            });
            continue;
        }
        let declared_size = entry.size();
        ensure!(
            declared_size <= limits.max_file_bytes,
            "zip_file_byte_limit_exceeded"
        );
        let next_total = total_bytes
            .checked_add(declared_size)
            .ok_or_else(|| anyhow!("zip_total_byte_count_overflowed"))?;
        ensure!(
            next_total <= limits.max_total_bytes,
            "zip_total_byte_limit_exceeded"
        );
        let mut output = extraction_root.create_file(&relative)?;
        let mut bounded = (&mut entry).take(declared_size.saturating_add(1));
        let written = std::io::copy(&mut bounded, &mut output)?;
        ensure!(written == declared_size, "zip_entry_size_mismatch");
        output.flush()?;
        output.sync_all()?;
        total_bytes = next_total;
        result.push(ZipEntryInfo {
            path: relative,
            size: declared_size,
            directory: false,
        });
    }
    Ok(result)
}

/// Validate and sanitize a single entry path from the archive.
fn sanitize_entry_path(raw: &Path, max_depth: usize) -> Result<PathBuf> {
    // Reject absolute paths.
    ensure!(
        raw.is_relative(),
        "archive entry path must be relative: {}",
        raw.display()
    );

    // Reject path traversal components.
    for component in raw.components() {
        match component {
            Component::ParentDir => {
                return Err(anyhow!(
                    "archive entry contains path traversal: {}",
                    raw.display()
                ));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(anyhow!(
                    "archive entry contains absolute or prefixed component: {}",
                    raw.display()
                ));
            }
            _ => {}
        }
    }

    // Reject empty paths or paths that normalize to empty.
    let normalized: PathBuf = raw
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if normalized.as_os_str().is_empty() {
        return Err(anyhow!("archive entry path is empty after normalization"));
    }

    // Every component must be portable independently of the host platform: the same
    // rules the ZIP path enforces, so a member name can never mean a different location
    // on a different host.
    for component in normalized.iter() {
        let name = component.to_str().ok_or_else(|| {
            anyhow!(
                "archive entry path is not portable UTF-8: {}",
                normalized.display()
            )
        })?;
        ensure!(
            !name.is_empty() && name != "." && name != "..",
            "archive entry path component is not portable: {}",
            normalized.display()
        );
        ensure!(
            !name.contains('\\') && !name.contains(':'),
            "archive entry path component is not portable: {}",
            normalized.display()
        );
        ensure!(
            !name.chars().any(char::is_control),
            "archive entry path component contains a control character: {}",
            normalized.display()
        );
    }

    // Check depth.
    let depth = normalized.components().count();
    ensure!(
        depth <= max_depth,
        "archive entry depth {} exceeds maximum {}: {}",
        depth,
        max_depth,
        normalized.display()
    );

    Ok(normalized)
}

/// A root directory held open for the whole extraction. On Unix every descendant is opened
/// relative to an already-open directory descriptor with `O_NOFOLLOW`, closing the ancestor
/// symlink race that path-based `canonicalize` checks leave behind.
struct ExtractionRoot {
    #[cfg(unix)]
    directory: fs::File,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl ExtractionRoot {
    fn open(path: &Path) -> Result<Self> {
        ensure!(!path.as_os_str().is_empty(), "archive destination is empty");
        #[cfg(unix)]
        {
            let mut current = if path.is_absolute() {
                open_directory(Path::new("/"))?
            } else {
                open_directory(Path::new("."))?
            };
            for component in path.components() {
                match component {
                    Component::RootDir | Component::CurDir => {}
                    Component::Normal(name) => {
                        current = open_or_create_directory_at(&current, name)?;
                    }
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(anyhow!(
                            "archive destination contains an unsafe path component"
                        ));
                    }
                }
            }
            Ok(Self { directory: current })
        }
        #[cfg(not(unix))]
        {
            create_directory_path_no_follow(path)?;
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }

    fn create_directory(&self, relative: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let _ = self.open_parent(relative, true)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            create_directory_path_no_follow(&self.path.join(relative))
        }
    }

    fn create_file(&self, relative: &Path) -> Result<fs::File> {
        let leaf = relative
            .file_name()
            .ok_or_else(|| anyhow!("archive file entry has no file name"))?;
        #[cfg(unix)]
        {
            let parent = self.open_parent(relative, false)?;
            create_file_at(&parent, leaf)
        }
        #[cfg(not(unix))]
        {
            let destination = self.path.join(relative);
            let parent = destination
                .parent()
                .ok_or_else(|| anyhow!("archive file entry has no parent"))?;
            create_directory_path_no_follow(parent)?;
            ensure_missing_or_regular_no_follow(&destination)?;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&destination)
                .with_context(|| "archive output file could not be created")
        }
    }

    #[cfg(unix)]
    fn open_parent(&self, relative: &Path, include_leaf: bool) -> Result<fs::File> {
        let mut current = self.directory.try_clone()?;
        let component_count = relative.components().count();
        for (index, component) in relative.components().enumerate() {
            let Component::Normal(name) = component else {
                return Err(anyhow!("archive entry contains an unsafe component"));
            };
            if !include_leaf && index + 1 == component_count {
                break;
            }
            current = open_or_create_directory_at(&current, name)?;
        }
        Ok(current)
    }
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .with_context(|| "archive destination ancestor is not a no-follow directory")
}

#[cfg(unix)]
fn component_cstring(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(name.as_bytes()).map_err(|_| anyhow!("archive path contains a NUL byte"))
}

#[cfg(unix)]
fn open_or_create_directory_at(parent: &fs::File, name: &std::ffi::OsStr) -> Result<fs::File> {
    let name = component_cstring(name)?;
    let flags =
        nix::libc::O_RDONLY | nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC;
    let mut fd = unsafe { nix::libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(anyhow!(
                "archive destination ancestor is not a no-follow directory"
            ));
        }
        let created = unsafe { nix::libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            let create_error = std::io::Error::last_os_error();
            if create_error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(anyhow!(
                    "archive destination directory could not be created"
                ));
            }
        }
        fd = unsafe { nix::libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(anyhow!(
            "archive destination ancestor changed during extraction"
        ));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn create_file_at(parent: &fs::File, name: &std::ffi::OsStr) -> Result<fs::File> {
    let name = component_cstring(name)?;
    let flags = nix::libc::O_WRONLY
        | nix::libc::O_CREAT
        | nix::libc::O_EXCL
        | nix::libc::O_NOFOLLOW
        | nix::libc::O_CLOEXEC;
    let fd = unsafe { nix::libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(anyhow!(
            "archive output must be a new regular file below the extraction root"
        ));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn create_directory_path_no_follow(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            // A Windows drive or UNC prefix is not a filesystem location by itself.
            // Probing `C:` before the following root component means "the current
            // directory on drive C" and can reject an otherwise valid absolute
            // destination. Build the rooted anchor first, then validate it and every
            // descendant without following links.
            Component::Prefix(_) => {
                current.push(component.as_os_str());
                continue;
            }
            Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(anyhow!("archive path contains a parent component"));
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "archive destination ancestor is not a no-follow directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                ensure_missing_or_regular_no_follow(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_missing_or_regular_no_follow(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            !metadata.file_type().is_symlink(),
            "archive output path is a symbolic link"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
