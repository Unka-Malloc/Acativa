//! Bounded private file I/O absorbed from the host foundations: owner-checked
//! private directories, atomic private writes, and private lock files. The
//! implementations are platform-adapted: descriptor-relative `O_NOFOLLOW`
//! handling on Unix, owner-only ACL application on Windows.

mod append_lock;
mod atomic_replace;
mod hardening;
mod marker;
mod policy;
mod sync;
#[cfg(unix)]
mod unix_hardening;
mod validation;
#[cfg(windows)]
mod windows_acl;

pub use append_lock::{append_private_line, open_private_lock_file};
pub use atomic_replace::{
    AtomicPrivateFile, AtomicWriteFailure, CleanupOutcome, CommitDurability,
    atomic_write_private_text, atomic_write_private_text_bounded,
};
pub use hardening::{ensure_private_dir, harden_private_path, harden_private_tree};
pub use marker::read_existing_private_text_bounded;
pub use marker::{
    create_private_state_marker, open_private_text_bounded, private_state_marker_exists,
    read_private_state_marker, read_private_text_bounded, remove_private_state_marker,
    validate_private_file_unchanged,
};
pub use sync::directory as sync_directory;
pub use validation::{
    validate_export_destination, validate_no_symlink_ancestors, validate_path_owner,
    validate_private_path_ancestors,
};
