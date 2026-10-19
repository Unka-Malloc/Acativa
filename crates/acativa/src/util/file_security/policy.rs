pub(super) const PRIVATE_STATE_FILE_MAX_BYTES: u64 = 64 * 1024;
pub(super) const PRIVATE_APPEND_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const PRIVATE_APPEND_LINE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub(super) const PRIVATE_LOCK_MARKER: &[u8] = b"acativa-private-lock-v1";
