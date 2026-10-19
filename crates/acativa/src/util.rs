//! Host-foundation utilities absorbed into Acativa so the engine carries zero
//! product-crate dependencies.
//!
//! These are the generic mechanics a collaboration host needs: private
//! directory and file hardening, atomic private writes, private lock files,
//! bounded archive extraction, SQLite schema-contract comparison, and display
//! naming for model identifiers. The code is host-agnostic.

pub mod file_security;
pub mod model_naming;
pub mod safe_archive;
pub mod sqlite_contract;

/// Hex-encoded SHA-256 digest, the engine's content-addressing primitive.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

pub use file_security::{
    atomic_write_private_text, ensure_private_dir, harden_private_path, open_private_lock_file,
};
pub use model_naming::model_display_name;
pub use safe_archive::{
    ZipEntryInfo, ZipExtractionLimits, default_zip_extraction_limits, extract_zip_safe,
};
