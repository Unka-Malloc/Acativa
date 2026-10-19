#![cfg(windows)]

use anyhow::{Result, anyhow};
use std::path::Path;
use std::process::{Command, Stdio};

pub(super) fn apply_owner_only(path: &Path) -> Result<()> {
    let ace = if path.is_dir() {
        "*S-1-3-4:(OI)(CI)(F)"
    } else {
        "*S-1-3-4:(F)"
    };
    let status = Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", ace])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| anyhow!("owner-only ACL tool could not be started"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("owner-only ACL could not be applied"))
    }
}
