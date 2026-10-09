//! `std::fs`, with the path in every error (rust guide R-ERR-1). The same
//! wrappers as the CLI crate's `fsx`, which this crate cannot depend on.
//!
//! `No such file or directory (os error 2)` names no file. These wrappers
//! are the same calls with `reading <path>` / `writing <path>` … as the
//! error's context, so a failure says which file without each call site
//! repeating a closure. A site that matches on the `io::ErrorKind` keeps
//! calling `std::fs` and adds its own context.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result};

/// [`fs::read_to_string`].
pub fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// [`fs::read`].
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

/// [`fs::create_dir_all`].
pub fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

/// [`fs::rename`].
pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let (from, to) = (from.as_ref(), to.as_ref());
    fs::rename(from, to).with_context(|| format!("moving {} to {}", from.display(), to.display()))
}

/// [`fs::set_permissions`].
pub fn set_permissions(path: impl AsRef<Path>, perm: fs::Permissions) -> Result<()> {
    let path = path.as_ref();
    fs::set_permissions(path, perm)
        .with_context(|| format!("setting the permissions of {}", path.display()))
}
