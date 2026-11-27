//! Free-space check of the data directory (statvfs).

use std::path::Path;

/// Bytes available to unprivileged users on the file system that holds `path`.
/// `None` when the call fails (the caller keeps its previous disk mode).
#[allow(clippy::useless_conversion)] // field widths differ between Linux and macOS
pub fn free_bytes(path: &Path) -> Option<u64> {
    let st = nix::sys::statvfs::statvfs(path).ok()?;
    Some(u64::from(st.blocks_available()).saturating_mul(u64::from(st.fragment_size())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_dir_has_free_space() {
        let d = tempfile::tempdir().unwrap();
        assert!(free_bytes(d.path()).unwrap() > 0);
        assert!(free_bytes(Path::new("/definitely/not/here")).is_none());
    }
}
