//! Gzip of finished day files.
//!
//! Procedure: write `<name>.jsonl.gz.tmp` (existing `.gz` content first, then a new
//! gzip member with the `.jsonl` data), fsync, rename over `<name>.jsonl.gz`, fsync
//! the directory, then delete the `.jsonl`. If any step fails the original stays.
//! Readers use a multi-member decoder, so appending a member is valid gzip.

use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Compresses `src` (a `.jsonl` file) into `src.gz` and removes `src`.
pub(crate) fn compress_file(src: &Path) -> io::Result<PathBuf> {
    let gz = gz_path(src);
    let tmp = tmp_path(&gz);
    match write_gz(src, &gz, &tmp) {
        Ok(()) => {}
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    fs::rename(&tmp, &gz)?;
    if let Some(dir) = gz.parent() {
        super::sync_dir(dir);
    }
    fs::remove_file(src)?;
    Ok(gz)
}

fn write_gz(src: &Path, gz: &Path, tmp: &Path) -> io::Result<()> {
    let mut out = BufWriter::with_capacity(64 * 1024, File::create(tmp)?);
    if gz.exists() {
        io::copy(&mut File::open(gz)?, &mut out)?;
    }
    let mut enc = GzEncoder::new(out, Compression::new(6));
    io::copy(&mut File::open(src)?, &mut enc)?;
    let mut out = enc.finish()?;
    out.flush()?;
    let file = out.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()
}

/// `samples-20260101.jsonl` -> `samples-20260101.jsonl.gz`.
pub(crate) fn gz_path(src: &Path) -> PathBuf {
    let mut s = src.as_os_str().to_owned();
    s.push(".gz");
    PathBuf::from(s)
}

fn tmp_path(gz: &Path) -> PathBuf {
    let mut s = gz.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::MultiGzDecoder;
    use std::io::Read;

    #[test]
    fn compress_and_append_member() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("events-20260101.jsonl");
        fs::write(&src, b"one\n").unwrap();
        let gz = compress_file(&src).unwrap();
        assert!(!src.exists());
        fs::write(&src, b"two\n").unwrap();
        compress_file(&src).unwrap();
        let mut s = String::new();
        MultiGzDecoder::new(File::open(&gz).unwrap())
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "one\ntwo\n");
        assert!(!tmp_path(&gz).exists());
    }

    #[test]
    fn missing_source_keeps_nothing_broken() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("events-20260101.jsonl");
        assert!(compress_file(&src).is_err());
        assert!(!gz_path(&src).exists());
        assert!(!tmp_path(&gz_path(&src)).exists());
    }
}
