//! Crash recovery of a session directory: repairs torn file tails, removes temporary
//! files and duplicate day files, finds the last valid `seq`, and reads heartbeat files.

use super::read::{Line, open_lines};
use super::{HEARTBEAT_FILE, StreamFile, list_stream_files};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Lines longer than this at the tail are treated as garbage.
const MAX_TAIL_LINE: u64 = super::read::MAX_LINE as u64;
/// At most this many invalid lines are removed from one tail.
const MAX_TAIL_REPAIRS: usize = 64;

/// Content of the `heartbeat` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Heartbeat {
    pub ts: DateTime<Utc>,
    pub boot_id: String,
    pub mono_ns: u64,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct TailRepair {
    pub last_seq: Option<u64>,
    pub truncated_bytes: u64,
}

#[derive(Deserialize)]
struct SeqOnly {
    seq: u64,
}

fn parse_seq(line: &[u8]) -> Option<u64> {
    serde_json::from_slice::<SeqOnly>(line).ok().map(|s| s.seq)
}

/// Makes the file end on a complete, valid line.
///
/// A last line without newline that is still a valid record gets its newline back.
/// Otherwise a partial or invalid last line is truncated (repeated for a few lines).
pub(crate) fn repair_tail(path: &Path) -> io::Result<TailRepair> {
    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let mut len = f.metadata()?.len();
    let mut out = TailRepair::default();
    let mut changed = false;
    for _ in 0..MAX_TAIL_REPAIRS {
        if len == 0 {
            break;
        }
        let tail = last_line(&mut f, len)?;
        let seq = tail.bytes.as_deref().and_then(parse_seq);
        if let Some(seq) = seq {
            if !tail.has_newline {
                f.seek(SeekFrom::End(0))?;
                f.write_all(b"\n")?;
                changed = true;
            }
            out.last_seq = Some(seq);
            break;
        }
        f.set_len(tail.start)?;
        out.truncated_bytes += len - tail.start;
        len = tail.start;
        changed = true;
    }
    if changed {
        f.sync_all()?;
    }
    Ok(out)
}

struct Tail {
    start: u64,
    /// `None` when the line is too long to be valid.
    bytes: Option<Vec<u8>>,
    has_newline: bool,
}

fn read_at(f: &mut File, pos: u64, buf: &mut [u8]) -> io::Result<()> {
    f.seek(SeekFrom::Start(pos))?;
    f.read_exact(buf)
}

/// Finds the last line in `[0, len)`.
fn last_line(f: &mut File, len: u64) -> io::Result<Tail> {
    let mut b = [0u8; 1];
    read_at(f, len - 1, &mut b)?;
    let has_newline = b[0] == b'\n';
    let end = if has_newline { len - 1 } else { len };
    const CHUNK: u64 = 64 * 1024;
    let mut pos = end;
    let mut chunk = vec![0u8; CHUNK as usize];
    let start = loop {
        if pos == 0 {
            break 0;
        }
        let n = CHUNK.min(pos);
        pos -= n;
        let buf = &mut chunk[..n as usize];
        read_at(f, pos, buf)?;
        if let Some(i) = buf.iter().rposition(|&c| c == b'\n') {
            break pos + i as u64 + 1;
        }
    };
    let bytes = if end - start <= MAX_TAIL_LINE {
        let mut v = vec![0u8; (end - start) as usize];
        read_at(f, start, &mut v)?;
        Some(v)
    } else {
        None
    };
    Ok(Tail {
        start,
        bytes,
        has_newline,
    })
}

/// Last valid seq of a (possibly compressed) file, scanning it from the start.
fn last_seq_scan(path: &Path, gz: bool) -> Option<u64> {
    let mut r = open_lines(path, gz).ok()?;
    let mut last = None;
    while let Ok(Some(line)) = r.next_line() {
        if let Line::Ok(b) = line
            && let Some(s) = parse_seq(b)
        {
            last = Some(s);
        }
    }
    last
}

/// Result of [`recover_session`].
#[derive(Debug, Default)]
pub(crate) struct Recovered {
    pub next_seq: u64,
    /// Newest day that has a file (writing continues there if the clock is behind).
    pub last_day: Option<NaiveDate>,
    /// Uncompressed files of days before `today` (to gzip in the background).
    pub old_files: Vec<PathBuf>,
    pub truncated_bytes: u64,
}

/// Repairs all stream files of `dir` and finds where `seq` continues.
pub(crate) fn recover_session(dir: &Path, today: NaiveDate) -> io::Result<Recovered> {
    remove_temp_files(dir);
    let files = list_stream_files(dir)?;
    let mut out = Recovered::default();
    let mut max_seq: Option<u64> = None;
    // Last seq of a .gz is needed only when its .jsonl sibling still exists (crash during
    // compression) or when it is the newest .gz of its stream (where seq continues).
    // Scanning every old day on each start would make startup time grow with session length.
    let mut gz_last: HashMap<PathBuf, Option<u64>> = HashMap::new();
    let plain_paths: std::collections::HashSet<&Path> = files.iter().filter(|f| !f.gz).map(|f| f.path.as_path()).collect();
    let mut newest_gz: HashMap<crate::model::Stream, &StreamFile> = HashMap::new();
    for f in files.iter().filter(|f| f.gz) {
        newest_gz.insert(f.stream, f); // files are sorted by day
    }
    for f in files.iter().filter(|f| f.gz) {
        let sib = jsonl_sibling(f);
        let newest = newest_gz.get(&f.stream).is_some_and(|n| n.path == f.path);
        if !newest && !plain_paths.contains(sib.as_path()) {
            continue;
        }
        let s = last_seq_scan(&f.path, true);
        max_seq = max_seq.max(s);
        gz_last.insert(sib, s);
    }
    let mut plain: Vec<&StreamFile> = Vec::new();
    for f in files.iter().filter(|f| !f.gz) {
        let rep = match repair_tail(&f.path) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(path = %f.path.display(), error = %e, "store: cannot repair file");
                continue;
            }
        };
        if rep.truncated_bytes > 0 {
            tracing::warn!(
                path = %f.path.display(),
                bytes = rep.truncated_bytes,
                "store: truncated partial or invalid tail after crash"
            );
            out.truncated_bytes += rep.truncated_bytes;
        }
        if let Some(g) = gz_last.get(&f.path) {
            // Both exist: a crash hit between rename of the .gz and removal of the .jsonl.
            if rep.last_seq.is_none() || rep.last_seq <= *g {
                tracing::info!(path = %f.path.display(), "store: removing day file already in .gz");
                if let Err(e) = fs::remove_file(&f.path) {
                    tracing::warn!(path = %f.path.display(), error = %e, "store: cannot remove duplicate");
                }
                continue;
            }
        }
        max_seq = max_seq.max(rep.last_seq);
        plain.push(f);
    }
    out.next_seq = max_seq.map_or(0, |s| s.saturating_add(1));
    out.last_day = files.iter().map(|f| f.day).max();
    let current = out.last_day.map_or(today, |d| d.max(today));
    out.old_files = plain
        .into_iter()
        .filter(|f| f.day < current)
        .map(|f| f.path.clone())
        .collect();
    Ok(out)
}

fn jsonl_sibling(gz: &StreamFile) -> PathBuf {
    gz.path.with_extension("")
}

/// Removes `*.tmp` files left by an interrupted atomic write or compression.
fn remove_temp_files(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "tmp") && e.file_type().is_ok_and(|t| t.is_file()) {
            match fs::remove_file(&p) {
                Ok(()) => tracing::info!(path = %p.display(), "store: removed leftover temp file"),
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "store: cannot remove temp file")
                }
            }
        }
    }
}

/// Heartbeat of this session (a new session has none: its gap is not measurable and
/// a gap of another session must not be reported as this session's downtime).
pub(crate) fn latest_heartbeat(session_dir: &Path) -> Option<Heartbeat> {
    super::read::read_json_file::<Heartbeat>(&session_dir.join(HEARTBEAT_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64) -> String {
        format!("{{\"v\":1,\"seq\":{seq}}}\n")
    }

    #[test]
    fn repair_truncates_partial_line() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        fs::write(&p, format!("{}{}{{\"v\":1,\"se", line(1), line(2))).unwrap();
        let r = repair_tail(&p).unwrap();
        assert_eq!(r.last_seq, Some(2));
        assert_eq!(r.truncated_bytes, 10);
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            format!("{}{}", line(1), line(2))
        );
    }

    #[test]
    fn repair_truncates_invalid_lines_and_nul_tail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        let mut data = format!("{}garbage\n", line(5)).into_bytes();
        data.extend_from_slice(&[0u8; 100]);
        fs::write(&p, &data).unwrap();
        let r = repair_tail(&p).unwrap();
        assert_eq!(r.last_seq, Some(5));
        assert_eq!(fs::read_to_string(&p).unwrap(), line(5));
    }

    #[test]
    fn repair_restores_missing_newline_of_valid_line() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        fs::write(&p, "{\"seq\":9}").unwrap();
        let r = repair_tail(&p).unwrap();
        assert_eq!(
            r,
            TailRepair {
                last_seq: Some(9),
                truncated_bytes: 0
            }
        );
        assert_eq!(fs::read_to_string(&p).unwrap(), "{\"seq\":9}\n");
    }

    #[test]
    fn repair_long_line_without_newline_in_chunks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        let mut data = line(3).into_bytes();
        data.extend(std::iter::repeat_n(b'a', 200_000));
        fs::write(&p, &data).unwrap();
        let r = repair_tail(&p).unwrap();
        assert_eq!(r.last_seq, Some(3));
        assert_eq!(r.truncated_bytes, 200_000);
    }

    #[test]
    fn empty_and_all_garbage_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.jsonl");
        fs::write(&p, "").unwrap();
        assert_eq!(repair_tail(&p).unwrap(), TailRepair::default());
        fs::write(&p, "junk").unwrap();
        let r = repair_tail(&p).unwrap();
        assert_eq!(r.last_seq, None);
        assert_eq!(fs::metadata(&p).unwrap().len(), 0);
    }
}
