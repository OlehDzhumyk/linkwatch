//! Readers for session directories: envelopes of one stream across days
//! (`.jsonl` and `.jsonl.gz`), the list of sessions, and summaries.
//!
//! All readers are synchronous and bounded per line; call them from a blocking thread.

use super::{META_FILE, SUMMARY_FILE, StreamFile, list_stream_files};
use crate::model::{Envelope, SessionMeta, Stream};
use chrono::NaiveDate;
use flate2::read::MultiGzDecoder;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// Longest line accepted. Longer lines are skipped as malformed.
pub(crate) const MAX_LINE: usize = 4 * 1024 * 1024;
/// Largest meta.json / summary.json accepted.
const MAX_SMALL_FILE: u64 = 4 * 1024 * 1024;

/// Reads lines with a length cap. Over-long lines are consumed and reported as `Line::TooLong`.
pub(crate) struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
}

pub(crate) enum Line<'a> {
    /// A complete or final line, without the trailing newline.
    Ok(&'a [u8]),
    TooLong,
}

impl<R: BufRead> LineReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Next line, `None` at end of input or on a read error (logged by the caller's count).
    pub(crate) fn next_line(&mut self) -> io::Result<Option<Line<'_>>> {
        self.buf.clear();
        let n = (&mut self.inner)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut self.buf)?;
        if n == 0 {
            return Ok(None);
        }
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
            return Ok(Some(Line::Ok(&self.buf)));
        }
        if self.buf.len() > MAX_LINE {
            // Discard the rest of this line.
            loop {
                let chunk = self.inner.fill_buf()?;
                if chunk.is_empty() {
                    break;
                }
                if let Some(i) = chunk.iter().position(|&b| b == b'\n') {
                    self.inner.consume(i + 1);
                    break;
                }
                let len = chunk.len();
                self.inner.consume(len);
            }
            return Ok(Some(Line::TooLong));
        }
        Ok(Some(Line::Ok(&self.buf)))
    }
}

type FileLines = LineReader<Box<dyn BufRead + Send>>;

/// Opens a stream file for reading, decompressing `.gz` files.
pub(crate) fn open_lines(path: &Path, gz: bool) -> io::Result<FileLines> {
    let f = File::open(path)?;
    let r: Box<dyn BufRead + Send> = if gz {
        Box::new(BufReader::with_capacity(
            64 * 1024,
            MultiGzDecoder::new(BufReader::new(f)),
        ))
    } else {
        Box::new(BufReader::with_capacity(64 * 1024, f))
    };
    Ok(LineReader::new(r))
}

/// Iterator over the envelopes of one stream, oldest day first.
///
/// Malformed lines and unreadable files are skipped and counted in [`EnvelopeIter::skipped`].
/// When a day exists both as `.gz` and as `.jsonl` (crash during compression), lines of the
/// `.jsonl` whose `seq` is already in the `.gz` are not returned twice.
pub struct EnvelopeIter {
    files: VecDeque<StreamFile>,
    /// Open file: reader, its day, whether it is gzip.
    cur: Option<(FileLines, NaiveDate, bool)>,
    /// Highest seq read from a `.gz` file of `day_gz_max.0`.
    day_gz_max: Option<(NaiveDate, u64)>,
    skipped: u64,
}

impl EnvelopeIter {
    /// Number of malformed lines and unreadable files skipped so far.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    fn open_next(&mut self) -> bool {
        while let Some(f) = self.files.pop_front() {
            match open_lines(&f.path, f.gz) {
                Ok(r) => {
                    self.cur = Some((r, f.day, f.gz));
                    return true;
                }
                Err(e) => {
                    tracing::debug!(path = %f.path.display(), error = %e, "store: cannot open file");
                    self.skipped += 1;
                }
            }
        }
        false
    }
}

enum Step {
    Eof,
    Broken,
    Bad,
    Blank,
    Env(Box<Envelope>),
}

impl Iterator for EnvelopeIter {
    type Item = Envelope;

    fn next(&mut self) -> Option<Envelope> {
        loop {
            if self.cur.is_none() && !self.open_next() {
                return None;
            }
            let (reader, day, gz) = self.cur.as_mut()?;
            let (day, gz) = (*day, *gz);
            let step = match reader.next_line() {
                Ok(None) => Step::Eof,
                // Truncated gzip or IO error: give up on this file.
                Err(_) => Step::Broken,
                Ok(Some(Line::TooLong)) => Step::Bad,
                Ok(Some(Line::Ok(bytes))) if bytes.iter().all(u8::is_ascii_whitespace) => {
                    Step::Blank
                }
                Ok(Some(Line::Ok(bytes))) => match serde_json::from_slice::<Envelope>(bytes) {
                    Ok(env) => Step::Env(Box::new(env)),
                    Err(_) => Step::Bad,
                },
            };
            let env = match step {
                Step::Eof => {
                    self.cur = None;
                    continue;
                }
                Step::Broken => {
                    self.skipped += 1;
                    self.cur = None;
                    continue;
                }
                Step::Bad => {
                    self.skipped += 1;
                    continue;
                }
                Step::Blank => continue,
                Step::Env(env) => *env,
            };
            if gz {
                let max = match self.day_gz_max {
                    Some((d, m)) if d == day => m.max(env.seq),
                    _ => env.seq,
                };
                self.day_gz_max = Some((day, max));
            } else if let Some((d, m)) = self.day_gz_max
                && d == day
                && env.seq <= m
            {
                continue;
            }
            return Some(env);
        }
    }
}

/// Iterates envelopes of `stream` in `session_dir` across days (`.jsonl` and `.jsonl.gz`),
/// skipping malformed lines (see [`EnvelopeIter::skipped`]).
pub fn iter(session_dir: &Path, stream: Stream) -> EnvelopeIter {
    let files = match list_stream_files(session_dir) {
        Ok(v) => v.into_iter().filter(|f| f.stream == stream).collect(),
        Err(_) => VecDeque::new(),
    };
    EnvelopeIter {
        files,
        cur: None,
        day_gz_max: None,
        skipped: 0,
    }
}

/// Like [`iter`], but skips day files before `since`.
pub fn iter_since(session_dir: &Path, stream: Stream, since: NaiveDate) -> EnvelopeIter {
    let mut it = iter(session_dir, stream);
    it.files.retain(|f| f.day >= since);
    it
}

/// All session directories of `data_dir` with a readable meta.json, oldest first.
pub fn sessions(data_dir: &Path) -> Vec<(PathBuf, SessionMeta)> {
    let Ok(rd) = std::fs::read_dir(data_dir) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, SessionMeta)> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let dir = e.path();
            let meta = read_json_file::<SessionMeta>(&dir.join(META_FILE))?;
            Some((dir, meta))
        })
        .collect();
    out.sort_by(|a, b| a.1.started.cmp(&b.1.started).then_with(|| a.0.cmp(&b.0)));
    out
}

/// summary.json of a session, if it exists and is valid JSON.
pub fn summary(session_dir: &Path) -> Option<serde_json::Value> {
    read_json_file(&session_dir.join(SUMMARY_FILE))
}

/// Time of the last heartbeat written in a session (its `heartbeat` file).
pub fn last_heartbeat(session_dir: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    #[derive(serde::Deserialize)]
    struct Ts {
        ts: chrono::DateTime<chrono::Utc>,
    }
    read_json_file::<Ts>(&session_dir.join(super::HEARTBEAT_FILE)).map(|t| t.ts)
}

/// Reads a small JSON file (size-capped). `None` on any error.
pub(crate) fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let f = File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(MAX_SMALL_FILE + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_SMALL_FILE {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn line_reader_caps_long_lines() {
        let mut data = vec![b'x'; MAX_LINE + 10];
        data.extend_from_slice(b"\nok\nlast");
        let mut r = LineReader::new(Cursor::new(data));
        assert!(matches!(r.next_line().unwrap(), Some(Line::TooLong)));
        assert!(matches!(r.next_line().unwrap(), Some(Line::Ok(b"ok"))));
        assert!(matches!(r.next_line().unwrap(), Some(Line::Ok(b"last"))));
        assert!(r.next_line().unwrap().is_none());
    }

    #[test]
    fn missing_dir_is_empty() {
        let mut it = iter(Path::new("/no/such/dir"), Stream::Events);
        assert!(it.next().is_none());
        assert!(sessions(Path::new("/no/such/dir")).is_empty());
    }
}
